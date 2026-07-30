#!/usr/bin/env bash
# Interactive control menu for the managed rqbit tunnel client.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
MANAGED_LAUNCHER='/opt/rqbit-tunnel/launcher'
BIN="${RQBIT_TUNNEL_BIN:-}"

if [[ -z "$BIN" && -x "$MANAGED_LAUNCHER" ]]; then
    BIN=$MANAGED_LAUNCHER
elif [[ -z "$BIN" && -x "$HERE/install-client.sh" && -f "$HERE/release-version.txt" ]]; then
    printf 'Installing the managed client release from this bundle...\n'
    sudo -- "$HERE/install-client.sh"
    BIN=$MANAGED_LAUNCHER
elif [[ -z "$BIN" && -x "$HERE/rqbit-tunnel" ]]; then
    BIN="$HERE/rqbit-tunnel"
elif [[ -z "$BIN" ]]; then
    BIN="$(command -v rqbit-tunnel || true)"
fi

if [[ -z "$BIN" || ! -x "$BIN" ]]; then
    echo "error: rqbit-tunnel was not found; use a complete release bundle or set RQBIT_TUNNEL_BIN" >&2
    exit 1
fi

run_client() {
    if "$BIN" "$@"; then
        return 0
    fi
    echo "operation failed" >&2
    return 1
}

run_protected_client() {
    # Keep the exact executable and argument vector intact for sudo.
    if sudo -- "$BIN" "$@"; then
        return 0
    fi
    echo "protected operation failed" >&2
    return 1
}

configure_client() {
    local endpoint socks carriers allow_lan
    local -a args=(client config set)

    read -r -p "Server endpoint HOST:PORT (blank keeps current): " endpoint
    read -r -p "SOCKS bind HOST:PORT (blank keeps current): " socks
    read -r -p "Carrier count (blank keeps current): " carriers
    read -r -p "Allow unauthenticated LAN SOCKS [true/false, blank keeps current]: " allow_lan

    [[ -z "$endpoint" ]] || args+=(--server-addr "$endpoint")
    [[ -z "$socks" ]] || args+=(--socks-listen "$socks")
    [[ -z "$carriers" ]] || args+=(--carriers "$carriers")
    case "$allow_lan" in
        "") ;;
        true|false) args+=(--allow-unauthenticated-lan-socks "$allow_lan") ;;
        *)
            echo "allow unauthenticated LAN SOCKS must be true, false, or blank" >&2
            return
            ;;
    esac

    if ((${#args[@]} == 3)); then
        echo "no configuration changes selected"
        return
    fi
    run_protected_client "${args[@]}"
}

service_menu() {
    local action
    cat <<'EOF'
Service actions:
  1) install/reload service definition
  2) start
  3) stop
  4) restart
  5) enable autostart
  6) disable autostart
EOF
    read -r -p "Select service action: " action
    case "$action" in
        1) run_protected_client client service install ;;
        2) run_protected_client client service start ;;
        3) run_protected_client client service stop ;;
        4) run_protected_client client service restart ;;
        5) run_protected_client client service enable-autostart ;;
        6) run_protected_client client service disable-autostart ;;
        *) echo "unknown service action" >&2 ;;
    esac
}

while true; do
    cat <<'EOF'

rqbit tunnel client
  1) open client dashboard
  2) import enrollment bundle
  3) show configuration
  4) configure client
  5) manage service
  6) show service status
  q) quit
EOF
    read -r -p "Select action: " selection
    case "$selection" in
        1) run_client client tui ;;
        2)
            read -r -p "Enrollment bundle path: " bundle
            if [[ -n "$bundle" ]] && run_protected_client client import --bundle "$bundle"; then
                run_protected_client client service install &&
                    run_protected_client client service enable-autostart &&
                    run_protected_client client service start
            fi
            ;;
        3) run_protected_client client config show ;;
        4) configure_client ;;
        5) service_menu ;;
        6) run_client client service status ;;
        q|Q) exit 0 ;;
        *) echo "unknown action" >&2 ;;
    esac
done
