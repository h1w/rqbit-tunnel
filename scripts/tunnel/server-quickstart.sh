#!/usr/bin/env bash
# Install and manage the root-owned rqbit tunnel server service.
set -euo pipefail
umask 077

readonly SERVICE_NAME='rqbit-tunnel-server.service'
readonly INSTALL_DIR='/opt/rqbit-tunnel'
readonly INSTALL_BIN="$INSTALL_DIR/rqbit-tunnel"
readonly CONFIG_DIR='/etc/rqbit-tunnel'
readonly CONFIG_PATH="$CONFIG_DIR/server.json"
readonly SERVER_KEY="$CONFIG_DIR/server.key"
readonly STATE_DIR='/var/lib/rqbit-tunnel'
readonly STATE_DB="$STATE_DIR/server-state.db"
readonly CARRIER_DIR="$STATE_DIR/carrier"
readonly RUN_DIR='/run/rqbit-tunnel'
readonly CONTROL_SOCKET="$RUN_DIR/server.sock"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

usage() {
    cat <<'EOF'
usage: server-quickstart.sh [--skip-tui]

Install or repair the managed rqbit tunnel server service. The script only asks
for root privileges while inspecting or changing protected installation state
and managing systemd.

When /opt/rqbit-tunnel/rqbit-tunnel is not already installed, set
RQBIT_TUNNEL_BIN to the explicit rqbit-tunnel binary to install. The script
never selects a binary from PATH. On a first key setup, set RQBIT_KEYGEN_BIN to
the explicit bundled rqbit binary (unless a bundled ./rqbit is beside this
script). Set SERVER_IP to the reachable public IPv4 address to avoid external
discovery. RQBIT_TUNNEL_UNIT may override the service-template source.

--skip-tui  Finish the installation without opening the interactive server TUI.
             This is the only noninteractive mode; it is intended for automation.
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

absolute_path() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *) printf '%s/%s\n' "$PWD" "$1" ;;
    esac
}


is_regular_file() {
    [[ -f "$1" && ! -L "$1" ]]
}

require_regular_file() {
    is_regular_file "$1" || die "expected a regular file: $1"
}

require_executable_file() {
    require_regular_file "$1"
    [[ -x "$1" ]] || die "expected an executable file: $1"
}

run_as_root() {
    if (( EUID == 0 )); then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo -- "$@"
    else
        die 'root privileges are required for installation; run as root or install sudo'
    fi
}

existing_regular_file_as_root() {
    local path=$1 parent=${1%/*}

    # First installs can prepare source material without elevation. Once the
    # protected parent exists, inspect it as root so access denial is never
    # misclassified as a missing config or key.
    if [[ ! -e "$parent" && ! -L "$parent" ]]; then
        return 1
    fi
    if run_as_root test -L "$path"; then
        die "$path exists but is a symbolic link"
    fi
    if run_as_root test -e "$path"; then
        run_as_root test -f "$path" || die "$path exists but is not a regular file"
        return 0
    fi
    return 1
}

valid_port() {
    [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] &&
        (( 10#$1 >= 1024 && 10#$1 <= 65535 ))
}

is_routable_ipv4() {
    local address=$1 first second third fourth octet

    [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r first second third fourth <<<"$address"
    for octet in "$first" "$second" "$third" "$fourth"; do
        (( 10#$octet <= 255 )) || return 1
    done

    first=$((10#$first))
    second=$((10#$second))
    third=$((10#$third))
    if (( first == 0 || first == 10 || first == 127 || first >= 224 )); then
        return 1
    fi
    if (( first == 100 && second >= 64 && second <= 127 )); then
        return 1
    fi
    if (( first == 169 && second == 254 )); then
        return 1
    fi
    if (( first == 172 && second >= 16 && second <= 31 )); then
        return 1
    fi
    if (( first == 192 )); then
        # Conservative 192.0.0/24 handling plus non-global IANA special-use ranges.
        if (( (second == 0 && (third == 0 || third == 2)) ||
            (second == 88 && third == 99) ||
            second == 168 )); then
            return 1
        fi
    fi
    if (( first == 198 )); then
        if (( second == 18 || second == 19 || (second == 51 && third == 100) )); then
            return 1
        fi
    fi
    if (( first == 203 && second == 0 && third == 113 )); then
        return 1
    fi
}

discover_server_ip() {
    local endpoint candidate

    if [[ -n "${SERVER_IP:-}" ]]; then
        is_routable_ipv4 "$SERVER_IP" || die 'SERVER_IP must be a reachable public numeric IPv4 address'
        printf '%s\n' "$SERVER_IP"
        return
    fi

    command -v curl >/dev/null 2>&1 || die 'set SERVER_IP to a reachable public numeric IPv4 address (curl is unavailable for discovery)'
    for endpoint in 'https://api.ipify.org' 'https://checkip.amazonaws.com'; do
        candidate=$(curl --fail --silent --show-error --max-time 5 --ipv4 "$endpoint" 2>/dev/null | tr -d '\r\n' || true)
        if is_routable_ipv4 "$candidate"; then
            printf '%s\n' "$candidate"
            return
        fi
    done

    die 'could not determine a reachable public numeric IPv4 address; set SERVER_IP explicitly'
}

valid_generated_key_file() {
    [[ -f "$1" && ! -L "$1" ]] || return 1
    [[ "$(grep -c '^' "$1")" -eq 1 ]] || return 1
    LC_ALL=C grep -Eqx '[[:xdigit:]]{64}' "$1"
}

normalize_generated_key() {
    local source=$1 destination=$2

    valid_generated_key_file "$source" || return 1
    LC_ALL=C tr -d '\r\n' <"$source" >"$destination"
    [[ "$(wc -c < "$destination")" -eq 64 ]] &&
        LC_ALL=C grep -Eqx '[[:xdigit:]]{64}' "$destination"
}

valid_installed_key() {
    run_as_root bash -c '
        path=$1
        [ -f "$path" ] && [ ! -L "$path" ] &&
            [ "$(wc -c < "$path")" -eq 64 ] &&
            LC_ALL=C grep -Eqx "[[:xdigit:]]{64}" "$path"
    ' bash "$SERVER_KEY"
}

control_socket_exists() {
    run_as_root test -e "$CONTROL_SOCKET" || run_as_root test -L "$CONTROL_SOCKET"
}

wait_for_control_socket_absence() {
    local deadline=$((SECONDS + 30))

    while control_socket_exists; do
        if (( SECONDS >= deadline )); then
            return 1
        fi
        sleep 1
    done
}

establish_managed_socket_ownership() {
    if run_as_root systemctl is-active --quiet "$SERVICE_NAME" >/dev/null 2>&1; then
        printf 'Stopping the active managed server before applying the installation...\n' >&2
        run_as_root systemctl stop "$SERVICE_NAME"
        if ! wait_for_control_socket_absence; then
            run_as_root systemctl --no-pager --full status "$SERVICE_NAME" >&2 || true
            die "managed service stopped but $CONTROL_SOCKET is still present; inspect it rather than starting beside an unknown server"
        fi
    elif control_socket_exists; then
        die "managed service is inactive but $CONTROL_SOCKET exists; inspect or remove the unknown control socket before continuing"
    fi
}

wait_for_health() {
    local health_json deadline

    printf 'Waiting for an active managed server and local control socket health...\n' >&2
    deadline=$((SECONDS + 30))
    while (( SECONDS < deadline )); do
        if run_as_root systemctl is-active --quiet "$SERVICE_NAME" >/dev/null 2>&1 &&
            health_json=$(run_as_root "$INSTALL_BIN" server users list --json 2>/dev/null); then
            case "$health_json" in
                \{*|\[* ) return 0 ;;
            esac
        fi
        sleep 1
    done

    run_as_root systemctl --no-pager --full status "$SERVICE_NAME" >&2 || true
    die 'managed server did not become active and return JSON health within 30 seconds'
}

skip_tui=0
while (($#)); do
    case "$1" in
        --skip-tui)
            skip_tui=1
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "unknown argument: $1"
            ;;
    esac
    shift
done

peer_port=${PEER_PORT:-4242}
valid_port "$peer_port" ||
    die 'PEER_PORT must be an unprivileged integer from 1024 through 65535 (the service drops all capabilities)'

unit_source=${RQBIT_TUNNEL_UNIT:-"$SCRIPT_DIR/../../systemd/$SERVICE_NAME"}
unit_source=$(absolute_path "$unit_source")
require_regular_file "$unit_source"

installed_binary_exists=0
if existing_regular_file_as_root "$INSTALL_BIN"; then
    installed_binary_exists=1
fi

needs_config=1
if existing_regular_file_as_root "$CONFIG_PATH"; then
    needs_config=0
fi

needs_key=1
if existing_regular_file_as_root "$SERVER_KEY"; then
    needs_key=0
fi

managed_state_exists=0
if existing_regular_file_as_root "$STATE_DB"; then
    managed_state_exists=1
fi
if (( needs_config && needs_key )); then
    (( ! managed_state_exists )) ||
        die 'managed server state exists without its original server.json and server.key; restore the protected identity instead of generating a replacement'
elif (( ! needs_config && ! needs_key )); then
    (( managed_state_exists )) ||
        die 'managed server.json and server.key exist without server-state.db; restore the original managed state before continuing'
else
    die 'managed server identity is incomplete; restore the original server.json and server.key instead of generating replacement enrollment identity'
fi

binary_source=${RQBIT_TUNNEL_BIN:-}
if [[ -n "$binary_source" ]]; then
    binary_source=$(absolute_path "$binary_source")
    require_executable_file "$binary_source"
elif (( ! installed_binary_exists )); then
    die "set RQBIT_TUNNEL_BIN to the explicit rqbit-tunnel binary to install at $INSTALL_BIN"
fi

staging=$(mktemp -d "${TMPDIR:-/tmp}/rqbit-tunnel-install.XXXXXX")
cleanup() {
    if [[ -n "${staging:-}" ]]; then
        rm -rf -- "$staging"
    fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

if (( needs_config )); then
    server_ip=$(discover_server_ip)
    cat >"$staging/server.json" <<EOF
{
  "schema_version": 1,
  "peer_listen": "$server_ip:$peer_port",
  "egress": {
    "allow_private": false,
    "allow_loopback": false,
    "allow_link_local": false,
    "allow_multicast": false
  },
  "default_client_socks_listen": "127.0.0.1:1080",
  "default_client_carriers": 4
}
EOF
fi

if (( needs_key )); then
    keygen_bin=${RQBIT_KEYGEN_BIN:-}
    if [[ -z "$keygen_bin" && -x "$SCRIPT_DIR/rqbit" ]]; then
        # A sibling binary is part of the same release bundle, unlike PATH.
        keygen_bin="$SCRIPT_DIR/rqbit"
    fi
    [[ -n "$keygen_bin" ]] || die 'set RQBIT_KEYGEN_BIN to the explicit bundled rqbit binary for first-time key generation'
    keygen_bin=$(absolute_path "$keygen_bin")
    require_executable_file "$keygen_bin"

    keygen_dir="$staging/keygen"
    if ! "$keygen_bin" tunnel keygen --output-dir "$keygen_dir" >/dev/null 2>&1; then
        die 'bundled key generation failed; no server key was installed'
    fi
    normalize_generated_key "$keygen_dir/server.key" "$staging/server.key" ||
        die 'bundled key generation did not produce one exact 64-character hexadecimal server key'
fi

establish_managed_socket_ownership

run_as_root install -d -o root -g root -m 0755 "$INSTALL_DIR"
run_as_root install -d -o root -g root -m 0750 "$CONFIG_DIR"
run_as_root install -d -o root -g root -m 0750 "$STATE_DIR"
run_as_root install -d -o root -g root -m 0750 "$CARRIER_DIR"
run_as_root install -d -o root -g root -m 0750 "$RUN_DIR"

if [[ -n "$binary_source" && "$binary_source" != "$INSTALL_BIN" ]]; then
    run_as_root install -o root -g root -m 0755 "$binary_source" "$INSTALL_BIN"
fi
run_as_root chown root:root "$INSTALL_BIN"
run_as_root chmod 0755 "$INSTALL_BIN"

if (( needs_config )); then
    run_as_root install -o root -g root -m 0600 "$staging/server.json" "$CONFIG_PATH"
fi
run_as_root chown root:root "$CONFIG_PATH"
run_as_root chmod 0600 "$CONFIG_PATH"

if (( needs_key )); then
    # Do not retain or copy the generated client material; only install server.key.
    run_as_root install -o root -g root -m 0600 "$staging/server.key" "$SERVER_KEY"
fi
valid_installed_key || die "$SERVER_KEY must contain exactly one 64-character hexadecimal key"
run_as_root chown root:root "$SERVER_KEY"
run_as_root chmod 0600 "$SERVER_KEY"

run_as_root install -d -o root -g root -m 0755 /etc/systemd/system
unit_destination="/etc/systemd/system/$SERVICE_NAME"
run_as_root install -o root -g root -m 0644 "$unit_source" "$unit_destination"
run_as_root systemctl daemon-reload
run_as_root systemctl enable --now "$SERVICE_NAME"

# Generated private material is no longer needed before waiting or opening the TUI.
cleanup
staging=''

wait_for_health
printf 'Managed rqbit tunnel server is healthy.\n'

if (( skip_tui )); then
    printf 'Server TUI intentionally skipped by --skip-tui.\n'
else
    printf 'Opening the server TUI (exit it to return to your shell).\n'
    run_as_root "$INSTALL_BIN" server tui
fi
