#!/usr/bin/env bash
# Exercise an installed Linux release bundle under a real systemd PID 1.
set -euo pipefail

readonly SERVICE_NAME='rqbit-tunnel-client.service'
readonly INSTALL_ROOT='/opt/rqbit-tunnel'
readonly CONFIG_DIR='/etc/rqbit-tunnel'
readonly DATA_DIR='/var/lib/rqbit-tunnel'
readonly RUN_DIR='/run/rqbit-tunnel-client'

usage() {
    cat <<'EOF'
usage: smoke-systemd.sh --bundle PATH

Runs only inside a disposable privileged Linux systemd container. It installs
the supplied Linux release archive, starts the managed client, checks local IPC
status, then stops and removes all managed state.
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

bundle=''
while (($#)); do
    case "$1" in
        --bundle)
            (($# >= 2)) || die '--bundle needs a path'
            bundle=$2
            shift
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

[[ -n "$bundle" ]] || die '--bundle is required'
[[ -f "$bundle" && ! -L "$bundle" ]] || die "bundle is not a regular file: $bundle"
(( EUID == 0 )) || die 'this smoke test must run as root in its disposable container'
command -v systemctl >/dev/null 2>&1 || die 'systemd is unavailable'

# systemd-tmpfiles clears /tmp during PID 1 startup, which races this smoke test.
work=$(mktemp -d /var/tmp/rqbit-tunnel-systemd-smoke.XXXXXX)
for protected_path in "$INSTALL_ROOT" "$CONFIG_DIR" "$DATA_DIR" "$RUN_DIR" "/etc/systemd/system/$SERVICE_NAME"; do
    [[ ! -e "$protected_path" && ! -L "$protected_path" ]] ||
        die "refusing to overwrite existing managed path: $protected_path"
done

cleanup() {
    systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
    rm -f -- "/etc/systemd/system/$SERVICE_NAME"
    systemctl daemon-reload >/dev/null 2>&1 || true
    rm -rf -- "$INSTALL_ROOT" "$CONFIG_DIR" "$DATA_DIR" "$RUN_DIR" "$work"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/extract"
tar -xzf "$bundle" -C "$work/extract"
shopt -s nullglob
entries=("$work/extract"/*)
(( ${#entries[@]} == 1 )) || die 'release archive must contain exactly one wrapper directory'
wrapper=${entries[0]}
[[ -d "$wrapper" && ! -L "$wrapper" ]] || die 'release archive wrapper is not a real directory'
[[ -x "$wrapper/install-client.sh" && -x "$wrapper/rqbit-tunnel-tray" \
    && -f "$wrapper/release-version.txt" ]] ||
    die 'release archive has no managed client bootstrap assets'

"$wrapper/install-client.sh" --skip-service

install -d -m 0700 -- "$CONFIG_DIR" "$DATA_DIR"
printf '%064d' 1 >"$CONFIG_DIR/client.key"
chmod 0600 "$CONFIG_DIR/client.key"
cat >"$CONFIG_DIR/client.json" <<'EOF'
{
  "schema_version": 1,
  "status_owner": {"platform": "unix", "uid": 1000},
  "server_addr": "127.0.0.1:4242",
  "server_public_key": "0202020202020202020202020202020202020202020202020202020202020202",
  "client_key_path": "/etc/rqbit-tunnel/client.key",
  "socks_listen": "127.0.0.1:1080",
  "carriers": 1,
  "carrier_root": "/var/lib/rqbit-tunnel/client-carrier",
  "allow_unauthenticated_lan_socks": false
}
EOF
chmod 0644 "$CONFIG_DIR/client.json"

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
for _ in $(seq 1 30); do
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        status_json=$("$INSTALL_ROOT/launcher" client service status --json 2>/dev/null || true)
        if [[ "$status_json" == *'"service":"running"'* ]]; then
            break
        fi
    fi
    sleep 1
done

systemctl is-active --quiet "$SERVICE_NAME" || {
    systemctl --no-pager --full status "$SERVICE_NAME" >&2 || true
    die 'client service did not become active'
}
status_json=$("$INSTALL_ROOT/launcher" client service status --json)
[[ "$status_json" == *'"service":"running"'* ]] || die "client status was not running: $status_json"

command -v setpriv >/dev/null 2>&1 || die 'setpriv is required to exercise desktop status access'
desktop_status_json=$(setpriv --reuid=1000 --regid=1000 --clear-groups \
    "$INSTALL_ROOT/launcher" client service status --json)
[[ "$desktop_status_json" == *'"service":"running"'* ]] ||
    die "desktop client status was not running: $desktop_status_json"

first_main_pid=$(systemctl show --property=MainPID --value "$SERVICE_NAME")
[[ "$first_main_pid" =~ ^[1-9][0-9]*$ ]] || die "client service has no main PID: $first_main_pid"

updated_wrapper="$work/updated-bundle"
cp -a -- "$wrapper" "$updated_wrapper"
printf '9.0.1\n' >"$updated_wrapper/release-version.txt"
"$updated_wrapper/install-client.sh"

second_main_pid=$(systemctl show --property=MainPID --value "$SERVICE_NAME")
[[ "$second_main_pid" =~ ^[1-9][0-9]*$ && "$second_main_pid" != "$first_main_pid" ]] ||
    die 'installing an updated release did not restart the active client service'

systemctl disable --now "$SERVICE_NAME"
if systemctl is-active --quiet "$SERVICE_NAME"; then
    die 'client service remained active after disable --now'
fi

printf 'systemd release smoke passed\n'
