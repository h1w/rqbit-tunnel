#!/usr/bin/env bash
# Verify client-run.sh turns a successful enrollment import into a managed service.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf 'usage: %s CLIENT_RUN_SCRIPT\n' "${0##*/}" >&2
    exit 64
fi

readonly CLIENT_RUN_SCRIPT=$1
[[ -f "$CLIENT_RUN_SCRIPT" ]] || {
    printf 'error: client launcher is absent: %s\n' "$CLIENT_RUN_SCRIPT" >&2
    exit 1
}

workspace=$(mktemp -d "${TMPDIR:-/tmp}/rqbit-tunnel-client-run.XXXXXX")
cleanup() {
    rm -rf -- "$workspace"
}
trap cleanup EXIT HUP INT TERM

log="$workspace/invocations"
mkdir -p "$workspace/bin"
cat >"$workspace/bin/rqbit-tunnel" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$RQBIT_TUNNEL_TEST_LOG"
EOF
cat >"$workspace/bin/sudo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == -- ]] && shift
exec "$@"
EOF
chmod 0755 "$workspace/bin/rqbit-tunnel" "$workspace/bin/sudo"

printf '2\n/secure/alice.rqbt\nq\n' | env \
    PATH="$workspace/bin:$PATH" \
    RQBIT_TUNNEL_BIN="$workspace/bin/rqbit-tunnel" \
    RQBIT_TUNNEL_TEST_LOG="$log" \
    bash "$CLIENT_RUN_SCRIPT" >/dev/null

expected=$(cat <<'EOF'
client import --bundle /secure/alice.rqbt
client service install
client service enable-autostart
client service start
EOF
)
[[ $(cat "$log") == "$expected" ]] || {
    printf 'error: enrollment did not install, enable, and start the managed service\n' >&2
    cat "$log" >&2
    exit 1
}

printf 'client launcher enrollment contract passed\n'
