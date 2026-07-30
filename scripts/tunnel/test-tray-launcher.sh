#!/usr/bin/env bash
# Verify the stable launcher selects the tray companion without forwarding its selector.
set -euo pipefail

usage() {
    cat <<'EOF'
usage: test-tray-launcher.sh LAUNCHER PAYLOAD TRAY
EOF
}

(($# == 3)) || {
    usage >&2
    exit 64
}

launcher=$1
payload=$2
tray=$3
for path in "$launcher" "$payload" "$tray"; do
    [[ -f "$path" && ! -L "$path" && -x "$path" ]] || {
        printf 'error: expected executable regular file: %s\n' "$path" >&2
        exit 1
    }
done

root=$(mktemp -d "${TMPDIR:-/tmp}/rqbit-tunnel-tray-launcher.XXXXXX")
cleanup() {
    rm -rf -- "$root"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$root/releases/1.2.3/payload"
install -m 0755 -- "$launcher" "$root/launcher"
install -m 0755 -- "$payload" "$root/releases/1.2.3/payload/rqbit-tunnel"
install -m 0755 -- "$tray" "$root/releases/1.2.3/payload/rqbit-tunnel-tray"
printf '%s' '{"version":"1.2.3","payload_dir":"releases/1.2.3/payload","launcher_abi":1}' >"$root/active.json"

if ! output=$("$root/launcher" tray --help 2>&1); then
    printf 'error: stable launcher rejected tray companion help:\n%s\n' "$output" >&2
    exit 1
fi
[[ "$output" == *'Run the per-user tunnel status tray'* ]] || {
    printf 'error: tray companion help was not rendered:\n%s\n' "$output" >&2
    exit 1
}

printf 'tray launcher contract passed\n'
