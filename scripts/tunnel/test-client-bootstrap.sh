#!/usr/bin/env bash
# Exercise the portable client bootstrap in a disposable unprivileged root.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf 'usage: %s INSTALLER\n' "${0##*/}" >&2
    exit 64
fi

readonly INSTALLER=$1
[[ -f "$INSTALLER" ]] || {
    printf 'error: installer is absent: %s\n' "$INSTALLER" >&2
    exit 1
}

workspace=$(mktemp -d "${TMPDIR:-/tmp}/rqbit-tunnel-client-bootstrap.XXXXXX")
cleanup() {
    rm -rf -- "$workspace"
}
trap cleanup EXIT HUP INT TERM

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

assert_regular_file() {
    [[ -f "$1" && ! -L "$1" ]] || fail "expected regular file: $1"
}

assert_mode() {
    local expected=$1 path=$2 actual
    actual=$(stat -c '%a' -- "$path")
    [[ "$actual" == "$expected" ]] || fail "expected mode $expected for $path, got $actual"
}

bundle="$workspace/bundle"
root="$workspace/install"
unit_dir="$workspace/units"
mkdir -p "$bundle/systemd"
cp "$INSTALLER" "$bundle/install-client.sh"

cat >"$bundle/rqbit-tunnel" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$bundle/rqbit-tunnel-updater" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$bundle/rqbit-tunnel-tray" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$bundle/launcher" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$bundle/systemd/rqbit-tunnel-client.service" <<'EOF'
[Service]
ExecStart=/opt/rqbit-tunnel/launcher client run --config /etc/rqbit-tunnel/client.json
EOF
printf '1.2.3\n' >"$bundle/release-version.txt"
chmod 0755 "$bundle/install-client.sh" "$bundle/rqbit-tunnel" \
    "$bundle/rqbit-tunnel-updater" "$bundle/rqbit-tunnel-tray" "$bundle/launcher"

"$bundle/install-client.sh" --root "$root" --unit-dir "$unit_dir" --skip-service

assert_regular_file "$root/launcher"
assert_regular_file "$root/releases/1.2.3/payload/rqbit-tunnel"
assert_regular_file "$root/releases/1.2.3/payload/rqbit-tunnel-updater"
assert_regular_file "$root/releases/1.2.3/payload/rqbit-tunnel-tray"
assert_regular_file "$unit_dir/rqbit-tunnel-client.service"
assert_mode 755 "$root/releases/1.2.3"
assert_mode 755 "$root/releases/1.2.3/payload"
assert_mode 644 "$root/active.json"
[[ $(cat "$root/active.json") == '{"version":"1.2.3","payload_dir":"releases/1.2.3/payload","launcher_abi":1}' ]] ||
    fail 'bootstrap wrote an unexpected active release pointer'

if "$bundle/install-client.sh" --root "$root" --unit-dir "$unit_dir" --skip-service >/dev/null 2>&1; then
    fail 'bootstrap must not overwrite an immutable existing release directory'
fi

printf 'client bootstrap contract passed\n'
