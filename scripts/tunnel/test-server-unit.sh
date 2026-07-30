#!/usr/bin/env bash
# Validate the managed server systemd template without touching the host service manager.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf 'usage: %s UNIT_FILE\n' "${0##*/}" >&2
    exit 64
fi

source_unit=$1
if [[ ! -f "$source_unit" ]]; then
    printf 'error: service template is absent: %s\n' "$source_unit" >&2
    exit 1
fi

tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/rqbit-tunnel-unit.XXXXXX")
trap 'rm -rf -- "$tmp_root"' EXIT HUP INT TERM

test_bin="$tmp_root/opt/rqbit-tunnel/rqbit-tunnel"
test_config="$tmp_root/etc/rqbit-tunnel/server.json"
unit_copy="$tmp_root/rqbit-tunnel-server.service"

mkdir -p "$(dirname "$test_bin")" "$(dirname "$test_config")"
printf '#!/bin/sh\nexit 0\n' >"$test_bin"
printf '{}\n' >"$test_config"
chmod 0755 "$test_bin"
chmod 0600 "$test_config"

require_line() {
    local expected=$1
    if ! grep -Fqx -- "$expected" "$source_unit"; then
        printf 'error: missing required directive: %s\n' "$expected" >&2
        exit 1
    fi
}

require_line '[Unit]'
require_line 'After=network-online.target'
require_line 'Wants=network-online.target'
require_line '[Service]'
require_line 'ExecStart=/opt/rqbit-tunnel/rqbit-tunnel server run --config /etc/rqbit-tunnel/server.json'
require_line 'Restart=on-failure'
require_line 'RestartSec=3'
require_line 'NoNewPrivileges=true'
require_line '[Install]'
require_line 'WantedBy=multi-user.target'

if grep -Eq '^\[Socket\]$' "$source_unit"; then
    printf 'error: the managed server unit must not be socket-activated\n' >&2
    exit 1
fi

if grep -Fqx -e 'After=rqbit.socket' -e 'Requires=rqbit.socket' -e 'Also=rqbit.socket' "$source_unit"; then
    printf 'error: the managed server unit must not depend on rqbit.socket\n' >&2
    exit 1
fi

# Keep the production command exact above, then replace both absolute paths in
# the disposable copy so systemd-analyze can verify an executable that exists.
while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == 'ExecStart=/opt/rqbit-tunnel/rqbit-tunnel server run --config /etc/rqbit-tunnel/server.json' ]]; then
        printf 'ExecStart=%s server run --config %s\n' "$test_bin" "$test_config"
    else
        printf '%s\n' "$line"
    fi
done <"$source_unit" >"$unit_copy"

if command -v systemd-analyze >/dev/null 2>&1; then
    systemd-analyze verify "$unit_copy"
else
    printf 'note: systemd-analyze is unavailable; skipped unit parser verification\n' >&2
fi

printf 'validated %s\n' "$source_unit"
