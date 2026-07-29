#!/usr/bin/env bash
set -euo pipefail

unit="${1:?pass path to rqbit-tunnel-client.service}"
grep -qx 'ExecStart=/opt/rqbit-tunnel/launcher client run --config /etc/rqbit-tunnel/client.json' "$unit"
grep -qx 'Restart=on-failure' "$unit"
grep -qx 'NoNewPrivileges=true' "$unit"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/rqbit-tunnel-client-unit.XXXXXX")
trap 'rm -rf -- "$tmp_root"' EXIT HUP INT TERM

test_bin="$tmp_root/opt/rqbit-tunnel/launcher"
test_config="$tmp_root/etc/rqbit-tunnel/client.json"
unit_copy="$tmp_root/rqbit-tunnel-client.service"

mkdir -p "$(dirname "$test_bin")" "$(dirname "$test_config")"
printf '#!/bin/sh\nexit 0\n' >"$test_bin"
printf '{}\n' >"$test_config"
chmod 0755 "$test_bin"
chmod 0600 "$test_config"

while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == 'ExecStart=/opt/rqbit-tunnel/launcher client run --config /etc/rqbit-tunnel/client.json' ]]; then
        printf 'ExecStart=%s client run --config %s\n' "$test_bin" "$test_config"
    else
        printf '%s\n' "$line"
    fi
done <"$unit" >"$unit_copy"

command -v systemd-analyze >/dev/null || exit 0
systemd-analyze verify "$unit_copy"
