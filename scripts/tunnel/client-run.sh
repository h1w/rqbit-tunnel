#!/usr/bin/env bash
# ── rqbit tunnel — client launcher (Linux) ──────────────────────────────────
#
#   ./client-run.sh <server-host:port>
#
# Expects client.key and server.pub next to this script (as printed by the
# server quickstart). Then point your browser/app SOCKS5 proxy at 127.0.0.1:1080.
#
# Overridable via env: RQBIT_BIN, TUNNEL_KEYS (dir with keys), SOCKS_LISTEN.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${RQBIT_BIN:-$HERE/rqbit}"
[ -x "$BIN" ] || BIN="$(command -v rqbit || true)"
[ -x "$BIN" ] || {
    echo "error: rqbit binary not found (put it next to this script or on PATH, or set RQBIT_BIN)" >&2
    exit 1
}

SERVER="${1:-${TUNNEL_SERVER:-}}"
[ -n "$SERVER" ] || read -rp "Server address (host:port): " SERVER

KEYS="${TUNNEL_KEYS:-$HERE}"
SOCKS="${SOCKS_LISTEN:-127.0.0.1:1080}"
DATA="${RQBIT_TUNNEL_DIR:-$HOME/.rqbit-tunnel}/client-data"
mkdir -p "$DATA"

for f in client.key server.pub; do
    [ -f "$KEYS/$f" ] || {
        echo "error: $KEYS/$f not found — copy it from the server quickstart output" >&2
        exit 1
    }
done

echo "Tunnel client -> $SERVER"
echo "Point your browser/app SOCKS5 proxy at $SOCKS"
HTTP_API="${RQBIT_HTTP_API:-127.0.0.1:3030}"
exec "$BIN" \
    --disable-dht --disable-dht-persistence \
    --disable-tcp-listen --disable-upnp-port-forward \
    --http-api-listen-addr "$HTTP_API" \
    server start --disable-persistence "$DATA" \
    --tunnel-mode client \
    --tunnel-socks-listen "$SOCKS" \
    --tunnel-server-addr "$SERVER" \
    --tunnel-client-key "$KEYS/client.key" \
    --tunnel-server-key "$KEYS/server.pub"
