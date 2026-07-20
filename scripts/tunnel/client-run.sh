#!/usr/bin/env bash
# ── rqbit tunnel — client launcher (Linux) ──────────────────────────────────
#
#   ./client-run.sh [server-host:port]
#
# The server address is OPTIONAL. Given (arg / TUNNEL_SERVER / prompt) it is used
# as a fast, reliable path. Left EMPTY, the client finds the server purely via
# the DHT (using the pinned server key) — handy when the server's IP changes,
# but it needs the server publicly reachable on its tunnel port and can take up
# to ~1 minute to discover.
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
[ -n "$SERVER" ] || read -rp "Server address host:port (or press Enter to find it via DHT): " SERVER

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

# DHT is left ENABLED: it lets the client find the server by its carrier hash
# (dynamic-IP friendly) and blends with real BitTorrent DHT traffic.
HTTP_API="${RQBIT_HTTP_API:-127.0.0.1:3030}"
ARGS=(
    --disable-tcp-listen --disable-upnp-port-forward
    --http-api-listen-addr "$HTTP_API"
    server start --disable-persistence "$DATA"
    --tunnel-mode client
    --tunnel-socks-listen "$SOCKS"
    --tunnel-client-key "$KEYS/client.key"
    --tunnel-server-key "$KEYS/server.pub"
)
if [ -n "$SERVER" ]; then
    ARGS+=(--tunnel-server-addr "$SERVER")
    echo "Tunnel client -> $SERVER (with DHT)"
else
    echo "Tunnel client -> discovering the server via DHT (can take up to ~1 min)"
fi
echo "Point your browser/app SOCKS5 proxy at $SOCKS"
exec "$BIN" "${ARGS[@]}"
