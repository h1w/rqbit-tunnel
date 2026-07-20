#!/usr/bin/env bash
# ── rqbit tunnel — server quickstart (Linux / VPS) ──────────────────────────
#
# One command: generates keys (once), starts the encrypted tunnel server, and
# prints exactly what to copy to your desktop client. Run it on the VPS.
#
#   ./server-quickstart.sh
#
# Overridable via env:
#   RQBIT_BIN=/path/to/rqbit     PEER_PORT=4242     SERVER_IP=1.2.3.4
#   RQBIT_TUNNEL_DIR=~/.rqbit-tunnel

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${RQBIT_BIN:-$HERE/rqbit}"
[ -x "$BIN" ] || BIN="$(command -v rqbit || true)"
[ -x "$BIN" ] || {
    echo "error: rqbit binary not found (put it next to this script or on PATH, or set RQBIT_BIN)" >&2
    exit 1
}

DIR="${RQBIT_TUNNEL_DIR:-$HOME/.rqbit-tunnel}"
PEER_PORT="${PEER_PORT:-4242}"
mkdir -p "$DIR/keys" "$DIR/data" "$DIR/carrier"

# 1. Generate keys once (no Python needed — the binary does it).
if [ ! -f "$DIR/keys/server.key" ]; then
    "$BIN" tunnel keygen --output-dir "$DIR/keys"
fi
cp -f "$DIR/keys/client.pub" "$DIR/keys/allowed-clients.txt"

# 2. Public address to hand to the client.
PUBIP="${SERVER_IP:-$(curl -fsS https://checkip.amazonaws.com 2>/dev/null || echo YOUR_SERVER_IP)}"

# 3. Print the client bundle.
cat <<EOF

================= CLIENT SETUP (copy to your desktop) =================
1) Save these two files next to the rqbit binary on your desktop:

--- client.key ---
$(cat "$DIR/keys/client.key")--- server.pub ---
$(cat "$DIR/keys/server.pub")
2) Start the client:
     Linux:    ./client-run.sh $PUBIP:$PEER_PORT
     Windows:  double-click client-run.bat  (enter $PUBIP:$PEER_PORT when asked)
   The address is the reliable fast path. You may instead leave it EMPTY to let
   the client find this server via the DHT (slower; needs this port reachable).

3) Point your browser/app SOCKS5 proxy at 127.0.0.1:1080.
======================================================================

Starting tunnel server on 0.0.0.0:$PEER_PORT (Ctrl-C to stop) ...
EOF

# 4. Start the server (foreground).
# DHT is left ENABLED: the server announces the carrier hash so the client can
# discover it, and it blends the connection with real BitTorrent DHT traffic.
HTTP_API="${RQBIT_HTTP_API:-127.0.0.1:3030}"
exec "$BIN" \
    --disable-tcp-listen --disable-upnp-port-forward \
    --http-api-listen-addr "$HTTP_API" \
    server start --disable-persistence "$DIR/data" \
    --tunnel-mode server \
    --tunnel-peer-listen "0.0.0.0:$PEER_PORT" \
    --tunnel-server-key "$DIR/keys/server.key" \
    --tunnel-allowed-clients "$DIR/keys/allowed-clients.txt" \
    --tunnel-carrier-root "$DIR/carrier"
