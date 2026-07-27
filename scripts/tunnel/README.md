# rqbit tunnel server operation

The Linux tunnel server is a root-owned systemd service, not a foreground
`rqbit` process. It exposes the encrypted tunnel peer listener configured in
`/etc/rqbit-tunnel/server.json`; its administration endpoint is the local Unix
socket `/run/rqbit-tunnel/server.sock`, never a TCP management port.

## Install on the VPS

Start with explicit paths from a trusted release bundle. The installer
intentionally does **not** choose a binary from `PATH` or copy an unknown
executable. On first setup it needs the bundled `rqbit` only to generate key
material; it copies only the generated server private key into the managed
configuration and deletes the temporary generated client material.

```bash
RQBIT_TUNNEL_BIN=/srv/rqbit-release/rqbit-tunnel \
RQBIT_KEYGEN_BIN=/srv/rqbit-release/rqbit \
./scripts/tunnel/server-quickstart.sh
```

The script first tries to discover a public IPv4 address. If that cannot work,
provide the reachable numeric address explicitly; it is put in enrollment
bundles, so it must not be a wildcard listener:

```bash
SERVER_IP="$PUBLIC_SERVER_IPV4" \
RQBIT_TUNNEL_BIN=/srv/rqbit-release/rqbit-tunnel \
RQBIT_KEYGEN_BIN=/srv/rqbit-release/rqbit \
./scripts/tunnel/server-quickstart.sh
```

Set `RQBIT_TUNNEL_UNIT=/path/to/rqbit-tunnel-server.service` when the template
is not in the source-tree location relative to the script. The installer asks
for `sudo` only while it inspects or changes protected installation state and
uses systemd. It creates and restricts:

```text
/opt/rqbit-tunnel/rqbit-tunnel              installed service executable
/etc/rqbit-tunnel/server.json               root-owned managed configuration
/etc/rqbit-tunnel/server.key                root-owned, mode 0600 private key
/var/lib/rqbit-tunnel/                      root-owned state and carrier storage
/run/rqbit-tunnel/server.sock               root-owned local control socket
```

The initial configuration uses a nonzero `peer_listen` address, blocks private,
loopback, link-local, and multicast egress by default, and sets client SOCKS
to `127.0.0.1:1080`. `PEER_PORT` must be in `1024..=65535` because the service
deliberately drops all Linux capabilities. Open the configured peer TCP port
(default `4242`) in the VPS firewall.

The installer creates the configuration and key only for a fresh managed
installation with no identity or `server-state.db`. If either identity file is
missing, or a complete identity has no state database, restore the original
protected state from backup instead of allowing a new server identity to
invalidate enrolled clients' bundles.

On a refresh, the installer stops an active managed service and waits for
`/run/rqbit-tunnel/server.sock` to disappear before replacing files and starting
it again; the protected configuration, key, and database remain in place. If
the unit is inactive while any control-socket path exists, it aborts rather than
starting beside a manual or unknown server.

After `daemon-reload` and `enable --now`, the installer waits up to 30 seconds
for both `rqbit-tunnel-server.service` to be active and `server users list
--json` to succeed over the newly attributable local control socket, then opens
the server TUI. For automation, the TUI is skipped **only** by the explicit
flag:

```bash
# Set PUBLIC_SERVER_IPV4 to the VPS's real reachable public IPv4 address.
SERVER_IP="$PUBLIC_SERVER_IPV4" \
RQBIT_TUNNEL_BIN=/srv/rqbit-release/rqbit-tunnel \
RQBIT_KEYGEN_BIN=/srv/rqbit-release/rqbit \
./scripts/tunnel/server-quickstart.sh --skip-tui
```

No quickstart output contains a private key or an enrollment bundle.

## Administer over SSH or locally

Open the terminal dashboard from an SSH session with a TTY:

```bash
ssh -t admin@your-vps 'sudo /opt/rqbit-tunnel/rqbit-tunnel server tui'
```

The dashboard refreshes live state once per second; press `F5` for an immediate
refresh. Its footer lists the keyboard controls: add/bundle, enable, disable,
delete, reset, and quit. Adding a user requires a name and an operator-chosen
export path, then a confirmation that names the unencrypted bundle.

The noninteractive CLI is the safe automation fallback:

```bash
# Local JSON health check and user inventory.
sudo /opt/rqbit-tunnel/rqbit-tunnel server users list --json

# Explicitly create one user and write its enrollment bundle.
sudo /opt/rqbit-tunnel/rqbit-tunnel server users add \
  --name alice --export /root/alice.rqbt

# The list output supplies USER_ID values for state changes.
sudo /opt/rqbit-tunnel/rqbit-tunnel server users disable USER_ID
sudo /opt/rqbit-tunnel/rqbit-tunnel server users enable USER_ID
sudo /opt/rqbit-tunnel/rqbit-tunnel server users delete USER_ID

# Read the active managed settings.
sudo /opt/rqbit-tunnel/rqbit-tunnel server settings show --json
```

For unattended mutations, use the command's explicit `--yes` confirmation
switch where it is offered (for example `users add`, `users delete`, and
`users reset`). Check service state with
`sudo systemctl status rqbit-tunnel-server.service`; stop it permanently with
`sudo systemctl disable --now rqbit-tunnel-server.service`.

Disabling a user removes its key from admission and terminates that user's
active carrier sessions until an operator explicitly re-enables that record.
Deleting does the same and removes the stored record; deletion requires
confirmation, and the old bundle remains revoked even if a later user is added.

## Traffic counters and durability

The dashboard and `--json` output show forwarded application-payload counters:

| Counter | Direction | Counted when |
| --- | --- | --- |
| Upload | client → VPS → destination | TCP payload is successfully written to the destination, or a UDP datagram is successfully sent there. |
| Download | destination → VPS → client | TCP is acknowledged after the client writes payload to its local SOCKS client; UDP is queued toward the client (UDP has no delivery acknowledgement). |

They exclude BitTorrent framing, MSE/Noise ciphertext overhead, carrier cover
messages, rejected requests, failed destination writes, and unsent queue data.
Counters update live in memory and are flushed to SQLite at least once per
second (and synchronously on graceful shutdown). A power loss can therefore
lose at most the last unflushed second of counter deltas; totals are not
per-byte crash-durable.

## Security boundaries

- **An exported enrollment bundle is an unencrypted transferable secret.** It
  contains a client private key. Anyone who obtains a copy can use the tunnel
  until that user is disabled or deleted. Export only to a protected path and
  transfer it with an authenticated channel.
- **Unauthenticated LAN SOCKS is a client-side risk, not a server feature.**
  This managed server has no SOCKS listener. Later client setup must keep SOCKS
  on loopback or add its own authentication before exposing it to a LAN.
- The server private key stays in `/etc/rqbit-tunnel/server.key` with mode
  `0600`; do not copy or print it. The quickstart never automatically creates
  a client user or bundle.
