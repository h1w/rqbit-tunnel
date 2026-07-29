# rqbit tunnel operation

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
provide the reachable numeric address explicitly; it is written as
`advertised_peer` into enrollment bundles while the service binds its
`peer_listen` address on all local IPv4 interfaces.

```bash
SERVER_IP="$PUBLIC_SERVER_IPV4" \
RQBIT_TUNNEL_BIN=/srv/rqbit-release/rqbit-tunnel \
RQBIT_KEYGEN_BIN=/srv/rqbit-release/rqbit \
./scripts/tunnel/server-quickstart.sh
```

Set `RQBIT_TUNNEL_UNIT=/path/to/rqbit-tunnel-server.service` when the template
is not in the source-tree location relative to the script. The installer obtains
`sudo` before inspecting protected state, holds an exclusive installation lock
through health verification, and creates and restricts:

```text
/opt/rqbit-tunnel/rqbit-tunnel              installed service executable
/etc/rqbit-tunnel/server.json               root-owned managed configuration
/etc/rqbit-tunnel/server.key                root-owned, mode 0600 private key
/var/lib/rqbit-tunnel/                      root-owned state and carrier storage
/var/lib/rqbit-tunnel/enrollments/          root-owned, mode 0700 bundle output
/run/rqbit-tunnel/server.sock               root-owned local control socket
```

The initial configuration binds `peer_listen` to `0.0.0.0:PEER_PORT` and writes
the VPS's reachable public IPv4 as `advertised_peer` for enrollment bundles. It
blocks private, loopback, link-local, and multicast egress by default, and sets
client SOCKS to `127.0.0.1:1080`. `PEER_PORT` must be in `1024..=65535` because
the service deliberately drops all Linux capabilities. Open the configured peer
TCP port (default `4242`) in the VPS firewall.

The installer creates the configuration and key only for a fresh managed
installation with no identity or `server-state.db`. A failure before any state
database exists rolls back only the new identity files. If either identity file
is missing, or a complete identity has no state database, restore the original
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
delete, reset, and quit. Adding a user requires a name and a service-visible
export path below `/var/lib/rqbit-tunnel/enrollments`, then a confirmation that
names the unencrypted bundle.

The noninteractive CLI is the safe automation fallback:

```bash
# Local JSON health check and user inventory.
sudo /opt/rqbit-tunnel/rqbit-tunnel server users list --json

# Explicitly create one user and write its enrollment bundle. The service
# cannot write to /root or /home because its systemd sandbox protects homes.
sudo /opt/rqbit-tunnel/rqbit-tunnel server users add \
  --name alice --export /var/lib/rqbit-tunnel/enrollments/alice.rqbt
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

## Managed client operation

An enrolled client runs as an operating-system service. Import one server-issued
bundle before starting it; after changing its endpoint, SOCKS listener, or
carrier count, restart the service. Do not run a detached foreground
`rqbit-tunnel client run` process.

### Linux

Extract a trusted signed Linux release bundle and bootstrap its immutable payload
layout once:

```bash
cd rqbit-tunnel-x86_64-unknown-linux-gnu
sudo ./install-client.sh
```

The bootstrap installs a stable `/opt/rqbit-tunnel/launcher`, an immutable
payload under `/opt/rqbit-tunnel/releases/<version>/payload`, and the delivered
systemd unit. The service always invokes the stable launcher; do not point a
unit at a versioned payload directly.

The service reads root-owned `/etc/rqbit-tunnel/client.json` and its separate
mode `0600` private key; status is exposed only through local IPC, never a
network management port.

```bash
# Import a bundle transferred over an authenticated channel.
sudo /opt/rqbit-tunnel/launcher client import --bundle /secure-transfer/alice.rqbt

/opt/rqbit-tunnel/launcher client config show --json

# The bundle supplies the endpoint. Override configuration only when needed.
sudo /opt/rqbit-tunnel/launcher client config set \
  --server-addr SERVER:PORT --socks-listen 127.0.0.1:1080

sudo /opt/rqbit-tunnel/launcher client service install
sudo /opt/rqbit-tunnel/launcher client service start
/opt/rqbit-tunnel/launcher client service status --json
sudo /opt/rqbit-tunnel/launcher client service enable-autostart

# Apply a configuration change, or stop/remove autostart.
sudo /opt/rqbit-tunnel/launcher client service restart
sudo /opt/rqbit-tunnel/launcher client service stop
sudo /opt/rqbit-tunnel/launcher client service disable-autostart
```

The delivered `client-run.sh` presents the same flow and uses `sudo` only for
protected operations:

```bash
RQBIT_TUNNEL_BIN=./rqbit-tunnel ./client-run.sh
```

`client service status` reads the local client IPC when available. A
`running`/`reconnecting` snapshot means the service and SOCKS listener are up
but no carrier is currently connected; it is not a successful tunnel
connection.

### Windows

Extract a trusted signed Windows release ZIP. From an Administrator PowerShell
at its root, bootstrap the stable launcher and immutable payload:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-client.ps1
```

Protected client configuration and data live below `%ProgramData%\rqbit-tunnel`;
the stable launcher is `%ProgramFiles%\rqbit-tunnel\launcher.exe`. From an
Administrator PowerShell:

```powershell
& "$env:ProgramFiles\rqbit-tunnel\launcher.exe" client import --bundle C:\SecureTransfer\alice.rqbt
& "$env:ProgramFiles\rqbit-tunnel\launcher.exe" client config show --json
& "$env:ProgramFiles\rqbit-tunnel\launcher.exe" client config set --socks-listen 127.0.0.1:1080
& "$env:ProgramFiles\rqbit-tunnel\launcher.exe" client service install
& "$env:ProgramFiles\rqbit-tunnel\launcher.exe" client service start
& "$env:ProgramFiles\rqbit-tunnel\launcher.exe" client service status --json
& "$env:ProgramFiles\rqbit-tunnel\launcher.exe" client service enable-autostart
& "$env:ProgramFiles\rqbit-tunnel\launcher.exe" client service restart
& "$env:ProgramFiles\rqbit-tunnel\launcher.exe" client service stop
& "$env:ProgramFiles\rqbit-tunnel\launcher.exe" client service disable-autostart
```

`client-run.ps1` and its `client-run.bat` double-click wrapper offer the same
interactive service and configuration flow from the extracted bundle.

### Tray status (Linux and Windows)

The tray is a best-effort, per-user status process; it never runs inside the
system service session and it never starts or stops that service. Start it from
a non-root Linux desktop session or a non-elevated Windows user session:

```bash
/opt/rqbit-tunnel/launcher tray
/opt/rqbit-tunnel/launcher tray enable-autostart
```

```powershell
& "$env:ProgramFiles\rqbit-tunnel\launcher.exe" tray
& "$env:ProgramFiles\rqbit-tunnel\launcher.exe" tray enable-autostart
```

Autostart affects only the invoking user's desktop session. A primary click
opens the client dashboard; the context menu exposes **Open control** and
**Exit tray**. The icon is green only with a live carrier, yellow while the
service is reconnecting or has no carrier, red for a failed service, and gray
when local status IPC is unavailable. Linux support depends on a compatible
StatusNotifier/AppIndicator environment; if none is available, the command
prints `tray unavailable` and exits successfully.

On Linux, `rqbit-tunnel-tray` is a separate companion binary. The managed
client service and terminal CLI do not require GTK, AppIndicator, or any other
desktop runtime; install the distribution's GTK/AppIndicator runtime only on
desktops where the tray companion is needed.

### Signed manual updates

Press `u` in the client dashboard, confirm the signed
[GitHub Release](https://github.com/h1w/rqbit-tunnel/releases) check, then
confirm the displayed target version to install it. The equivalent automation
commands are:

```bash
/opt/rqbit-tunnel/launcher client update check
sudo /opt/rqbit-tunnel/launcher client update install --target-version VERSION
```

Updates are manual only: no background check or download occurs while the
dashboard is open. The temporary updater accepts only the repository's pinned
Ed25519-signed release manifest and its selected SHA-256 archive. It stops the
service only after verification, switches `active.json` atomically, and restores
the previous release if local IPC health does not return. If the release needs a
newer launcher ABI, install a matching signed client bundle manually instead of
forcing an update.


### Client SOCKS boundary

The default server-issued bundle configures the local SOCKS listener as
`127.0.0.1:1080`. The service does not add SOCKS authentication. A
non-loopback listener is rejected unless the operator explicitly acknowledges
it:

```bash
sudo /opt/rqbit-tunnel/launcher client config set \
  --socks-listen 0.0.0.0:1080 --allow-unauthenticated-lan-socks true
sudo /opt/rqbit-tunnel/launcher client service restart
```

That setting creates an unauthenticated open proxy for every host that can
reach the listener. Use it only behind a trusted network boundary; the client
dashboard keeps a persistent critical open-proxy warning while it is enabled.

## Traffic counters and durability

The dashboard and `--json` output show forwarded application-payload counters:

| Counter | Direction | Counted when |
| --- | --- | --- |
| Upload | client → VPS → destination | TCP payload is successfully written to the destination, or a UDP datagram is successfully sent there. |
| Download | destination → VPS → client | TCP is acknowledged after the client writes payload to its local SOCKS client; UDP is queued toward the client (UDP has no delivery acknowledgement). |

They exclude BitTorrent framing, MSE/Noise ciphertext overhead, carrier cover
messages, rejected requests, failed destination writes, and unsent queue data.
Counters update live in memory and attempt a SQLite flush at least once per
second (and synchronously on graceful shutdown). After successful flushes, a
power loss can lose at most the last unflushed second of counter deltas. If
SQLite remains unwritable, pending deltas stay in memory and a power loss can
lose every delta since the last successful flush; totals are not per-byte
crash-durable.

## Security boundaries

- **An exported enrollment bundle is an unencrypted transferable secret.** It
  contains a client private key. Anyone who obtains a copy can use the tunnel
  until that user is disabled or deleted. Export only to a protected path and
  transfer it with an authenticated channel.
- **Unauthenticated LAN SOCKS is a client-side risk, not a server feature.**
  This managed server has no SOCKS listener. The managed client defaults to
  loopback and requires explicit acknowledgement before binding an open LAN
  proxy.
- The server private key stays in `/etc/rqbit-tunnel/server.key` with mode
  `0600`; do not copy or print it. The quickstart never automatically creates
  a client user or bundle.
