# rqbit tunnel harness: server and client operations design

## Status

Approved architecture for a single release that adds managed server and client operation around the existing encrypted tunnel. This document defines the product boundary and implementation contract; it does not begin implementation.

## Goal

Ship a terminal-first `rqbit-tunnel` harness alongside the existing `rqbit` binary. It manages a VPS tunnel server and Linux/Windows tunnel clients without exposing a public control API.

The release provides:

- a server TUI and non-interactive CLI for VPS user administration, traffic visibility, and server settings;
- one named user per tunnel client public key, with live and persistent upload/download counters;
- a system service on Linux systems with systemd and on Windows x64 systems using the Service Control Manager;
- client TUI/CLI actions for configuration, service state, autostart, bundle import, and manual update;
- a user-session tray agent that reflects service/tunnel state and launches the client TUI;
- one-click, signed GitHub Release updates initiated from the client TUI.

`rqbit` remains the underlying tunnel engine and keeps its existing direct `--tunnel-*` CLI path. The harness does not turn the general torrent CLI into a desktop/service manager.

## Supported platform contract

| Capability | Supported targets |
| --- | --- |
| Server runtime and server TUI | Linux x86_64/aarch64 with systemd; administration over local terminal or SSH |
| Client system service | Linux x86_64/aarch64 with systemd; Windows 10/11 and Windows Server x64 |
| Client TUI/CLI | Any supported terminal on the above targets, including SSH and Windows Terminal/PowerShell |
| Tray agent | Windows user sessions; Linux GUI sessions exposing StatusNotifier/AppIndicator support |
| Linux without systemd or without tray support | Portable CLI/TUI only; no claim of a native service installer or tray icon |

“Works everywhere” means the TUI has a stable CLI fallback inside this matrix. It does not claim that all Linux init systems, headless machines, Wayland compositors, or GNOME configurations expose a tray protocol.

## Non-goals

- A public HTTP, web, or remote-control management panel.
- User traffic quotas, automatic suspension at a limit, billing, or multi-device users.
- Background automatic updates; updates start only from the client TUI.
- One-time remote enrollment codes or a new public enrollment protocol.
- A promise that the tray appears on every Linux desktop environment.
- Support for non-systemd Linux init systems in this release.
- Changing ordinary torrent behavior or replacing the existing direct tunnel CLI.

## Product structure

A new workspace binary crate, `crates/rqbit-tunnel`, owns the harness. The release bundle contains `rqbit`, `rqbit-tunnel`, a stable launcher, an updater helper, and platform scripts.

`rqbit-tunnel` has explicit role commands:

```text
rqbit-tunnel server run|tui|users|settings|service
rqbit-tunnel client run|tui|config|service|import|update
rqbit-tunnel tray
rqbit-tunnel updater
```

The interactive TUI is a client of the running service, never the service process itself. Every interactive mutation also has a composable command with `--json` output, for example:

```text
rqbit-tunnel server users list --json
rqbit-tunnel server users add --name alice --export /secure/path/alice.bundle
rqbit-tunnel client service status --json
rqbit-tunnel client config set --socks-listen 127.0.0.1:1080
```

This separation prevents service lifecycle code from being coupled to terminal state, makes SSH administration safe, and gives scripts and the tray a typed local control surface.

## Local control plane

Each runtime owns a versioned, framed local IPC endpoint:

- Linux: Unix-domain socket under `/run/rqbit-tunnel/`;
- Windows: named pipe scoped to the installed client owner and administrators.

No control endpoint listens on TCP. The protocol has read-only requests for health, state, current config summary, live users, and counters; mutation requests add/remove/enable/disable users, reset counters, import bundles, and request a graceful stop/reload.

Linux socket permissions distinguish a root/admin mutation endpoint from a status endpoint readable by the configured tray user. Windows pipe ACLs make the corresponding distinction. The tray receives only non-secret state. It cannot alter protected configuration or service state by itself; it launches the elevated TUI when an action requires sudo/UAC.

The server TUI polls a snapshot endpoint once per second. The client TUI and tray subscribe to/poll a compact status snapshot. IPC versions are negotiated explicitly, so a newer tray cannot silently send a mutation to an older service.

## Server runtime and persistence

### Files and service

The system installer creates:

```text
/etc/rqbit-tunnel/server.json          root-owned server configuration
/etc/rqbit-tunnel/server.key           mode 0600 server static private key
/var/lib/rqbit-tunnel/server-state.db  SQLite user and traffic state
/var/lib/rqbit-tunnel/carrier/         existing carrier storage
/etc/systemd/system/rqbit-tunnel-server.service
```

`rqbit-tunnel-server.service` launches `rqbit-tunnel server run`. Configuration changes validate before the on-disk replacement; a failed validation leaves the active service configuration unchanged. The service only exposes the existing tunnel peer listener, never a SOCKS listener or management port.

### User record

A user is exactly one client static public key. The database stores:

```text
users:          id, unique name, public_key, enabled, created_at, reset_at
traffic_totals: user_id, upload_bytes, download_bytes, updated_at
settings:       schema_version and managed server settings
```

The server private key remains a root-only file and is never stored in SQLite or returned through IPC. SQLite WAL mode and a single asynchronous state-writer task serialize mutations and counter snapshots.

### Add, remove, and export

Adding a user generates a client X25519 keypair on the server, registers the public key, and can export a bundle containing the client private key, server public key, server endpoint, and compatible client defaults. The client TUI imports that bundle into protected client configuration.

The requested export is deliberately **unencrypted**. Any copy of that bundle can use the tunnel until the operator disables or deletes that user. The server TUI must display a critical confirmation before export, label the output as secret, and never retain an automatic extra copy after writing the operator-selected path. This is an accepted operator risk, not a secure default.

Disabling or removing a user atomically removes the key from admission and terminates all active carrier sessions for that user. Deletion requires confirmation. Reset atomically sets both traffic totals to zero and records `reset_at`.

## Dynamic admission and traffic accounting

The current tunnel server receives a static `HashSet<TunnelPublicKey>` at startup. The harness requires a minimal `librqbit` extension:

1. a dynamic admission abstraction replaces the static handshake-only allowlist;
2. an accepted peer receives a user-specific admission context;
3. the server relay receives an allocation-free per-user traffic meter and lifecycle hooks.

The harness maintains an atomically swappable public-key registry. Admission resolves a key once, yielding an `Arc<UserMeter>` stored directly on the admitted peer. The relay performs only `AtomicU64::fetch_add` operations on payload paths; it does not look up a user or allocate per byte/frame.

Traffic has user-facing directions:

| Counter | Counted only when |
| --- | --- |
| Upload (`client → VPS → destination`) TCP | the server successfully writes the payload to the destination socket |
| Upload UDP | the server successfully sends the datagram to the destination |
| Download (`destination → VPS → client`) TCP | the client sends a `Credit` after writing payload to the local SOCKS client |
| Download UDP | the server successfully queues the datagram toward the client; UDP has no delivery acknowledgement |

The counters describe forwarded application payload. They exclude BitTorrent framing, MSE/Noise ciphertext overhead, carrier cover messages, rejected requests, failed destination writes, and unsent queue contents.

Meters update live in memory. The state writer flushes dirty deltas in a SQLite transaction at least once per second and flushes synchronously during graceful shutdown. A power loss can omit no more than the last unflushed second of counter deltas; the UI and documentation must state this boundary rather than claim impossible per-byte crash durability.

The server dashboard refreshes users every second and shows name, enabled/connected state, aggregate upload/download totals, rolling rate, and last-seen time.

## Server TUI and CLI

The server TUI is terminal-first and works over SSH. Its main dashboard provides:

- auto-refreshing user list and traffic totals;
- add user, export bundle, enable, disable, delete, and reset actions;
- server listener and egress-policy settings;
- service health and restart/error status;
- explicit warning banners for secret bundle export.

Keys are keyboard-driven and discoverable in the footer. Non-TTY CLI commands are the supported automation and accessibility fallback. No behavior depends exclusively on terminal escape-sequence support.

## Client runtime and configuration

### Files and service

The client is a real system service, not a detached launch script:

| Platform | Install and runtime layout |
| --- | --- |
| Linux | Versioned executable bundles under `/opt/rqbit-tunnel`, protected configuration under `/etc/rqbit-tunnel`, mutable data under `/var/lib/rqbit-tunnel`, and `rqbit-tunnel-client.service` managed by systemd |
| Windows | Versioned bundles under `Program Files`, protected configuration/data under `ProgramData`, and a Windows service registered with the Service Control Manager |

The service runs `rqbit-tunnel client run`, initializes `librqbit` client tunnel mode, owns the SOCKS listener, and publishes local read-only status. It survives logout and reboots. The client supervisor's existing reconnect behavior remains authoritative: a service may be healthy while temporarily disconnected from the VPS.

### Client TUI actions

The client TUI displays service status, tunnel connection status, server endpoint, SOCKS listener, and current version. It supports:

- import of an exported client bundle;
- editing server endpoint, SOCKS listener, carrier count, and supported client options;
- start, stop, restart, status, and log navigation;
- enable/disable system autostart;
- explicit manual update;
- an always visible security banner for unsafe LAN SOCKS configuration.

Changes validate before persistence. Protected configuration or system-service actions relaunch the terminal with sudo/UAC when required; status remains readable without elevation for the tray agent.

### LAN SOCKS choice

The default listener is `127.0.0.1:1080`. The user explicitly permits LAN binds without SOCKS authentication. The harness therefore permits a non-loopback listener only after an explicit `allow_unauthenticated_lan_socks` acknowledgement is persisted. It adds **no** authentication or CIDR restriction. The TUI and tray show a persistent critical warning because this creates an open proxy reachable from that LAN. This is an accepted operator risk, not a secure default.

## Scripts and platform service adapters

Existing tunnel launch scripts become control entry points rather than foreground tunnel wrappers:

- Linux `client-run.sh` opens the client TUI/menu and elevates only protected actions.
- Windows `client-run.bat` launches the PowerShell menu; it requests UAC only for service/config operations.
- Linux server setup script installs/enables the server unit and opens server TUI rather than permanently `exec`ing a foreground server.

A `ServiceManager` boundary maps the shared operations to `systemctl` on Linux and the Windows Service Control Manager on Windows. `autostart` means `systemctl enable` or an Automatic Windows service start type. All operations wait for the manager's observed state and report actionable errors; they never claim success merely because a command was spawned.

## Tray agent

`rqbit-tunnel tray` is a separate per-user process. It never runs in Windows Session 0, where a Windows service cannot safely display UI.

- Windows starts it for the current user through a user-level logon entry.
- Linux creates an XDG user autostart entry and publishes a StatusNotifier/AppIndicator icon when the active desktop supports one.
- On unsupported/headless Linux sessions, no icon is attempted; the TUI/CLI remain fully usable.

Tray state derives from local IPC:

| Icon state | Meaning |
| --- | --- |
| Gray | Tray agent cannot inspect the service |
| Red | Service stopped or has a fatal runtime/configuration error |
| Yellow | Service is running and reconnecting/discovering the VPS |
| Green | Service is running with at least one live carrier |

A primary click opens the client TUI. The context menu exposes status and exit-agent actions. Privileged service mutations go through the elevated TUI, not the tray process.

## Signed client update

The client TUI's update action uses only stable GitHub Releases from `h1w/rqbit-tunnel`. It never downloads source or executes artifacts from `main`.

Each release target includes a `release-manifest.json` with version, target, filename, size, SHA-256, and minimum launcher ABI. CI creates a detached Ed25519 signature from a protected release key. The harness compiles the corresponding public key and rejects all unverified manifests.
If a manifest requires a newer launcher ABI, the updater refuses the release without stopping the current service and directs the user to run a manually installed bundle that supplies a compatible launcher.

The update flow is:

1. discover the latest non-draft, non-prerelease release for the exact target;
2. download manifest and signature over HTTPS, verify Ed25519 signature, then validate schema, version monotonicity, target, size, filename, and SHA-256;
3. extract only into a new staging/version directory after rejecting traversal and unexpected archive entries;
4. validate the staged executable and migrate configuration before activation;
5. run a temporary updater helper that stops the service, atomically switches the active version pointer, restarts the service, and asks the tray agent to re-exec;
6. wait for local IPC readiness and successful configuration load, not for a VPS connection;
7. if health fails, restore the previous pointer and restart the previous service.

A stable launcher is the registered systemd/SCM/tray-autostart target. It reads an atomically replaced active-version pointer and starts the selected immutable bundle. This avoids replacing a running Windows service executable. The updater runs from a temporary/staged copy, not from the file it replaces.

Invalid signature, checksum, target, archive layout, or configuration rejects an update before the active service is stopped. Interrupted download leaves the active version unchanged. Update/rollback results appear in the TUI, tray state, and protected logs. The server has no automatic update action in this release; only the requested client TUI owns it.

## Error handling and secret boundaries

- Validate config before write; atomically replace valid configuration only.
- Keep server/client private keys in protected files; redact keys, bundle bodies, payload, destinations, and decrypted frames from logs and IPC.
- Require typed confirmations for delete, reset, service disable, and unencrypted export.
- Preserve the old service and config after failed reload/update.
- Surface a specific cause and recovery action through TUI/CLI rather than using generic “failed” status.
- Treat a disconnected client tunnel as a reconnecting state, not as a stopped service.

## Verification strategy

### Core and storage

- Unit-test user-key uniqueness, enable/disable/delete transitions, atomic registry replacement, and active-session revocation.
- Test all traffic accounting points with successful, rejected, failed, reset, TCP, and UDP paths; assert no cover/encryption overhead is included.
- Test SQLite schema migration, one-second batch flush, graceful flush, reset semantics, and bounded crash-recovery behavior.
- Test local IPC frame versioning, read-only vs mutation authorization, malformed message rejection, and secret omission.

### TUI and service lifecycle

- Exercise TUI state reducers/key actions without a real terminal; snapshot semantic screens and error states.
- Test CLI `--json` contracts for every operation represented in the TUI.
- Test shared service lifecycle behavior with mock systemd/SCM adapters, including observed start/stop/restart/enable/disable failures.
- Run target-specific smoke jobs that install, start, configure, query, stop, and remove Linux systemd and Windows services. The Linux smoke environment must boot systemd; a shell-only CI container is not sufficient evidence.
- Test tray status mapping from all service snapshots and its supported-Linux fallback path.

### Update and packaging

- Fixture-test valid signed manifests plus tampered signature, checksum, version, target, archive entry, and downgrade failures.
- Test staging, activation, health success, restart failure, and rollback without using the live GitHub API.
- Change `release-tunnel.yml` to package all harness binaries/scripts and publish signed per-target manifests in addition to checksums.
- End-to-end smoke-test client bundle import, service start, SOCKS request through the existing tunnel fixture, live counter update, user disable/revocation, and client updater restart.

## Delivery criteria

The release is complete only when:

1. a VPS administrator can install the server service, use SSH TUI/CLI to add/remove/disable one-key users, and observe live persistent traffic totals;
2. a Linux or Windows client can import the exported bundle, install/start/stop/status/enable its actual system service from the provided launcher/TUI, and reconnect after service restart;
3. traffic totals follow the defined direction and success semantics;
4. the client tray accurately reflects local service/tunnel state where the platform supports a tray and falls back cleanly where it does not;
5. client TUI update rejects untrusted artifacts, successfully swaps to a signed release, restarts the service/tray, and rolls back on failed health check;
6. all specified unit, integration, platform smoke, and tunnel end-to-end checks pass.

## Repository evidence

- `scripts/tunnel/client-run.sh`, `client-run.ps1`, `client-run.bat`, and `server-quickstart.sh`: current foreground launchers to replace with managed control entry points.
- `crates/librqbit/src/tunnel/server.rs`: static allowlist and admitted peer boundary.
- `crates/librqbit/src/tunnel/relay.rs`: exact TCP/UDP payload-success paths and client key passed into server relay.
- `crates/librqbit/src/tunnel/client_supervisor.rs`: client service can be healthy while reconnecting.
- `crates/librqbit/src/tunnel/options.rs`: current server/client tunnel configuration boundary.
- `crates/rqbit/src/main.rs`: existing direct tunnel CLI and key-generation utility.
- `.github/workflows/release-tunnel.yml`: current per-target packaging and checksum-only release path.
- `desktop/src-tauri/src/main.rs`: existing desktop application is a torrent UI, not a suitable Session 0/service tray host.
