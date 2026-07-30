# Tunnel Harness Client Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver Linux systemd and Windows Service tunnel clients with protected configuration, bundle import, a terminal TUI/CLI, service controls, autostart, and truthful local tunnel status.

**Architecture:** Extend the Plan 1 harness crate with a client runtime that builds `librqbit` client tunnel mode from a protected bundle-derived config and exposes read-only local IPC. Isolate platform service operations behind a synchronous `ServiceManager`, so the TUI/CLI shares the same observed start/stop/status/autostart behavior on systemd and the Windows Service Control Manager.

**Tech Stack:** Rust 2024, Tokio, `librqbit`, Clap, Ratatui/Crossterm, Unix sockets, Tokio Windows named pipes, systemd, Windows API via `windows` crate, Bash, PowerShell.

**Execution order:** Plan 2 of 3. Execute after `2026-07-27-tunnel-harness-server-control-plane.md`. It supplies the client runtime required by the tray and signed updater in `2026-07-27-tunnel-harness-tray-updater.md`.

---

## File structure

| File | Responsibility |
| --- | --- |
| `crates/librqbit/src/tunnel/service.rs` | Public, non-secret client/server status snapshots. |
| `crates/librqbit/src/tunnel/socks.rs` | Correct TCP/UDP bind/reply behavior for a configured non-loopback listener. |
| `crates/librqbit/src/lib.rs` | Re-export status types used by the harness. |
| `crates/rqbit-tunnel/src/model.rs` | Add `ClientConfig`, client snapshots, and config-validation error DTOs. |
| `crates/rqbit-tunnel/src/paths.rs` | Add system client paths and test-root override paths. |
| `crates/rqbit-tunnel/src/config.rs` | Atomic, permission-aware client config/key import. |
| `crates/rqbit-tunnel/src/runtime/client.rs` | Run/reload client `Session`, publish status, and own read-only IPC. |
| `crates/rqbit-tunnel/src/ipc/protocol.rs` | Add client snapshot/reload protocol messages. |
| `crates/rqbit-tunnel/src/ipc/windows.rs` | Windows named-pipe transport with owner/admin access control. |
| `crates/rqbit-tunnel/src/platform/{mod.rs,linux.rs,windows.rs}` | Service install/start/stop/status/autostart implementations and testable command boundary. |
| `crates/rqbit-tunnel/src/cli.rs` | Add `client import|config|service|tui` commands. |
| `crates/rqbit-tunnel/src/tui/client.rs` | Client status/config/service terminal UI reducer and renderer. |
| `systemd/rqbit-tunnel-client.service` | Linux client service unit. |
| `scripts/tunnel/client-run.sh` | Linux control menu with least-privilege sudo escalation. |
| `scripts/tunnel/client-run.ps1` | Windows control menu and UAC relaunch. |
| `scripts/tunnel/client-run.bat` | Double-click PowerShell wrapper. |
| `scripts/tunnel/README.md`, `README.md` | Client install, service, LAN safety warning, and recovery operation. |

## Task 1: Define protected client config and bundle import

**Files:**
- Modify: `crates/rqbit-tunnel/src/model.rs`
- Modify: `crates/rqbit-tunnel/src/paths.rs`
- Create: `crates/rqbit-tunnel/src/config.rs`
- Modify: `crates/rqbit-tunnel/src/lib.rs`
- Test: inline tests in `model.rs` and `config.rs`

- [ ] **Step 1: Write failing validation and import tests**

```rust
#[test]
fn non_loopback_listener_requires_explicit_insecure_acknowledgement() {
    let config = ClientConfig::for_test("0.0.0.0:1080".parse().unwrap());
    assert_eq!(config.validate().unwrap_err(), ClientConfigError::InsecureLanSocksNotAcknowledged);
}

#[test]
fn imported_bundle_writes_private_key_outside_json_config() {
    let paths = ClientPaths::under(tempfile::tempdir().unwrap().path());
    import_bundle(&paths, sample_bundle()).unwrap();
    let config = load_client_config(&paths).unwrap();
    assert_eq!(config.client_key_path, paths.client_key_path());
    assert!(!std::fs::read_to_string(paths.config_path()).unwrap().contains("070707"));
}
```

- [ ] **Step 2: Run the tests and confirm the client config layer is absent**

Run: `cargo test -p rqbit-tunnel non_loopback_listener_requires_explicit_insecure_acknowledgement`

Expected: FAIL because `ClientConfig`, `ClientPaths`, and `import_bundle` do not exist.

- [ ] **Step 3: Add the exact config model and validation rule**

Add `ClientConfig` with schema version, optional server address, server public key, `client_key_path`, `socks_listen`, `carriers`, carrier data root, and `allow_unauthenticated_lan_socks`.

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    pub schema_version: u32,
    pub server_addr: Option<SocketAddr>,
    #[serde(serialize_with = "serialize_hex_key", deserialize_with = "deserialize_hex_key")]
    pub server_public_key: [u8; 32],
    pub client_key_path: PathBuf,
    pub socks_listen: SocketAddr,
    pub carriers: usize,
    pub carrier_root: PathBuf,
    pub allow_unauthenticated_lan_socks: bool,
}

impl ClientConfig {
    pub fn validate(&self) -> Result<(), ClientConfigError> {
        if self.carriers == 0 || self.carriers > 16 {
            return Err(ClientConfigError::InvalidCarrierCount);
        }
        if !self.socks_listen.ip().is_loopback() && !self.allow_unauthenticated_lan_socks {
            return Err(ClientConfigError::InsecureLanSocksNotAcknowledged);
        }
        Ok(())
    }
}
```

Define the status DTOs consumed by Task 3, Task 5, and Plan 3 in the same module:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalServiceState {
    Running,
    Stopped,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalTunnelState {
    Connected,
    Reconnecting,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSnapshot {
    pub service: LocalServiceState,
    pub tunnel: LocalTunnelState,
    pub socks_listen: Option<SocketAddr>,
    pub configured_carriers: usize,
    pub live_carriers: usize,
    pub version: String,
    pub error: Option<String>,
}
```

Do not add SOCKS authentication or CIDR filtering: the approved product decision permits an explicitly acknowledged open LAN proxy. Task 5 renders this condition as a persistent critical warning.

- [ ] **Step 4: Implement atomic import with protected key storage**

`ClientPaths::system()` uses `/etc/rqbit-tunnel`, `/var/lib/rqbit-tunnel`, and `/run/rqbit-tunnel` on Linux; Windows uses `ProgramData\\rqbit-tunnel` for protected config/data. `import_bundle` must validate schema/key length/socket address before writing. Write client key to a separate file with Unix mode `0600`, write config through a same-directory temporary file plus `sync_all`/rename, and remove the temporary files on error.

```rust
pub fn import_bundle(paths: &ClientPaths, bundle: EnrollmentBundle) -> Result<ClientConfig, ConfigError> {
    let config = ClientConfig::from_bundle(paths, &bundle)?;
    config.validate()?;
    write_private_key(paths.client_key_path(), bundle.client_private_key)?;
    atomic_write_json(paths.config_path(), &config)?;
    Ok(config)
}
```

On Windows, create the root during elevated install and apply an ACL granting full control only to Administrators, SYSTEM, and the selected installing user. Never place client private key text in a status DTO, log record, or JSON config.

- [ ] **Step 5: Run config tests, format, and commit**

Run:

```bash
cargo test -p rqbit-tunnel config::tests
cargo test -p rqbit-tunnel model::tests
cargo fmt --all
```

Expected: loopback defaults validate; LAN bind requires acknowledgement; imported key is outside config JSON.

Commit:

```bash
git add crates/rqbit-tunnel/src/{model.rs,paths.rs,config.rs,lib.rs}
git commit -m "feat(tunnel): add protected client configuration"
```

## Task 2: Expose truthful client health from `librqbit` and fix LAN UDP binding

**Files:**
- Modify: `crates/librqbit/src/tunnel/service.rs`
- Modify: `crates/librqbit/src/tunnel/socks.rs`
- Modify: `crates/librqbit/src/lib.rs`
- Test: inline tests in `service.rs` and `socks.rs`

- [ ] **Step 1: Add failing service-status tests**

```rust
#[tokio::test]
async fn client_status_reports_bound_socks_and_zero_live_carriers_when_reconnecting() {
    let service = start_client_with_unreachable_server().await;
    let status = service.status();
    assert!(matches!(status, TunnelServiceStatus::Client {
        live_carriers: 0,
        configured_carriers: 1,
        ..
    }));
}

#[test]
fn udp_bind_address_uses_the_accepted_listener_address() {
    let accepted = "192.0.2.10:1080".parse().unwrap();
    assert_eq!(udp_bind_addr(accepted), "192.0.2.10:0".parse().unwrap());
}
```

- [ ] **Step 2: Run the tests and confirm the status API is absent**

Run: `cargo test -p librqbit client_status_reports_bound_socks_and_zero_live_carriers_when_reconnecting`

Expected: FAIL because `TunnelService::status` and `TunnelServiceStatus` do not exist.

- [ ] **Step 3: Add public immutable service snapshots**

Define and re-export:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelServiceStatus {
    Client {
        socks_listen: SocketAddr,
        configured_carriers: usize,
        live_carriers: usize,
    },
    Server {
        peer_listen: SocketAddr,
        admitted_peers: usize,
    },
}
```

`TunnelService` stores a role-specific status source: client keeps the `Arc<CarrierPool>` and bound address; server keeps `Arc<TunnelServer>` and bound address. `status()` snapshots `CarrierPool::live_count()` or `TunnelServer::peer_count()` without exposing private keys, destination addresses, or payload.

- [ ] **Step 4: Bind UDP and SOCKS replies to the actual listener interface**

Pass `stream.local_addr()?` from `SocksIngress::run` into `handle_connection`. Replace fixed `127.0.0.1:0` UDP bind/reply values with `udp_bind_addr(accepted_listener)`.

```rust
fn udp_bind_addr(accepted_listener: SocketAddr) -> SocketAddr {
    SocketAddr::new(accepted_listener.ip(), 0)
}
```

For TCP `CONNECT`, reply with the accepted listener address with port `0` instead of an unconditional loopback address. Preserve no-auth SOCKS negotiation exactly; this task must not silently add authentication.

- [ ] **Step 5: Run focused core regressions and commit**

Run:

```bash
cargo test -p librqbit client_status_reports_bound_socks_and_zero_live_carriers_when_reconnecting
cargo test -p librqbit socks::tests
cargo test -p librqbit tunnel
cargo fmt --all
```

Expected: status, SOCKS formatting, TCP, and UDP tunnel tests pass.

Commit:

```bash
git add crates/librqbit/src/tunnel/{service.rs,socks.rs} crates/librqbit/src/lib.rs
git commit -m "feat(tunnel): expose client service health"
```

## Task 3: Run the managed client and publish read-only local status

**Files:**
- Create: `crates/rqbit-tunnel/src/runtime/client.rs`
- Modify: `crates/rqbit-tunnel/src/runtime/mod.rs`
- Modify: `crates/rqbit-tunnel/src/ipc/protocol.rs`
- Modify: `crates/rqbit-tunnel/src/ipc/mod.rs`
- Create: `crates/rqbit-tunnel/src/ipc/windows.rs`
- Test: inline tests in `runtime/client.rs`, `ipc/protocol.rs`, and platform-gated tests in `ipc/windows.rs`

- [ ] **Step 1: Write failing client-status IPC tests**

```rust
#[tokio::test]
async fn client_snapshot_is_healthy_while_the_vps_is_unreachable() {
    let client = ManagedClient::start(test_paths_with_unreachable_server()).await.unwrap();
    let snapshot = client.snapshot().await;
    assert_eq!(snapshot.service, LocalServiceState::Running);
    assert_eq!(snapshot.tunnel, LocalTunnelState::Reconnecting);
    client.shutdown().await.unwrap();
}
```

- [ ] **Step 2: Run the test and confirm the client runtime is absent**

Run: `cargo test -p rqbit-tunnel client_snapshot_is_healthy_while_the_vps_is_unreachable`

Expected: FAIL because `ManagedClient` does not exist.

- [ ] **Step 3: Build a `librqbit` client session from protected config**

Load/validate config and the private key file, then construct exactly one managed `Session` with tunnel client mode, no ordinary torrent listener, no HTTP API, and no persistence database.

```rust
let tunnel = TunnelOptions::Client(TunnelClientOptions {
    socks_listen: config.socks_listen,
    server_addr: config.server_addr,
    identity_key: TunnelPrivateKey(read_private_key(&config.client_key_path)?),
    expected_server_key: TunnelPublicKey(config.server_public_key),
    carriers: config.carriers,
    carrier_root: config.carrier_root.clone(),
    pairing: None,
});
let session = Session::new_with_opts(
    paths.data_dir.clone(),
    SessionOptions {
        listen: None,
        connect: None,
        persistence: None,
        tunnel: Some(tunnel),
        cancellation_token: Some(shutdown.clone()),
        ..Default::default()
    },
).await?;
```

Map `TunnelServiceStatus::Client { live_carriers: 0, .. }` to `Reconnecting`, not `Stopped`. Map a successful local SOCKS bind plus one or more live carriers to `Connected`.

- [ ] **Step 4: Add read-only client IPC transports**

Extend the versioned protocol with `ClientRequest::Snapshot` and `ClientResponse::Snapshot(ClientSnapshot)`. Linux reuses the Unix framing implementation but creates a socket readable by the configured tray user. On Windows, implement the same envelope over `\\.\\pipe\\rqbit-tunnel-client-<owner-sid>` and create the pipe with a security descriptor granting read/write only to SYSTEM, Administrators, and the owner SID.

Do not expose config mutation, bundle bytes, private keys, or raw logs through this read-only service endpoint.

- [ ] **Step 5: Run client runtime and IPC tests, then commit**

Run:

```bash
cargo test -p rqbit-tunnel runtime::client::tests
cargo test -p rqbit-tunnel ipc::protocol::tests
cargo test -p rqbit-tunnel --target x86_64-pc-windows-msvc ipc::windows::tests --no-run
cargo fmt --all
```

Expected: Linux tests pass; the Windows target compiles named-pipe code without running it on Linux.

Commit:

```bash
git add crates/rqbit-tunnel/src/{runtime,ipc}
git commit -m "feat(tunnel): run managed client service runtime"
```

## Task 4: Implement observed system service control on Linux and Windows

**Files:**
- Create: `crates/rqbit-tunnel/src/platform/mod.rs`
- Create: `crates/rqbit-tunnel/src/platform/linux.rs`
- Create: `crates/rqbit-tunnel/src/platform/windows.rs`
- Modify: `crates/rqbit-tunnel/src/lib.rs`
- Test: inline tests in `platform/linux.rs` and `platform/windows.rs`

- [ ] **Step 1: Write failing state-transition tests against a fake command runner**

```rust
#[test]
fn systemctl_start_waits_for_active_state() {
    let runner = FakeRunner::from_lines(["activating", "active"]);
    let manager = LinuxServiceManager::new(runner);
    assert_eq!(manager.start(CLIENT_SERVICE).unwrap(), ServiceState::Running);
}

#[test]
fn service_stop_reports_failed_state_instead_of_success() {
    let runner = FakeRunner::from_lines(["stopping", "failed"]);
    let manager = LinuxServiceManager::new(runner);
    assert_eq!(manager.stop(CLIENT_SERVICE).unwrap_err(), ServiceError::FailedState);
}
```

- [ ] **Step 2: Run the Linux test and confirm the adapter is absent**

Run: `cargo test -p rqbit-tunnel systemctl_start_waits_for_active_state`

Expected: FAIL because `LinuxServiceManager` does not exist.

- [ ] **Step 3: Define the platform-neutral service contract**

```rust
pub const CLIENT_SERVICE: &str = "rqbit-tunnel-client";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState { Running, Stopped, Starting, Stopping, Failed, Unknown }

pub trait ServiceManager: Send + Sync {
    fn install(&self, spec: &ServiceInstallSpec) -> Result<(), ServiceError>;
    fn start(&self, name: &str) -> Result<ServiceState, ServiceError>;
    fn stop(&self, name: &str) -> Result<ServiceState, ServiceError>;
    fn restart(&self, name: &str) -> Result<ServiceState, ServiceError>;
    fn status(&self, name: &str) -> Result<ServiceState, ServiceError>;
    fn set_autostart(&self, name: &str, enabled: bool) -> Result<(), ServiceError>;
}
```

All implementations must poll observed manager state with a bounded deadline. A spawned command is never treated as proof of success.

- [ ] **Step 4: Implement both real adapters**

Linux uses `systemctl daemon-reload`, `enable|disable`, `start|stop|restart`, and `show --property=ActiveState --value`, injected through a `CommandRunner` for tests. Windows uses `OpenSCManagerW`, `CreateServiceW`, `OpenServiceW`, `StartServiceW`, `ControlService`, `QueryServiceStatusEx`, and `ChangeServiceConfigW(SERVICE_AUTO_START|SERVICE_DEMAND_START)` through the existing `windows` workspace dependency with `Win32_System_Services`, `Win32_Security`, and `Win32_System_Threading` features.

`ServiceInstallSpec` must contain the exact launcher/binary path, quoted arguments, working directory, and service display name. Reject relative executable paths and embedded NULs before making a platform call.

- [ ] **Step 5: Run adapter tests and commit**

Run:

```bash
cargo test -p rqbit-tunnel platform::linux::tests
cargo test -p rqbit-tunnel --target x86_64-pc-windows-msvc platform::windows::tests --no-run
cargo fmt --all
```

Expected: Linux transition tests pass and Windows service code cross-compiles.

Commit:

```bash
git add crates/rqbit-tunnel/src/{lib.rs,platform}
git commit -m "feat(tunnel): control client system services"
```

## Task 5: Add client CLI/TUI and platform launcher scripts

**Files:**
- Modify: `crates/rqbit-tunnel/src/cli.rs`
- Create: `crates/rqbit-tunnel/src/tui/client.rs`
- Modify: `crates/rqbit-tunnel/src/tui/mod.rs`
- Modify: `crates/rqbit-tunnel/src/bin/rqbit-tunnel.rs`
- Create: `systemd/rqbit-tunnel-client.service`
- Modify: `scripts/tunnel/client-run.sh`
- Modify: `scripts/tunnel/client-run.ps1`
- Modify: `scripts/tunnel/client-run.bat`
- Test: inline tests in `cli.rs`, `tui/client.rs`, and `scripts/tunnel/test-client-unit.sh`

- [ ] **Step 1: Add failing UI security-banner and CLI JSON tests**

```rust
#[test]
fn lan_listener_renders_a_persistent_critical_banner() {
    let view = ClientTuiState::from_snapshot(lan_snapshot());
    assert!(view.security_banner().contains("unauthenticated LAN SOCKS proxy"));
}

#[test]
fn client_service_status_json_has_no_key_material() {
    let stdout = render_json(&sample_client_snapshot());
    assert!(serde_json::from_str::<ClientSnapshot>(&stdout).is_ok());
    assert!(!stdout.contains("client_private_key"));
}
```

- [ ] **Step 2: Run the tests and confirm client UI is missing**

Run: `cargo test -p rqbit-tunnel lan_listener_renders_a_persistent_critical_banner`

Expected: FAIL because `ClientTuiState` does not exist.

- [ ] **Step 3: Add stable commands and a pure client TUI reducer**

Add `client import`, `client config show|set`, `client service install|start|stop|restart|status|enable-autostart|disable-autostart`, and `client tui`. Support `--json` for all noninteractive read operations.

The dashboard must render service state, tunnel state, endpoint, SOCKS bind, current version, and actions `[i]mport [c]onfigure [s]tart/stop [a]utostart [l]ogs q`. Add update action only in Plan 3; do not ship a no-op update button.

Define the privilege handoff used by every mutating command:

```rust
pub enum PrivilegeAction {
    Continue,
    Reexec { program: OsString, args: Vec<OsString> },
}

pub fn ensure_privileged(program: &OsStr, args: &[OsString]) -> Result<PrivilegeAction, PrivilegeError> {
    if is_elevated()? {
        Ok(PrivilegeAction::Continue)
    } else {
        Ok(PrivilegeAction::Reexec {
            program: program.to_os_string(),
            args: args.to_vec(),
        })
    }
}
```

The Linux wrapper executes the returned command through `sudo --`; the Windows wrapper passes the same argument vector to `Start-Process -Verb RunAs`. Never interpolate arguments into a shell string.

Configuration/service mutations call `ensure_privileged` before touching protected paths. On Linux it returns a concrete `sudo rqbit-tunnel …` re-exec command; on Windows the PowerShell wrapper re-launches itself with `Start-Process -Verb RunAs`. Status rendering itself never requires elevation.

- [ ] **Step 4: Install actual service units and interactive launchers**

Create `rqbit-tunnel-client.service` with `After=network-online.target`, `Wants=network-online.target`, `ExecStart=/opt/rqbit-tunnel/rqbit-tunnel client run --config /etc/rqbit-tunnel/client.json`, `Restart=on-failure`, `RestartSec=3`, and `NoNewPrivileges=true`.

Create `scripts/tunnel/test-client-unit.sh` in the same task:

```bash
#!/usr/bin/env bash
set -euo pipefail
unit="${1:?pass path to rqbit-tunnel-client.service}"
grep -qx 'ExecStart=/opt/rqbit-tunnel/rqbit-tunnel client run --config /etc/rqbit-tunnel/client.json' "$unit"
grep -qx 'Restart=on-failure' "$unit"
grep -qx 'NoNewPrivileges=true' "$unit"
command -v systemd-analyze >/dev/null || exit 0
systemd-analyze verify "$unit"
```

Rewrite `client-run.sh` as an interactive menu that invokes `rqbit-tunnel client tui`, uses `sudo` only for protected operations, and never starts a detached foreground tunnel process. Rewrite `client-run.ps1` to detect Administrator privileges, re-launch the selected protected command with UAC, and map menu selections to the same `rqbit-tunnel client` commands. Keep `client-run.bat` as the double-click wrapper with argument forwarding and a final `pause`.

- [ ] **Step 5: Run UI/script tests, build, and commit**

Run:

```bash
cargo test -p rqbit-tunnel cli::tests
cargo test -p rqbit-tunnel tui::client::tests
bash scripts/tunnel/test-client-unit.sh systemd/rqbit-tunnel-client.service
cargo build -p rqbit-tunnel
cargo fmt --all
```

Expected: UI reducer and JSON tests pass; the systemd template validates where systemd tooling is available; binary builds.

Commit:

```bash
git add crates/rqbit-tunnel/src/{bin/rqbit-tunnel.rs,cli.rs,tui} systemd/rqbit-tunnel-client.service scripts/tunnel/client-run.{sh,ps1,bat} scripts/tunnel/test-client-unit.sh
git commit -m "feat(tunnel): add managed client service controls"
```

## Task 6: Verify client import, service lifecycle, and tunnel behavior end-to-end

**Files:**
- Create: `crates/rqbit-tunnel/tests/client_service_e2e.rs`
- Modify: `scripts/tunnel/README.md`
- Modify: `README.md`

- [ ] **Step 1: Write the end-to-end client flow test**

Use a temporary client root and a fake `ServiceManager`. Import an enrollment bundle, start `ManagedClient`, assert the snapshot reaches `Reconnecting` against an unreachable endpoint, switch to a live tunnel fixture, assert it reaches `Connected`, then stop/restart through the manager boundary and assert a new snapshot is produced.

```rust
assert_eq!(manager.calls(), ["install", "start", "status", "restart", "stop"]);
assert_eq!(snapshot.socks_listen, configured_socks);
assert_eq!(connected.tunnel, LocalTunnelState::Connected);
```

- [ ] **Step 2: Run the test to establish the first red state**

Run: `cargo test -p rqbit-tunnel --test client_service_e2e -- --nocapture`

Expected: FAIL until import, runtime status, and observed lifecycle behavior are connected.

- [ ] **Step 3: Fix production integration only**

Wire the real config importer, `ManagedClient`, IPC snapshot, and service adapter into the test. Do not substitute a fake tunnel state inside the production runtime; only the platform manager is fake.

- [ ] **Step 4: Document and run the focused acceptance suite**

Document Linux and Windows install/start/stop/status/autostart flows, bundle import, loopback default, explicit LAN acknowledgement, and the persistent open-proxy warning. Then run:

```bash
cargo test -p rqbit-tunnel --test client_service_e2e -- --nocapture
cargo test -p rqbit-tunnel
cargo test -p librqbit tunnel
cargo fmt --all -- --check
```

Expected: import/service/tunnel flow and all focused tests pass.

- [ ] **Step 5: Commit the client acceptance flow**

```bash
git add crates/rqbit-tunnel/tests/client_service_e2e.rs scripts/tunnel/README.md README.md
git commit -m "test(tunnel): cover managed client service flow"
```
