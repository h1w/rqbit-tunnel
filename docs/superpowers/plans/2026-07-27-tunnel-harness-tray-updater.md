# Tunnel Harness Tray and Signed Updater Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a best-effort Linux/Windows client tray agent plus a manual, signed GitHub Release updater that stages, activates, health-checks, and rolls back managed client bundles.

**Architecture:** Register a small stable launcher with systemd, the Windows Service Control Manager, and user tray autostart. It reads an atomically replaced active-version pointer and executes the immutable payload release. The client TUI invokes an updater copied into a temporary staging directory; it verifies a pinned Ed25519-signed manifest and SHA-256 before stopping the service, then rolls back if local IPC health fails.

**Tech Stack:** Rust 2024, Tokio, `reqwest`, `ed25519-dalek`, `semver`, `sha2`, `tar`, `zip`, `tray-icon`, systemd, Windows SCM/Registry APIs, GitHub Actions.

**Execution order:** Plan 3 of 3. Execute after `2026-07-27-tunnel-harness-server-control-plane.md` and `2026-07-27-tunnel-harness-client-service.md`. This plan changes the Plan 2 direct service target into the final versioned-bundle/launcher layout before any release is published.

---

## File structure

| File | Responsibility |
| --- | --- |
| `Cargo.toml`, `Cargo.lock` | Add update, archive, semver, and tray dependencies. |
| `crates/rqbit-tunnel/Cargo.toml` | Define payload, stable launcher, updater, and release-sign binaries. |
| `crates/rqbit-tunnel/src/version.rs` | Active-release pointer and safe versioned installation paths. |
| `crates/rqbit-tunnel/src/update/{mod.rs,manifest.rs,github.rs,stage.rs,activate.rs}` | Manifest trust, release discovery, safe extraction, activation, health/rollback. |
| `crates/rqbit-tunnel/src/tray/{mod.rs,state.rs,agent.rs}` | Pure status mapping, event loop, click/menu behavior, and payload-version re-exec. |
| `crates/rqbit-tunnel/src/platform/{linux.rs,windows.rs}` | User tray autostart and stable-launcher service registration. |
| `crates/rqbit-tunnel/src/tui/client.rs` | Add the manual update action and visible update errors. |
| `crates/rqbit-tunnel/src/bin/rqbit-tunnel-launcher.rs` | Stable registered process that resolves `active.json` and execs payload roles. |
| `crates/rqbit-tunnel/src/bin/rqbit-tunnel-updater.rs` | Temporary updater entrypoint invoked by the client TUI. |
| `crates/rqbit-tunnel/src/bin/rqbit-tunnel-release-sign.rs` | CI-only detached manifest signer; never package the signing key. |
| `crates/rqbit-tunnel/resources/release-public-key.hex` | Pinned 32-byte Ed25519 public verification key. |
| `.github/workflows/release-tunnel.yml` | Package every harness binary, generate/sign manifest, publish it with artifacts. |
| `.github/workflows/tunnel-harness-smoke.yml` | Linux systemd and Windows SCM smoke jobs. |
| `scripts/tunnel/smoke-systemd.sh` | In-container actual systemd install/start/status/stop smoke flow. |
| `scripts/tunnel/smoke-windows-service.ps1` | Actual SCM install/start/status/stop/delete smoke flow. |
| `scripts/tunnel/README.md`, `README.md` | Tray capability/fallback and signed-update/rollback operation. |

## Task 1: Add the versioned bundle layout and stable launcher

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/rqbit-tunnel/Cargo.toml`
- Create: `crates/rqbit-tunnel/src/version.rs`
- Create: `crates/rqbit-tunnel/src/bin/rqbit-tunnel-launcher.rs`
- Modify: `systemd/rqbit-tunnel-client.service`
- Modify: `crates/rqbit-tunnel/src/platform/{linux.rs,windows.rs}`
- Test: inline tests in `version.rs`

- [ ] **Step 1: Write failing active-pointer validation tests**

```rust
#[test]
fn active_release_rejects_parent_components_and_absolute_payload_paths() {
    assert!(ActiveRelease::new(Version::new(1, 2, 3), PathBuf::from("../evil"), 1).is_err());
    assert!(ActiveRelease::new(Version::new(1, 2, 3), PathBuf::from("/tmp/evil"), 1).is_err());
}

#[test]
fn active_release_round_trips_through_atomic_json() {
    let root = tempfile::tempdir().unwrap();
    let active = ActiveRelease::new(Version::new(1, 2, 3), PathBuf::from("releases/1.2.3"), 1).unwrap();
    write_active_release(root.path(), &active).unwrap();
    assert_eq!(read_active_release(root.path()).unwrap(), active);
}
```

- [ ] **Step 2: Run the tests and confirm version layout code is missing**

Run: `cargo test -p rqbit-tunnel active_release_rejects_parent_components_and_absolute_payload_paths`

Expected: FAIL because `ActiveRelease` and active-pointer functions do not exist.

- [ ] **Step 3: Add constrained installation paths and atomic pointer writes**

Use this immutable layout:

```text
<install-root>/
  launcher[.exe]
  active.json
  releases/<semver>/rqbit-tunnel[.exe]
  releases/<semver>/rqbit[.exe]
  releases/<semver>/rqbit-tunnel-updater[.exe]
  staging/
  config/ data/ logs/
```

`ActiveRelease` contains `version`, a relative `payload_dir`, and `launcher_abi`. `write_active_release` serializes to a same-directory temp file, calls `sync_all`, renames it atomically, and syncs the parent directory on Unix. `payload_path` must reject every absolute path, `..`, prefix, or non-normal component.

Add `semver` as a workspace and `rqbit-tunnel` dependency in this task; `ActiveRelease.version` is a `semver::Version` and Task 1 must compile independently.

Define the launcher constants/helpers in `version.rs` so Tasks 2–6 use one contract:

```rust
pub const LAUNCHER_ABI: u32 = 1;

pub fn current_exe_suffix() -> &'static str {
    if cfg!(windows) { ".exe" } else { "" }
}
```

- [ ] **Step 4: Implement the stable launcher and migrate service targets**

The launcher takes exactly one role after `--`: `server`, `client`, or `tray`. It reads `active.json`, checks that its own `LAUNCHER_ABI >= active.launcher_abi`, resolves a safe payload path, and `exec`s/starts `rqbit-tunnel` with the remaining role arguments. It never downloads, verifies, or parses private config.

```rust
let active = read_active_release(&install_root)?;
if active.launcher_abi > LAUNCHER_ABI {
    bail!("active release requires launcher ABI {}, installed ABI is {}", active.launcher_abi, LAUNCHER_ABI);
}
let payload = active.payload_executable(&install_root, current_exe_suffix())?;
let status = Command::new(payload).args(role_args).status()?;
std::process::exit(status.code().unwrap_or(1));
```

Change the Linux unit and Windows `ServiceInstallSpec` to target `launcher client run --config …`, not the payload directly. Plan 2 tests must be updated to assert the launcher target.

- [ ] **Step 5: Run version/launcher tests and commit**

Run:

```bash
cargo test -p rqbit-tunnel version::tests
cargo run -p rqbit-tunnel --bin rqbit-tunnel-launcher -- --help
cargo fmt --all
```

Expected: pointer tests pass and launcher help exits 0.

Commit:

```bash
git add Cargo.toml Cargo.lock crates/rqbit-tunnel systemd/rqbit-tunnel-client.service
git commit -m "feat(tunnel): add versioned bundle launcher"
```

## Task 2: Define and verify the signed release manifest

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/rqbit-tunnel/Cargo.toml`
- Create: `crates/rqbit-tunnel/src/update/mod.rs`
- Create: `crates/rqbit-tunnel/src/update/manifest.rs`
- Create: `crates/rqbit-tunnel/resources/release-public-key.hex`
- Modify: `crates/rqbit-tunnel/src/lib.rs`
- Create: `crates/rqbit-tunnel/src/bin/rqbit-tunnel-release-sign.rs`
- Test: inline tests in `update/manifest.rs`

- [ ] **Step 1: Add failing signature, target, downgrade, and ABI tests**

```rust
#[test]
fn verifier_rejects_tampered_manifest_bytes() {
    let (manifest, signature, key) = signed_fixture();
    let mut tampered = manifest;
    tampered[0] ^= 1;
    assert!(verify_manifest(&tampered, &signature, &key).is_err());
}

#[test]
fn selected_asset_requires_exact_platform_and_newer_version() {
    let manifest = fixture_manifest("1.2.3", "x86_64-unknown-linux-gnu");
    assert!(manifest.select_asset("x86_64-pc-windows-msvc", &Version::new(1, 2, 2), 1).is_err());
    assert!(manifest.select_asset("x86_64-unknown-linux-gnu", &Version::new(1, 2, 3), 1).is_err());
}
```

- [ ] **Step 2: Run the test and confirm trust primitives are absent**

Run: `cargo test -p rqbit-tunnel verifier_rejects_tampered_manifest_bytes`

Expected: FAIL because manifest types and `verify_manifest` do not exist.

- [ ] **Step 3: Add exact manifest schema and raw-byte signature verification**

Add workspace dependencies `ed25519-dalek`, `base64`, `tar`, `flate2`, `zip`, and `walkdir`; add `reqwest = { workspace = true, features = ["json", "stream", "rustls-tls"] }` to the harness crate. The manifest is signed as the exact UTF-8 JSON bytes downloaded by the client; verification must not deserialize/re-serialize before checking the detached signature.

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub version: Version,
    pub launcher_abi: u32,
    pub assets: Vec<ReleaseAsset>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseAsset {
    pub target: String,
    pub archive: String,
    pub bytes: u64,
    pub sha256: String,
}

pub fn verify_manifest(raw: &[u8], signature_b64: &str, key: &VerifyingKey) -> Result<ReleaseManifest, UpdateError> {
    let signature = Signature::from_slice(&BASE64_STANDARD.decode(signature_b64.trim())?)?;
    key.verify_strict(raw, &signature)?;
    Ok(serde_json::from_slice(raw)?)
}
```

Define every error variant consumed by Tasks 3–5 in the same module:

```rust
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("no newer stable release is available")]
    NoUpdate,
    #[error("release manifest signature is invalid")]
    InvalidSignature,
    #[error("release manifest is invalid: {0}")]
    InvalidManifest(String),
    #[error("download checksum does not match signed manifest")]
    ChecksumMismatch,
    #[error("release requires launcher ABI {required}; installed ABI is {installed}")]
    UnsupportedLauncherAbi { required: u32, installed: u32 },
    #[error("release download failed: {0}")]
    Download(String),
    #[error("release archive is unsafe: {0}")]
    UnsafeArchive(String),
    #[error("service control failed: {0}")]
    ServiceControl(String),
    #[error("local service health check timed out")]
    HealthTimeout,
    #[error("update rolled back: {source}")]
    RolledBack { source: Box<UpdateError> },
}
```

Map base64, signature, and JSON parser errors to `InvalidSignature` or `InvalidManifest`; do not use a blanket `anyhow` conversion at this public result boundary.

Validate schema version, canonical semver, target equality, filename without path components, lowercase 64-character SHA-256, positive bounded byte length, strictly newer version, and `manifest.launcher_abi <= LAUNCHER_ABI`. An ABI mismatch is a rejection before any service action, with recovery text instructing manual bundle installation.

- [ ] **Step 4: Add a CI-only manifest signer with no shipped private key**

`rqbit-tunnel-release-sign` reads `TUNNEL_RELEASE_SIGNING_KEY` only from its environment as base64 32-byte Ed25519 seed, calculates assets from a supplied dist directory, writes `release-manifest.json`, and writes base64 detached `release-manifest.sig`. It is not copied into release archives.

```rust
let signing_key = SigningKey::from_bytes(&decode_seed(env::var("TUNNEL_RELEASE_SIGNING_KEY")?)?);
let bytes = serde_json::to_vec_pretty(&manifest)?;
let signature = signing_key.sign(&bytes);
fs::write(output.join("release-manifest.json"), &bytes)?;
fs::write(output.join("release-manifest.sig"), BASE64_STANDARD.encode(signature.to_bytes()))?;
```

Commit only the public key file. Tests create ephemeral signing keys in memory and never depend on the protected CI secret.

Add a CI-tool-only `keygen --stdout` subcommand that emits one base64 seed and its hex public key exactly once. The release owner stores the seed as the protected GitHub Actions secret `TUNNEL_RELEASE_SIGNING_KEY`, writes only the public key to `resources/release-public-key.hex`, and verifies a fixture signature before enabling release publication. The command must never write a private seed into the repository, release archive, log file, or GitHub artifact.

- [ ] **Step 5: Run trust tests and commit**

Run:

```bash
cargo test -p rqbit-tunnel update::manifest::tests
cargo run -p rqbit-tunnel --bin rqbit-tunnel-release-sign -- --help
cargo fmt --all
```

Expected: all invalid-signature/target/version/ABI fixtures fail as asserted; signer help exits 0.

Commit:

```bash
git add Cargo.toml Cargo.lock crates/rqbit-tunnel
git commit -m "feat(tunnel): verify signed release manifests"
```

## Task 3: Implement GitHub discovery, safe staging, activation, health checks, and rollback

**Files:**
- Create: `crates/rqbit-tunnel/src/update/github.rs`
- Create: `crates/rqbit-tunnel/src/update/stage.rs`
- Create: `crates/rqbit-tunnel/src/update/activate.rs`
- Create: `crates/rqbit-tunnel/src/bin/rqbit-tunnel-updater.rs`
- Modify: `crates/rqbit-tunnel/src/update/mod.rs`
- Test: inline tests in `github.rs`, `stage.rs`, and `activate.rs`; `crates/rqbit-tunnel/tests/update_e2e.rs`

- [ ] **Step 1: Add failing staging and rollback tests**

```rust
#[test]
fn archive_extraction_rejects_parent_traversal_before_writing_files() {
    let archive = archive_with_entry("../outside");
    let staging = tempfile::tempdir().unwrap();
    assert!(extract_verified_archive(&archive, staging.path(), ArchiveKind::TarGz).is_err());
    assert!(!staging.path().join("outside").exists());
}

#[tokio::test]
async fn failed_health_check_restores_previous_active_release() {
    let install = test_install_with_active("1.0.0");
    let updater = test_updater(install.path(), AlwaysFailHealth);
    assert!(updater.activate("1.1.0").await.is_err());
    assert_eq!(read_active_release(install.path()).unwrap().version, Version::new(1, 0, 0));
}
```

Define the injectable local-health boundary used by the test and production updater:

```rust
pub trait LocalHealth: Send + Sync {
    fn wait_for_ready<'a>(&'a self, deadline: Duration)
        -> Pin<Box<dyn Future<Output = Result<(), UpdateError>> + Send + 'a>>;
}

pub struct AlwaysFailHealth;
impl LocalHealth for AlwaysFailHealth {
    fn wait_for_ready<'a>(&'a self, _: Duration)
        -> Pin<Box<dyn Future<Output = Result<(), UpdateError>> + Send + 'a>> {
        Box::pin(async { Err(UpdateError::HealthTimeout) })
    }
}
```

Use `AlwaysFailHealth` in the test instead of an undeclared `Health::AlwaysFail` value.

- [ ] **Step 2: Run the tests and confirm updater components are absent**

Run: `cargo test -p rqbit-tunnel archive_extraction_rejects_parent_traversal_before_writing_files`

Expected: FAIL because `extract_verified_archive` and `Updater` do not exist.

- [ ] **Step 3: Discover only the approved GitHub Release and stage safely**

Query `https://api.github.com/repos/h1w/rqbit-tunnel/releases/latest` with an explicit User-Agent, 15-second request timeout, and no token. Reject draft/prerelease responses, then download only the manifest, signature, and selected exact asset from the release assets list.

Write archive bytes into a unique staging directory while hashing them; reject early if the byte count exceeds the manifest size and reject after download unless both byte count and SHA-256 match. For tar/zip entries, reject absolute paths, `..`, non-normal components, symlinks/hardlinks, duplicate normalized paths, and any top-level layout other than the expected bundle directory. Extract files without following links and verify that exactly the expected payload executables are present.

- [ ] **Step 4: Activate from a temporary updater and roll back on local health failure**

The TUI launches `rqbit-tunnel-updater` copied into staging/temp, passing only install root and target version. The updater:

1. asks `ServiceManager` to stop the client and observes `Stopped`;
2. moves verified staging to `releases/<version>` without overwriting an existing directory;
3. atomically writes `active.json`;
4. starts the service through the stable launcher;
5. polls the read-only client IPC for `LocalServiceState::Running` and a valid config snapshot for at most 30 seconds;
6. on failure, restores the old pointer, restarts old service, and returns structured rollback diagnostics.

Do not require a live VPS carrier for health; the existing supervisor reconnects asynchronously.

```rust
let previous = read_active_release(&root)?;
service.stop(CLIENT_SERVICE)?;
write_active_release(&root, &candidate)?;
if let Err(error) = start_and_wait_for_local_health(&service, &health).await {
    write_active_release(&root, &previous)?;
    let _ = service.start(CLIENT_SERVICE);
    return Err(UpdateError::RolledBack { source: Box::new(error) });
}
```

- [ ] **Step 5: Add a complete local update fixture and run tests**

`update_e2e.rs` serves signed fixture assets from a local HTTP server, injects the release endpoint URL, uses a fake observed service manager, and proves valid update, checksum failure, signature failure, health rollback, and reconnecting-but-healthy status. It must never call the live GitHub API.

Run:

```bash
cargo test -p rqbit-tunnel update::
cargo test -p rqbit-tunnel --test update_e2e -- --nocapture
cargo fmt --all
```

Expected: all valid/invalid update and rollback cases pass.

- [ ] **Step 6: Commit updater behavior**

```bash
git add crates/rqbit-tunnel/src/update crates/rqbit-tunnel/src/bin/rqbit-tunnel-updater.rs crates/rqbit-tunnel/tests/update_e2e.rs
git commit -m "feat(tunnel): update signed client bundles safely"
```

## Task 4: Add the client TUI update action

**Files:**
- Modify: `crates/rqbit-tunnel/src/cli.rs`
- Modify: `crates/rqbit-tunnel/src/tui/client.rs`
- Test: inline tests in `cli.rs` and `tui/client.rs`

- [ ] **Step 1: Add failing reducer tests for update confirmation and result rendering**

```rust
#[test]
fn update_key_requires_confirmation_before_spawning_an_updater() {
    let mut state = ClientTuiState::from_snapshot(sample_client_snapshot());
    state.handle_key(KeyCode::Char('u'));
    assert!(matches!(state.modal, Some(Modal::ConfirmUpdate)));
    assert!(state.pending_update.is_none());
}

#[test]
fn rolled_back_update_is_rendered_with_a_recovery_action() {
    let state = ClientTuiState::with_update_error(UpdateErrorDto::rolled_back("IPC health timeout"));
    assert!(state.status_line().contains("old version restored"));
}
```

- [ ] **Step 2: Run tests and confirm update UI wiring is missing**

Run: `cargo test -p rqbit-tunnel update_key_requires_confirmation_before_spawning_an_updater`

Expected: FAIL because update UI state is absent.

- [ ] **Step 3: Implement one explicit manual update command**

Add `rqbit-tunnel client update check|install` and `[u]pdate` to the TUI footer. `install` confirms target version, releases terminal mode, spawns only the temporary updater helper, and waits for its structured result. It does not schedule background checks or download while the user is merely viewing status.

Show precise failures: no newer version, invalid signature, checksum mismatch, unsupported launcher ABI, service-stop failure, local-health timeout with rollback, and successfully installed version. Never show raw manifest body or private configuration in the TUI.

Use one serializable UI result type rather than passing implementation errors through the terminal reducer:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateErrorDto {
    NoUpdate,
    InvalidSignature,
    ChecksumMismatch,
    UnsupportedLauncherAbi,
    ServiceControl(String),
    RolledBack(String),
}

impl UpdateErrorDto {
    pub fn rolled_back(reason: impl Into<String>) -> Self {
        Self::RolledBack(reason.into())
    }
}
```

- [ ] **Step 4: Run client UI/update tests and commit**

Run:

```bash
cargo test -p rqbit-tunnel tui::client::tests
cargo test -p rqbit-tunnel cli::tests
cargo fmt --all
```

Expected: confirmation, error, and success reducer tests pass.

Commit:

```bash
git add crates/rqbit-tunnel/src/{cli.rs,tui/client.rs}
git commit -m "feat(tunnel): add manual client update action"
```

## Task 5: Add a best-effort tray agent that never runs in the service session

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/rqbit-tunnel/Cargo.toml`
- Create: `crates/rqbit-tunnel/src/tray/mod.rs`
- Create: `crates/rqbit-tunnel/src/tray/state.rs`
- Create: `crates/rqbit-tunnel/src/tray/agent.rs`
- Modify: `crates/rqbit-tunnel/src/platform/linux.rs`
- Modify: `crates/rqbit-tunnel/src/platform/windows.rs`
- Modify: `crates/rqbit-tunnel/src/cli.rs`
- Test: inline tests in `tray/state.rs`

- [ ] **Step 1: Add failing tray-state mapping tests**

```rust
#[test]
fn tray_state_is_green_only_with_a_live_carrier() {
    assert_eq!(TrayState::from_snapshot(&connected_snapshot()), TrayState::Green);
    assert_eq!(TrayState::from_snapshot(&reconnecting_snapshot()), TrayState::Yellow);
}

#[test]
fn unavailable_ipc_is_gray_and_fatal_service_is_red() {
    assert_eq!(TrayState::from_input(TrayInput::Unavailable), TrayState::Gray);
    assert_eq!(TrayState::from_input(TrayInput::Snapshot(failed_snapshot())), TrayState::Red);
}
```

- [ ] **Step 2: Run the tests and confirm tray state mapping is absent**

Run: `cargo test -p rqbit-tunnel tray_state_is_green_only_with_a_live_carrier`

Expected: FAIL because `TrayState` does not exist.

- [ ] **Step 3: Implement a pure state layer and colored runtime icons**

Add `tray-icon` as a target-supported dependency. Define `TrayState::{Gray, Red, Yellow, Green}` purely from the Plan 2 read-only client snapshot. Generate a 32×32 RGBA colored circle in memory for each state, avoiding external asset conversion and avoiding secrets in tooltip/menu text.

Keep the tray reducer independent of IPC implementation details:

```rust
pub enum TrayInput {
    Snapshot(ClientSnapshot),
    Unavailable,
}

impl TrayState {
    pub fn from_input(input: TrayInput) -> Self {
        match input {
            TrayInput::Unavailable => Self::Gray,
            TrayInput::Snapshot(snapshot) if snapshot.service == LocalServiceState::Failed => Self::Red,
            TrayInput::Snapshot(snapshot) if snapshot.tunnel == LocalTunnelState::Connected => Self::Green,
            TrayInput::Snapshot(_) => Self::Yellow,
        }
    }
}
```

```rust
pub fn color_for(state: TrayState) -> [u8; 4] {
    match state {
        TrayState::Gray => [128, 128, 128, 255],
        TrayState::Red => [220, 53, 69, 255],
        TrayState::Yellow => [255, 193, 7, 255],
        TrayState::Green => [25, 135, 84, 255],
    }
}
```

- [ ] **Step 4: Run the tray event agent in the user session**

`rqbit-tunnel tray` polls read-only IPC every second and updates the icon/tooltip. A primary click spawns the stable launcher with `client tui`; a context menu contains only `Open control` and `Exit tray`. It never starts/stops the service directly and never executes inside the Windows service process.

On Linux, if the tray backend cannot connect to a supported StatusNotifier/AppIndicator environment, log `tray unavailable` and exit 0; do not claim an icon exists. On active-version change, the agent launches its successor through the stable launcher and exits after the successor has started.

- [ ] **Step 5: Register per-user tray autostart and commit**

Linux writes `~/.config/autostart/rqbit-tunnel-tray.desktop` pointing at `launcher tray`. Windows writes a current-user Run entry pointing at `launcher.exe tray`; do not use the Windows service account or Session 0. Add/remove operations must touch only the invoking user's autostart entry.

Run:

```bash
cargo test -p rqbit-tunnel tray::state::tests
cargo build -p rqbit-tunnel
cargo fmt --all
```

Expected: pure mapping tests pass and tray code builds on Linux/Windows targets.

Commit:

```bash
git add Cargo.toml Cargo.lock crates/rqbit-tunnel/src/{tray,platform,cli.rs}
git commit -m "feat(tunnel): add client tray status agent"
```

## Task 6: Package, sign, and smoke-test the complete release

**Files:**
- Modify: `.github/workflows/release-tunnel.yml`
- Create: `.github/workflows/tunnel-harness-smoke.yml`
- Create: `scripts/tunnel/smoke-systemd.sh`
- Create: `scripts/tunnel/smoke-windows-service.ps1`
- Modify: `scripts/tunnel/README.md`
- Modify: `README.md`

- [ ] **Step 1: Add a failing release-manifest packaging test**

Create a local fixture directory containing Linux and Windows archives. Run the release signer using an ephemeral `TUNNEL_RELEASE_SIGNING_KEY`, then verify its generated manifest with the matching fixture public key and assert every archive is represented exactly once.

```bash
TUNNEL_RELEASE_SIGNING_KEY="$TEST_SIGNING_KEY" \
  cargo run -p rqbit-tunnel --bin rqbit-tunnel-release-sign -- \
  --dist "$fixture_dist" --output "$fixture_dist"
cargo test -p rqbit-tunnel release_signer_lists_each_target_once
```

Expected: FAIL before the workflow/signing layout is implemented.

- [ ] **Step 2: Build and package all runtime binaries per target**

Change `release-tunnel.yml` matrix builds to compile `rqbit`, `rqbit-tunnel`, `rqbit-tunnel-launcher`, and `rqbit-tunnel-updater`. Linux archives include the executable payloads, launcher, updater, `client-run.sh`, `client-run.ps1`, `client-run.bat`, `server-quickstart.sh`, and both systemd templates. Windows ZIPs include the `.exe` files and Windows launcher scripts.

In the release job, check out source, install Rust, download artifacts, run the un-packaged `rqbit-tunnel-release-sign` with the protected `TUNNEL_RELEASE_SIGNING_KEY` secret, and upload `release-manifest.json` plus `release-manifest.sig` as release assets. Retain SHA256SUMS as a human/operator diagnostic, but updater trust comes solely from the Ed25519 signature plus manifest hash check.

- [ ] **Step 3: Add real Linux systemd smoke test**

`smoke-systemd.sh` runs inside a privileged Ubuntu 24.04 systemd container. It installs the Linux artifact into a temporary root, creates a valid generated client config with loopback SOCKS and synthetic keys, copies the unit, executes `systemctl daemon-reload`, `enable --now`, waits for `is-active`, requests client status through IPC, then `disable --now` and asserts `is-active` is inactive. It cleans up unit, process, and root in a trap.

The workflow must run this container with `--privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw`; a shell-only container is not accepted as a systemd test.

- [ ] **Step 4: Add real Windows SCM smoke test**

`smoke-windows-service.ps1` creates a unique service name, creates a temporary ProgramData-style root/config with synthetic keys, installs the launcher service through `sc.exe create`, starts it, polls `sc.exe query` for `RUNNING`, invokes client status, stops it, verifies `STOPPED`, and deletes the service in a `finally` block. The workflow runs it on `windows-latest` in an elevated runner and uploads logs on failure.

- [ ] **Step 5: Document final operation and run full verification**

Document: supported tray environments and fallback, icon state meanings, manual update only, signed release source, rollback behavior, unsupported launcher ABI recovery, bundle secret handling, and open-LAN SOCKS warning.

Run:

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
bash scripts/tunnel/smoke-systemd.sh --help
pwsh -NoProfile -File scripts/tunnel/smoke-windows-service.ps1 -Help
```

Expected: workspace tests, formatting, clippy, and smoke-script help checks pass.

- [ ] **Step 6: Commit release integration**

```bash
git add .github/workflows/release-tunnel.yml .github/workflows/tunnel-harness-smoke.yml scripts/tunnel/smoke-systemd.sh scripts/tunnel/smoke-windows-service.ps1 scripts/tunnel/README.md README.md
git commit -m "feat(tunnel): ship signed managed client releases"
```
