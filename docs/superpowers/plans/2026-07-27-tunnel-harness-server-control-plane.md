# Tunnel Harness Server Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a systemd-managed VPS tunnel server with terminal TUI/CLI user administration, dynamic admission, and durable per-user payload traffic accounting.

**Architecture:** Add a dedicated `rqbit-tunnel` workspace crate that owns server configuration, SQLite state, a mutable key registry, a Unix-domain IPC control plane, and a terminal TUI. Extend `librqbit` narrowly so a server can authorize a key dynamically, attach an allocation-free session meter to an admitted peer, terminate that peer on revocation, and report only successfully forwarded payload bytes.

**Tech Stack:** Rust 2024, Tokio, `librqbit`, `rusqlite` with bundled SQLite, Serde JSON, Clap, Ratatui/Crossterm, Unix-domain sockets, systemd.

**Execution order:** Plan 1 of 3. It must land before `2026-07-27-tunnel-harness-client-service.md` and `2026-07-27-tunnel-harness-tray-updater.md`; release packaging is intentionally deferred to Plan 3.

---

## File structure

| File | Responsibility |
| --- | --- |
| `Cargo.toml` | Add the harness workspace member and shared SQLite/TUI dependencies. |
| `crates/librqbit/src/tunnel/options.rs` | Define dynamic authorization/session-observer interfaces while preserving static direct-CLI authorization. |
| `crates/librqbit/src/tunnel/crypto.rs` | Authenticate a Noise key through an authorizer without replying to rejected keys. |
| `crates/librqbit/src/tunnel/server.rs` | Carry the authorization session through admission and honor per-user revocation. |
| `crates/librqbit/src/tunnel/relay.rs` | Count only successful TCP/UDP application payload at the four specified accounting points. |
| `crates/librqbit/src/tunnel/service.rs` | Start a server with dynamic authorization and expose a non-secret status snapshot. |
| `crates/librqbit/src/lib.rs` | Re-export harness-facing tunnel hook and status types. |
| `crates/rqbit-tunnel/Cargo.toml` | Build the new harness binary and library. |
| `crates/rqbit-tunnel/src/model.rs` | Schema-versioned server config, enrollment bundle, user snapshots, and IPC DTOs. |
| `crates/rqbit-tunnel/src/paths.rs` | Root-owned server path layout and testable override roots. |
| `crates/rqbit-tunnel/src/store.rs` | SQLite migrations and transactional user/counter persistence. |
| `crates/rqbit-tunnel/src/registry.rs` | `TunnelServerAuthorizer`, per-user meters, cancellation, and periodic durable flush. |
| `crates/rqbit-tunnel/src/runtime/server.rs` | Build `SessionOptions`, run the tunnel server, and serve control requests. |
| `crates/rqbit-tunnel/src/ipc/{mod.rs,protocol.rs,unix.rs}` | Length-delimited local protocol and Unix socket client/server. |
| `crates/rqbit-tunnel/src/cli.rs` | Stable `server run`, `server tui`, and `server users … --json` commands. |
| `crates/rqbit-tunnel/src/tui/{mod.rs,server.rs}` | Keyboard-driven dashboard and deterministic state reducer. |
| `crates/rqbit-tunnel/src/bin/rqbit-tunnel.rs` | Runtime entrypoint and signal-aware Tokio setup. |
| `systemd/rqbit-tunnel-server.service` | System service template targeting the managed server runtime. |
| `scripts/tunnel/server-quickstart.sh` | Install/manage menu rather than a foreground `rqbit` wrapper. |
| `scripts/tunnel/README.md`, `README.md` | Managed-server operation and explicit secret-bundle risk. |

## Task 1: Create the harness crate and stable server data model

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/rqbit-tunnel/Cargo.toml`
- Create: `crates/rqbit-tunnel/src/lib.rs`
- Create: `crates/rqbit-tunnel/src/model.rs`
- Create: `crates/rqbit-tunnel/src/bin/rqbit-tunnel.rs`

- [ ] **Step 1: Add a model round-trip test before defining the model**

```rust
#[test]
fn enrollment_bundle_round_trips_hex_keys_without_leaking_extra_fields() {
    let bundle = EnrollmentBundle::for_test("alice", [7; 32], [8; 32], "203.0.113.8:4242");
    let encoded = serde_json::to_string(&bundle).unwrap();
    assert!(encoded.contains("0707070707070707070707070707070707070707070707070707070707070707"));
    assert!(!encoded.contains("carrier_root"));
    assert_eq!(serde_json::from_str::<EnrollmentBundle>(&encoded).unwrap(), bundle);
}
```

- [ ] **Step 2: Run the focused test and confirm the crate is absent**

Run: `cargo test -p rqbit-tunnel enrollment_bundle_round_trips_hex_keys_without_leaking_extra_fields`

Expected: FAIL because package `rqbit-tunnel` does not exist.

- [ ] **Step 3: Add the workspace member and minimal crate manifest**

Add `"crates/rqbit-tunnel"` to `[workspace].members`. Add shared `rusqlite = { version = "0.37", features = ["bundled"] }`, `ratatui = "0.29"`, and `crossterm = "0.28"` workspace dependencies. Create the crate manifest with `tokio`, `tokio-util`, `serde`, `serde_json`, `uuid` (`v4`, `serde`), `rusqlite`, `clap`, `thiserror`, `tracing`, `hex`, `sha2`, `directories`, `ratatui`, and `crossterm` inherited from the workspace where available. Defer the `librqbit` dependency to Task 4, where the registry first implements its tunnel traits; a model-only crate must not select a TLS backend.

```toml
[package]
name = "rqbit-tunnel"
edition = "2024"
version.workspace = true

[dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread", "net", "io-util", "signal", "sync", "time"] }
tokio-util.workspace = true
serde.workspace = true
serde_json.workspace = true
uuid = { workspace = true, features = ["v4", "serde"] }
rusqlite = { workspace = true }
clap.workspace = true
thiserror.workspace = true
tracing.workspace = true
hex.workspace = true
ratatui.workspace = true
crossterm.workspace = true
```

- [ ] **Step 4: Implement the DTO boundary with hex key serialization**

Define `ServerConfig`, `EnrollmentBundle`, `UserRecord`, `UserSnapshot`, `TrafficTotals`, and `ServerSnapshot` in `model.rs`. Do not serialize `TunnelPrivateKey([u8; 32])` as an integer array; use private `serialize_hex_key`/`deserialize_hex_key` helpers and fields of type `[u8; 32]` at the on-disk boundary.

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentBundle {
    pub schema_version: u32,
    pub user_name: String,
    #[serde(serialize_with = "serialize_hex_key", deserialize_with = "deserialize_hex_key")]
    pub client_private_key: [u8; 32],
    #[serde(serialize_with = "serialize_hex_key", deserialize_with = "deserialize_hex_key")]
    pub server_public_key: [u8; 32],
    pub server_addr: SocketAddr,
    pub socks_listen: SocketAddr,
    pub carriers: usize,
}

pub const BUNDLE_SCHEMA_VERSION: u32 = 1;
```

In this task `lib.rs` publicly exposes only `model`, because the other public modules do not exist yet. Task 4 adds `paths`, `registry`, and `store`; Task 5 adds `runtime` and `ipc`. No task exposes internal TUI state.

- [ ] **Step 5: Run the model test, format, and commit**

Run:

```bash
cargo test -p rqbit-tunnel enrollment_bundle_round_trips_hex_keys_without_leaking_extra_fields
cargo fmt --all
```

Expected: test passes and formatter exits 0.

Commit:

```bash
git add Cargo.toml Cargo.lock crates/rqbit-tunnel
git commit -m "feat(tunnel): scaffold managed harness model"
```

## Task 2: Make admission dynamically authorizable without breaking direct CLI users

**Files:**
- Modify: `crates/librqbit/src/tunnel/options.rs`
- Modify: `crates/librqbit/src/tunnel/crypto.rs`
- Modify: `crates/librqbit/src/tunnel/server.rs`
- Modify: `crates/librqbit/src/tunnel/service.rs`
- Modify: `crates/librqbit/src/lib.rs`
- Modify: `crates/rqbit/src/main.rs`
- Modify: `crates/librqbit/tests/tunnel.rs`
- Test: inline tests in `options.rs`, `crypto.rs`, and `server.rs`

- [ ] **Step 0: Map every exported option callsite before changing it**

Use LSP references for `TunnelServerOptions` and text search only to confirm its `allowed_client_keys` field literals. Record every construction site in this task before adding `authorizer`; migrate all of them in the same commit so no compatibility shim or uninitialized field remains.

- [ ] **Step 1: Add a failing dynamic-authorizer test**

In `options.rs`, add an authorizer that accepts no static key but returns a session for `[9; 32]`. Assert that `TunnelOptions::Server` validates with an empty `allowed_client_keys` only when `authorizer` is present.

```rust
#[test]
fn dynamic_authorizer_allows_an_empty_static_allowlist() {
    let options = TunnelOptions::Server(TunnelServerOptions {
        allowed_client_keys: HashSet::new(),
        authorizer: Some(Arc::new(TestAuthorizer)),
        ..test_server_options(HashSet::new())
    });
    assert!(options.validate().is_ok());
}
```

- [ ] **Step 2: Run the focused test and confirm the missing API failure**

Run: `cargo test -p librqbit dynamic_authorizer_allows_an_empty_static_allowlist`

Expected: FAIL because `TunnelServerAuthorizer` and `authorizer` do not exist.

- [ ] **Step 3: Define the exact observer contract in `options.rs`**

Add these public types, implement manual `Debug` for `TunnelServerOptions`, and keep `allowed_client_keys` for direct callers:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelTrafficDirection {
    Upload,
    Download,
}

pub trait TunnelServerSession: Send + Sync + 'static {
    fn record_payload(&self, direction: TunnelTrafficDirection, bytes: usize);
    fn cancellation_token(&self) -> CancellationToken;
    fn connected(&self);
    fn disconnected(&self);
}

pub trait TunnelServerAuthorizer: Send + Sync + 'static {
    fn authorize(&self, key: &TunnelPublicKey) -> Option<Arc<dyn TunnelServerSession>>;
}

pub struct TunnelServerOptions {
    pub peer_listen: SocketAddr,
    pub identity_key: TunnelPrivateKey,
    pub allowed_client_keys: HashSet<TunnelPublicKey>,
    pub authorizer: Option<Arc<dyn TunnelServerAuthorizer>>,
    pub egress_policy: EgressPolicy,
    pub carrier_root: PathBuf,
}
```

Validation must reject an empty static set only when `authorizer.is_none()`. Re-export the traits and direction from `librqbit::lib`. Update every existing `TunnelServerOptions` struct literal—including `rqbit::build_tunnel_opts`, `librqbit` inline tests, and `crates/librqbit/tests/tunnel.rs`—to set `authorizer: None`, so the direct `--tunnel-allowed-clients` CLI keeps its current behavior.

- [ ] **Step 4: Refactor Noise admission to retain a session exactly once**

Extract a crate-private generic helper in `crypto.rs`; it must derive the remote key, call `authorize` once, and write the Noise response only after authorization succeeds.

```rust
pub(crate) fn responder_accept_with<T>(
    local_key: &TunnelPrivateKey,
    msg: &[u8],
    authorize: impl FnOnce(&TunnelPublicKey) -> Option<T>,
) -> Result<(NoiseTransport, TunnelPublicKey, T, Vec<u8>), TunnelCryptoError> {
    // Preserve the existing responder construction/read_message code.
    let remote_pub = TunnelPublicKey(remote_static);
    let context = authorize(&remote_pub)
        .ok_or_else(|| TunnelCryptoError::ClientNotAllowed(remote_pub.clone()))?;
    let reply_len = responder.write_message(&[], &mut reply_buf)
        .map_err(|e| TunnelCryptoError::HandshakeFailed(format!("responder write: {e}")))?;
    let transport = responder.into_transport_mode()
        .map_err(|e| TunnelCryptoError::HandshakeFailed(format!("responder transport: {e}")))?;
    Ok((NoiseTransport { noise: transport }, remote_pub, context, reply_buf[..reply_len].to_vec()))
}
```

Keep `responder_accept` as the existing static-allowlist wrapper using `then_some(())`, so its present tests and direct callers retain their behavior.

In `server.rs`, make `seed_until_promoted` return `Arc<dyn TunnelServerSession>` with the transport/key. Add `session` to `AdmittedPeer`, call `session.connected()` after promotion, and call `session.disconnected()` exactly once when the relay task ends. Static allowlist admission receives a no-op session implementation.

- [ ] **Step 5: Add revocation-aware cancellation to the server task**

When spawning `run_server_relay`, create an effective child token cancelled by either the global server token or `peer.session.cancellation_token()`. Use that effective token for the relay and every spawned stream task. Do not cancel the authorizer-owned token from the relay.

```rust
let relay_shutdown = peer_shutdown.child_token();
let user_shutdown = peer.session.cancellation_token();
let bridge_shutdown = relay_shutdown.clone();
tokio::spawn(async move {
    tokio::select! {
        _ = peer_shutdown.cancelled() => bridge_shutdown.cancel(),
        _ = user_shutdown.cancelled() => bridge_shutdown.cancel(),
    }
});
```

Add a server test whose session token is cancelled after admission and assert the relay cancellation token becomes cancelled.

- [ ] **Step 6: Run the core regression subset and commit**

Run:

```bash
cargo test -p librqbit dynamic_authorizer_allows_an_empty_static_allowlist
cargo test -p librqbit rejects_a_client_not_in_the_server_allowlist
cargo test -p librqbit tunnel
cargo fmt --all
```

Expected: all selected tests pass; static rejection behavior remains unchanged.

Commit:

```bash
git add crates/librqbit/src/tunnel/{options.rs,crypto.rs,server.rs,service.rs} crates/librqbit/src/lib.rs crates/librqbit/tests/tunnel.rs crates/rqbit/src/main.rs
git commit -m "feat(tunnel): support dynamic server authorization"
```

## Task 3: Account relay payload at success boundaries

**Files:**
- Modify: `crates/librqbit/src/tunnel/relay.rs`
- Test: inline tests in `crates/librqbit/src/tunnel/relay.rs`

- [ ] **Step 1: Add failing tests for bounded TCP credits and UDP accounting**

Add a `RecordingSession` that records `(TunnelTrafficDirection, usize)` pairs. Test that a credit larger than outstanding data records only the outstanding amount; test that a failed UDP `send_to` records zero; test that an accepted UDP response records exactly its datagram length.

```rust
assert_eq!(take_acknowledged(&pending, 4096), 1024);
assert_eq!(pending.load(Ordering::Relaxed), 0);
assert_eq!(recorded(), vec![(TunnelTrafficDirection::Download, 1024)]);
```

- [ ] **Step 2: Run the new tests and confirm missing accounting helpers**

Run: `cargo test -p librqbit relay::tests::credit_is_bounded_by_forwarded_bytes`

Expected: FAIL because `take_acknowledged` and the meter wiring do not exist.

- [ ] **Step 3: Add per-stream outstanding-download accounting**

Add `download_uncredited: Arc<AtomicU64>` to `TcpEntry`. Pass it into `handle_tcp_stream` and `open_and_pump`. Increment it only after `sink.send(TunnelFrame::TcpData { … }).await` returns `true`.

```rust
fn take_acknowledged(pending: &AtomicU64, requested: u32) -> usize {
    let mut observed = pending.load(Ordering::Acquire);
    loop {
        let accepted = observed.min(u64::from(requested));
        match pending.compare_exchange_weak(
            observed,
            observed - accepted,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return accepted as usize,
            Err(next) => observed = next,
        }
    }
}
```

In the `Credit` arm, grant and record only `take_acknowledged`; never grant a peer extra credit merely because it sent a larger number.

- [ ] **Step 4: Put each metric at the specified successful I/O point**

Pass `Arc<dyn TunnelServerSession>` into TCP and UDP workers. Record upload after a successful `dest_write.write_all(&bytes).await`; record TCP download after accepting bounded `Credit`; record UDP upload from `Ok(sent)` returned by `send_to`; record UDP download only when `try_send_lossy` returns true.

```rust
if dest_write.write_all(&bytes).await.is_err() {
    break;
}
session.record_payload(TunnelTrafficDirection::Upload, bytes.len());
```

Never count frame headers, ciphertext, cover data, rejected authorization, reset paths, or queue contents.

- [ ] **Step 5: Run relay and end-to-end tunnel tests, then commit**

Run:

```bash
cargo test -p librqbit relay::tests
cargo test -p librqbit socks_connect_reaches_server_side_tcp_echo_only_through_tunnel
cargo test -p librqbit udp_associate_echoes_datagram_through_tunnel
cargo fmt --all
```

Expected: accounting tests and existing TCP/UDP tunnel tests pass.

Commit:

```bash
git add crates/librqbit/src/tunnel/relay.rs
git commit -m "feat(tunnel): meter successful relay payload"
```

## Task 4: Persist users and counters through a SQLite-backed registry

**Files:**
- Create: `crates/rqbit-tunnel/src/paths.rs`
- Create: `crates/rqbit-tunnel/src/store.rs`
- Modify: `crates/rqbit-tunnel/Cargo.toml`
- Create: `crates/rqbit-tunnel/src/registry.rs`
- Modify: `crates/rqbit-tunnel/src/lib.rs`
- Test: inline tests in `store.rs` and `registry.rs`

- [ ] **Step 1: Add failing persistence and revocation tests**

```rust
#[tokio::test]
async fn disabling_a_user_rejects_new_admission_and_cancels_existing_sessions() {
    let registry = test_registry().await;
    let user = registry.create_user("alice").await.unwrap();
    let session = registry.authorize(&user.public_key).unwrap();
    registry.set_enabled(user.id, false).await.unwrap();
    assert!(registry.authorize(&user.public_key).is_none());
    assert!(session.cancellation_token().is_cancelled());
}

#[tokio::test]
async fn flush_persists_both_direction_deltas() {
    let registry = test_registry().await;
    let user = registry.create_user("alice").await.unwrap();
    let session = registry.authorize(&user.public_key).unwrap();
    session.record_payload(TunnelTrafficDirection::Upload, 9);
    session.record_payload(TunnelTrafficDirection::Download, 14);
    registry.flush().await.unwrap();
    assert_eq!(registry.snapshot(user.id).await.unwrap().traffic, TrafficTotals { upload: 9, download: 14 });
}
```

- [ ] **Step 2: Run the tests and confirm the storage layer is absent**

Run: `cargo test -p rqbit-tunnel disabling_a_user_rejects_new_admission_and_cancels_existing_sessions`

Expected: FAIL because `ServerStore` and `UserRegistry` do not exist.

- [ ] **Step 3: Implement path policy and transactional migrations**

`ServerPaths::system()` returns `/etc/rqbit-tunnel`, `/var/lib/rqbit-tunnel`, `/run/rqbit-tunnel`; `ServerPaths::under(root)` exists only for tests/install staging. Add `arc-swap` as a normal workspace dependency and `tempfile` as a dev-dependency to `rqbit-tunnel` in this task. Add `librqbit = { workspace = true, default-features = false, features = ["tracing-subscriber-utils"] }` plus crate features `default = ["default-tls"]`, `default-tls = ["librqbit/default-tls"]`, and `rust-tls = ["librqbit/rust-tls"]`. Thus normal workspace builds select the existing default TLS backend, while a Rustls workspace build must explicitly select `rqbit-tunnel/rust-tls` alongside `rqbit/rust-tls`; never select both. `ServerStore::open` must set `journal_mode = WAL`, `foreign_keys = ON`, and execute an idempotent migration creating `users`, `traffic_totals`, and `settings` exactly as specified.

```sql
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    public_key BLOB NOT NULL UNIQUE,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL,
    reset_at INTEGER
);
CREATE TABLE IF NOT EXISTS traffic_totals (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    upload_bytes INTEGER NOT NULL DEFAULT 0 CHECK (upload_bytes >= 0),
    download_bytes INTEGER NOT NULL DEFAULT 0 CHECK (download_bytes >= 0),
    updated_at INTEGER NOT NULL
);
```

Use `Transaction` for create/delete/enable/reset and `spawn_blocking` for every SQLite call from async code.

- [ ] **Step 4: Implement `UserRegistry` as the core authorizer**

Maintain `ArcSwap<HashMap<TunnelPublicKey, Arc<UserMeter>>>`. `UserMeter` owns atomics for both totals, a `CancellationToken`, connected-count, and last-seen timestamp. Implement `TunnelServerAuthorizer` and `TunnelServerSession` directly; `record_payload` is one relaxed atomic increment plus a dirty flag, and never touches SQLite.

```rust
impl TunnelServerAuthorizer for UserRegistry {
    fn authorize(&self, key: &TunnelPublicKey) -> Option<Arc<dyn TunnelServerSession>> {
        self.by_key.load().get(key).cloned().map(|meter| meter as Arc<dyn TunnelServerSession>)
    }
}
```

On disable/delete, remove the meter from the swapped map before cancelling its token. On reset, atomically zero both meters, update `reset_at`, and persist the reset in the same transaction. A one-second task calls `flush`; graceful runtime shutdown calls `flush` synchronously.

- [ ] **Step 5: Run storage/registry tests and commit**

Run:

```bash
cargo test -p rqbit-tunnel store::tests
cargo test -p rqbit-tunnel registry::tests
cargo fmt --all
```

Expected: user lifecycle, bidirectional flush, and revocation tests pass.

Commit:

git add crates/rqbit-tunnel/Cargo.toml crates/rqbit-tunnel/src/{lib.rs,paths.rs,store.rs,registry.rs}
git commit -m "feat(tunnel): persist managed server users and traffic"
```

## Task 5: Implement framed Unix IPC and a managed server runtime

**Files:**
- Create: `crates/rqbit-tunnel/src/ipc/mod.rs`
- Create: `crates/rqbit-tunnel/src/ipc/protocol.rs`
- Create: `crates/rqbit-tunnel/src/ipc/unix.rs`
- Create: `crates/rqbit-tunnel/src/runtime/mod.rs`
- Create: `crates/rqbit-tunnel/src/runtime/server.rs`
- Modify: `crates/rqbit-tunnel/src/lib.rs`
- Test: inline tests in `ipc/protocol.rs`, `ipc/unix.rs`, and `runtime/server.rs`

- [ ] **Step 1: Add a failing IPC round-trip test**

```rust
#[tokio::test]
async fn snapshot_request_round_trips_over_a_unix_socket() {
    let socket = tempfile::tempdir().unwrap().path().join("server.sock");
    let server = spawn_test_server(&socket).await;
    let response = UnixControlClient::connect(&socket).await.unwrap()
        .request(ServerRequest::Snapshot).await.unwrap();
    assert!(matches!(response, ServerResponse::Snapshot(_)));
    server.shutdown().await;
}
```

- [ ] **Step 2: Run the test and confirm IPC types are missing**

Run: `cargo test -p rqbit-tunnel snapshot_request_round_trips_over_a_unix_socket`

Expected: FAIL because `ServerRequest`, `ServerResponse`, and `UnixControlClient` do not exist.

- [ ] **Step 3: Define the versioned length-delimited protocol**

Use a four-byte big-endian length plus JSON body, reject zero-length or frames above 64 KiB before allocation, and include `protocol_version: 1` in every envelope.

```rust
pub enum ServerRequest {
    Snapshot,
    ListUsers,
    AddUser { name: String, export_path: Option<PathBuf> },
    SetEnabled { id: Uuid, enabled: bool },
    DeleteUser { id: Uuid },
    ResetTraffic { id: Uuid },
    ReloadConfig,
    Shutdown,
}
```

`ServerResponse` must use structured `Ok` payloads and a typed `{ code, message, recovery }` error; it must never serialize private key bytes except in the explicit `AddUser` export operation, which writes to a file instead of returning the bundle through IPC.

- [ ] **Step 4: Start `librqbit` server mode from managed configuration**

`ManagedServer::start` loads root-owned JSON config/key material, opens store/registry, creates `TunnelServerOptions { authorizer: Some(registry.clone()), allowed_client_keys: HashSet::new(), … }`, and starts `Session::new_with_opts` with normal tunnel DHT behavior but no ordinary torrent listener or HTTP API.

```rust
let session = Session::new_with_opts(
    paths.data_dir.clone(),
    SessionOptions {
        listen: None,
        connect: None,
        persistence: None,
        tunnel: Some(TunnelOptions::Server(tunnel_options)),
        cancellation_token: Some(shutdown.clone()),
        ..Default::default()
    },
).await?;
```

Bind the control socket after removing only an existing socket owned by the configured runtime path. Create its parent with `0750` and socket with group-readable admin permissions. On `Shutdown`, stop the session, flush registry counters, remove the socket, and return only after the task exits.

- [ ] **Step 5: Run IPC/runtime tests and commit**

Run:

```bash
cargo test -p rqbit-tunnel ipc::
cargo test -p rqbit-tunnel runtime::server::tests
cargo fmt --all
```

Expected: malformed frames are rejected, snapshots round-trip, and graceful shutdown flushes state.

Commit:

```bash
git add crates/rqbit-tunnel/src/{lib.rs,ipc,runtime}
git commit -m "feat(tunnel): run managed server control plane"
```

## Task 6: Add stable server CLI and terminal dashboard

**Files:**
- Create: `crates/rqbit-tunnel/src/cli.rs`
- Create: `crates/rqbit-tunnel/src/tui/mod.rs`
- Create: `crates/rqbit-tunnel/src/tui/server.rs`
- Modify: `crates/rqbit-tunnel/src/bin/rqbit-tunnel.rs`
- Test: inline tests in `cli.rs` and `tui/server.rs`

- [ ] **Step 1: Add failing CLI JSON and reducer tests**

```rust
#[test]
fn list_users_json_is_machine_readable_without_terminal_escape_bytes() {
    let stdout = render_json(&ServerResponse::Users(vec![sample_user()]));
    assert_eq!(serde_json::from_str::<Vec<UserSnapshot>>(&stdout).unwrap()[0].name, "alice");
}

#[test]
fn delete_key_opens_confirmation_before_mutating() {
    let mut state = ServerTuiState::with_users(vec![sample_user()]);
    state.handle_key(KeyCode::Char('x'));
    assert!(matches!(state.modal, Some(Modal::ConfirmDelete(_))));
}
```

- [ ] **Step 2: Run tests and confirm the CLI/TUI types are absent**

Run: `cargo test -p rqbit-tunnel list_users_json_is_machine_readable_without_terminal_escape_bytes`

Expected: FAIL because `ServerTuiState` and `render_json` do not exist.

- [ ] **Step 3: Implement commands with no hidden TUI-only behavior**

Use Clap commands `server run`, `server tui`, `server users list|add|enable|disable|delete|reset`, and `server settings show|set`. Every mutation calls the Unix IPC client; `--json` writes only serialized DTOs to stdout and diagnostics to stderr.

```rust
#[derive(Subcommand)]
enum ServerUsersCommand {
    List { #[arg(long)] json: bool },
    Add { #[arg(long)] name: String, #[arg(long)] export: Option<PathBuf> },
    Enable { id: Uuid },
    Disable { id: Uuid },
    Delete { id: Uuid, #[arg(long)] yes: bool },
    Reset { id: Uuid, #[arg(long)] yes: bool },
}
```

Refuse delete/reset/export without explicit terminal confirmation or `--yes`; export must print the destination and an unencrypted-secret warning to stderr.

- [ ] **Step 4: Implement the one-second Ratatui dashboard**

`ServerTuiState` is a pure reducer over `ServerSnapshot`, selected row, modal, and last error. The terminal loop polls the IPC snapshot every second and uses a 250 ms event tick. Render user name, enabled/connected state, totals, rolling rate, last seen, and a footer with `[a]dd [e]nable [d]isable [x] delete [r]eset [b]undle F5 q`.

The polling driver computes each rate from the same user ID in the immediately previous snapshot: `saturating_sub(current_total, previous_total) / elapsed_seconds` independently for upload and download. A new/reset user has a zero rate for its first frame. This derived value is never persisted or fed back into the counters.

Do not put database or socket logic in the reducer. Test the reducer with plain `KeyCode` events; use a terminal backend only in `run_server_tui`.

- [ ] **Step 5: Run CLI/TUI tests, build the binary, and commit**

Run:

```bash
cargo test -p rqbit-tunnel cli::tests
cargo test -p rqbit-tunnel tui::server::tests
cargo build -p rqbit-tunnel
cargo fmt --all
```

Expected: tests pass and `target/debug/rqbit-tunnel server --help` exits 0.

Commit:

```bash
git add crates/rqbit-tunnel/src/{bin/rqbit-tunnel.rs,cli.rs,tui}
git commit -m "feat(tunnel): add server management TUI and CLI"
```

## Task 7: Install the server as a real systemd service and document the operation

**Files:**
- Create: `systemd/rqbit-tunnel-server.service`
- Modify: `scripts/tunnel/server-quickstart.sh`
- Modify: `scripts/tunnel/README.md`
- Modify: `README.md`
- Test: `scripts/tunnel/test-server-unit.sh`

- [ ] **Step 1: Add a failing unit-template validation script**

Create `scripts/tunnel/test-server-unit.sh` that copies the template to a temporary root, substitutes an executable path, and asserts all required directives exist with `systemd-analyze verify` when available.

```bash
set -euo pipefail
unit="$1"
grep -qx 'ExecStart=/opt/rqbit-tunnel/rqbit-tunnel server run --config /etc/rqbit-tunnel/server.json' "$unit"
grep -qx 'Restart=on-failure' "$unit"
command -v systemd-analyze >/dev/null || exit 0
systemd-analyze verify "$unit"
```

- [ ] **Step 2: Run the script and confirm the unit is absent**

Run: `bash scripts/tunnel/test-server-unit.sh systemd/rqbit-tunnel-server.service`

Expected: FAIL because the service template does not exist.

- [ ] **Step 3: Create the unit and replace the foreground quickstart behavior**

Create a non-socket-activated unit with `After=network-online.target`, `Wants=network-online.target`, `ExecStart=/opt/rqbit-tunnel/rqbit-tunnel server run --config /etc/rqbit-tunnel/server.json`, `Restart=on-failure`, `RestartSec=3`, and `NoNewPrivileges=true`. Do not use the old `rqbit.service` socket activation template.

Rewrite `server-quickstart.sh` to:

1. require root/sudo only for install/configuration;
2. create root-owned config/data/key directories with restrictive permissions;
3. generate the server key once through harness setup;
4. install the unit, `daemon-reload`, `enable --now` it, and wait for the control socket health response;
5. invoke `rqbit-tunnel server tui` after successful setup.

It must never echo private client key material to the terminal automatically. User export is now an explicit TUI/CLI action.

- [ ] **Step 4: Document exact operation and risk boundaries**

Update both READMEs with server install, SSH TUI/CLI examples, counter semantics, live refresh behavior, user revoke behavior, and the two explicit risk statements: unencrypted exported bundle is a transferable secret; unauthenticated LAN SOCKS is handled in the client plan.

- [ ] **Step 5: Validate, run relevant tests, and commit**

Run:

```bash
bash scripts/tunnel/test-server-unit.sh systemd/rqbit-tunnel-server.service
cargo test -p rqbit-tunnel
cargo test -p librqbit tunnel
cargo fmt --all -- --check
```

Expected: unit template validates where systemd tooling is available; Rust tests and formatting pass.

Commit:

```bash
git add systemd/rqbit-tunnel-server.service scripts/tunnel/server-quickstart.sh scripts/tunnel/test-server-unit.sh scripts/tunnel/README.md README.md
git commit -m "feat(tunnel): install managed server service"
```

## Task 8: Run the server acceptance smoke test

**Files:**
- Create: `crates/rqbit-tunnel/tests/server_control_e2e.rs`
- Modify: `crates/rqbit-tunnel/src/runtime/server.rs` only if the smoke test exposes a real lifecycle defect

- [ ] **Step 1: Write an end-to-end control-plane test**

Start `ManagedServer` under a temporary `ServerPaths`, add an `alice` user through IPC, assert the exported bundle file has mode `0600` on Unix, connect an existing tunnel fixture using that client key, send payload in both directions, wait for an IPC snapshot update, disable the user, and assert the fixture connection is cancelled.

```rust
assert_eq!(snapshot.users[0].traffic.upload, sent_to_destination as u64);
assert_eq!(snapshot.users[0].traffic.download, received_by_socks as u64);
control.set_enabled(alice.id, false).await.unwrap();
assert!(wait_for_cancelled(&session_token).await);
```

- [ ] **Step 2: Run the test to establish the first red state**

Run: `cargo test -p rqbit-tunnel --test server_control_e2e -- --nocapture`

Expected: FAIL until IPC, dynamic revocation, and accounting are connected end-to-end.

- [ ] **Step 3: Fix only the real integration seams exposed by the test**

Do not add test-only bypasses. Keep the production IPC path, registry, and `librqbit` session observer active in the test; use temporary paths and loopback ports only.

- [ ] **Step 4: Re-run the test and the server regression suite**

Run:

```bash
cargo test -p rqbit-tunnel --test server_control_e2e -- --nocapture
cargo test -p rqbit-tunnel
cargo test -p librqbit tunnel
```

Expected: end-to-end user creation, accounting, and immediate revocation pass without regressing the tunnel suite.

- [ ] **Step 5: Commit the acceptance test**

```bash
git add crates/rqbit-tunnel/tests/server_control_e2e.rs crates/rqbit-tunnel/src
git commit -m "test(tunnel): cover managed server control flow"
```
