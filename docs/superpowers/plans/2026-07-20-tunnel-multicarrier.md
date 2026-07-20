# Tunnel Multi-Carrier Implementation Plan (Plan 1 of 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Spread tunnel SOCKS streams across N independent carrier TCP connections (per-stream striping) so aggregate throughput fills the link and one dead carrier no longer stalls everything.

**Architecture:** A new `CarrierPool` owns N `TunnelClientSupervisor`s (each already manages one carrier connection with independent reconnect). Each new SOCKS stream is assigned to the least-loaded live carrier via a pure `select_carrier` function and lives there for its lifetime — no frame resequencing, no wire-protocol change. `ClientMux` gains an O(1) load counter. `SocksIngress` calls `pool.pick()` instead of `supervisor.current()`.

**Tech Stack:** Rust, tokio, `arc_swap::ArcSwapOption`, `tokio_util::sync::CancellationToken`. Crate: `librqbit` (`crates/librqbit/src/tunnel/`), CLI in `crates/rqbit/src/main.rs`.

## Global Constraints

- Design is spec'd in `docs/superpowers/specs/2026-07-20-tunnel-multicarrier-bufferbloat-design.md`. This plan covers **Part A1 only** (multi-carrier). Adaptive window / bufferbloat (Part B2) is Plan 2.
- No wire-protocol change in this plan. Per-stream striping only (a single stream uses one carrier).
- Carrier count: new client option `carriers`, default **4**, valid range **1..=16**.
- Preserve the existing `TCP_NODELAY`-on-carrier behavior (uncommitted in `client.rs`/`server.rs`); every carrier connection still runs through `TunnelClient::connect`, which sets it.
- Follow existing tunnel code style: `pub(crate)` for internal items, typed errors (not `anyhow`) on internal paths, tracing via `tracing::{info,warn,debug}`.
- After each task: `cargo check -p librqbit` and `cargo clippy -p librqbit --all-targets` must pass before commit.

## File Structure

- **Create** `crates/librqbit/src/tunnel/client_pool.rs` — `CarrierPool` (owns N supervisors) + pure `select_carrier`. One responsibility: carrier selection + lifecycle fan-out.
- **Modify** `crates/librqbit/src/tunnel/mod.rs` — add `mod client_pool;`.
- **Modify** `crates/librqbit/src/tunnel/config.rs` — add `DEFAULT_CARRIERS`, `MAX_CARRIERS`.
- **Modify** `crates/librqbit/src/tunnel/options.rs` — add `carriers: usize` to `TunnelClientOptions` (+ `Default`), validate range.
- **Modify** `crates/librqbit/src/tunnel/client_mux.rs` — add atomic load counter + `load()`.
- **Modify** `crates/librqbit/src/tunnel/socks.rs` — `SocksIngress` takes `Arc<CarrierPool>`; `pick()` per connection.
- **Modify** `crates/librqbit/src/tunnel/service.rs` — build the pool, pass it to the ingress.
- **Modify** `crates/rqbit/src/main.rs` — `--tunnel-carriers` flag, thread into `TunnelClientOptions`.
- **Test** `crates/librqbit/src/tests/tunnel.rs` — integration test (N carriers, stream distribution, one-carrier-death survival).

---

### Task 1: Carrier-count config plumbing

Add the `carriers` option end-to-end (struct field, default, range validation, CLI flag) so later tasks can read `opts.carriers`.

**Files:**
- Modify: `crates/librqbit/src/tunnel/config.rs` (after `DHT_PEER_CACHE`, ~line 70)
- Modify: `crates/librqbit/src/tunnel/options.rs:34-65` (struct + Default), `options.rs:15-22` (error enum), `options.rs:121-142` (`validate`)
- Modify: `crates/rqbit/src/main.rs:245-323` (flag), `main.rs:834-884` (build), `main.rs:705-747` (validate table)
- Test: inline `#[cfg(test)]` in `options.rs`

**Interfaces:**
- Produces: `TunnelClientOptions.carriers: usize`; consts `config::DEFAULT_CARRIERS: usize = 4`, `config::MAX_CARRIERS: usize = 16`; error `TunnelConfigError::InvalidCarrierCount`.

- [ ] **Step 1: Write the failing test** — append to the `#[cfg(test)] mod tests` in `crates/librqbit/src/tunnel/options.rs` (create the module if absent):

```rust
#[cfg(test)]
mod carrier_tests {
    use super::*;

    #[test]
    fn client_options_default_carriers_is_four() {
        assert_eq!(TunnelClientOptions::default().carriers, 4);
    }

    #[test]
    fn validate_rejects_zero_carriers() {
        let mut opts = TunnelClientOptions {
            expected_server_key: TunnelPublicKey([1u8; 32]),
            ..Default::default()
        };
        opts.carriers = 0;
        assert!(matches!(
            TunnelOptions::Client(opts).validate(),
            Err(TunnelConfigError::InvalidCarrierCount)
        ));
    }

    #[test]
    fn validate_rejects_too_many_carriers() {
        let opts = TunnelClientOptions {
            expected_server_key: TunnelPublicKey([1u8; 32]),
            carriers: super::super::config::MAX_CARRIERS + 1,
            ..Default::default()
        };
        assert!(matches!(
            TunnelOptions::Client(opts).validate(),
            Err(TunnelConfigError::InvalidCarrierCount)
        ));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p librqbit carrier_tests 2>&1 | tail -20`
Expected: FAIL to compile — `no field 'carriers'` / `no variant InvalidCarrierCount`.

- [ ] **Step 3: Add the consts** in `crates/librqbit/src/tunnel/config.rs` (end of file):

```rust
// ── Carriers ─────────────────────────────────────────────────────────────────

/// Default number of parallel carrier connections a client opens to the server.
/// Streams are striped per-connection across them; aggregate throughput fills
/// the link and one dead carrier only resets its own streams.
pub(crate) const DEFAULT_CARRIERS: usize = 4;

/// Upper bound on `--tunnel-carriers` (beyond this, diminishing returns plus
/// extra handshakes / DHT noise).
pub(crate) const MAX_CARRIERS: usize = 16;
```

- [ ] **Step 4: Add the field + Default + error + validation** in `crates/librqbit/src/tunnel/options.rs`.

Add to `TunnelClientOptions` (after `pairing`, `options.rs:52`):
```rust
    /// Number of parallel carrier connections to open (per-stream striping).
    pub carriers: usize,
```
Add to its `Default` impl (`options.rs:55-65`, inside the struct literal):
```rust
            carriers: super::config::DEFAULT_CARRIERS,
```
Add error variant to `TunnelConfigError` (`options.rs:15-22`):
```rust
    #[error("carriers must be between 1 and {max}")]
    InvalidCarrierCount,
```
(If the enum's variants carry no fields elsewhere, keep this fieldless; drop the `{max}` interpolation and hard-code the range text: `#[error("carriers must be between 1 and 16")]`.)

Add to the client arm of `validate` (`options.rs:125-131`, before `Ok(())`):
```rust
                if opts.carriers == 0 || opts.carriers > super::config::MAX_CARRIERS {
                    return Err(TunnelConfigError::InvalidCarrierCount);
                }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p librqbit carrier_tests 2>&1 | tail -20`
Expected: PASS (3 tests).

- [ ] **Step 6: Add the CLI flag** in `crates/rqbit/src/main.rs`.

Flag field (in the `--tunnel-*` block, after `tunnel_egress_policy`, `main.rs:323`):
```rust
    /// Number of parallel carrier connections in client mode (default 4, max 16).
    #[arg(long = "tunnel-carriers", env = "RQBIT_TUNNEL_CARRIERS", global = true)]
    pub tunnel_carriers: Option<usize>,
```
In `build_tunnel_opts` client branch, add to the `TunnelClientOptions { ... }` literal (`main.rs:877-883`):
```rust
                carriers: opts
                    .tunnel_carriers
                    .unwrap_or(librqbit::tunnel_config::DEFAULT_CARRIERS)
                    .clamp(1, librqbit::tunnel_config::MAX_CARRIERS),
```
If `config` consts are not re-exported from `librqbit`, instead hard-code the clamp bounds and default here: `.unwrap_or(4).clamp(1, 16)` — this keeps the CLI crate free of a new dependency on internal consts. Prefer the hard-coded form unless a re-export already exists.

Add `"--tunnel-carriers"` to the client-only rows of the `validate_tunnel_flags` table (`main.rs:710-747`) so it errors without `--tunnel-mode`.

- [ ] **Step 7: Verify build + commit**

Run: `cargo check -p librqbit && cargo check -p rqbit && cargo clippy -p librqbit --all-targets 2>&1 | tail -5`
Expected: clean.

```bash
git add crates/librqbit/src/tunnel/config.rs crates/librqbit/src/tunnel/options.rs crates/rqbit/src/main.rs
git commit -m "feat(tunnel): add --tunnel-carriers option (default 4, 1..=16)"
```

---

### Task 2: Pure carrier-selection function

The least-loaded-live selection logic, isolated as a pure function so it is fully unit-testable without any mux/transport.

**Files:**
- Create: `crates/librqbit/src/tunnel/client_pool.rs`
- Modify: `crates/librqbit/src/tunnel/mod.rs` (add `mod client_pool;`)
- Test: inline in `client_pool.rs`

**Interfaces:**
- Produces: `pub(crate) fn select_carrier(loads: &[Option<usize>]) -> Option<usize>` — index of the least-loaded available carrier (`None` entry = unavailable). Ties break to the lowest index. `None` if none available.

- [ ] **Step 1: Write the failing test** — create `crates/librqbit/src/tunnel/client_pool.rs` with ONLY the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::select_carrier;

    #[test]
    fn none_when_empty() {
        assert_eq!(select_carrier(&[]), None);
    }

    #[test]
    fn none_when_all_unavailable() {
        assert_eq!(select_carrier(&[None, None]), None);
    }

    #[test]
    fn picks_minimum_load() {
        assert_eq!(select_carrier(&[Some(3), Some(1), Some(2)]), Some(1));
    }

    #[test]
    fn ties_break_to_lowest_index() {
        assert_eq!(select_carrier(&[Some(2), Some(2)]), Some(0));
    }

    #[test]
    fn skips_unavailable_carriers() {
        assert_eq!(select_carrier(&[None, Some(5), None, Some(4)]), Some(3));
    }
}
```

Add `mod client_pool;` to `crates/librqbit/src/tunnel/mod.rs` (next to the other `mod` lines).

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p librqbit client_pool 2>&1 | tail -20`
Expected: FAIL — `cannot find function select_carrier`.

- [ ] **Step 3: Implement `select_carrier`** at the top of `client_pool.rs` (above the test module):

```rust
/// Pick the index of the least-loaded available carrier.
///
/// `loads[i] == None` means carrier `i` is currently unavailable (not
/// connected). Returns `None` if no carrier is available. Ties break toward the
/// lowest index for determinism.
pub(crate) fn select_carrier(loads: &[Option<usize>]) -> Option<usize> {
    loads
        .iter()
        .enumerate()
        .filter_map(|(i, load)| load.map(|l| (i, l)))
        .min_by_key(|&(i, load)| (load, i))
        .map(|(i, _)| i)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p librqbit client_pool 2>&1 | tail -20`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/librqbit/src/tunnel/client_pool.rs crates/librqbit/src/tunnel/mod.rs
git commit -m "feat(tunnel): pure least-loaded carrier selection"
```

---

### Task 3: ClientMux load counter

Give each carrier an O(1) live-stream count so the pool can compare loads without locking the route maps.

**Files:**
- Modify: `crates/librqbit/src/tunnel/client_mux.rs:57-65` (struct), `:67-91` (`new`), `:100-133` (`open_tcp`), `:156-162` (`unregister_tcp`), `:164-183` (`open_udp`), `:198-203` (`close_udp`)
- Test: `crates/librqbit/src/tests/tunnel.rs` (integration, uses existing in-process harness)

**Interfaces:**
- Consumes: nothing new.
- Produces: `ClientMux::load(&self) -> usize` — count of currently-registered TCP streams + UDP associations.

- [ ] **Step 1: Inspect the harness.** Read `crates/librqbit/src/tests/tunnel.rs` and find the existing in-process client+server helper (the test that drives a real SOCKS round-trip). Note the function that yields a connected `Arc<ClientMux>` (or the `TunnelClientSupervisor`, from which `.current()` gives the mux). You will mirror it.

- [ ] **Step 2: Write the failing test** — add to `crates/librqbit/src/tests/tunnel.rs`, mirroring the harness setup found in Step 1 (pseudocode wrapper; fill the `setup_*` call with the real helper name):

```rust
#[tokio::test]
async fn client_mux_load_tracks_open_streams() {
    // <use the existing harness to get a connected mux + a sink destination server>
    let mux = /* Arc<ClientMux> from the harness (supervisor.current().unwrap()) */;
    assert_eq!(mux.load(), 0);

    let (_id_a, _rx_a, _cr_a) = mux.open_tcp(dest_localhost()).await.unwrap();
    let (id_b, _rx_b, _cr_b) = mux.open_tcp(dest_localhost()).await.unwrap();
    assert_eq!(mux.load(), 2);

    mux.unregister_tcp(id_b).await;
    assert_eq!(mux.load(), 1);
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p librqbit client_mux_load_tracks_open_streams 2>&1 | tail -20`
Expected: FAIL — `no method named 'load'`.

- [ ] **Step 4: Implement the counter** in `crates/librqbit/src/tunnel/client_mux.rs`.

Add to the struct (`client_mux.rs:57-65`):
```rust
    load: AtomicUsize,
```
(ensure `use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};` — `AtomicU64`/`Ordering` are already imported for `next_stream_id`.)

In `new` (`client_mux.rs:75-84`, inside the `Self { ... }` literal):
```rust
            load: AtomicUsize::new(0),
```

In `open_tcp`, after the route is inserted and the `OpenTcp` frame send succeeds (i.e. on the success path that returns `Some((stream_id, rx, send_credit))`), before returning:
```rust
        self.load.fetch_add(1, Ordering::Relaxed);
```
(Do NOT increment on the failure path that removes the route and returns `None`.)

In `open_udp`, on the success path before returning `Some((assoc_id, rx))`:
```rust
        self.load.fetch_add(1, Ordering::Relaxed);
```

In `unregister_tcp` (`client_mux.rs:156-162`), decrement only if a route was actually removed:
```rust
    pub(crate) async fn unregister_tcp(&self, stream_id: u64) {
        let removed = self.tcp.lock().await.remove(&stream_id);
        if let Some(route) = removed {
            route.send_credit.close();
            self.load.fetch_sub(1, Ordering::Relaxed);
        }
    }
```
(Adapt to the exact current body; the invariant is: decrement exactly once, only when the entry existed.)

In `close_udp` (`client_mux.rs:198-203`), decrement only if the association existed:
```rust
        if self.udp.lock().await.remove(&association_id).is_some() {
            self.load.fetch_sub(1, Ordering::Relaxed);
        }
```

Add the accessor (near `is_shutdown`, `client_mux.rs:205`):
```rust
    /// Number of currently-registered TCP streams + UDP associations.
    pub(crate) fn load(&self) -> usize {
        self.load.load(Ordering::Relaxed)
    }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p librqbit client_mux_load_tracks_open_streams 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Verify + commit**

Run: `cargo clippy -p librqbit --all-targets 2>&1 | tail -5`

```bash
git add crates/librqbit/src/tunnel/client_mux.rs crates/librqbit/src/tests/tunnel.rs
git commit -m "feat(tunnel): O(1) live-stream load counter on ClientMux"
```

---

### Task 4: CarrierPool over N supervisors

The pool spawns N `TunnelClientSupervisor`s and resolves `pick()` to the least-loaded live mux using `select_carrier`.

**Files:**
- Modify: `crates/librqbit/src/tunnel/client_pool.rs` (add `CarrierPool` above the test module)
- Test: inline in `client_pool.rs` (construction) + covered end-to-end in Task 6

**Interfaces:**
- Consumes: `TunnelClientSupervisor::start(opts, dht, shutdown) -> Arc<Self>`; `TunnelClientSupervisor::current() -> Option<Arc<ClientMux>>`; `ClientMux::load()`, `ClientMux::is_shutdown()`; `select_carrier`.
- Produces:
  - `CarrierPool::start(opts: TunnelClientOptions, dht: Option<Dht>, shutdown: CancellationToken) -> Arc<CarrierPool>`
  - `CarrierPool::pick(&self) -> Option<Arc<ClientMux>>`
  - `CarrierPool::live_count(&self) -> usize`

- [ ] **Step 1: Write the failing test** — add to the `tests` module in `client_pool.rs`:

```rust
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn pool_spawns_requested_carrier_count() {
        // No server needed: with no reachable address the supervisors stay
        // disconnected, but the pool must still hold N of them and report
        // zero live carriers / None from pick().
        let mut opts = crate::tunnel::options::TunnelClientOptions {
            expected_server_key: crate::tunnel::frame::TunnelPublicKey([9u8; 32]),
            server_addr: Some(([127, 0, 0, 1], 1).into()), // unreachable
            ..Default::default()
        };
        opts.carriers = 3;
        let pool = super::CarrierPool::start(opts, None, CancellationToken::new());
        assert_eq!(pool.carrier_count(), 3);
        assert_eq!(pool.live_count(), 0);
        assert!(pool.pick().is_none());
    }
```
(Adjust the `TunnelPublicKey` import path to the actual re-export used elsewhere in the crate.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p librqbit pool_spawns_requested_carrier_count 2>&1 | tail -20`
Expected: FAIL — `no type CarrierPool`.

- [ ] **Step 3: Implement `CarrierPool`** in `client_pool.rs` (above the tests):

```rust
use std::sync::Arc;

use dht::Dht;
use tokio_util::sync::CancellationToken;

use super::client_mux::ClientMux;
use super::client_supervisor::TunnelClientSupervisor;
use super::options::TunnelClientOptions;

/// A fixed pool of independent carrier connections. Each carrier is a
/// `TunnelClientSupervisor` that connects and reconnects on its own; the pool
/// only load-balances new streams across whichever carriers are live.
pub(crate) struct CarrierPool {
    carriers: Vec<Arc<TunnelClientSupervisor>>,
}

impl CarrierPool {
    /// Spawn `opts.carriers` supervisors, all targeting the same server. The
    /// `opts` are cloned per carrier (each moves its own copy into its task).
    pub(crate) fn start(
        opts: TunnelClientOptions,
        dht: Option<Dht>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let n = opts.carriers.max(1);
        let carriers = (0..n)
            .map(|_| TunnelClientSupervisor::start(opts.clone(), dht.clone(), shutdown.clone()))
            .collect();
        Arc::new(Self { carriers })
    }

    /// Total configured carriers (live or not).
    pub(crate) fn carrier_count(&self) -> usize {
        self.carriers.len()
    }

    /// Snapshot the current live muxes (connected, not shut down).
    fn live_muxes(&self) -> Vec<Option<Arc<ClientMux>>> {
        self.carriers
            .iter()
            .map(|sup| sup.current().filter(|m| !m.is_shutdown()))
            .collect()
    }

    /// Number of carriers currently connected.
    pub(crate) fn live_count(&self) -> usize {
        self.live_muxes().iter().filter(|m| m.is_some()).count()
    }

    /// The least-loaded live mux, or `None` if no carrier is connected.
    pub(crate) fn pick(&self) -> Option<Arc<ClientMux>> {
        let muxes = self.live_muxes();
        let loads: Vec<Option<usize>> = muxes
            .iter()
            .map(|m| m.as_ref().map(|mux| mux.load()))
            .collect();
        let idx = select_carrier(&loads)?;
        muxes.into_iter().nth(idx).flatten()
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p librqbit pool_spawns_requested_carrier_count 2>&1 | tail -20`
Expected: PASS. (`select_carrier` unit tests still pass.)

- [ ] **Step 5: Verify + commit**

Run: `cargo clippy -p librqbit --all-targets 2>&1 | tail -5`

```bash
git add crates/librqbit/src/tunnel/client_pool.rs
git commit -m "feat(tunnel): CarrierPool over N independent supervisors"
```

---

### Task 5: Wire the pool into the SOCKS ingress + service

Replace the single-supervisor path with the pool so streams actually stripe across carriers.

**Files:**
- Modify: `crates/librqbit/src/tunnel/socks.rs:98-142` (ingress holds/queries the pool), imports `:24`
- Modify: `crates/librqbit/src/tunnel/service.rs:48-71` (client arm), imports `:17`
- Test: covered by Task 6 integration test (compile-gated here)

**Interfaces:**
- Consumes: `CarrierPool::start`, `CarrierPool::pick`.
- Produces: `SocksIngress::run(self, listener, pool: Arc<CarrierPool>, shutdown)`.

- [ ] **Step 1: Change `SocksIngress::run` to take the pool.** In `crates/librqbit/src/tunnel/socks.rs`:

Replace the import (`socks.rs:24`):
```rust
use super::client_pool::CarrierPool;
```
(remove `use super::client_supervisor::TunnelClientSupervisor;` if now unused).

Change the `run` signature (`socks.rs:114-119`):
```rust
    pub(crate) async fn run(
        self,
        listener: TcpListener,
        pool: Arc<CarrierPool>,
        shutdown: CancellationToken,
    ) {
```

Change the per-connection mux acquisition (`socks.rs:125-134`):
```rust
                            let mux = match pool.pick() {
                                Some(mux) => mux,
                                None => {
                                    tracing::debug!(
                                        client_addr = %addr,
                                        "no live tunnel carrier; dropping SOCKS connection"
                                    );
                                    continue;
                                }
                            };
```
(`pick()` already filters `is_shutdown`, so the old `if !mux.is_shutdown()` guard is folded in.)

- [ ] **Step 2: Build the pool in `service.rs`.** In `crates/librqbit/src/tunnel/service.rs` client arm (`service.rs:60-68`):

Replace the import (`service.rs:17`):
```rust
use super::client_pool::CarrierPool;
```
(remove the `TunnelClientSupervisor` import if now unused).

Replace supervisor construction + ingress spawn:
```rust
                let dht = session.get_dht().cloned();
                let pool = CarrierPool::start(opts, dht, shutdown.clone());

                let ingress = SocksIngress::new(local_addr);
                let socks_shutdown = shutdown.clone();
                tokio::spawn(async move {
                    ingress.run(listener, pool, socks_shutdown).await;
                });

                tracing::info!("tunnel client SOCKS5 listening on {local_addr}");
```

- [ ] **Step 3: Verify build**

Run: `cargo check -p librqbit 2>&1 | tail -20`
Expected: clean (fix any now-unused imports flagged by clippy).

- [ ] **Step 4: Manual smoke test** — reuse the local harness from the diagnosis session (scratchpad `origin.py`, `delayproxy.py`, keygen). Start server + a client with `--tunnel-carriers 4`, confirm the server log shows **4** `tunnel peer admitted` lines (one per carrier) and a `curl --socks5-hostname` download succeeds.

Run (server log): `rg "tunnel peer admitted" <server.log> | wc -l`
Expected: `4`.

- [ ] **Step 5: Commit**

```bash
git add crates/librqbit/src/tunnel/socks.rs crates/librqbit/src/tunnel/service.rs
git commit -m "feat(tunnel): stripe SOCKS streams across the carrier pool"
```

---

### Task 6: Integration test — distribution + carrier-death survival

Prove streams distribute across carriers and that killing one carrier only resets its own streams.

**Files:**
- Test: `crates/librqbit/src/tests/tunnel.rs`

**Interfaces:**
- Consumes: the existing in-process client+server harness (from Task 3 Step 1); `CarrierPool`, `ClientMux::load`, `pool.pick`.

- [ ] **Step 1: Write the test** — add to `crates/librqbit/src/tests/tunnel.rs`, mirroring the harness. Two carriers, open several streams, assert both carriers receive some load (distribution), then drop all handles and assert loads return to zero:

```rust
#[tokio::test]
async fn streams_distribute_across_carriers() {
    // Harness: start an in-process tunnel server + a sink destination, then a
    // CarrierPool client with carriers = 2 pointed at it. Wait until
    // pool.live_count() == 2 (poll with a timeout).
    // <setup from the existing harness; server_addr = the in-process server>

    // Open 4 streams; keep the handles alive so load() stays > 0.
    let mut handles = Vec::new();
    for _ in 0..4 {
        let mux = pool.pick().expect("a live carrier");
        let triple = mux.open_tcp(dest_localhost()).await.expect("open");
        handles.push((mux, triple));
    }

    // Least-loaded assignment must have used BOTH carriers (2+2 or 3+1, never 4+0).
    let live = pool.live_muxes_for_test(); // add a #[cfg(test)] accessor returning Vec<Option<Arc<ClientMux>>>
    let loads: Vec<usize> = live.iter().flatten().map(|m| m.load()).collect();
    assert_eq!(loads.iter().sum::<usize>(), 4);
    assert!(loads.iter().all(|&l| l >= 1), "each carrier got >=1 stream, got {loads:?}");

    drop(handles);
    // After unregister (dropping the SOCKS side triggers unregister_tcp in the
    // real path); for the unit-level test, explicitly unregister each stream.
}
```
Add a `#[cfg(test)] pub(crate) fn live_muxes_for_test(&self) -> Vec<Option<Arc<ClientMux>>> { self.live_muxes() }` to `CarrierPool`.

- [ ] **Step 2: Run test to verify it fails** (before adding the test accessor, or with an intentionally wrong assertion), then implement the `live_muxes_for_test` accessor.

Run: `cargo test -p librqbit streams_distribute_across_carriers 2>&1 | tail -20`
Expected: first FAIL (missing accessor), then PASS after adding it.

- [ ] **Step 3: Add carrier-death test** — same harness, then cancel one carrier's connection (drop/cancel its child token via the harness, or shut the in-process server socket for one carrier) and assert `pool.live_count()` drops by 1 while `pool.pick()` still returns a live mux:

```rust
#[tokio::test]
async fn one_dead_carrier_leaves_others_serving() {
    // start pool with carriers = 2, wait live_count() == 2
    // kill one carrier (harness-specific)
    // poll until pool.live_count() == 1 (timeout ~2s)
    assert_eq!(pool.live_count(), 1);
    assert!(pool.pick().is_some(), "remaining carrier still serves");
}
```

- [ ] **Step 4: Run the full tunnel test suite**

Run: `cargo test -p librqbit tunnel 2>&1 | tail -25`
Expected: all tunnel tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/librqbit/src/tunnel/client_pool.rs crates/librqbit/src/tests/tunnel.rs
git commit -m "test(tunnel): stream distribution + carrier-death survival"
```

---

### Task 7: Throughput verification (manual, documented)

Confirm the real win with the delay-proxy harness and record numbers.

**Files:** none (verification only). Harness scripts live in the session scratchpad (`origin.py`, `delayproxy.py`, `bench.sh`).

- [ ] **Step 1:** Start N delay-proxies (one per carrier) OR a single shared 100 ms proxy, server + client with `--tunnel-carriers 4`, and run `bench.sh` with 8 parallel streams @100 ms RTT.

- [ ] **Step 2:** Record aggregate vs the single-carrier baseline (single-carrier @100 ms measured 312 Mbit down / 275 up in the diagnosis). Expect multi-carrier aggregate to scale toward the crypto ceiling and, on a lossy real path, to recover the upload that a single Windows-side flow lost.

- [ ] **Step 3:** Append the numbers to `docs/superpowers/specs/2026-07-20-tunnel-multicarrier-bufferbloat-design.md` under a new "## Results (Plan 1)" heading and commit.

```bash
git add docs/superpowers/specs/2026-07-20-tunnel-multicarrier-bufferbloat-design.md
git commit -m "docs(tunnel): record multi-carrier throughput results"
```

---

## Self-Review

- **Spec coverage (Part A1):** carrier count option (Task 1) ✓; per-stream least-loaded striping (Tasks 2–5) ✓; no wire change ✓; parallel Noise = free consequence of N independent connections ✓; one-carrier-death isolation (Task 6) ✓; `--tunnel-carriers` default 4 / max 16 ✓; server unchanged (pool = N ordinary connections) ✓. Per-client egress limit note is documented in the spec; N×256 is acceptable for v1, no task needed.
- **Deferred to Plan 2 (Part B2):** Ping/Pong RTT measurement, delay-adaptive window, dynamic per-stream window, pacing. Not in this plan by design.
- **Placeholder scan:** the two integration tests (Task 3, Task 6) intentionally reference "the existing harness" because its helper names must be read from `tests/tunnel.rs` first (Task 3 Step 1) — this is a read-then-mirror instruction, not a code placeholder. All other steps carry complete code.
- **Type consistency:** `select_carrier(&[Option<usize>]) -> Option<usize>` (Task 2) is consumed unchanged in `CarrierPool::pick` (Task 4). `CarrierPool::{start,pick,carrier_count,live_count}` signatures match between Tasks 4, 5, 6. `ClientMux::load(&self) -> usize` (Task 3) matches its use in Task 4.
