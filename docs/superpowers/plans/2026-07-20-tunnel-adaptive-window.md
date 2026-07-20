# Tunnel Adaptive-Window / Bufferbloat Implementation Plan (Plan 2 of 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Kill the tunnel's bufferbloat (measured loaded latency 652 ms download / 1902 ms upload) so latency under load stays near the base RTT, while keeping aggregate throughput high across many streams.

**Architecture:** Two phases. **Phase A** (low-risk, most of the win): make the per-stream credit window runtime-configurable and small by default, add per-carrier RTT measurement via the existing `Ping`/`Pong` frames, and pace the writer. **Phase B** (the delay-adaptive optimum): a per-carrier Vegas/LEDBAT-style controller that grows the in-flight target until queuing delay appears, then backs off — driving the window and pacing rate.

**Tech Stack:** Rust, tokio, `tokio::sync::Semaphore` (credit), `tokio::time::interval` (ping/pacing). Crate: `librqbit` (`crates/librqbit/src/tunnel/`).

## Global Constraints

- Design: `docs/superpowers/specs/2026-07-20-tunnel-multicarrier-bufferbloat-design.md` (Part B2). Part A1 (multi-carrier) is already merged.
- **No wire-protocol change.** `Ping{nonce}`/`Pong{nonce}` frames already exist (`frame.rs:113-116`); the server already replies to `Ping` with `Pong` (`relay.rs:350-353`). We only add the CLIENT side (send Ping, handle Pong) and — for upload-direction RTT — a client `Ping→Pong` reply.
- Per-stream striping is unchanged; this plan only changes flow control within a carrier.
- Preserve the uncommitted `TCP_NODELAY`-on-carrier behavior (`client.rs`/`server.rs`); do not touch those files.
- Typed errors on internal paths; `pub(crate)` internal items; `tracing` for logs.
- After each task: `cargo check -p librqbit` + `cargo clippy -p librqbit --all-targets` clean before commit.

## Key mechanism decision (resolve before coding)

Credit is **sender-side**: `SendCredit` is a semaphore the *sender* drains on send and the *receiver* replenishes via `Credit` frames as it drains locally (client download receiver: `client_mux.rs grant_credit`; server upload receiver: `relay.rs:478`). Today the receiver grants 1:1 immediately, so max in-flight = the fixed 4 MiB initial window per stream → tens of MB buffered across streams → bufferbloat.

Two control levers, both no-wire-change:
1. **Window size (per stream, at open).** `SendCredit::new()` seeds the semaphore from `INITIAL_WINDOW`. Making that a runtime value and lowering the default directly caps max in-flight. This is the dominant bufferbloat lever and is simple.
2. **Grant gating (existing streams, adaptive).** The receiver withholds/paces `Credit` grants when queuing delay is high, shrinking in-flight below the semaphore max without reopening streams. This is how the delay-adaptive controller acts on *already-open* streams (Phase B).

RTT is measured by whichever side pings; the receiver-side controller for a direction needs that direction's RTT. Download receiver = client (client pings, server Pongs — already works once the client handles Pong). Upload receiver = server (server must ping; client must reply Pong — add a client `Ping→Pong` arm). Both sides thus measure RTT and run a receiver-side controller for the direction they drain.

**Recommendation:** land **Phase A first** (Tasks 1-4). It captures most of the bufferbloat reduction (a 256 KiB window is 16× less buffering than 4 MiB) at low risk, and builds the RTT infrastructure. Then decide on **Phase B** (Tasks 5-6, the adaptive controller) with Phase A's numbers in hand.

## File Structure

- **Modify** `tunnel/config.rs` — new B2 constants (default window lowered, ping interval, pacing, rtt EWMA, controller thresholds).
- **Modify** `tunnel/flow.rs` — `SendCredit::with_window(n)`; add `RttEstimator` (pure) and the `WindowController` (pure core).
- **Modify** `tunnel/client_mux.rs` — thread runtime window into `SendCredit`; spawn a per-carrier ping task; handle `Pong` (and reply to `Ping`) in `reader_loop`; hold the carrier's `RttEstimator`/controller.
- **Modify** `tunnel/relay.rs` — thread runtime window into server `SendCredit`; add a server-side ping task + `Pong` handling; token-bucket pacing in `spawn_frame_writer`.
- **Modify** `tunnel/socks.rs` — per-stream open window comes from the carrier controller (Phase B).
- **Modify** `crates/rqbit/src/main.rs` + `tunnel/options.rs` — optional `--tunnel-window` override (Phase A).

---

## Phase A — RTT infrastructure + smaller dynamic window + pacing

### Task 1: B2 config constants

**Files:** Modify `crates/librqbit/src/tunnel/config.rs`

**Interfaces produced:** `DEFAULT_WINDOW: usize` (lowered, e.g. `256 * 1024`), `MIN_WINDOW`, `MAX_WINDOW`, `PING_INTERVAL: Duration`, `RTT_EWMA_ALPHA` (as integer permille to stay const-friendly, e.g. `RTT_EWMA_NUM/RTT_EWMA_DEN`), `PACING_BURST` — all `pub(crate)`.

- [ ] **Step 1** Add consts with doc comments. `DEFAULT_WINDOW = 256 * 1024` (at 100 ms that is ~20 Mbit/stream; the many-streams workload aggregates well above the line, and buffering drops 16× vs 4 MiB). Keep `INITIAL_WINDOW` as an alias = `DEFAULT_WINDOW` OR replace its uses (Task 2). `PING_INTERVAL = Duration::from_secs(1)`.
- [ ] **Step 2** `cargo check -p librqbit`; commit `feat(tunnel): B2 tuning constants`.

*(No test — pure constants; exercised by later tasks.)*

### Task 2: Runtime-sized credit window

**Files:** `tunnel/flow.rs` (add `with_window`), `tunnel/client_mux.rs` (open_tcp construction), `tunnel/relay.rs:224` (server construction), `tunnel/config.rs` (queue depths → runtime helper), plus the `PER_STREAM_QUEUE`/`PER_CONN_QUEUE` consumers (`relay.rs:222`, `client_mux.rs:105,166`).

**Interfaces produced:** `SendCredit::with_window(window: usize) -> Self`; a helper `queue_depth(window: usize) -> usize` (= `window / READ_CHUNK + 8`).

- [ ] **Step 1: Failing test** in `flow.rs`: `SendCredit::with_window(1024)` allows exactly 1024 bytes of `reserve` before blocking (spawn a task that reserves 1024 then 1 more; assert the second is pending). Assert `reserve` returns immediately for `<= window` and blocks beyond.
- [ ] **Step 2** Run → FAIL (no `with_window`).
- [ ] **Step 3** Implement `with_window` (`Semaphore::new(window)`); refactor `new()` to `Self::with_window(config::DEFAULT_WINDOW)`. Replace the compile-time `PER_STREAM_QUEUE`/`PER_CONN_QUEUE` consts with a `fn queue_depth(window)`; update the three `mpsc::channel(...)` sites to size from the window in play. Thread the window value at the two `SendCredit::new()` sites (a fixed `DEFAULT_WINDOW` for now; Phase B feeds the adaptive value).
- [ ] **Step 4** Run → PASS. `cargo test -p librqbit tunnel` still green (lower window must not break the large-transfer flow-control test — it will just take more round trips).
- [ ] **Step 5** Commit `feat(tunnel): runtime-sized credit window (default 256 KiB)`.

### Task 3: Per-carrier RTT measurement (Ping/Pong)

**Files:** `tunnel/flow.rs` (add `RttEstimator`), `tunnel/client_mux.rs` (ping task + Pong/Ping arms + nonce map), `tunnel/relay.rs` (server ping task + Pong arm — server already replies to Ping).

**Interfaces produced:** `RttEstimator` with `record(sample: Duration)`, `rtt_min() -> Duration`, `rtt_smooth() -> Duration`, `queuing_delay() -> Duration` (= smooth − min). Held behind `Arc<Mutex<..>>` or an atomics-based cell so both the ping task and the reader can touch it.

- [ ] **Step 1: Failing unit test** (`flow.rs`) for `RttEstimator`: feed samples `[100ms, 120ms, 110ms]` → `rtt_min()==100ms`; `rtt_smooth()` tracks EWMA toward recent; `queuing_delay()` = smooth−min ≥ 0. Feed a lower sample later → `rtt_min` drops.
- [ ] **Step 2** Run → FAIL.
- [ ] **Step 3** Implement `RttEstimator` (integer-permille EWMA to avoid float determinism issues in tests). Wire the client: in `ClientMux::new`, spawn a ping task (`interval(PING_INTERVAL)`) that stamps a monotonic send-time per `nonce` (a small `Mutex<HashMap<u64, Instant>>` capped in size) and `sink.send(Ping{nonce})`; add a `Pong{nonce}` arm to `reader_loop` that looks up the send-time, computes the sample, and `record`s it. Add a `Ping{nonce}` arm to the client reader that replies `Pong{nonce}` (so the server can measure the upload direction). Mirror a ping task + `Pong` handling on the server (`run_server_relay`) using its `sink`.
- [ ] **Step 4: Integration test** using the live harness (mirror Task-6-style `TunnelServer` + `CarrierPool`, but here just one carrier): connect through the delay-proxy is not available in-process, so instead assert `rtt_smooth()`/`rtt_min()` become non-zero and finite after ~3 ping intervals over the loopback in-process server (RTT will be sub-ms but non-zero-recorded). Expose a `#[cfg(test)]` accessor on `ClientMux` for its `RttEstimator`.
- [ ] **Step 5** `cargo test -p librqbit tunnel`; commit `feat(tunnel): per-carrier RTT via Ping/Pong`.

### Task 4: Writer pacing (token bucket)

**Files:** `tunnel/relay.rs` (`spawn_frame_writer`).

**Interfaces produced:** pacing gate inside the writer loop between `rx.recv()` and `write_all`.

- [ ] **Step 1** Design note in-code: pace at a rate derived from the carrier's target (Phase B) or, in Phase A, a generous cap (e.g. no-op / very high rate) so this task lands the *mechanism* (a `TokenBucket` struct) without yet coupling to the controller. **Failing unit test** for a pure `TokenBucket { rate_bytes_per_s, burst }`: `take(n)` returns the delay needed; at rate R after consuming `burst`, `take(R/10)` ≈ 100 ms.
- [ ] **Step 2** Run → FAIL.
- [ ] **Step 3** Implement `TokenBucket` (monotonic-time based; pass `now` in for testability — `Instant` is fine in non-workflow code). Insert into `spawn_frame_writer`: after popping a frame, `sleep(bucket.take(frame_len))` before writing. Phase-A rate = a high cap from config (effectively off); Phase B sets it from `target/rtt`.
- [ ] **Step 4** Run → PASS; `cargo test -p librqbit tunnel` green (pacing at high cap must not regress throughput).
- [ ] **Step 5** Commit `feat(tunnel): token-bucket pacing hook in writer`.

---

## Phase B — delay-adaptive window controller

### Task 5: Pure delay-adaptive controller

**Files:** `tunnel/flow.rs` (add `WindowController`).

**Interfaces produced:** `WindowController` with `on_rtt(estimator) ` / `step(queuing_delay, utilized: bool) -> ()` updating `inflight_target`; `per_stream_window(active_streams: usize) -> usize` = `clamp(target / max(streams,1), MIN_WINDOW, MAX_WINDOW)`; `target() -> usize`.

- [ ] **Step 1: Failing unit tests**: starting at `target = MIN`, repeated `step(delay < LOW, utilized=true)` grows target additively up to `MAX_TARGET`; a `step(delay > HIGH, _)` multiplies target by 0.85 (down, floored at `MIN_TARGET`); `per_stream_window` splits and clamps. Cover: growth caps at MAX, backoff floors at MIN, split clamps.
- [ ] **Step 2** Run → FAIL.
- [ ] **Step 3** Implement the AIMD controller (integer math; `LOW`/`HIGH` from config as `Duration`). Pure — no I/O.
- [ ] **Step 4** Run → PASS; commit `feat(tunnel): delay-adaptive window controller (pure)`.

### Task 6: Wire the controller into carrier flow control

**Files:** `tunnel/client_mux.rs` (drive controller from the ping task; new streams open with `per_stream_window`; receiver grant-gating), `tunnel/relay.rs` (same on the server upload receiver), `tunnel/socks.rs` (open window from controller).

**Interfaces consumed:** `RttEstimator` (Task 3), `WindowController` (Task 5), `TokenBucket` (Task 4).

- [ ] **Step 1** Drive it: the ping task, after each RTT sample, calls `controller.step(estimator.queuing_delay(), utilized)` where `utilized` = the carrier had backpressure since last tick (send credit hit 0 on any stream — track a flag). New `open_tcp` streams seed `SendCredit::with_window(controller.per_stream_window(load))`. Set the writer's `TokenBucket` rate to `controller.target() / rtt_smooth`. On the receiver grant path, when `queuing_delay > HIGH`, delay/withhold grants so existing streams' in-flight shrinks toward the new target (bounded by a small `sleep` or a per-carrier grant budget).
- [ ] **Step 2: Integration test (the payoff)** — mirror the Task-6 live harness with one carrier, drive a sustained bulk transfer, and assert that a concurrently-measured `rtt_smooth()` stays within a small multiple of `rtt_min()` (no runaway queue) while throughput remains > a floor. This is the bufferbloat-gone assertion. (On lossless loopback the absolute numbers are small; the invariant "queuing delay stays bounded under load" is the real check.)
- [ ] **Step 3** `cargo test -p librqbit tunnel`; commit `feat(tunnel): delay-adaptive flow control end-to-end`.
- [ ] **Step 4: Manual verification** — rebuild; run the delay-proxy harness at 100 ms; confirm loaded latency stays near 100 ms (vs the pre-fix 652/1902 ms) while multi-stream aggregate stays high. Record in the design doc under "## Results (Plan 2)".

---

## Self-Review

- **Spec coverage (B2):** Ping/Pong RTT (Task 3) ✓; delay-adaptive window (Tasks 5-6) ✓; dynamic per-stream window derived from target/streams (Tasks 2, 6) ✓; pacing (Tasks 4, 6) ✓; tunables in `config.rs` (Task 1) ✓.
- **Phasing:** Phase A (Tasks 1-4) is independently shippable and reviewable — it lands a smaller window + RTT + pacing hook and should cut bufferbloat substantially on its own. Phase B (Tasks 5-6) adds the adaptive optimum on top.
- **Risk callouts (honest):** Task 6 is the subtle one — receiver grant-gating and the controller's coupling to real backpressure need iteration and the manual 100 ms harness check to confirm. The pure cores (Tasks 3, 5) are unit-tested; the wiring is validated by the loaded-latency integration test. If Task 6 proves fragile, Phase A alone (smaller fixed window + pacing off) already delivers most of the latency win and can ship independently.
- **Open decision for review:** `DEFAULT_WINDOW` value (256 KiB proposed) trades single-stream throughput for buffering; confirm it fits the intended many-streams workload, or expose `--tunnel-window` and keep a larger default.
