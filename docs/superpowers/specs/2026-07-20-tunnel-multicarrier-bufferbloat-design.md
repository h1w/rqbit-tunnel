# Tunnel: multi-carrier + adaptive-window (bufferbloat) design

Date: 2026-07-20
Status: approved (design), pending implementation plan
Area: `crates/librqbit/src/tunnel/`

## Problem & evidence

The SOCKS-over-BitTorrent tunnel multiplexes **all** client streams over a
**single** carrier TCP connection (`client_supervisor.rs` owns one `ClientMux`).
Measured against a real deployment (client = home PC, server = NL VPS):

| Path | Down | Up | Latency (idle / down-load / up-load) |
|------|------|----|--------------------------------------|
| Home line, no tunnel | 533 Mbit | 543 Mbit | 9 ms |
| VPS direct, no tunnel | 1202 Mbit | 432 Mbit | — |
| **Through tunnel** | **225 Mbit** | **33 Mbit** | **102 / 652 / 1902 ms** |

Root causes, confirmed with a local harness (server+client + a userspace
delay-proxy injecting 50 ms each way = 100 ms RTT; lossless):

1. **Per-stream window / RTT ceiling.** Flow control uses a fixed
   `INITIAL_WINDOW = 4 MiB` credit window (`tunnel/config.rs`). A single stream
   is capped at `window / RTT`. Measured @100 ms: 4 MiB → 303 Mbit; rebuilt with
   16 MiB → 1147 Mbit. The code comment already states "throughput ≈ window /
   RTT".
2. **Single carrier TCP flow.** On a real ~90 ms lossy path one TCP flow cannot
   fill a 500 Mbit pipe. The up/down asymmetry (33 vs 225) is congestion-control:
   the download sender is the VPS (BBR enabled) and holds up; the upload sender is
   the Windows PC (no BBR) and collapses under slight loss. Locally (lossless) the
   tunnel is symmetric and healthy (down 312 / up 275 Mbit @100 ms), so there is
   **no upload-path bug** — it is real-path physics on a single flow.
3. **Bufferbloat.** Fixed 4 MiB window × N streams + window-derived queues
   (`PER_STREAM_QUEUE`, `PER_CONN_QUEUE`, `OUTBOUND_QUEUE`) buffer tens of MB at
   the bottleneck → loaded latency 652 / 1902 ms.

A complementary fix is already in the working tree (uncommitted): `TCP_NODELAY`
on both carrier ends (`client.rs`, `server.rs`) so Nagle + delayed-ACK do not
stall small `Credit` frames. The design below assumes and preserves it (every
carrier must set `TCP_NODELAY`).

## Goals / non-goals

**Goals**
- Fill the link across many concurrent streams (browsing, speedtest, typical
  apps) — aggregate throughput approaching the native line.
- Fix upload collapse and download halving on real high-RTT lossy paths.
- Keep loaded latency near the base RTT (kill bufferbloat).

**Non-goals**
- Maxing out a *single* stream (per-stream striping; a lone bulk transfer uses
  one carrier — accepted, per product decision).
- No UDP/QUIC transport rewrite. A UDP carrier with its own congestion control is
  the theoretical ceiling (removes TCP-over-TCP) but is out of scope; recorded in
  "Future work". Multi-carrier TCP + adaptive window addresses the measured gap.
- No change to the on-wire framing beyond adding `Ping`/`Pong` (see B2).

## Approach (chosen)

**A1 — pool of N independent carriers** + **B2 — delay-adaptive window**.

### A1: CarrierPool (client)

Replace the single `ClientMux` in the client path with a `CarrierPool` owning
**N `CarrierHandle`s**. Each carrier is an independent tunnel connection (own
Noise handshake, own MSE carrier, own reconnect/backoff). Refactor the current
`client_supervisor` into a **single-carrier supervisor**; the pool runs N of them.

- The pool exposes the existing mux surface: `open_tcp(dest)` / `open_udp()`.
  It selects the **least-loaded live carrier** (by in-flight bytes + active
  stream count) and delegates. A stream lives on its carrier for its lifetime —
  no reordering, no reassembly.
- `socks.rs` changes minimally: `mux.open_tcp()` → `pool.open_tcp()`. `pump_tcp`,
  credit accounting, UDP handling are unchanged but bound to the chosen carrier's
  mux.
- **Server:** no change for basic operation — each carrier is an ordinary client
  connection; the accept loop + per-connection relay already handle many. One
  awareness item: per-client egress limits (`max_tcp_streams_per_client = 256`,
  `egress.rs`) are effectively per-connection today, so N carriers get N×256; if a
  true per-key cap is wanted, share the counter by client key (small change).
- **Bonuses:** N Noise sessions encrypt in parallel across cores (lifts the
  ~1.2 Gbit single-core crypto ceiling measured at 0 ms RTT); one carrier dying
  resets only its streams (apps reconnect onto a live carrier); the other N−1
  keep flowing. Zero wire-protocol change for A1.
- **Config:** `--tunnel-carriers N`, default **4** (sane max ~16; beyond that,
  diminishing returns + extra handshakes / DHT noise).

### B2: delay-adaptive window (per carrier)

Make the credit window self-tune by **queuing delay** — grow until the pipe is
full, back off when a queue forms. Vegas/LEDBAT-style, applied to our credit
window.

1. **RTT measurement.** Add `Ping{nonce, ts}` / `Pong{nonce, ts}` frames (also
   keepalive / dead-carrier detection — the only wire addition). Each carrier is
   pinged ~1/s; track `rtt_min` (base RTT, min over a window) and `rtt_smooth`
   (EWMA).
2. **Controller (per carrier).** Maintain `inflight_target` (total bytes allowed
   in flight on the carrier):
   - `queuing_delay = rtt_smooth − rtt_min`.
   - `queuing_delay < LOW`  → `target += gain` (additive increase).
   - `queuing_delay > HIGH` → `target *= 0.85` (multiplicative decrease).
   - Clamp to `[MIN_TARGET, MAX_TARGET]`. Converges to in-flight ≈ BDP with
     near-zero standing queue.
3. **Per-stream window** = `clamp(inflight_target / max(active_streams, 1),
   MIN_WIN, MAX_WIN)`. Stream credit windows derive from the carrier target;
   `PER_STREAM_QUEUE` / `PER_CONN_QUEUE` become functions of the current window
   (keep the invariant "queue capacity ≥ window", so the shared reader never
   head-of-line-blocks).
4. **Pacing (included in this version).** The carrier writer emits at
   ≈ `inflight_target / rtt_smooth` (token bucket) instead of in bursts —
   smooths the queue and is gentler on the underlying TCP carrier.

Effect: link stays full (high aggregate) while loaded latency stays near
`rtt_min` instead of +550 / +1800 ms; more loss-tolerant than a fixed large
window. Tunables (`LOW`, `HIGH`, `gain`, clamps, ping period) live in
`config.rs`.

## Data flow

New SOCKS connect → `pool.open_tcp(dest)` → pool picks least-loaded **live**
carrier → `OpenTcp` on that mux with the current per-stream window → `pump_tcp`
runs on that carrier until stream end. Stream↔carrier binding is fixed for the
stream's life.

## Error handling / reconnect

- **Carrier drop:** its supervisor cancels its token → the carrier's streams reset
  (existing mux behaviour), their SOCKS conns close; apps reconnect → pool places
  them on a live carrier. The dropped carrier reconnects in the background
  (existing exponential backoff) without touching the other N−1.
- **All carriers down:** `pool.open_tcp()` waits for the first to come up (bounded
  by `OPEN_TIMEOUT`), else returns a SOCKS error. Graceful degradation, not
  session teardown. The SOCKS listener is always up.
- **Liveness:** missing Pongs (e.g. 3 consecutive) mark a carrier dead before the
  TCP timeout → faster reconnect.
- **Startup:** N carriers are brought up in parallel; SOCKS serves as soon as
  ≥1 is live (don't wait for all N).

## Testing

**Unit**
- Carrier selection: least-loaded, skips dead, roughly even under load.
- RTT: EWMA, `rtt_min` tracking, dead-carrier detection via missed Pongs.
- Window controller: grows when `queuing_delay < LOW`, backs off when `> HIGH`,
  respects clamps; per-stream split and "queue ≥ window" invariant.
- Pacing: token bucket emits ≈ `target / rtt`.

**Integration (reuse the delay-proxy harness)**
- N delay-proxies @100 ms RTT: multi-carrier aggregate >> single-carrier; loaded
  latency stays near base RTT (bufferbloat gone — vs the measured 652 / 1902 ms).
- Up/down symmetry preserved.
- Kill one carrier mid-transfer: streams on other carriers survive; aggregate dips
  only ~1/N.

Harness already has: origin (GET download / PUT sink), delay-proxy with a live
RTT-control file, `bench.sh` (N parallel curls). Extend to multi-carrier and add
a latency-under-load probe.

## Risks

- Adaptive controller mistuned → oscillation or under-fill. Mitigate with
  conservative defaults + the integration latency/throughput test as a guard.
- `Ping/Pong` addition must stay backward-tolerant (unknown-frame handling).
- Per-client egress limit semantics change with N connections (documented above).

## Results (Plan 1 — multi-carrier)

Measured 2026-07-20 with the local delay-proxy harness (in-process origin ~24
Gbit/s ceiling; a single userspace proxy carrying all N carrier connections; 8
parallel curl streams unless noted). Lossless localhost — this isolates the
tunnel's own scaling and does NOT reproduce real-path packet loss.

| RTT | carriers | streams | throughput |
|-----|----------|---------|-----------|
| 0 ms (direct) | 1 | 8 | 1254 Mbit/s |
| 0 ms (direct) | 4 | 8 | **3509 Mbit/s (2.8×)** |
| 100 ms | 1 | 8 | 1100 Mbit/s |
| 100 ms | 4 | 8 | **1604 Mbit/s (1.46×)** |
| 100 ms | 4 | 1 | 305 Mbit/s |

- **Multi-carrier lifts the single-core crypto ceiling**: N independent Noise
  sessions encrypt in parallel across cores (0 ms: 1254 → 3509 Mbit/s). A real
  gain even with no loss.
- The 100 ms N=4 number is limited by the single Python proxy's CPU at these
  rates (not the tunnel); the parallel-crypto benefit still shows (1.46×).
- **Single-stream at 100 ms is unchanged** (~305 Mbit ≈ 4 MiB window / RTT) —
  Plan 1 deliberately does not touch the per-stream window; that is Plan 2
  (adaptive window / B2).
- **Not shown on lossless localhost**: the primary real-world win — N parallel
  TCP flows are far more loss-tolerant than one, which is what caused the user's
  upload collapse (542→33) and download halving (532→225). Demonstrating it
  needs an actual lossy path (or `tc netem`, which needs root).

## Future work (out of scope)

- **UDP/QUIC carrier with own (BBR-style) congestion control** — removes
  TCP-over-TCP entirely; the true ceiling. Could masquerade as BitTorrent uTP.
- **Per-frame striping / single-stream aggregation** — needs resequencing; only
  if maxing a lone stream ever becomes a goal.
