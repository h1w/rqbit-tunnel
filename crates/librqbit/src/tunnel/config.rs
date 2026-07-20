// ── Tunnel tuning constants ─────────────────────────────────────────────────
//
// Single place for the tunnel's internal tuning knobs, so they are discoverable
// and easy to adjust. These are protocol-internal defaults, not per-deployment
// configuration — the user-facing knobs live on `TunnelClientOptions` /
// `TunnelServerOptions` (e.g. the egress `idle_timeout`).

use std::time::Duration;

// ── Framing / buffers ───────────────────────────────────────────────────────

/// Chunk size for reading a destination or local socket before wrapping the
/// bytes in a `TcpData` frame. Kept well under the 2-byte (u16) frame length
/// prefix so a single frame's ciphertext can never overflow it.
pub(crate) const READ_CHUNK: usize = 16 * 1024;

/// Maximum datagram size read from a destination UDP socket.
pub(crate) const UDP_READ_BUF: usize = 64 * 1024;

// ── Flow control ────────────────────────────────────────────────────────────

/// Default per-stream credit window. Lower than the old 4 MiB to bound
/// in-flight data (bufferbloat); many concurrent streams still fill the link.
/// Both peers assume this much credit at stream open, so no
/// window-advertisement handshake is needed. Larger values improve throughput
/// on high bandwidth-delay-product links (throughput ≈ window / RTT for a
/// single bulk stream) at the cost of more per-stream buffering (worst case ≈
/// window × max streams per client).
pub(crate) const DEFAULT_WINDOW: usize = 256 * 1024;

/// Clamp bounds for the adaptive window (used by later B2 tasks).
pub(crate) const MIN_WINDOW: usize = 64 * 1024;
pub(crate) const MAX_WINDOW: usize = 4 * 1024 * 1024;

/// Clamp bounds for the per-carrier in-flight target driven by
/// `flow::WindowController` (delay-adaptive AIMD over `RttEstimator`'s
/// `queuing_delay`).
pub(crate) const MIN_TARGET: usize = 256 * 1024;
pub(crate) const MAX_TARGET: usize = 16 * 1024 * 1024;

/// Below this queuing delay (and while the carrier is actually utilized), the
/// link isn't self-inflicting bufferbloat, so `WindowController` grows the
/// target additively.
pub(crate) const QUEUING_DELAY_LOW: Duration = Duration::from_millis(5);

/// Above this queuing delay, the carrier is buffering under its own load, so
/// `WindowController` backs the target off multiplicatively.
pub(crate) const QUEUING_DELAY_HIGH: Duration = Duration::from_millis(25);

/// Additive per-step growth of the in-flight target while queuing delay stays
/// low and the carrier is utilized.
pub(crate) const TARGET_GROW_STEP: usize = 128 * 1024;

/// Multiplicative backoff factor (`NUM/DEN` = 0.85) applied to the in-flight
/// target when queuing delay exceeds `QUEUING_DELAY_HIGH`.
pub(crate) const TARGET_BACKOFF_NUM: usize = 85;
pub(crate) const TARGET_BACKOFF_DEN: usize = 100;

// ── Queue depths ────────────────────────────────────────────────────────────

/// Bound on the outbound frame queue feeding a connection's single writer task.
pub(crate) const OUTBOUND_QUEUE: usize = 256;

/// Per-stream queue depth (in `READ_CHUNK`-sized frames). Derived from the flow
/// window so it can hold a full window's worth of in-flight data: a
/// credit-limited sender can then never fill the queue, so the shared frame
/// reader never blocks on a single stream (no head-of-line blocking). The `+8`
/// is slack for control frames.
pub(crate) const PER_STREAM_QUEUE: usize = DEFAULT_WINDOW / READ_CHUNK + 8;

/// Bound on the client mux's per-connection inbound queue (TCP events / UDP
/// datagrams routed to a single SOCKS handler). Same window-derived sizing.
pub(crate) const PER_CONN_QUEUE: usize = DEFAULT_WINDOW / READ_CHUNK + 8;

// ── Timeouts ────────────────────────────────────────────────────────────────

/// How long the server waits for a destination TCP connection to establish.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the client waits for the server's `TcpOpened`/`TcpReset` verdict
/// after sending `OpenTcp`.
pub(crate) const OPEN_TIMEOUT: Duration = Duration::from_secs(30);

// ── Client reconnection backoff ─────────────────────────────────────────────

/// First delay before the client retries a failed tunnel connection.
pub(crate) const INITIAL_BACKOFF: Duration = Duration::from_millis(500);

/// Cap on the exponential reconnection backoff.
pub(crate) const MAX_BACKOFF: Duration = Duration::from_secs(30);

// ── DHT discovery ────────────────────────────────────────────────────────────

/// Per-candidate connect+handshake timeout when trying an address (static or
/// DHT-discovered), so a dead/poisoned DHT peer can't stall the attempt loop.
pub(crate) const CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Max recent DHT-discovered candidate addresses kept for the tunnel client to
/// try. Bounds memory (the DHT lookup channel is drained into this cache).
pub(crate) const DHT_PEER_CACHE: usize = 32;

// ── Ping / RTT measurement ──────────────────────────────────────────────────

/// How often each side sends a `Ping` on every carrier connection. Feeds the
/// per-carrier `RttEstimator` (running-min + EWMA-smoothed RTT) — the
/// observability foundation for the later adaptive-window controller.
pub(crate) const PING_INTERVAL: Duration = Duration::from_secs(1);

/// EWMA smoothing factor for `RttEstimator::record`: alpha = NUM/DEN = 1/8,
/// the standard TCP RTO smoothing factor (RFC 6298). Kept as an integer
/// fraction (rather than a float) so the EWMA math is deterministic in tests.
pub(crate) const RTT_EWMA_NUM: u32 = 1;
pub(crate) const RTT_EWMA_DEN: u32 = 8;

/// Cap on the inflight `Ping` nonce→send-time map (per side, per carrier
/// connection). Bounds memory if `Pong`s are lost — the oldest (smallest,
/// since nonces are assigned monotonically) entry is evicted first.
pub(crate) const PING_NONCE_MAP_CAP: usize = 256;

// ── Pacing (writer-side token bucket) ───────────────────────────────────────

/// Default pacing rate for the frame writer's token bucket, in bytes/second.
/// Effectively unlimited (10 GB/s) — this task lands the pacing *mechanism*
/// only; a later controller task drives this down from congestion signals
/// (queuing delay from `flow::RttEstimator`). At this default the bucket
/// never meaningfully delays a frame, so throughput is unchanged.
pub(crate) const PACING_DEFAULT_RATE: u64 = 10 * 1024 * 1024 * 1024;

/// Token bucket burst allowance, in bytes. Lets a burst of already-queued
/// frames through immediately even at a low configured rate, so pacing only
/// smooths sustained throughput rather than adding latency to every frame.
pub(crate) const PACING_BURST: u64 = 256 * 1024;

// ── Carriers ─────────────────────────────────────────────────────────────────

/// Default number of parallel carrier connections a client opens to the server.
/// Streams are striped per-connection across them; aggregate throughput fills
/// the link and one dead carrier only resets its own streams.
pub(crate) const DEFAULT_CARRIERS: usize = 4;

/// Upper bound on `--tunnel-carriers` (beyond this, diminishing returns plus
/// extra handshakes / DHT noise).
pub(crate) const MAX_CARRIERS: usize = 16;
