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

/// Initial per-stream receive window (bytes). Both peers assume this much
/// credit at stream open, so no window-advertisement handshake is needed.
/// Larger values improve throughput on high bandwidth-delay-product links
/// (throughput ≈ window / RTT for a single bulk stream) at the cost of more
/// per-stream buffering (worst case ≈ window × max streams per client).
pub(crate) const INITIAL_WINDOW: usize = 4 * 1024 * 1024;

// ── Queue depths ────────────────────────────────────────────────────────────

/// Bound on the outbound frame queue feeding a connection's single writer task.
pub(crate) const OUTBOUND_QUEUE: usize = 256;

/// Per-stream queue depth (in `READ_CHUNK`-sized frames). Derived from the flow
/// window so it can hold a full window's worth of in-flight data: a
/// credit-limited sender can then never fill the queue, so the shared frame
/// reader never blocks on a single stream (no head-of-line blocking). The `+8`
/// is slack for control frames.
pub(crate) const PER_STREAM_QUEUE: usize = INITIAL_WINDOW / READ_CHUNK + 8;

/// Bound on the client mux's per-connection inbound queue (TCP events / UDP
/// datagrams routed to a single SOCKS handler). Same window-derived sizing.
pub(crate) const PER_CONN_QUEUE: usize = INITIAL_WINDOW / READ_CHUNK + 8;

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
