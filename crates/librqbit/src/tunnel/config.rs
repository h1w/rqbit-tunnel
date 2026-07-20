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
/// Larger values improve throughput on high bandwidth-delay-product links at
/// the cost of more per-stream buffering.
pub(crate) const INITIAL_WINDOW: usize = 256 * 1024;

// ── Queue depths ────────────────────────────────────────────────────────────

/// Bound on the outbound frame queue feeding a connection's single writer task.
pub(crate) const OUTBOUND_QUEUE: usize = 256;

/// Bound on the server's per-stream peer→destination queue.
pub(crate) const PER_STREAM_QUEUE: usize = 64;

/// Bound on the client mux's per-connection inbound queue (TCP events / UDP
/// datagrams routed to a single SOCKS handler).
pub(crate) const PER_CONN_QUEUE: usize = 128;

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
