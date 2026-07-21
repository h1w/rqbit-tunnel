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

/// Clamp bounds for the adaptive window (kept for documentation of the window
/// ceiling; `MAX_WINDOW == OPEN_WINDOW` so a per-stream window never exceeds the
/// fixed open window).
pub(crate) const MIN_WINDOW: usize = 64 * 1024;
pub(crate) const MAX_WINDOW: usize = OPEN_WINDOW;

/// Fixed, generous per-stream credit window used at EVERY stream open (both the
/// client `open_tcp` and the server `OpenTcp` handler). This is a deliberate
/// backstop that never binds in practice: aggregate per-carrier in-flight is
/// bounded by the writer's *pacing* rate (`target / rtt`), not by this window,
/// so a single long-lived stream still gets the full paced rate (throughput)
/// while the pacing loop bounds latency. Because the receive queues are sized
/// from this value (see `PER_STREAM_QUEUE` / `PER_CONN_QUEUE`), the invariant
/// "queue capacity ≥ window" always holds — a stalled destination can never
/// fill an undersized queue and head-of-line-block the shared reader.
pub(crate) const OPEN_WINDOW: usize = 4 * 1024 * 1024;

/// Clamp bounds for the per-carrier in-flight target driven by
/// `flow::WindowController` (delay-adaptive AIMD over `RttEstimator`'s
/// `queuing_delay`). `MAX_TARGET` is aligned with `OPEN_WINDOW` so pacing at
/// `target / rtt` is always the binding in-flight constraint, never the window.
pub(crate) const MIN_TARGET: usize = 256 * 1024;
pub(crate) const MAX_TARGET: usize = 4 * 1024 * 1024;

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

/// Per-stream queue depth (in `READ_CHUNK`-sized frames). Derived from the
/// LARGEST window a stream can ever be opened with (`OPEN_WINDOW`) — NOT the
/// smaller `DEFAULT_WINDOW` — so it can always hold a full window's worth of
/// in-flight data. This is the CRITICAL "queue capacity ≥ window" invariant: a
/// credit-limited sender can then never fill the queue, so a stalled
/// destination can't block the shared frame reader and head-of-line-block every
/// other stream on the carrier. The `+8` is slack for control frames. The
/// compile-time assertions below make the invariant un-rottable.
pub(crate) const PER_STREAM_QUEUE: usize = OPEN_WINDOW / READ_CHUNK + 8;

/// Bound on the client mux's per-connection inbound queue (TCP events / UDP
/// datagrams routed to a single SOCKS handler). Same `OPEN_WINDOW`-derived
/// sizing, for the same head-of-line-blocking-avoidance reason.
pub(crate) const PER_CONN_QUEUE: usize = OPEN_WINDOW / READ_CHUNK + 8;

// The receive queues MUST be able to hold a full open-window of in-flight data,
// or a stalled stream fills its queue and blocks the shared reader (carrier-wide
// head-of-line blocking). These compile-time checks make that invariant
// impossible to violate silently by retuning a constant.
const _: () = assert!(
    PER_STREAM_QUEUE * READ_CHUNK >= OPEN_WINDOW,
    "PER_STREAM_QUEUE must hold a full OPEN_WINDOW of in-flight data"
);
const _: () = assert!(
    PER_CONN_QUEUE * READ_CHUNK >= OPEN_WINDOW,
    "PER_CONN_QUEUE must hold a full OPEN_WINDOW of in-flight data"
);

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
/// per-carrier `RttEstimator` (running-min + EWMA-smoothed RTT) and drives one
/// step of the adaptive-window control loop, so a faster interval means a
/// faster ramp / quicker reaction to congestion. 250 ms is a balance between
/// responsiveness and per-carrier ping overhead.
pub(crate) const PING_INTERVAL: Duration = Duration::from_millis(250);

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

/// Floor for the writer's pacing rate once the controller drives it live from
/// `target / rtt` (bytes/s). Guards the pathological small-target / large-RTT
/// combination — without it a tiny target over a multi-second RTT would compute
/// a near-zero rate and stall the writer. The writer can always push at least
/// this much, so forward progress (and thus fresh RTT samples) is guaranteed.
pub(crate) const MIN_PACING_RATE: u64 = MIN_TARGET as u64;

// ── Carriers ─────────────────────────────────────────────────────────────────

/// Default number of parallel carrier connections a client opens to the server.
/// Streams are striped per-connection across them; aggregate throughput fills
/// the link and one dead carrier only resets its own streams.
pub(crate) const DEFAULT_CARRIERS: usize = 4;

/// Upper bound on `--tunnel-carriers` (beyond this, diminishing returns plus
/// extra handshakes / DHT noise).
pub(crate) const MAX_CARRIERS: usize = 16;

// ── Seeder (pre-auth active-probe resistance) ───────────────────────────────

/// Idle timeout for the pre-Noise seeder loop
/// (`server.rs::seed_until_promoted`): how long the server keeps serving
/// BitTorrent cover (`Request` → `Piece`) to an unauthenticated peer before
/// treating it as an ordinary BT peer that came and went. This — not a
/// dropped connection on bad/absent Noise traffic — is the only way an
/// unpromoted connection ever ends, so a censor probing the public
/// rendezvous cannot distinguish "real BT peer churn" from "tunnel server
/// rejected my handshake". Long enough to look like a real idle BT peer, not
/// a deliberately short leash.
pub(crate) const SEEDER_IDLE: Duration = Duration::from_secs(120);

/// Overall wall-clock deadline for the ENTIRE pre-auth seed loop
/// (`server.rs::seed_until_promoted`), mirroring
/// `carrier_wire::ESTABLISH_DEADLINE`'s reasoning exactly: `SEEDER_IDLE`
/// resets on every message, so alone it can't bound a peer that streams
/// `Request`s (each driving a 256 KiB disk read + `Piece` write) just fast
/// enough to never go idle. This bounds the WHOLE seed window regardless of
/// activity. On elapse the connection is treated exactly like an ordinary
/// idle disconnect (`AcceptOutcome::Seeded`), never an error — a censor
/// probing the rendezvous learns nothing from it.
pub(crate) const SEED_WINDOW_DEADLINE: Duration = Duration::from_secs(120);

/// Per-connection cap on the number of `Piece`s served to one
/// not-yet-authenticated peer (`carrier_peer::TunnelCarrierPeer::on_request`)
/// before it is self-choked (no further `Request`s served, an explicit
/// `Choke` sent). A real overloaded seeder does exactly this. A legitimate
/// client authenticates almost immediately (it sends its Noise handshake
/// right after the carrier handshake completes, without streaming cover
/// `Request`s first) and never comes close to this cap.
pub(crate) const MAX_SEEDER_PIECES_PER_CONN: usize = 64;

/// Maximum number of peers the seeder keeps concurrently UNCHOKED (i.e.
/// actually willing to serve `Piece`s to), tracked server-wide via a
/// semaphore (see `server.rs`'s upload-slot admission in `accept`). A real
/// seeder optimistically unchokes but only actually reciprocates to a
/// handful of peers at a time; this bounds aggregate pre-auth disk/CPU load
/// across ALL connections, not just one (that's `MAX_SEEDER_PIECES_PER_CONN`).
pub(crate) const SEEDER_UPLOAD_SLOTS: usize = 4;

/// Per-source-IP cap on concurrent PRE-AUTH seeder connections, checked in
/// `server.rs::run`'s accept loop before the MSE/BT handshake starts.
/// Authenticated connections RELEASE their slot on promotion, so this bounds
/// only handshaking/probing peers — never trusted long-lived relay carriers.
/// Kept comfortably above `MAX_CARRIERS` (16) so a single legitimate client's
/// concurrent carrier handshakes never trip it, with headroom for several
/// clients sharing one CGNAT/VPN egress IP (a common case for circumvention
/// users), while still bounding a single-IP pre-auth flood — each such
/// connection is itself bounded by the seed-window deadline + pieces cap.
pub(crate) const MAX_SEEDER_CONNS_PER_IP: usize = 64;

/// Global cap on concurrent pre-auth seeder connections, across all source
/// IPs (checked alongside `MAX_SEEDER_CONNS_PER_IP` in `server.rs::run`).
pub(crate) const MAX_SEEDER_CONNS_TOTAL: usize = 256;

/// Plausible size band (bytes) for a Noise IK initiator message, used in
/// `server.rs::seed_until_promoted` as a CHEAP length gate before ever building
/// a `snow` IK responder / doing an X25519 DH. A
/// `Noise_IK_25519_ChaChaPoly_SHA256` first message with an empty payload is a
/// small fixed size — exactly 96 bytes: 32 (ephemeral `e`) + 48 (encrypted
/// static `s`: 32 + 16-byte AEAD tag) + 16 (encrypted empty payload tag) — so a
/// blob outside this tight band cannot be a real client's Noise init. Such a
/// blob is skipped WITHOUT calling `responder_accept` and WITHOUT counting
/// against `MAX_NOISE_ATTEMPTS` (rejected on length alone). The band is
/// deliberately a little wider than 96 so a real client is never rejected.
pub(crate) const NOISE_INIT_MIN: usize = 48;
pub(crate) const NOISE_INIT_MAX: usize = 160;

/// Per-connection cap on the number of Noise IK handshake ATTEMPTS
/// (`crypto::responder_accept` calls — each builds a fresh `snow` IK responder
/// and does one X25519 DH) served to a not-yet-authenticated peer in
/// `server.rs::seed_until_promoted`. `CarrierDefragmenter::push` returns EVERY
/// complete unit from a single `rq_tunnel` message at once, so one 16 KiB
/// message packed with ~36-byte units would otherwise drive ~455 inline DH ops
/// on the tokio worker. A legitimate client sends exactly ONE Noise init (as its
/// first blob), so a tight cap never rejects a real client; once the cap is
/// reached we stop calling `responder_accept` for the rest of the connection but
/// KEEP SEEDING (no drop, no tell). Hard bound: ≤ `MAX_NOISE_ATTEMPTS` X25519
/// ops per connection.
pub(crate) const MAX_NOISE_ATTEMPTS: usize = 8;

// ── Carrier identity (masquerade torrent shape) ──────────────────────────────

/// Piece length for the synthetic carrier torrent. 256 KiB is a common real
/// value for GiB-scale single-file torrents.
pub(crate) const CARRIER_PIECE_LENGTH: u32 = 256 * 1024;

/// Corpus size band (bytes). The concrete size is chosen deterministically per
/// carrier hash within [MIN, MAX] so different servers look like different
/// torrents while staying cheap to generate/store.
pub(crate) const CARRIER_CORPUS_MIN: u64 = 8 * 1024 * 1024;
pub(crate) const CARRIER_CORPUS_MAX: u64 = 24 * 1024 * 1024;

/// Plausible display names; one is chosen deterministically per carrier hash.
pub(crate) const CARRIER_DISPLAY_NAMES: &[&str] = &[
    "debian-12.7.0-amd64-netinst.iso",
    "ubuntu-24.04.1-desktop-amd64.iso",
    "archlinux-2024.09.01-x86_64.iso",
    "Fedora-Workstation-Live-x86_64-40.iso",
    "linuxmint-22-cinnamon-64bit.iso",
    "manjaro-kde-24.0-240513-linux69.iso",
    "openSUSE-Leap-15.6-DVD-x86_64.iso",
    "pop-os_22.04_amd64_intel.iso",
];
