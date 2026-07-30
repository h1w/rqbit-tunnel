// ── Tunnel frame relay (shared wire helpers + server egress relay) ───────────
//
// This module contains:
//   1. Shared "wire" helpers used by both the client mux and the server relay:
//      a single writer task (so outbound frame order == Noise sequence order)
//      and a lock-minimal encrypted-frame reader.
//   2. The production server egress relay: reads authenticated frames from an
//      admitted peer, enforces the egress policy, and relays TCP streams and
//      UDP associations to real destinations.
//
// Concurrency model (see `NoiseTransport`): the Noise transport is a single
// object with coupled send/recv state, so it lives behind one `Mutex`.  The
// lock is only ever held across a crypto call — never across socket I/O.  A
// SINGLE writer task drains an mpsc of outbound frames, so frames hit the wire
// in the exact order their sequence numbers were assigned.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex as ParkingMutex;
use peer_binary_protocol::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use super::carrier_peer::CoverMessage;
use super::config::{
    CONNECT_TIMEOUT, KEEPALIVE_INTERVAL, OPEN_WINDOW, OUTBOUND_QUEUE, PACING_BURST,
    PER_STREAM_QUEUE, PING_INTERVAL, PING_NONCE_MAP_CAP, READ_CHUNK, UDP_READ_BUF,
};
use super::crypto::NoiseTransport;
use super::egress::{EgressPolicy, EgressTransport};
use super::flow::{
    IdleGuard, RttEstimator, SendCredit, TokenBucket, WindowController, drive_flow_control,
    record_ping_sent,
};
use super::frame::{TunnelDestination, TunnelErrorCode, TunnelFrame};
use super::options::{TunnelServerSession, TunnelTrafficDirection};
use super::server::AdmittedPeer;

// ── Shared wire helpers ─────────────────────────────────────────────────────

/// Read carrier messages until one decrypted tunnel `TunnelFrame` is available,
/// serving piece cover (Request→Piece) via `cover_tx` along the way.
///
/// Shared by BOTH the server relay and the client mux reader. `rq_tunnel`
/// messages carry chunked Noise ciphertext which is defragmented, then each
/// complete ciphertext blob is decrypted into a `TunnelFrame`. Because
/// `defrag.push` can yield MULTIPLE blobs in one call, decoded-but-not-yet-
/// returned blobs are buffered in `pending` and drained one at a time at the
/// top of the loop, so no frame is ever lost.
///
/// Returns `None` on disconnect, a hard decrypt error, a defrag error (an
/// oversized declared length — closes a pre-auth memory-DoS), or a carrier peer
/// disconnect request.
pub(crate) async fn next_tunnel_frame(
    read_half: &mut super::carrier_wire::CarrierReadHalf,
    defrag: &mut super::carrier_chunk::CarrierDefragmenter,
    pending: &mut VecDeque<Vec<u8>>,
    transport: &Mutex<NoiseTransport>,
    carrier_peer: &mut super::carrier_peer::TunnelCarrierPeer,
    cover_tx: &mpsc::Sender<CoverMessage>,
) -> Option<TunnelFrame> {
    use peer_binary_protocol::extended::ExtendedMessage;
    loop {
        // Drain any already-defragmented blob before reading a new message, so a
        // single `push` that yielded several blobs returns them all in order.
        if let Some(blob) = pending.pop_front() {
            let mut t = transport.lock().await;
            return match t.decrypt(&blob) {
                Ok(frame) => Some(frame),
                Err(e) => {
                    tracing::debug!(error = %e, "carrier frame decrypt failed");
                    None
                }
            };
        }

        let msg = read_half.recv_message().await.ok()??;
        match msg {
            Message::Extended(ExtendedMessage::RqTunnel(rq)) => match defrag.push(rq.as_bytes()) {
                Ok(blobs) => {
                    for blob in blobs {
                        pending.push_back(blob);
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "carrier defrag error");
                    return None;
                }
            },
            Message::KeepAlive => {}
            other => match carrier_peer.on_message(other).await {
                Ok(actions) => {
                    for a in actions {
                        match a {
                            super::carrier_peer::CarrierAction::OutgoingMessage(m) => {
                                // NON-BLOCKING: the reader must never block on the
                                // best-effort cover channel — doing so would stall
                                // inbound tunnel frames, credit, and pong behind
                                // cover backpressure. Drop the cover message if the
                                // writer's cover lane is saturated.
                                match cover_tx.try_send(m) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        tracing::debug!(
                                            "cover channel full; dropping cover message"
                                        );
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => return None,
                                }
                            }
                            super::carrier_peer::CarrierAction::Disconnect(reason) => {
                                tracing::debug!(%reason, "carrier peer requested disconnect");
                                return None;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "carrier cover error");
                    return None;
                }
            },
        }
    }
}

/// Cloneable handle for submitting frames to the single writer task.
///
/// Outbound frames are split across TWO channels drained by the same writer:
///   * a **control** priority lane for the order-independent frames, and
///   * an ordered **data** lane for stream bytes and their close/reset markers.
///
/// The writer's `biased` select always services the control lane first, so a
/// `Ping`/`Pong`/`Credit` is never stuck behind a `TcpData` frame that is
/// asleep on its pacing deadline. Without this split, control frames share the
/// one FIFO with paced data: under sustained load the measured RTT self-inflates
/// (control queues behind seconds of paced data), the `WindowController` reads a
/// huge queuing delay, and pacing locks at `MIN_TARGET` forever.
///
/// See [`FrameSink::is_data`] for the exact per-variant routing and why
/// `TcpFin`/`TcpReset` ride the ordered data lane rather than preempting.
struct DataLaneLiveness {
    receiver_open: bool,
}

/// Owns the writer-side data receiver and synchronously marks it unavailable
/// before that receiver can be dropped, including when the writer task aborts.
struct DataLaneReceiver {
    receiver: mpsc::Receiver<TunnelFrame>,
    liveness: Arc<ParkingMutex<DataLaneLiveness>>,
}

impl DataLaneReceiver {
    fn new(
        receiver: mpsc::Receiver<TunnelFrame>,
        liveness: Arc<ParkingMutex<DataLaneLiveness>>,
    ) -> Self {
        Self { receiver, liveness }
    }

    async fn recv(&mut self) -> Option<TunnelFrame> {
        self.receiver.recv().await
    }
}

impl Drop for DataLaneReceiver {
    fn drop(&mut self) {
        self.liveness.lock().receiver_open = false;
    }
}

#[derive(Clone)]
pub(crate) struct FrameSink {
    /// Priority lane: `Ping`/`Pong`/`Credit` + lifecycle frames. Never paced.
    control_tx: mpsc::Sender<TunnelFrame>,
    /// Ordered lane: `TcpData` (paced) + `TcpFin`/`TcpReset`/`UdpDatagram`
    /// (unpaced). FIFO so a stream's close never overtakes its own data.
    data_tx: mpsc::Sender<TunnelFrame>,
    /// Serializes accepted TCP publication with writer data-receiver teardown.
    data_liveness: Arc<ParkingMutex<DataLaneLiveness>>,
}

enum LossySendOutcome {
    Queued,
    Dropped,
    Closed,
}

impl LossySendOutcome {
    fn is_alive(&self) -> bool {
        !matches!(self, Self::Closed)
    }
}

impl FrameSink {
    /// Routing table (the ONLY place a frame is classified). Returns `true` for
    /// the ordered data lane, `false` for the control priority lane.
    ///
    /// The lane split is NOT simply "control vs data" — it is "must stay ordered
    /// behind this stream's `TcpData`" vs "order-independent, safe to preempt":
    ///
    ///   * Data lane (FIFO, so per-stream order is preserved): `TcpData` (the
    ///     only PACED frame), and `TcpFin`/`TcpReset` — a graceful half-close or
    ///     reset is logically part of the stream's byte sequence and is emitted
    ///     AFTER that stream's data, so it must never overtake still-pending
    ///     paced `TcpData` (doing so truncates the stream at the receiver).
    ///     `UdpDatagram` also rides here: it needs no ordering, but must stay
    ///     OFF the control lane so a UDP flood can't crowd out `Ping`/`Credit`.
    ///
    ///   * Control priority lane (unpaced, `biased`-preempts data): `Ping`,
    ///     `Pong`, `Credit` — the RTT + flow-control frames whose queuing behind
    ///     paced data is the exact bug this split fixes — plus the lifecycle
    ///     frames (`OpenTcp`, `TcpOpened`, `OpenUdp`, `CloseUdp`,
    ///     `ClientHello`, `ServerHello`) which are order-independent of any
    ///     in-flight `TcpData` (an open/hello always precedes its stream's data;
    ///     a UDP close racing a trailing lossy datagram is harmless).
    ///
    /// (This intentionally deviates from the original task's routing table,
    /// which listed `TcpFin`/`TcpReset` on the control lane — that reordering
    /// truncates streams and is caught by
    /// `real_relay_transfers_large_payload_with_flow_control`.)
    ///
    /// Written as an EXHAUSTIVE match with no `_` arm ON PURPOSE: the module's
    /// blanket `#![allow(dead_code, unused_variables)]` will not flag a
    /// mis-routed frame, but a non-exhaustive match is a hard error regardless
    /// of any `allow`, so adding a new `TunnelFrame` variant forces a routing
    /// decision here at compile time. Mis-routing is the whole bug class this
    /// fix guards against: bulk data on the control lane bypasses pacing
    /// (bufferbloat returns); a control frame on the data lane gets paced (the
    /// self-inflated-RTT bug).
    fn is_data(frame: &TunnelFrame) -> bool {
        match frame {
            // Ordered data lane.
            TunnelFrame::TcpData { .. }
            | TunnelFrame::TcpFin { .. }
            | TunnelFrame::TcpReset { .. }
            | TunnelFrame::UdpDatagram { .. } => true,
            // Control priority lane.
            TunnelFrame::ClientHello(_)
            | TunnelFrame::ServerHello(_)
            | TunnelFrame::OpenTcp { .. }
            | TunnelFrame::TcpOpened { .. }
            | TunnelFrame::OpenUdp { .. }
            | TunnelFrame::CloseUdp { .. }
            | TunnelFrame::Credit { .. }
            | TunnelFrame::Ping { .. }
            | TunnelFrame::Pong { .. } => false,
        }
    }

    /// Enqueue a frame for encryption+write. Returns `false` if the writer task
    /// has stopped (peer gone). Routes by variant to the control or data lane.
    pub(crate) async fn send(&self, frame: TunnelFrame) -> bool {
        let tx = if Self::is_data(&frame) {
            &self.data_tx
        } else {
            &self.control_tx
        };
        tx.send(frame).await.is_ok()
    }

    /// Reserve data-lane capacity before taking a stream-specific accounting
    /// gate, so writer backpressure cannot stall relay frame processing.
    async fn reserve_data(&self) -> Option<mpsc::Permit<'_, TunnelFrame>> {
        self.data_tx.reserve().await.ok()
    }

    /// Publish a reserved TCP frame only while the writer still owns its data
    /// receiver. Both the liveness check and permit send are one synchronous
    /// critical section, so a reserved permit cannot become dropped payload.
    async fn publish_reserved_tcp_data<'a>(
        &'a self,
        permit: mpsc::Permit<'a, TunnelFrame>,
        stream_id: u64,
        bytes: Bytes,
        pending: &AtomicU64,
        download_gate: &Mutex<()>,
    ) -> bool {
        let _download_gate = download_gate.lock().await;
        let liveness = self.data_liveness.lock();
        if !liveness.receiver_open {
            return false;
        }
        let len = bytes.len();
        permit.send(TunnelFrame::TcpData { stream_id, bytes });
        pending.fetch_add(len as u64, Ordering::Release);
        true
    }

    /// Best-effort enqueue for lossy traffic (UDP datagrams). Drops the frame
    /// if the destination lane is full instead of blocking the caller — which
    /// would head-of-line-block every other stream on this connection. Routes by
    /// variant like `send`, so `UdpDatagram`s land on the data lane (they must
    /// never flood the control priority lane). Returns `false` only if the peer
    /// connection is gone.
    pub(crate) fn try_send_lossy(&self, frame: TunnelFrame) -> bool {
        self.try_send_lossy_outcome(frame).is_alive()
    }

    fn try_send_lossy_outcome(&self, frame: TunnelFrame) -> LossySendOutcome {
        use mpsc::error::TrySendError;
        let tx = if Self::is_data(&frame) {
            &self.data_tx
        } else {
            &self.control_tx
        };
        match tx.try_send(frame) {
            Ok(()) => LossySendOutcome::Queued,
            Err(TrySendError::Full(_)) => LossySendOutcome::Dropped,
            Err(TrySendError::Closed(_)) => LossySendOutcome::Closed,
        }
    }
}

async fn send_frame_until_cancelled(
    sink: &FrameSink,
    frame: TunnelFrame,
    token: &CancellationToken,
) -> bool {
    tokio::select! {
        biased;
        _ = token.cancelled() => false,
        sent = sink.send(frame) => sent,
    }
}

/// The on-wire ciphertext byte-length pacing budgets against for a `TcpData`
/// frame, derived arithmetically so NOTHING is encrypted (or even allocated) on
/// the hot path just to measure a length.
///
/// Encryption is deferred to write time so Noise's per-message sequence order
/// stays == wire order: a `TcpData` frame pre-encrypted (consuming sequence N)
/// and then held for pacing while a `Ping` (sequence N+1) jumps ahead of it on
/// the wire would desync the peer's cipher. So the writer holds the PLAINTEXT
/// frame while pending and can't read the real blob length early — it computes
/// it here instead.
///
/// Mirrors `TunnelFrame::encode` + `NoiseTransport::encrypt` exactly:
///   encoded = version(1) + type(1) + varint(stream_id) + u16 len(2) + payload
///   cipher  = seq(8) + encoded + Poly1305 tag(16)
/// i.e. `payload + 28 + varint_len(stream_id)`.
fn tcp_data_wire_len(stream_id: u64, payload_len: usize) -> u64 {
    let mut varint = 1u64;
    let mut v = stream_id >> 7;
    while v != 0 {
        varint += 1;
        v >>= 7;
    }
    payload_len as u64 + 28 + varint
}

/// Spawn the single writer task. It owns the write half and the shared
/// transport, encrypting each queued frame and writing it in order.
///
/// `pacing_rate` is a shared bytes/second cell: the writer's token bucket
/// re-reads it on every frame, so a later controller task can drive it down
/// from congestion signals while this task's callers just seed it at
/// `config::PACING_DEFAULT_RATE` (effectively unlimited).
///
/// `paced` is the shared "the writer actually pace-throttled since the last
/// control tick" flag: the writer sets it `true` whenever a pacing sleep really
/// occurs (delay > 0). The control loop (`drive_flow_control`) reads-and-resets
/// it as its `utilized` signal, so the controller only grows the target when
/// pacing at `target / rtt` was genuinely the bottleneck — not on any trickle
/// of traffic. It MUST be the SAME `Arc` handed to the control task.
pub(crate) fn spawn_frame_writer(
    transport: Arc<Mutex<NoiseTransport>>,
    mut write_half: super::carrier_wire::CarrierWriteHalf,
    mut cover_rx: mpsc::Receiver<CoverMessage>,
    shutdown: CancellationToken,
    pacing_rate: Arc<AtomicU64>,
    paced: Arc<AtomicBool>,
) -> (FrameSink, JoinHandle<()>) {
    // TWO lanes, one writer. `OUTBOUND_QUEUE` each: the control lane is a
    // priority lane the writer's `biased` select always drains first, so
    // `Ping`/`Pong`/`Credit` never wait behind a paced `TcpData` frame.
    let (control_tx, mut control_rx) = mpsc::channel::<TunnelFrame>(OUTBOUND_QUEUE);
    let (data_tx, data_rx) = mpsc::channel::<TunnelFrame>(OUTBOUND_QUEUE);
    let data_liveness = Arc::new(ParkingMutex::new(DataLaneLiveness {
        receiver_open: true,
    }));
    let mut data_rx = DataLaneReceiver::new(data_rx, data_liveness.clone());
    let handle = tokio::spawn(async move {
        // Base instant for the pure `TokenBucket`'s injected clock — it never
        // calls `Instant::now()` itself, so it stays deterministically
        // testable.
        let base = Instant::now();
        let mut bucket = TokenBucket::new(pacing_rate.load(Ordering::Relaxed), PACING_BURST);

        // Encrypt + write one frame in place. Encryption happens HERE (not when
        // the frame is popped) so encrypt-order == wire-order: while a `TcpData`
        // frame waits out its pacing deadline it stays plaintext in `pending`,
        // and a control frame that preempts it is encrypted+written first with
        // the earlier Noise sequence number — keeping the peer's cipher in sync.
        // Returns `false` on any fatal error (encrypt/IO), signalling the loop
        // to break.
        async fn write_frame(
            write_half: &mut super::carrier_wire::CarrierWriteHalf,
            transport: &Mutex<NoiseTransport>,
            frame: &TunnelFrame,
            shutdown: &CancellationToken,
        ) -> bool {
            let blob = {
                let mut t = transport.lock().await;
                match t.encrypt(frame) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::debug!(error = %e, "tunnel writer encrypt failed");
                        return false;
                    }
                }
            };
            // The Noise ciphertext is chunked across one or more `rq_tunnel`
            // extended messages; a write failure on any chunk breaks the writer.
            for chunk in super::carrier_chunk::chunk_ciphertext(&blob) {
                let result = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => return false,
                    result = write_half.send_tunnel(&chunk) => result,
                };
                if result.is_err() {
                    return false;
                }
            }
            true
        }

        // A data frame awaiting its pacing deadline (kept PLAINTEXT — see
        // `write_frame`), and the instant it may be written.
        let mut pending: Option<TunnelFrame> = None;
        let mut deadline: Option<tokio::time::Instant> = None;
        // Per-lane liveness. A closed channel's `recv()` is instantly ready with
        // `None`, so once a lane closes we disable its arm via these flags
        // (rather than letting it spin). Note the `else`/all-disabled fallback
        // can't exit us here — the `shutdown` arm has an irrefutable pattern and
        // is never disabled — so both-closed exit is an explicit top-of-loop
        // check instead.
        let mut control_open = true;
        let mut data_open = true;
        // The cover lane (piece Request→Piece responses) is best-effort and does
        // NOT gate writer exit: once it closes we just disable its arm so a
        // closed `recv()` (instantly-ready `None`) can't livelock the `biased`
        // select and starve data.
        let mut cover_open = true;

        // Periodic BitTorrent `KeepAlive` cadence so an idle-but-open masquerade
        // connection sends keepalives like a real BT peer (no "never sends a
        // keepalive" tell). `interval_at` starts the FIRST tick one full interval
        // out — a real peer doesn't fire a keepalive the instant after its
        // handshake — after which it ticks every `KEEPALIVE_INTERVAL`. Emitted at
        // the LOWEST priority (below control, data, and cover); a keepalive is
        // best-effort, so it never preempts real traffic. The default
        // `MissedTickBehavior::Burst` is harmless here: a keepalive on a busy
        // connection is realistic, and skipped ticks never accumulate work worth
        // reasoning about.
        let mut keepalive = tokio::time::interval_at(
            tokio::time::Instant::now() + KEEPALIVE_INTERVAL,
            KEEPALIVE_INTERVAL,
        );

        loop {
            // Both PRIMARY lanes drained and closed, nothing left to flush: peer
            // gone. Cover is secondary and never keeps the writer alive.
            if !control_open && !data_open && pending.is_none() {
                break;
            }
            tokio::select! {
                // Priority order: shutdown, then the control lane, then a due
                // pending data frame, then admitting a new data frame, then the
                // cover lane LAST. `biased` is what makes the control lane preempt
                // paced data: whenever a control frame is ready it is serviced
                // before the pending data's deadline arm and before pulling more
                // data. Cover is best-effort and is drained only when neither
                // control nor real tunnel data is ready, so it can never starve
                // real tunnel data.
                biased;

                _ = shutdown.cancelled() => break,

                // Control priority lane — never paced, always first.
                ctrl = control_rx.recv(), if control_open => match ctrl {
                    Some(ctrl) => {
                        if !write_frame(&mut write_half, &transport, &ctrl, &shutdown).await {
                            break;
                        }
                    }
                    None => control_open = false,
                },

                // The pending data frame's pace deadline elapsed. `sleep_until`
                // with an already-past deadline returns immediately, so a
                // control frame that jumped ahead (advancing the loop) simply
                // lets this fire on the next pass. Only armed while a frame is
                // actually pending.
                _ = async { tokio::time::sleep_until(deadline.unwrap()).await }, if pending.is_some() => {
                    let frame = pending.take().unwrap();
                    deadline = None;
                    if !write_frame(&mut write_half, &transport, &frame, &shutdown).await {
                        break;
                    }
                }

                // Admit the next bulk frame — but only while nothing is already
                // pending, so a single in-flight pacing deadline is honored
                // before we pull more.
                data = data_rx.recv(), if data_open && pending.is_none() => {
                    let data = match data {
                        Some(data) => data,
                        None => {
                            data_open = false;
                            continue;
                        }
                    };
                    // Pace `TcpData` ONLY. `UdpDatagram`/`TcpFin`/`TcpReset` ride
                    // the data lane (for ordering / to stay off the control
                    // priority lane) but are never paced: pacing them adds
                    // latency for no throughput benefit and they stay out of the
                    // growth signal entirely.
                    let pace_len = match &data {
                        TunnelFrame::TcpData { stream_id, bytes } => {
                            Some(tcp_data_wire_len(*stream_id, bytes.len()))
                        }
                        _ => None,
                    };
                    match pace_len {
                        Some(pace_len) => {
                            // Re-read the rate each frame so a live controller
                            // update takes effect on the very next one.
                            bucket.set_rate(pacing_rate.load(Ordering::Relaxed));
                            let now_nanos = base.elapsed().as_nanos() as u64;
                            let delay_nanos = bucket.take(now_nanos, pace_len);
                            if delay_nanos == 0 {
                                if !write_frame(&mut write_half, &transport, &data, &shutdown).await {
                                    break;
                                }
                            } else {
                                // A real pacing delay: raise the shared `paced`
                                // flag (the control loop's `utilized` signal —
                                // "pacing was the bottleneck") and hold the
                                // frame plaintext until its deadline.
                                paced.store(true, Ordering::Relaxed);
                                deadline =
                                    Some(tokio::time::Instant::now() + Duration::from_nanos(delay_nanos));
                                pending = Some(data);
                            }
                        }
                        None => {
                            if !write_frame(&mut write_half, &transport, &data, &shutdown).await {
                                break;
                            }
                        }
                    }
                }

                // Cover lane — piece Request→Piece cover, unpaced, LOWEST priority.
                // Placed last (below both data arms) so best-effort cover can never
                // starve real tunnel data: it is only drained when neither control
                // nor data is ready. A cover message that fails to SERIALIZE (e.g.
                // an oversized Piece a malicious peer tried to request) must NOT
                // kill the tunnel — skip it. Only a real write/IO failure breaks.
                cover = cover_rx.recv(), if cover_open => match cover {
                    Some(m) => {
                        let message = m.to_message();
                        let result = tokio::select! {
                            biased;
                            _ = shutdown.cancelled() => break,
                            result = write_half.send_message(&message) => result,
                        };
                        match result {
                            Ok(()) => {}
                            Err(super::carrier_wire::CarrierWireError::Serialize(_)) => {
                                tracing::debug!("skipping unserializable cover message");
                            }
                            Err(_) => break,
                        }
                    }
                    None => cover_open = false,
                },

                // Keepalive cadence — LOWEST priority, best-effort. Placed last so
                // it can never preempt control, data, or cover. A `KeepAlive` is a
                // plain BT message (NOT a tunnel frame), so it does NOT touch
                // `NoiseTransport` and cannot perturb the Noise sequence order —
                // which is exactly why a serialize OR write failure here is
                // swallowed (never breaks the writer): unlike the ordered lanes,
                // a dropped keepalive desyncs nothing. If the connection is truly
                // dead, the next control/data write breaks the writer instead.
                _ = keepalive.tick() => {
                    let result = tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => break,
                        result = write_half.send_message(&Message::KeepAlive) => result,
                    };
                    if let Err(e) = result {
                        tracing::debug!(error = %e, "skipping keepalive");
                    }
                }
            }
        }
    });
    (
        FrameSink {
            control_tx,
            data_tx,
            data_liveness,
        },
        handle,
    )
}

// ── Destination helpers ─────────────────────────────────────────────────────

fn parse_destination(host: &str, port: u16) -> TunnelDestination {
    match host.parse::<IpAddr>() {
        Ok(ip) => TunnelDestination::Ip(SocketAddr::new(ip, port)),
        Err(_) => TunnelDestination::Domain(host.to_string(), port),
    }
}

// ── Server relay state ──────────────────────────────────────────────────────

/// Message from the peer→destination side of a TCP stream.
enum PeerToDest {
    Data(Bytes),
    Fin,
}

struct TcpEntry {
    to_dest: mpsc::Sender<PeerToDest>,
    /// Credit the server may use to send dest→peer data (granted by the client
    /// via `Credit` frames as it drains its local socket).
    send_credit: SendCredit,
    /// Payload accepted by the peer but not yet acknowledged with `Credit`.
    download_uncredited: Arc<AtomicU64>,
    /// Serializes TCP payload publication with incoming `Credit` processing.
    download_gate: Arc<Mutex<()>>,
    /// Set after the destination egress half stops producing payload.
    download_finished: Arc<AtomicBool>,
    /// Bidirectional idle watchdog, poked on activity in either direction.
    idle: IdleGuard,
    shutdown: CancellationToken,
}

struct UdpEntry {
    socket: Arc<UdpSocket>,
    idle: IdleGuard,
    shutdown: CancellationToken,
}

type TcpMap = Arc<Mutex<HashMap<u64, TcpEntry>>>;
type UdpMap = Arc<Mutex<HashMap<u64, UdpEntry>>>;
/// Nonce → send-time for pings the server has sent but not yet heard a `Pong`
/// for. Mirrors the client mux's identical bookkeeping.
type PingInflight = Arc<StdMutex<HashMap<u64, Instant>>>;

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

fn apply_acknowledged_credit(
    send_credit: &SendCredit,
    pending: &AtomicU64,
    requested: u32,
    session: &dyn TunnelServerSession,
) -> usize {
    let accepted = take_acknowledged(pending, requested);
    if accepted != 0 {
        send_credit.grant(accepted);
        session.record_payload(TunnelTrafficDirection::Download, accepted);
    }
    accepted
}

async fn enqueue_tcp_data(
    sink: &FrameSink,
    stream_id: u64,
    bytes: Bytes,
    pending: &AtomicU64,
    download_gate: &Mutex<()>,
) -> bool {
    let Some(permit) = sink.reserve_data().await else {
        return false;
    };
    sink.publish_reserved_tcp_data(permit, stream_id, bytes, pending, download_gate)
        .await
}

/// Apply one peer `Credit` after serializing with destination payload
/// publication for this stream.
async fn acknowledge_tcp_credit(
    tcp: &TcpMap,
    stream_id: u64,
    requested: u32,
    session: &dyn TunnelServerSession,
    token: &CancellationToken,
) {
    let entry = tokio::select! {
        biased;
        _ = token.cancelled() => return,
        entry = async {
            let map = tcp.lock().await;
            map.get(&stream_id).map(|entry| {
                (
                    entry.send_credit.clone(),
                    entry.download_uncredited.clone(),
                    entry.download_finished.clone(),
                    entry.download_gate.clone(),
                )
            })
        } => entry,
    };
    if let Some((send_credit, download_uncredited, download_finished, download_gate)) = entry {
        let _download_gate = tokio::select! {
            biased;
            _ = token.cancelled() => return,
            guard = download_gate.lock() => guard,
        };
        if token.is_cancelled() {
            return;
        }
        apply_acknowledged_credit(&send_credit, &download_uncredited, requested, session);
        let _ = retire_finished_tcp_entry(tcp, stream_id, &download_uncredited, &download_finished)
            .await;
    }
}

/// Mark the egress half closed while retaining its entry until every accepted
/// destination payload has been acknowledged.
async fn finish_tcp_download(
    tcp: &TcpMap,
    stream_id: u64,
    download_uncredited: &Arc<AtomicU64>,
    download_finished: &Arc<AtomicBool>,
    download_gate: &Arc<Mutex<()>>,
) {
    let _download_gate = download_gate.lock().await;
    download_finished.store(true, Ordering::Release);
    let _ = retire_finished_tcp_entry(tcp, stream_id, download_uncredited, download_finished).await;
}

/// Remove a completed TCP entry only after its final valid acknowledgement.
///
/// Callers hold the entry's `download_gate`, so no accepted `TcpData` can be
/// published or acknowledged while this checks the outstanding count.
async fn retire_finished_tcp_entry(
    tcp: &TcpMap,
    stream_id: u64,
    download_uncredited: &Arc<AtomicU64>,
    download_finished: &Arc<AtomicBool>,
) -> bool {
    let entry = {
        let mut map = tcp.lock().await;
        let should_remove = match map.get(&stream_id) {
            Some(entry) => {
                Arc::ptr_eq(&entry.download_uncredited, download_uncredited)
                    && Arc::ptr_eq(&entry.download_finished, download_finished)
                    && entry.download_finished.load(Ordering::Acquire)
                    && entry.download_uncredited.load(Ordering::Acquire) == 0
            }
            None => false,
        };
        if should_remove {
            map.remove(&stream_id)
        } else {
            None
        }
    };
    let removed = entry.is_some();
    if let Some(entry) = entry {
        entry.send_credit.close();
        entry.shutdown.cancel();
        entry.idle.shutdown().await;
    }
    removed
}

/// Run the full egress relay for one admitted peer until the peer disconnects
/// or `shutdown` fires, then cancel and join every relay descendant before
/// returning.
pub(crate) async fn run_server_relay(
    peer: AdmittedPeer,
    egress: Arc<EgressPolicy>,
    shutdown: CancellationToken,
) {
    let AdmittedPeer {
        client_key,
        session,
        transport,
        mut read_half,
        write_half,
        carrier_peer,
        ..
    } = peer;
    let relay_shutdown = shutdown.child_token();

    let transport = Arc::new(Mutex::new(transport));
    // Cover lane: `next_tunnel_frame` funnels piece Request→Piece cover here and
    // the writer task drains it (unpaced, below control priority).
    let (cover_tx, cover_rx) = mpsc::channel::<CoverMessage>(OUTBOUND_QUEUE);
    // ONE pacing-rate cell shared by the writer (which re-reads it per frame)
    // and the control task below (which drives it to `target / rtt`). Seeded at
    // the effectively-unlimited default until the first RTT sample lands.
    let pacing_rate = Arc::new(AtomicU64::new(super::config::PACING_DEFAULT_RATE));
    // ONE "the writer pace-throttled since the last tick" flag, shared by the
    // writer (which sets it) and the control task (which reads-and-resets it as
    // its `utilized` signal). Same-Arc sharing is what makes the signal live.
    let paced = Arc::new(AtomicBool::new(false));
    let (sink, writer_handle) = spawn_frame_writer(
        transport.clone(),
        write_half,
        cover_rx,
        relay_shutdown.clone(),
        pacing_rate.clone(),
        paced.clone(),
    );

    let tcp: TcpMap = Arc::new(Mutex::new(HashMap::new()));
    let udp: UdpMap = Arc::new(Mutex::new(HashMap::new()));

    // Per-carrier RTT measurement (§flow::RttEstimator): our own ping task
    // probes the download direction; the `Ping` arm below answers the
    // client's pings so it can measure the upload direction.
    let rtt = Arc::new(StdMutex::new(RttEstimator::new()));
    // Delay-adaptive in-flight controller. The control task steps it from
    // queuing delay + the writer's `paced` flag and drives `pacing_rate`
    // (target / rtt), which bounds aggregate dest→peer in-flight data. New
    // streams open with a fixed generous `OPEN_WINDOW` — pacing, not the
    // window, is the in-flight control.
    let controller = Arc::new(StdMutex::new(WindowController::new()));
    let ping_inflight: PingInflight = Arc::new(StdMutex::new(HashMap::new()));
    let control_handle = tokio::spawn(server_control_task(
        sink.clone(),
        ping_inflight.clone(),
        rtt.clone(),
        controller.clone(),
        paced.clone(),
        pacing_rate.clone(),
        relay_shutdown.clone(),
    ));
    let mut descendants = JoinSet::new();

    // Carrier read state: the defragmenter reassembles chunked Noise ciphertext,
    // `pending` buffers multiple blobs a single `push` can yield, and
    // `carrier_peer` handles inbound piece cover.
    let mut defrag = super::carrier_chunk::CarrierDefragmenter::new(
        super::carrier_chunk::MAX_CARRIER_CIPHERTEXT,
    );
    let mut pending: VecDeque<Vec<u8>> = VecDeque::new();
    let mut carrier_peer = carrier_peer;

    loop {
        while let Some(result) = descendants.try_join_next() {
            if let Err(error) = result {
                tracing::debug!(%error, "tunnel relay descendant stopped unexpectedly");
            }
        }

        let frame = tokio::select! {
            biased;
            _ = relay_shutdown.cancelled() => break,
            f = next_tunnel_frame(
                &mut read_half,
                &mut defrag,
                &mut pending,
                &transport,
                &mut carrier_peer,
                &cover_tx,
            ) => match f {
                Some(f) => f,
                None => {
                    tracing::debug!("tunnel server relay: peer read ended");
                    break;
                }
            },
        };

        match frame {
            TunnelFrame::OpenTcp {
                stream_id,
                host,
                port,
            } => {
                let mut map = tcp.lock().await;
                if map.contains_key(&stream_id) {
                    // Duplicate stream id — protocol violation; ignore.
                    continue;
                }
                if map.len() >= egress.max_tcp_streams_per_client {
                    drop(map);
                    tracing::debug!(stream_id, "tcp stream limit reached; refusing");
                    let _ = send_frame_until_cancelled(
                        &sink,
                        TunnelFrame::TcpReset {
                            stream_id,
                            code: TunnelErrorCode::ConnectionRefused,
                        },
                        &relay_shutdown,
                    )
                    .await;
                    continue;
                }
                let (to_dest_tx, to_dest_rx) = mpsc::channel::<PeerToDest>(PER_STREAM_QUEUE);
                let stream_token = relay_shutdown.child_token();
                // Open the dest→peer send window at the fixed generous
                // `OPEN_WINDOW`: a backstop that never binds (aggregate in-flight
                // is bounded by pacing at `target / rtt`, not this window), while
                // the receive queue (`PER_STREAM_QUEUE`, sized from OPEN_WINDOW)
                // is guaranteed to hold a full window — so a stalled destination
                // can never head-of-line-block the shared reader.
                let send_credit = SendCredit::with_window(OPEN_WINDOW);
                let download_uncredited = Arc::new(AtomicU64::new(0));
                let download_gate = Arc::new(Mutex::new(()));
                let download_finished = Arc::new(AtomicBool::new(false));
                let idle = IdleGuard::spawn(egress.idle_timeout, stream_token.clone());
                map.insert(
                    stream_id,
                    TcpEntry {
                        to_dest: to_dest_tx,
                        send_credit: send_credit.clone(),
                        download_uncredited: download_uncredited.clone(),
                        download_gate: download_gate.clone(),
                        download_finished: download_finished.clone(),
                        idle: idle.clone(),
                        shutdown: stream_token.clone(),
                    },
                );
                drop(map);

                let _ = descendants.spawn(handle_tcp_stream(
                    stream_id,
                    host,
                    port,
                    egress.clone(),
                    session.clone(),
                    sink.clone(),
                    tcp.clone(),
                    to_dest_rx,
                    send_credit,
                    download_uncredited,
                    download_finished,
                    download_gate,
                    idle,
                    stream_token,
                ));
            }
            TunnelFrame::TcpData { stream_id, bytes } => {
                let entry = {
                    let map = tcp.lock().await;
                    map.get(&stream_id)
                        .map(|e| (e.to_dest.clone(), e.idle.clone()))
                };
                if let Some((to_dest, idle)) = entry {
                    idle.poke();
                    // Credit flow control keeps this queue below its bound, so
                    // the send never blocks long enough to stall other streams.
                    let _ = tokio::select! {
                        biased;
                        _ = relay_shutdown.cancelled() => break,
                        result = to_dest.send(PeerToDest::Data(bytes)) => result,
                    };
                }
            }
            TunnelFrame::TcpFin { stream_id } => {
                let to_dest = {
                    let map = tcp.lock().await;
                    map.get(&stream_id).map(|e| e.to_dest.clone())
                };
                if let Some(to_dest) = to_dest {
                    let _ = tokio::select! {
                        biased;
                        _ = relay_shutdown.cancelled() => break,
                        result = to_dest.send(PeerToDest::Fin) => result,
                    };
                }
            }
            TunnelFrame::Credit { stream_id, bytes } => {
                // Acknowledge only payload the peer actually accepted from the
                // destination, so peer credit and download accounting cannot
                // exceed successful relay delivery.
                acknowledge_tcp_credit(&tcp, stream_id, bytes, session.as_ref(), &relay_shutdown)
                    .await;
            }
            TunnelFrame::TcpReset { stream_id, .. } => {
                let entry = { tcp.lock().await.remove(&stream_id) };
                if let Some(entry) = entry {
                    entry.send_credit.close();
                    entry.shutdown.cancel();
                    entry.idle.shutdown().await;
                }
            }
            TunnelFrame::OpenUdp { association_id } => {
                let map = udp.lock().await;
                if map.contains_key(&association_id) {
                    continue;
                }
                if map.len() >= egress.max_udp_associations_per_client {
                    drop(map);
                    tracing::debug!(association_id, "udp association limit reached; ignoring");
                    continue;
                }
                drop(map);

                let socket = tokio::select! {
                    biased;
                    _ = relay_shutdown.cancelled() => break,
                    result = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))) => result,
                };
                let socket = match socket {
                    Ok(socket) => Arc::new(socket),
                    Err(error) => {
                        tracing::debug!(error = %error, "failed to bind egress udp socket");
                        continue;
                    }
                };
                let token = relay_shutdown.child_token();
                let idle = IdleGuard::spawn(egress.idle_timeout, token.clone());
                udp.lock().await.insert(
                    association_id,
                    UdpEntry {
                        socket: socket.clone(),
                        idle: idle.clone(),
                        shutdown: token.clone(),
                    },
                );
                let _ = descendants.spawn(udp_recv_loop(
                    association_id,
                    socket,
                    sink.clone(),
                    session.clone(),
                    idle,
                    token,
                ));
            }
            TunnelFrame::UdpDatagram {
                association_id,
                destination,
                bytes,
            } => {
                let entry = {
                    let map = udp.lock().await;
                    map.get(&association_id)
                        .map(|e| (e.socket.clone(), e.idle.clone()))
                };
                if let Some((socket, idle)) = entry {
                    idle.poke();
                    let resolved = tokio::select! {
                        biased;
                        _ = relay_shutdown.cancelled() => break,
                        result = egress.authorize(&destination, EgressTransport::Udp) => result,
                    };
                    match resolved {
                        Ok(resolved) => {
                            let _ = send_udp_payload(
                                socket.as_ref(),
                                resolved.selected,
                                &bytes,
                                session.as_ref(),
                                &relay_shutdown,
                            )
                            .await;
                        }
                        Err(e) => {
                            tracing::debug!(association_id, error = %e, "udp egress denied");
                        }
                    }
                }
            }
            TunnelFrame::CloseUdp { association_id } => {
                let entry = { udp.lock().await.remove(&association_id) };
                if let Some(entry) = entry {
                    entry.shutdown.cancel();
                    entry.idle.shutdown().await;
                }
            }
            TunnelFrame::Ping { nonce } => {
                let _ =
                    send_frame_until_cancelled(&sink, TunnelFrame::Pong { nonce }, &relay_shutdown)
                        .await;
            }
            TunnelFrame::Pong { nonce } => {
                let sent_at = ping_inflight.lock().unwrap().remove(&nonce);
                if let Some(sent_at) = sent_at {
                    rtt.lock().unwrap().record(sent_at.elapsed());
                }
            }
            // Frames a server never expects to receive, or that need no action.
            _ => {}
        }
    }

    // Peer gone or cancellation fired: cancel every descendant before joining
    // it, so no relay task can account payload after this function returns.
    relay_shutdown.cancel();
    let tcp_entries: Vec<_> = tcp.lock().await.drain().map(|(_, entry)| entry).collect();
    for entry in tcp_entries {
        entry.send_credit.close();
        entry.shutdown.cancel();
        entry.idle.shutdown().await;
    }
    let udp_entries: Vec<_> = udp.lock().await.drain().map(|(_, entry)| entry).collect();
    for entry in udp_entries {
        entry.shutdown.cancel();
        entry.idle.shutdown().await;
    }
    while let Some(result) = descendants.join_next().await {
        if let Err(error) = result {
            tracing::debug!(%error, "tunnel relay descendant stopped unexpectedly");
        }
    }
    let _ = control_handle.await;
    let _ = writer_handle.await;
    tracing::debug!(?client_key, "tunnel server relay: peer session ended");
}

/// Mirrors the client mux's control task: probe RTT on the download direction
/// (from the server's perspective) with our own periodic `Ping`s, then drive
/// the carrier's `WindowController` + pacing rate from the freshest sample. The
/// `Ping` arm in `run_server_relay` already answers the client's pings, which
/// is how the client measures the upload direction; the `Pong` arm records our
/// own probes' samples into `rtt`.
///
/// Stops on shutdown, or once the sink is gone. The relay cancels and joins
/// the writer before it returns, so this task cannot outlive relay shutdown.
async fn server_control_task(
    sink: FrameSink,
    inflight: PingInflight,
    rtt: Arc<StdMutex<RttEstimator>>,
    controller: Arc<StdMutex<WindowController>>,
    paced: Arc<AtomicBool>,
    pacing_rate: Arc<AtomicU64>,
    shutdown: CancellationToken,
) {
    let mut interval = tokio::time::interval(PING_INTERVAL);
    let mut next_nonce: u64 = 0;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            _ = interval.tick() => {}
        }
        let nonce = next_nonce;
        next_nonce = next_nonce.wrapping_add(1);
        {
            let mut map = inflight.lock().unwrap();
            record_ping_sent(&mut map, nonce, Instant::now(), PING_NONCE_MAP_CAP);
        }
        if !send_frame_until_cancelled(&sink, TunnelFrame::Ping { nonce }, &shutdown).await {
            break;
        }
        // Step the controller from the freshest RTT estimate (fed by prior
        // probes' `Pong`s) and the writer's `paced` flag, and update the
        // writer's pacing rate — the same shared `pacing_rate` cell the writer
        // re-reads per frame.
        drive_flow_control(&rtt, &controller, &paced, &pacing_rate);
    }
}

// ── Per-TCP-stream egress ───────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_stream(
    stream_id: u64,
    host: String,
    port: u16,
    egress: Arc<EgressPolicy>,
    session: Arc<dyn TunnelServerSession>,
    sink: FrameSink,
    tcp: TcpMap,
    to_dest_rx: mpsc::Receiver<PeerToDest>,
    send_credit: SendCredit,
    download_uncredited: Arc<AtomicU64>,
    download_finished: Arc<AtomicBool>,
    download_gate: Arc<Mutex<()>>,
    idle: IdleGuard,
    token: CancellationToken,
) {
    let result = open_and_pump(
        stream_id,
        host,
        port,
        &egress,
        &sink,
        session,
        to_dest_rx,
        &send_credit,
        &idle,
        download_uncredited.clone(),
        download_gate.clone(),
        &token,
    )
    .await;

    if let Err(code) = result {
        let _ =
            send_frame_until_cancelled(&sink, TunnelFrame::TcpReset { stream_id, code }, &token)
                .await;
    }

    finish_tcp_download(
        &tcp,
        stream_id,
        &download_uncredited,
        &download_finished,
        &download_gate,
    )
    .await;
}

async fn pump_peer_to_destination(
    stream_id: u64,
    mut dest_write: tokio::net::tcp::OwnedWriteHalf,
    mut to_dest_rx: mpsc::Receiver<PeerToDest>,
    session: Arc<dyn TunnelServerSession>,
    sink: FrameSink,
    idle: IdleGuard,
    token: CancellationToken,
) {
    loop {
        let message = tokio::select! {
            biased;
            _ = token.cancelled() => break,
            message = to_dest_rx.recv() => message,
        };
        match message {
            Some(PeerToDest::Data(bytes)) => {
                let bytes_written = bytes.len();
                let write_result = tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    result = dest_write.write_all(&bytes) => result,
                };
                if write_result.is_err() || token.is_cancelled() {
                    break;
                }
                session.record_payload(TunnelTrafficDirection::Upload, bytes_written);
                idle.poke();
                let sent_credit = tokio::select! {
                    biased;
                    _ = token.cancelled() => false,
                    sent = sink.send(TunnelFrame::Credit {
                        stream_id,
                        bytes: bytes_written as u32,
                    }) => sent,
                };
                if !sent_credit {
                    break;
                }
            }
            Some(PeerToDest::Fin) | None => {
                let _ = tokio::select! {
                    biased;
                    _ = token.cancelled() => Ok(()),
                    result = dest_write.shutdown() => result,
                };
                break;
            }
        }
    }
}

/// Authorize + connect the destination, then pump both directions until the
/// stream ends. On any pre-connect failure returns `Err(code)` so the caller
/// sends a single `TcpReset`. The nested peer→destination writer is joined
/// before this function returns.
#[allow(clippy::too_many_arguments)]
async fn open_and_pump(
    stream_id: u64,
    host: String,
    port: u16,
    egress: &EgressPolicy,
    sink: &FrameSink,
    session: Arc<dyn TunnelServerSession>,
    to_dest_rx: mpsc::Receiver<PeerToDest>,
    send_credit: &SendCredit,
    idle: &IdleGuard,
    download_uncredited: Arc<AtomicU64>,
    download_gate: Arc<Mutex<()>>,
    token: &CancellationToken,
) -> Result<(), TunnelErrorCode> {
    let destination = parse_destination(&host, port);
    let resolved = tokio::select! {
        biased;
        _ = token.cancelled() => return Ok(()),
        result = egress.authorize(&destination, EgressTransport::Tcp) => {
            result.map_err(|error| error.to_error_code())?
        }
    };

    let connect = tokio::select! {
        biased;
        _ = token.cancelled() => return Ok(()),
        result = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(resolved.selected)) => result,
    };
    let dest = match connect {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::debug!(stream_id, error = %e, dest = %resolved.selected, "egress connect failed");
            return Err(TunnelErrorCode::ConnectionRefused);
        }
        Err(_) => {
            tracing::debug!(stream_id, dest = %resolved.selected, "egress connect timed out");
            return Err(TunnelErrorCode::TimedOut);
        }
    };
    let _ = dest.set_nodelay(true);
    let bind_addr = dest
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

    if !send_frame_until_cancelled(
        sink,
        TunnelFrame::TcpOpened {
            stream_id,
            bind_addr,
        },
        token,
    )
    .await
    {
        return Ok(());
    }

    let (mut dest_read, dest_write) = dest.into_split();

    // peer → destination: write received data, then grant the peer credit for
    // exactly what we drained so it may send that much more.
    let peer_to_dest = tokio::spawn(pump_peer_to_destination(
        stream_id,
        dest_write,
        to_dest_rx,
        session,
        sink.clone(),
        idle.clone(),
        token.clone(),
    ));

    // destination → peer (runs in this task). Reserve send credit before each
    // chunk so we never overrun the peer's receive window.
    let mut buf = vec![0u8; READ_CHUNK];
    let mut result_code: Option<TunnelErrorCode> = None;
    loop {
        let read = tokio::select! {
            biased;
            _ = token.cancelled() => { break; }
            r = dest_read.read(&mut buf) => r,
        };
        match read {
            Ok(0) => {
                // Destination closed: half-close toward the peer.
                let _ = send_frame_until_cancelled(sink, TunnelFrame::TcpFin { stream_id }, token)
                    .await;
                break;
            }
            Ok(n) => {
                let reserved = tokio::select! {
                    biased;
                    _ = token.cancelled() => false,
                    ok = send_credit.reserve(n) => ok,
                };
                if !reserved {
                    break;
                }
                idle.poke();
                let queued = tokio::select! {
                    biased;
                    _ = token.cancelled() => false,
                    queued = enqueue_tcp_data(
                        sink,
                        stream_id,
                        Bytes::copy_from_slice(&buf[..n]),
                        &download_uncredited,
                        download_gate.as_ref(),
                    ) => queued,
                };
                if !queued {
                    break;
                }
            }
            Err(e) => {
                tracing::debug!(stream_id, error = %e, "egress read error");
                result_code = Some(TunnelErrorCode::ConnectionRefused);
                break;
            }
        }
    }

    if let Some(code) = result_code {
        // TcpOpened was already sent, so surface late errors as a reset here
        // rather than via the caller's Err path (which would double-signal).
        // Keep the stream token live until the ordered reset is queued; its
        // parent still cancels it immediately if relay/session shutdown wins.
        if !token.is_cancelled() {
            let _ =
                send_frame_until_cancelled(sink, TunnelFrame::TcpReset { stream_id, code }, token)
                    .await;
        }
    }

    token.cancel();
    let _ = peer_to_dest.await;
    Ok(())
}

// ── Per-UDP-association egress ──────────────────────────────────────────────

async fn send_udp_payload(
    socket: &UdpSocket,
    destination: SocketAddr,
    bytes: &[u8],
    session: &dyn TunnelServerSession,
    token: &CancellationToken,
) -> std::io::Result<usize> {
    let sent = tokio::select! {
        biased;
        _ = token.cancelled() => return Ok(0),
        result = socket.send_to(bytes, destination) => result?,
    };
    if token.is_cancelled() {
        return Ok(0);
    }
    session.record_payload(TunnelTrafficDirection::Upload, sent);
    Ok(sent)
}

fn queue_udp_response(
    sink: &FrameSink,
    association_id: u64,
    source: SocketAddr,
    bytes: Bytes,
    session: &dyn TunnelServerSession,
    token: &CancellationToken,
) -> bool {
    if token.is_cancelled() {
        return false;
    }
    let len = bytes.len();
    match sink.try_send_lossy_outcome(TunnelFrame::UdpDatagram {
        association_id,
        destination: TunnelDestination::Ip(source),
        bytes,
    }) {
        LossySendOutcome::Queued => {
            if token.is_cancelled() {
                return false;
            }
            session.record_payload(TunnelTrafficDirection::Download, len);
            true
        }
        LossySendOutcome::Dropped => true,
        LossySendOutcome::Closed => false,
    }
}

async fn udp_recv_loop(
    association_id: u64,
    socket: Arc<UdpSocket>,
    sink: FrameSink,
    session: Arc<dyn TunnelServerSession>,
    idle: IdleGuard,
    token: CancellationToken,
) {
    let mut buf = vec![0u8; UDP_READ_BUF];
    loop {
        let recv = tokio::select! {
            biased;
            _ = token.cancelled() => break,
            r = socket.recv_from(&mut buf) => r,
        };
        match recv {
            Ok((n, src)) => {
                idle.poke();
                // Lossy: drop under congestion rather than stall other streams.
                let alive = queue_udp_response(
                    &sink,
                    association_id,
                    src,
                    Bytes::copy_from_slice(&buf[..n]),
                    session.as_ref(),
                    &token,
                );
                if !alive {
                    break;
                }
            }
            // Socket error: end the association (idle handled by the watchdog).
            Err(_) => break,
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use parking_lot::Mutex as ParkingMutex;
    use std::collections::{HashMap, HashSet};
    use std::net::Ipv6Addr;

    use super::super::options::{TunnelServerSession, TunnelTrafficDirection};

    struct RecordingSession {
        payloads: ParkingMutex<Vec<(TunnelTrafficDirection, usize)>>,
        shutdown: CancellationToken,
    }

    impl RecordingSession {
        fn new() -> Self {
            Self {
                payloads: ParkingMutex::new(Vec::new()),
                shutdown: CancellationToken::new(),
            }
        }

        fn recorded(&self) -> Vec<(TunnelTrafficDirection, usize)> {
            self.payloads.lock().clone()
        }
    }

    impl TunnelServerSession for RecordingSession {
        fn record_payload(&self, direction: TunnelTrafficDirection, bytes: usize) {
            self.payloads.lock().push((direction, bytes));
        }

        fn cancellation_token(&self) -> CancellationToken {
            self.shutdown.clone()
        }

        fn connected(&self) {}

        fn disconnected(&self) {}
    }

    use super::super::carrier::{TunnelCarrierConfig, TunnelCarrierStore};
    use super::super::carrier_chunk::{
        CarrierDefragmenter, MAX_CARRIER_CIPHERTEXT, chunk_ciphertext, recv_one_ciphertext,
    };
    use super::super::carrier_peer::TunnelCarrierPeer;
    use super::super::carrier_wire::{CarrierReadHalf, CarrierWire, CarrierWriteHalf};
    use super::super::config::PACING_DEFAULT_RATE;
    use super::super::crypto::{
        generate_keypair, initiator_complete, initiator_start, responder_accept,
    };
    use super::super::frame::TunnelPublicKey;
    use super::super::peer_wire_crypto::PeerWireCrypto;
    use super::*;

    /// A real (in-process) authenticated Noise pair, so `spawn_frame_writer`
    /// exercises its actual `encrypt()` call rather than a stub.
    fn handshake_pair() -> (NoiseTransport, NoiseTransport) {
        let (client_priv, client_pub) = generate_keypair();
        let (server_priv, server_pub) = generate_keypair();
        let mut allowed: HashSet<TunnelPublicKey> = HashSet::new();
        allowed.insert(client_pub);

        let (handshake, msg1) = initiator_start(&client_priv, &server_pub).unwrap();
        let (server_transport, _remote, reply) =
            responder_accept(&server_priv, &msg1, &allowed).unwrap();
        let client_transport = initiator_complete(handshake, &reply).unwrap();
        (client_transport, server_transport)
    }

    type CarrierHalves = (CarrierReadHalf, CarrierWriteHalf, TunnelCarrierPeer);

    /// Build a real BitTorrent-masquerade carrier pair over an in-process
    /// duplex, returning both ends' `(read, write, cover-peer)` halves. The
    /// writer tests drive the client write half and receive on the server read
    /// half via `next_tunnel_frame`, so the whole carrier receive path (defrag +
    /// decrypt) is exercised alongside the pacing/priority logic.
    async fn carrier_test_pair() -> (CarrierHalves, CarrierHalves) {
        let dir = tempfile::TempDir::new().unwrap();
        // Leak the tempdir so the store's files outlive this fn for the test.
        let path = dir.keep();
        let config = TunnelCarrierConfig {
            corpus_bytes: 512 * 1024,
            piece_length: 128 * 1024,
            display_name: "debian-12.iso".to_string(),
            seed: [0u8; 32],
        };
        let store = Arc::new(
            TunnelCarrierStore::open_or_initialize(&path, &config)
                .await
                .unwrap(),
        );
        let info_hash = store.descriptor().handshake_info_hash;
        let (client_io, server_io) = tokio::io::duplex(8 * 1024 * 1024);
        let server_store = store.clone();
        let server = tokio::spawn(async move {
            let enc = PeerWireCrypto::responder(server_io, info_hash)
                .await
                .unwrap();
            CarrierWire::establish(enc.reader, enc.writer, server_store, info_hash)
                .await
                .unwrap()
                .into_halves()
        });
        let enc = PeerWireCrypto::initiator(client_io, info_hash)
            .await
            .unwrap();
        let client_halves = CarrierWire::establish(enc.reader, enc.writer, store, info_hash)
            .await
            .unwrap()
            .into_halves();
        let server_halves = server.await.unwrap();
        (client_halves, server_halves)
    }

    /// Run the real writer task over a real Noise transport + carrier, send `n`
    /// frames each carrying `payload_len` bytes, and return (wall-clock elapsed,
    /// total paced bytes, the shared `paced` flag) by receiving every frame back
    /// through the carrier read path (`next_tunnel_frame`) on the other end.
    /// `total_bytes` is the sum of `tcp_data_wire_len` per received `TcpData` —
    /// the exact byte count the writer's token bucket paced against. The returned
    /// `paced` Arc is the EXACT one handed to the writer, so a test can prove the
    /// writer sets it when (and only when) it actually throttles.
    async fn run_writer_and_measure(
        rate_bytes_per_s: u64,
        n_frames: usize,
        payload_len: usize,
    ) -> (Duration, u64, Arc<AtomicBool>) {
        let (client_transport, server_transport) = handshake_pair();
        let ((_c_read, c_write, _c_peer), (mut s_read, _s_write, s_peer)) =
            carrier_test_pair().await;

        let shutdown = CancellationToken::new();
        let pacing_rate = Arc::new(AtomicU64::new(rate_bytes_per_s));
        let paced = Arc::new(AtomicBool::new(false));
        let (cover_tx, cover_rx) = mpsc::channel::<CoverMessage>(OUTBOUND_QUEUE);
        let (sink, _handle) = spawn_frame_writer(
            Arc::new(Mutex::new(client_transport)),
            c_write,
            cover_rx,
            shutdown.clone(),
            pacing_rate,
            paced.clone(),
        );

        let start = Instant::now();
        for i in 0..n_frames {
            let ok = sink
                .send(TunnelFrame::TcpData {
                    stream_id: 1,
                    bytes: Bytes::from(vec![0u8; payload_len]).slice(0..payload_len),
                })
                .await;
            assert!(ok, "frame {i} should have been accepted by the writer");
        }

        // Receive exactly `n_frames` frames back through the carrier; this only
        // completes once the (possibly paced) writer has actually written every
        // byte, so `start.elapsed()` captures the full pacing delay. `cover_tx`
        // is unused (no inbound Requests), so it never blocks.
        let s_transport = Arc::new(Mutex::new(server_transport));
        let mut defrag = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
        let mut pending: VecDeque<Vec<u8>> = VecDeque::new();
        let mut s_peer = s_peer;
        let (rx_cover_tx, _rx_cover_rx) = mpsc::channel::<CoverMessage>(OUTBOUND_QUEUE);
        let mut total_bytes: u64 = 0;
        for _ in 0..n_frames {
            let frame = next_tunnel_frame(
                &mut s_read,
                &mut defrag,
                &mut pending,
                &s_transport,
                &mut s_peer,
                &rx_cover_tx,
            )
            .await
            .expect("frame must arrive");
            if let TunnelFrame::TcpData { stream_id, bytes } = frame {
                total_bytes += tcp_data_wire_len(stream_id, bytes.len());
            }
        }
        let elapsed = start.elapsed();

        let _ = cover_tx;
        shutdown.cancel();
        (elapsed, total_bytes, paced)
    }

    /// The whole point of Task C: prove the writer's `tokio::time::sleep` is
    /// actually awaited, not merely computed and discarded (the tunnel
    /// module's blanket `#[allow(dead_code, unused_variables)]` would let
    /// exactly that bug compile clean and silently do nothing). At a rate far
    /// below what's needed to carry the frames instantly, total wall-clock
    /// time must track `deficit_bytes / rate`, not the near-zero time an
    /// in-memory duplex pipe would otherwise take.
    #[tokio::test]
    async fn writer_paces_sends_at_a_low_rate() {
        const PAYLOAD: usize = 16 * 1024; // matches READ_CHUNK
        const N_FRAMES: usize = 18; // comfortably exceeds PACING_BURST (256 KiB)
        const LOW_RATE: u64 = 64 * 1024; // 64 KiB/s

        let (elapsed, total_bytes, paced) =
            run_writer_and_measure(LOW_RATE, N_FRAMES, PAYLOAD).await;

        // The writer must have raised the SHARED `paced` flag: this is the exact
        // `Arc` the control loop reads as its `utilized` signal, so this proves
        // the writer→control-loop half of the pacing-bound utilization wiring.
        assert!(
            paced.load(Ordering::Relaxed),
            "writer must set the shared `paced` flag when it throttles for pacing"
        );

        let deficit = total_bytes.saturating_sub(PACING_BURST);
        assert!(
            deficit > 0,
            "test setup should send more than one burst's worth of bytes, sent {total_bytes}"
        );
        let expected_delay = Duration::from_secs_f64(deficit as f64 / LOW_RATE as f64);

        // A generous window: real pacing must land in the right ballpark
        // (ruling out "no delay at all"), without making the test flaky
        // under CI scheduling jitter.
        assert!(
            elapsed >= expected_delay.mul_f64(0.5),
            "expected at least ~{expected_delay:?} of pacing delay for a {deficit}-byte \
             deficit at {LOW_RATE} B/s, only took {elapsed:?} (total {total_bytes} bytes) \
             — is the writer's sleep actually being awaited?"
        );
        assert!(
            elapsed <= expected_delay.mul_f64(2.5) + Duration::from_millis(500),
            "pacing delay much larger than expected: {elapsed:?} vs expected ~{expected_delay:?}"
        );
    }

    /// No-regression companion: at the production default (effectively
    /// unlimited) rate, the same frames must clear near-instantly — pacing
    /// must not add meaningful latency when it isn't supposed to throttle.
    #[tokio::test]
    async fn writer_default_rate_does_not_pace() {
        const PAYLOAD: usize = 16 * 1024;
        const N_FRAMES: usize = 18;

        let (elapsed, _total_bytes, paced) =
            run_writer_and_measure(PACING_DEFAULT_RATE, N_FRAMES, PAYLOAD).await;

        // The precise "no throttling" proof is the `!paced` assertion below; this
        // wall-clock ceiling only rules out a pacing-scale stall. It is generous
        // because receiving through the real carrier (BT framing + defrag + Noise
        // decrypt, unoptimized) has a fixed per-frame cost and this runs under
        // heavy parallel-test contention — far below the multi-second delay a
        // genuinely-throttled writer would incur for these bytes.
        assert!(
            elapsed < Duration::from_secs(3),
            "default pacing rate should not meaningfully delay throughput, took {elapsed:?}"
        );
        // At the effectively-unlimited default rate the writer never sleeps for
        // pacing, so the shared `paced` flag must stay false — the control loop
        // must NOT see a spurious "utilized" signal when pacing didn't bind.
        assert!(
            !paced.load(Ordering::Relaxed),
            "writer must NOT set `paced` when the default rate never throttles"
        );
    }

    /// Regression guard for THE bug: control frames sharing the single FIFO with
    /// paced data. At a low rate the tail of a burst of `TcpData` is held on a
    /// pacing deadline; a `Ping` enqueued AFTER all of it must still jump ahead
    /// on the wire (control priority lane) instead of coming out dead last as it
    /// would in the old single-queue writer.
    ///
    /// Decrypting every frame in wire order with the peer's transport also
    /// proves the writer preserved Noise's per-message sequence order == wire
    /// order despite the reordering: a `TcpData` frame pre-encrypted and then
    /// overtaken by the `Ping` would desync the cipher and fail to decrypt here.
    #[tokio::test]
    async fn control_frames_preempt_paced_data() {
        const PAYLOAD: usize = 16 * 1024; // matches READ_CHUNK
        const N_DATA: usize = 18; // > PACING_BURST (256 KiB) so the tail paces
        const LOW_RATE: u64 = 64 * 1024; // 64 KiB/s

        let (client_transport, server_transport) = handshake_pair();
        let ((_c_read, c_write, _c_peer), (mut s_read, _s_write, s_peer)) =
            carrier_test_pair().await;
        let shutdown = CancellationToken::new();
        let pacing_rate = Arc::new(AtomicU64::new(LOW_RATE));
        let paced = Arc::new(AtomicBool::new(false));
        let (_cover_tx, cover_rx) = mpsc::channel::<CoverMessage>(OUTBOUND_QUEUE);
        let (sink, _handle) = spawn_frame_writer(
            Arc::new(Mutex::new(client_transport)),
            c_write,
            cover_rx,
            shutdown.clone(),
            pacing_rate,
            paced.clone(),
        );

        // A burst of bulk data (the tail of which the writer WILL pace), then a
        // single control `Ping` enqueued after all of it. In the old
        // single-FIFO writer the `Ping` would sit behind every paced `TcpData`
        // and be written LAST.
        for _ in 0..N_DATA {
            let ok = sink
                .send(TunnelFrame::TcpData {
                    stream_id: 1,
                    bytes: Bytes::from(vec![0u8; PAYLOAD]),
                })
                .await;
            assert!(ok, "data frame should be accepted");
        }
        assert!(
            sink.send(TunnelFrame::Ping { nonce: 42 }).await,
            "ping should be accepted"
        );

        // Receive + decrypt every frame in wire order through the carrier read
        // path. Decrypting in order also proves the writer preserved Noise's
        // per-message sequence order == wire order despite the reordering.
        let s_transport = Arc::new(Mutex::new(server_transport));
        let mut defrag = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
        let mut pending: VecDeque<Vec<u8>> = VecDeque::new();
        let mut s_peer = s_peer;
        let (rx_cover_tx, _rx_cover_rx) = mpsc::channel::<CoverMessage>(OUTBOUND_QUEUE);
        let mut frames = Vec::with_capacity(N_DATA + 1);
        for _ in 0..(N_DATA + 1) {
            frames.push(
                next_tunnel_frame(
                    &mut s_read,
                    &mut defrag,
                    &mut pending,
                    &s_transport,
                    &mut s_peer,
                    &rx_cover_tx,
                )
                .await
                .expect("wire order must equal Noise sequence order"),
            );
        }
        shutdown.cancel();

        let data_count = frames
            .iter()
            .filter(|f| matches!(f, TunnelFrame::TcpData { .. }))
            .count();
        assert_eq!(
            data_count, N_DATA,
            "no data frame may be dropped or duplicated"
        );

        let ping_pos = frames
            .iter()
            .position(|f| matches!(f, TunnelFrame::Ping { nonce: 42 }))
            .expect("the ping must be written");

        // The decisive assertion: the ping is NOT the last frame. At least one
        // still-pending paced `TcpData` follows it, i.e. control preempted data.
        // In the buggy single-queue writer the ping would be at index N_DATA
        // (dead last).
        assert!(
            ping_pos < frames.len() - 1,
            "control ping must preempt still-pending paced data; instead it came \
             out at index {ping_pos} of {} — control is queued behind paced data \
             (the self-inflated-RTT bug)",
            frames.len()
        );
    }

    /// Dropping every `FrameSink` clone closes BOTH lanes; the writer must then
    /// exit on its own, WITHOUT the shutdown token firing. (The `biased` select
    /// keeps a never-disabled `shutdown` arm, so both-closed exit can't fall out
    /// of an `else`/all-disabled path — it's an explicit check that this guards.)
    #[tokio::test]
    async fn writer_exits_when_both_lanes_close() {
        let (client_transport, _server_transport) = handshake_pair();
        let ((_c_read, c_write, _c_peer), _server_halves) = carrier_test_pair().await;
        let shutdown = CancellationToken::new();
        let pacing_rate = Arc::new(AtomicU64::new(PACING_DEFAULT_RATE));
        let paced = Arc::new(AtomicBool::new(false));
        let (_cover_tx, cover_rx) = mpsc::channel::<CoverMessage>(OUTBOUND_QUEUE);
        let (sink, handle) = spawn_frame_writer(
            Arc::new(Mutex::new(client_transport)),
            c_write,
            cover_rx,
            shutdown.clone(),
            pacing_rate,
            paced,
        );

        drop(sink); // closes both control_tx and data_tx
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("writer must exit promptly once both lanes close")
            .expect("writer task must not panic");
        assert!(
            !shutdown.is_cancelled(),
            "writer must exit on channel close, not by relying on shutdown"
        );
    }

    /// Plan C Task 2: a real BitTorrent peer sends a periodic `KeepAlive` on an
    /// otherwise-idle-but-open connection (~every 2 min). The carrier writer
    /// must do the same, or a passive observer watching a quiet open connection
    /// that NEVER sends a keepalive has a tell no real peer exhibits.
    ///
    /// This exercises the SINGLE shared writer (`spawn_frame_writer`), which is
    /// the outbound path for BOTH the server relay and the client mux, so one
    /// test covers both endpoints' keepalive cadence.
    ///
    /// Observed via the message-level `CarrierTrace` tap on `write_message` (the
    /// single outgoing serialization choke point). `start_paused` freezes the
    /// clock so the 110 s cadence is driven with `tokio::time::advance` instead
    /// of a real wait. The keepalive is a plain BT message (NOT a tunnel frame),
    /// so it never touches `NoiseTransport`; we therefore assert on the emitted
    /// `CarrierEvent::KeepAlive` directly rather than round-tripping a frame.
    #[tokio::test(start_paused = true)]
    async fn writer_emits_periodic_keepalive_when_idle() {
        use super::super::carrier_wire::{clear_carrier_trace, install_carrier_trace};
        use super::super::config::KEEPALIVE_INTERVAL;
        use super::super::test_capture::CarrierEvent;

        let trace = install_carrier_trace();
        // RAII: always clear the thread-local trace so it can't leak events into
        // a later test scheduled on this same current-thread runtime worker.
        struct ClearTraceGuard;
        impl Drop for ClearTraceGuard {
            fn drop(&mut self) {
                clear_carrier_trace();
            }
        }
        let _clear_trace_guard = ClearTraceGuard;

        let keepalive_count =
            |trace: &Arc<parking_lot::Mutex<super::super::test_capture::CarrierTrace>>| {
                trace
                    .lock()
                    .events()
                    .iter()
                    .filter(|e| **e == CarrierEvent::KeepAlive)
                    .count()
            };

        let (client_transport, _server_transport) = handshake_pair();
        let ((_c_read, c_write, _c_peer), _server_halves) = carrier_test_pair().await;
        let shutdown = CancellationToken::new();
        let pacing_rate = Arc::new(AtomicU64::new(PACING_DEFAULT_RATE));
        let paced = Arc::new(AtomicBool::new(false));
        // Idle writer: no control/data/cover frames are ever enqueued.
        let (_cover_tx, cover_rx) = mpsc::channel::<CoverMessage>(OUTBOUND_QUEUE);
        let (_sink, _handle) = spawn_frame_writer(
            Arc::new(Mutex::new(client_transport)),
            c_write,
            cover_rx,
            shutdown.clone(),
            pacing_rate,
            paced,
        );

        // Let the writer task run once at t=0 so it registers its keepalive
        // interval (first tick due one full interval out). Yielding keeps this
        // test task runnable, so the paused clock never auto-advances here.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }

        // Baseline: the handshake wrote Bitfield/Unchoke/Interested/
        // ExtendedHandshake but no KeepAlive, and the first keepalive tick is one
        // full interval out, so none is present yet — proving the writer does NOT
        // fire a keepalive the instant it starts.
        assert_eq!(
            keepalive_count(&trace),
            0,
            "no keepalive should be sent before the interval elapses"
        );

        // Advance one full keepalive interval (plus slack past the exact
        // deadline); the idle writer's timer arm must fire and put a `KeepAlive`
        // on the wire.
        tokio::time::advance(KEEPALIVE_INTERVAL + Duration::from_secs(1)).await;
        // Yield so the woken writer task runs and serializes the keepalive.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }

        assert!(
            keepalive_count(&trace) >= 1,
            "an idle carrier writer must emit a BT KeepAlive within KEEPALIVE_INTERVAL"
        );

        shutdown.cancel();
    }
    #[tokio::test]
    async fn credit_is_bounded_by_forwarded_bytes() {
        let pending = AtomicU64::new(1024);
        assert_eq!(take_acknowledged(&pending, 4096), 1024);
        assert_eq!(pending.load(Ordering::Relaxed), 0);

        let stream_id = 7;
        let download_uncredited = Arc::new(AtomicU64::new(1024));
        let download_finished = Arc::new(AtomicBool::new(false));
        let download_gate = Arc::new(Mutex::new(()));
        let shutdown = CancellationToken::new();
        let idle = IdleGuard::spawn(Duration::from_secs(60), shutdown.clone());
        let (to_dest, _to_dest_rx) = mpsc::channel(1);
        let send_credit = SendCredit::with_window(0);
        let tcp: TcpMap = Arc::new(Mutex::new(HashMap::new()));
        tcp.lock().await.insert(
            stream_id,
            TcpEntry {
                to_dest,
                send_credit: send_credit.clone(),
                download_uncredited: download_uncredited.clone(),
                download_gate,
                download_finished,
                idle,
                shutdown: shutdown.clone(),
            },
        );
        let session = RecordingSession::new();

        acknowledge_tcp_credit(&tcp, stream_id, 4096, &session, &shutdown).await;
        assert_eq!(download_uncredited.load(Ordering::Relaxed), 0);
        assert_eq!(
            session.recorded(),
            vec![(TunnelTrafficDirection::Download, 1024)]
        );
        assert!(send_credit.reserve(1024).await);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), send_credit.reserve(1))
                .await
                .is_err(),
            "the credit grant must not exceed successfully forwarded bytes"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn failed_udp_send_to_records_no_upload_payload() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let session = RecordingSession::new();

        assert!(
            send_udp_payload(
                &socket,
                SocketAddr::from((Ipv6Addr::LOCALHOST, 9)),
                b"payload",
                &session,
                &session.shutdown,
            )
            .await
            .is_err()
        );
        assert!(session.recorded().is_empty());
    }

    #[test]
    fn accepted_udp_response_queues_its_datagram_and_records_download() {
        let (control_tx, _control_rx) = mpsc::channel(1);
        let (data_tx, mut data_rx) = mpsc::channel(1);
        let sink = FrameSink {
            control_tx,
            data_tx,
            data_liveness: Arc::new(ParkingMutex::new(DataLaneLiveness {
                receiver_open: true,
            })),
        };
        let session = RecordingSession::new();
        let payload = Bytes::from_static(b"response");

        assert!(queue_udp_response(
            &sink,
            7,
            SocketAddr::from(([127, 0, 0, 1], 9000)),
            payload.clone(),
            &session,
            &session.shutdown,
        ));
        match data_rx.try_recv().unwrap() {
            TunnelFrame::UdpDatagram {
                association_id,
                bytes,
                ..
            } => {
                assert_eq!(association_id, 7);
                assert_eq!(bytes, payload);
            }
            frame => panic!("expected queued UDP response, got {frame:?}"),
        }
        assert_eq!(
            session.recorded(),
            vec![(TunnelTrafficDirection::Download, payload.len())]
        );
    }

    #[test]
    fn dropped_udp_response_records_no_download_payload() {
        let (control_tx, _control_rx) = mpsc::channel(1);
        let (data_tx, _data_rx) = mpsc::channel(1);
        data_tx
            .try_send(TunnelFrame::UdpDatagram {
                association_id: 1,
                destination: TunnelDestination::Ip(SocketAddr::from(([127, 0, 0, 1], 9000))),
                bytes: Bytes::new(),
            })
            .unwrap();
        let sink = FrameSink {
            control_tx,
            data_tx,
            data_liveness: Arc::new(ParkingMutex::new(DataLaneLiveness {
                receiver_open: true,
            })),
        };
        let session = RecordingSession::new();

        assert!(queue_udp_response(
            &sink,
            7,
            SocketAddr::from(([127, 0, 0, 1], 9000)),
            Bytes::from_static(b"response"),
            &session,
            &session.shutdown,
        ));
        assert!(session.recorded().is_empty());
    }

    #[tokio::test]
    async fn closed_tcp_stream_keeps_download_accounting_until_credit_arrives() {
        let stream_id = 7;
        let download_uncredited = Arc::new(AtomicU64::new(1024));
        let download_finished = Arc::new(AtomicBool::new(false));
        let download_gate = Arc::new(Mutex::new(()));
        let shutdown = CancellationToken::new();
        let idle = IdleGuard::spawn(Duration::from_secs(60), shutdown.clone());
        let (to_dest, _to_dest_rx) = mpsc::channel(1);
        let tcp: TcpMap = Arc::new(Mutex::new(HashMap::new()));
        tcp.lock().await.insert(
            stream_id,
            TcpEntry {
                to_dest,
                send_credit: SendCredit::with_window(0),
                download_uncredited: download_uncredited.clone(),
                download_finished: download_finished.clone(),
                download_gate: download_gate.clone(),
                idle,
                shutdown: shutdown.clone(),
            },
        );
        let session = RecordingSession::new();

        finish_tcp_download(
            &tcp,
            stream_id,
            &download_uncredited,
            &download_finished,
            &download_gate,
        )
        .await;
        assert!(tcp.lock().await.contains_key(&stream_id));

        acknowledge_tcp_credit(&tcp, stream_id, 4096, &session, &shutdown).await;
        assert!(!tcp.lock().await.contains_key(&stream_id));
        assert_eq!(
            session.recorded(),
            vec![(TunnelTrafficDirection::Download, 1024)]
        );
    }

    #[tokio::test]
    async fn tcp_data_waits_for_queue_capacity_before_taking_credit_gate() {
        let (control_tx, _control_rx) = mpsc::channel(1);
        let (data_tx, mut data_rx) = mpsc::channel(1);
        data_tx
            .try_send(TunnelFrame::UdpDatagram {
                association_id: 1,
                destination: TunnelDestination::Ip(SocketAddr::from(([127, 0, 0, 1], 9000))),
                bytes: Bytes::new(),
            })
            .unwrap();
        let sink = FrameSink {
            control_tx,
            data_tx,
            data_liveness: Arc::new(ParkingMutex::new(DataLaneLiveness {
                receiver_open: true,
            })),
        };
        let download_uncredited = Arc::new(AtomicU64::new(0));
        let download_gate = Arc::new(Mutex::new(()));
        let send = tokio::spawn({
            let sink = sink.clone();
            let download_uncredited = download_uncredited.clone();
            let download_gate = download_gate.clone();
            async move {
                enqueue_tcp_data(
                    &sink,
                    7,
                    Bytes::from_static(b"response"),
                    &download_uncredited,
                    &download_gate,
                )
                .await
            }
        });

        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            download_gate.try_lock().is_ok(),
            "waiting for data-lane capacity must not block the relay reader on this stream"
        );

        data_rx.try_recv().unwrap();
        assert!(send.await.unwrap());
        assert_eq!(
            download_uncredited.load(Ordering::Relaxed),
            b"response".len() as u64
        );
    }

    #[tokio::test]
    async fn closed_writer_data_lane_rejects_reserved_tcp_publication() {
        let data_liveness = Arc::new(ParkingMutex::new(DataLaneLiveness {
            receiver_open: true,
        }));
        let (control_tx, _control_rx) = mpsc::channel(1);
        let (data_tx, data_rx) = mpsc::channel(1);
        let sink = FrameSink {
            control_tx,
            data_tx,
            data_liveness: data_liveness.clone(),
        };
        let permit = sink.reserve_data().await.unwrap();
        drop(DataLaneReceiver::new(data_rx, data_liveness));

        let download_uncredited = AtomicU64::new(0);
        let download_gate = Mutex::new(());
        assert!(
            !sink
                .publish_reserved_tcp_data(
                    permit,
                    7,
                    Bytes::from_static(b"response"),
                    &download_uncredited,
                    &download_gate,
                )
                .await
        );
        assert_eq!(download_uncredited.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn cancelled_peer_destination_writer_does_not_record_payload() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind destination listener");
        let destination_addr = listener.local_addr().expect("destination listener address");
        let client = TcpStream::connect(destination_addr)
            .await
            .expect("connect destination writer");
        let (_destination, _) = listener.accept().await.expect("accept destination writer");

        let (control_tx, _control_rx) = mpsc::channel(1);
        let (data_tx, _data_rx) = mpsc::channel(1);
        let sink = FrameSink {
            control_tx,
            data_tx,
            data_liveness: Arc::new(ParkingMutex::new(DataLaneLiveness {
                receiver_open: true,
            })),
        };
        let (to_dest_tx, to_dest_rx) = mpsc::channel(1);
        to_dest_tx
            .send(PeerToDest::Data(Bytes::from_static(
                b"must not be accounted",
            )))
            .await
            .expect("queue peer payload");

        let session = Arc::new(RecordingSession::new());
        let writer_session: Arc<dyn TunnelServerSession> = session.clone();
        let token = CancellationToken::new();
        token.cancel();
        let idle = IdleGuard::spawn(Duration::from_secs(60), token.clone());

        pump_peer_to_destination(
            7,
            client.into_split().1,
            to_dest_rx,
            writer_session,
            sink,
            idle,
            token,
        )
        .await;

        tokio::task::yield_now().await;
        assert!(
            session.recorded().is_empty(),
            "a cancelled destination writer must not record payload after its parent has stopped"
        );
    }
    #[tokio::test]
    async fn destination_read_error_after_tcp_opened_sends_one_reset() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind destination listener");
        let destination_addr = listener.local_addr().expect("destination listener address");
        let (reset_tx, reset_rx) = tokio::sync::oneshot::channel();
        let destination = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept destination connection");
            reset_rx.await.expect("request destination reset");
            #[allow(deprecated)]
            {
                stream
                    .set_linger(Some(Duration::ZERO))
                    .expect("configure destination reset");
            }
            drop(stream);
        });

        let (control_tx, mut control_rx) = mpsc::channel(1);
        let (data_tx, mut data_rx) = mpsc::channel(1);
        let sink = FrameSink {
            control_tx,
            data_tx,
            data_liveness: Arc::new(ParkingMutex::new(DataLaneLiveness {
                receiver_open: true,
            })),
        };
        let token = CancellationToken::new();
        let idle = IdleGuard::spawn(Duration::from_secs(60), token.clone());
        let (_to_dest_tx, to_dest_rx) = mpsc::channel(1);
        let session: Arc<dyn TunnelServerSession> = Arc::new(RecordingSession::new());
        let egress = EgressPolicy::default();
        let send_credit = SendCredit::with_window(0);
        let download_uncredited = Arc::new(AtomicU64::new(0));
        let download_gate = Arc::new(Mutex::new(()));
        let observe_reset = async {
            let opened = tokio::time::timeout(Duration::from_secs(1), control_rx.recv())
                .await
                .expect("TcpOpened must arrive before destination failure")
                .expect("control lane must stay open");
            assert!(
                matches!(opened, TunnelFrame::TcpOpened { stream_id: 7, .. }),
                "destination failure must occur after TcpOpened, got {opened:?}"
            );
            reset_tx.send(()).expect("signal destination reset");

            let reset = tokio::time::timeout(Duration::from_secs(1), data_rx.recv())
                .await
                .expect("post-open destination error must emit TcpReset")
                .expect("data lane must stay open");
            assert_eq!(
                reset,
                TunnelFrame::TcpReset {
                    stream_id: 7,
                    code: TunnelErrorCode::ConnectionRefused,
                }
            );
            assert!(
                data_rx.try_recv().is_err(),
                "a post-open destination error must emit exactly one TcpReset"
            );
        };
        let pump = open_and_pump(
            7,
            "127.0.0.1".to_owned(),
            destination_addr.port(),
            &egress,
            &sink,
            session,
            to_dest_rx,
            &send_credit,
            &idle,
            download_uncredited,
            download_gate,
            &token,
        );
        let (result, ()) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(1), pump),
            observe_reset
        );

        assert!(
            result.expect("relay pump must finish").is_ok(),
            "post-open destination reset is reported on the wire, not as a second caller reset"
        );
        destination
            .await
            .expect("destination reset task must not panic");
        assert!(
            token.is_cancelled(),
            "stream tears down only after its reset is sent"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn relay_shutdown_joins_idle_watchdog() {
        let (exit_gate, _clear_exit_gate) = super::super::flow::install_idle_guard_exit_gate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind destination listener");
        let destination_addr = listener.local_addr().expect("destination listener address");
        let (close_destination, wait_for_close) = tokio::sync::oneshot::channel();
        let destination = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept destination connection");
            wait_for_close.await.expect("close destination connection");
            drop(stream);
        });

        let (mut client_transport, server_transport) = handshake_pair();
        let (
            (mut client_read, mut client_write, _client_peer),
            (server_read, server_write, server_peer),
        ) = carrier_test_pair().await;
        let shutdown = CancellationToken::new();
        let session: Arc<dyn TunnelServerSession> = Arc::new(RecordingSession::new());
        let mut relay = tokio::spawn(run_server_relay(
            AdmittedPeer {
                client_key: TunnelPublicKey([0; 32]),
                session,
                transport: server_transport,
                read_half: server_read,
                write_half: server_write,
                carrier_peer: server_peer,
            },
            Arc::new(EgressPolicy {
                idle_timeout: Duration::from_secs(60),
                ..EgressPolicy::default()
            }),
            shutdown.clone(),
        ));

        let open = client_transport
            .encrypt(&TunnelFrame::OpenTcp {
                stream_id: 7,
                host: "127.0.0.1".to_owned(),
                port: destination_addr.port(),
            })
            .expect("encrypt OpenTcp");
        for chunk in chunk_ciphertext(&open) {
            client_write
                .send_tunnel(&chunk)
                .await
                .expect("send OpenTcp");
        }

        let mut defrag = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
        let opened = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let ciphertext = recv_one_ciphertext(&mut client_read, &mut defrag)
                    .await
                    .expect("server must respond over the carrier");
                let frame = client_transport
                    .decrypt(&ciphertext)
                    .expect("decrypt server response");
                if matches!(frame, TunnelFrame::TcpOpened { stream_id: 7, .. }) {
                    return frame;
                }
            }
        })
        .await
        .expect("TcpOpened must prove the relay created its stream watchdog");
        assert!(matches!(
            opened,
            TunnelFrame::TcpOpened { stream_id: 7, .. }
        ));

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), exit_gate.wait_until_entered())
            .await
            .expect("idle watchdog must observe relay cancellation");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut relay)
                .await
                .is_err(),
            "relay shutdown must wait for its idle watchdog to exit"
        );

        exit_gate.release();
        tokio::time::timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay shutdown must finish after watchdog exit")
            .expect("relay task must not panic");
        close_destination
            .send(())
            .expect("release destination connection");
        destination.await.expect("destination task must not panic");
    }
}
