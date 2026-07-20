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

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::type_aliases::BoxAsyncWrite;

use super::config::{
    CONNECT_TIMEOUT, OPEN_WINDOW, OUTBOUND_QUEUE, PACING_BURST, PER_STREAM_QUEUE, PING_INTERVAL,
    PING_NONCE_MAP_CAP, READ_CHUNK, UDP_READ_BUF,
};
use super::crypto::{NoiseTransport, TunnelCryptoError};
use super::egress::{EgressPolicy, EgressTransport};
use super::flow::{
    IdleGuard, RttEstimator, SendCredit, TokenBucket, WindowController, drive_flow_control,
    record_ping_sent,
};
use super::frame::{MAX_FRAME_PAYLOAD, TunnelDestination, TunnelErrorCode, TunnelFrame};
use super::server::AdmittedPeer;

// ── Shared wire helpers ─────────────────────────────────────────────────────

/// Read one length-prefixed, Noise-encrypted frame.
///
/// The socket read happens WITHOUT the transport lock; the lock is taken only
/// to decrypt, so a blocked/idle read never starves the writer task.
pub(crate) async fn read_encrypted_frame<R: AsyncRead + Unpin>(
    transport: &Mutex<NoiseTransport>,
    reader: &mut R,
) -> Result<TunnelFrame, TunnelCryptoError> {
    let mut len_buf = [0u8; 2];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| TunnelCryptoError::DecryptFailed(format!("read len: {e}")))?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_PAYLOAD + 32 {
        return Err(TunnelCryptoError::DecryptFailed(format!(
            "invalid frame length: {len}"
        )));
    }
    let mut ciphertext = vec![0u8; len];
    reader
        .read_exact(&mut ciphertext)
        .await
        .map_err(|e| TunnelCryptoError::DecryptFailed(format!("read frame: {e}")))?;
    let mut t = transport.lock().await;
    t.decrypt(&ciphertext)
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
#[derive(Clone)]
pub(crate) struct FrameSink {
    /// Priority lane: `Ping`/`Pong`/`Credit` + lifecycle frames. Never paced.
    control_tx: mpsc::Sender<TunnelFrame>,
    /// Ordered lane: `TcpData` (paced) + `TcpFin`/`TcpReset`/`UdpDatagram`
    /// (unpaced). FIFO so a stream's close never overtakes its own data.
    data_tx: mpsc::Sender<TunnelFrame>,
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

    /// Best-effort enqueue for lossy traffic (UDP datagrams). Drops the frame
    /// if the destination lane is full instead of blocking the caller — which
    /// would head-of-line-block every other stream on this connection. Routes by
    /// variant like `send`, so `UdpDatagram`s land on the data lane (they must
    /// never flood the control priority lane). Returns `false` only if the peer
    /// connection is gone.
    pub(crate) fn try_send_lossy(&self, frame: TunnelFrame) -> bool {
        use mpsc::error::TrySendError;
        let tx = if Self::is_data(&frame) {
            &self.data_tx
        } else {
            &self.control_tx
        };
        match tx.try_send(frame) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => true, // dropped; connection still alive
            Err(TrySendError::Closed(_)) => false,
        }
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
    mut writer: BoxAsyncWrite,
    shutdown: CancellationToken,
    pacing_rate: Arc<AtomicU64>,
    paced: Arc<AtomicBool>,
) -> (FrameSink, JoinHandle<()>) {
    // TWO lanes, one writer. `OUTBOUND_QUEUE` each: the control lane is a
    // priority lane the writer's `biased` select always drains first, so
    // `Ping`/`Pong`/`Credit` never wait behind a paced `TcpData` frame.
    let (control_tx, mut control_rx) = mpsc::channel::<TunnelFrame>(OUTBOUND_QUEUE);
    let (data_tx, mut data_rx) = mpsc::channel::<TunnelFrame>(OUTBOUND_QUEUE);
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
            writer: &mut BoxAsyncWrite,
            transport: &Mutex<NoiseTransport>,
            frame: &TunnelFrame,
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
            let len = (blob.len() as u16).to_be_bytes();
            !(writer.write_all(&len).await.is_err()
                || writer.write_all(&blob).await.is_err()
                || writer.flush().await.is_err())
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

        loop {
            // Both lanes drained and closed, nothing left to flush: peer gone.
            if !control_open && !data_open && pending.is_none() {
                break;
            }
            tokio::select! {
                // Priority order: shutdown, then the control lane, then a due
                // pending data frame, then admitting a new data frame. `biased`
                // is what makes the control lane preempt paced data: whenever a
                // control frame is ready it is serviced before the pending
                // data's deadline arm and before pulling more data.
                biased;

                _ = shutdown.cancelled() => break,

                // Control priority lane — never paced, always first.
                ctrl = control_rx.recv(), if control_open => match ctrl {
                    Some(ctrl) => {
                        if !write_frame(&mut writer, &transport, &ctrl).await {
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
                    if !write_frame(&mut writer, &transport, &frame).await {
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
                                if !write_frame(&mut writer, &transport, &data).await {
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
                            if !write_frame(&mut writer, &transport, &data).await {
                                break;
                            }
                        }
                    }
                }
            }
        }
    });
    (
        FrameSink {
            control_tx,
            data_tx,
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

/// Run the full egress relay for one admitted peer until the peer disconnects
/// or `shutdown` fires.
pub(crate) async fn run_server_relay(
    peer: AdmittedPeer,
    egress: Arc<EgressPolicy>,
    shutdown: CancellationToken,
) {
    let AdmittedPeer {
        client_key,
        transport,
        mut reader,
        writer,
    } = peer;

    let transport = Arc::new(Mutex::new(transport));
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
        writer,
        shutdown.clone(),
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
    tokio::spawn(server_control_task(
        sink.clone(),
        ping_inflight.clone(),
        rtt.clone(),
        controller.clone(),
        paced.clone(),
        pacing_rate.clone(),
        shutdown.clone(),
    ));

    loop {
        let frame = tokio::select! {
            _ = shutdown.cancelled() => break,
            r = read_encrypted_frame(&transport, &mut reader) => match r {
                Ok(f) => f,
                Err(e) => {
                    tracing::debug!(error = %e, "tunnel server relay: peer read ended");
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
                    sink.send(TunnelFrame::TcpReset {
                        stream_id,
                        code: TunnelErrorCode::ConnectionRefused,
                    })
                    .await;
                    continue;
                }
                let (to_dest_tx, to_dest_rx) = mpsc::channel::<PeerToDest>(PER_STREAM_QUEUE);
                let stream_token = shutdown.child_token();
                // Open the dest→peer send window at the fixed generous
                // `OPEN_WINDOW`: a backstop that never binds (aggregate in-flight
                // is bounded by pacing at `target / rtt`, not this window), while
                // the receive queue (`PER_STREAM_QUEUE`, sized from OPEN_WINDOW)
                // is guaranteed to hold a full window — so a stalled destination
                // can never head-of-line-block the shared reader.
                let send_credit = SendCredit::with_window(OPEN_WINDOW);
                let idle = IdleGuard::spawn(egress.idle_timeout, stream_token.clone());
                map.insert(
                    stream_id,
                    TcpEntry {
                        to_dest: to_dest_tx,
                        send_credit: send_credit.clone(),
                        idle: idle.clone(),
                        shutdown: stream_token.clone(),
                    },
                );
                drop(map);

                tokio::spawn(handle_tcp_stream(
                    stream_id,
                    host,
                    port,
                    egress.clone(),
                    sink.clone(),
                    tcp.clone(),
                    to_dest_rx,
                    send_credit,
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
                    let _ = to_dest.send(PeerToDest::Data(bytes)).await;
                }
            }
            TunnelFrame::TcpFin { stream_id } => {
                let to_dest = {
                    let map = tcp.lock().await;
                    map.get(&stream_id).map(|e| e.to_dest.clone())
                };
                if let Some(to_dest) = to_dest {
                    let _ = to_dest.send(PeerToDest::Fin).await;
                }
            }
            TunnelFrame::Credit { stream_id, bytes } => {
                // The client drained `bytes` of dest→peer data; replenish the
                // server's send credit for this stream.
                let map = tcp.lock().await;
                if let Some(entry) = map.get(&stream_id) {
                    entry.send_credit.grant(bytes as usize);
                }
            }
            TunnelFrame::TcpReset { stream_id, .. } => {
                if let Some(entry) = tcp.lock().await.remove(&stream_id) {
                    entry.send_credit.close();
                    entry.shutdown.cancel();
                }
            }
            TunnelFrame::OpenUdp { association_id } => {
                let mut map = udp.lock().await;
                if map.contains_key(&association_id) {
                    continue;
                }
                if map.len() >= egress.max_udp_associations_per_client {
                    drop(map);
                    tracing::debug!(association_id, "udp association limit reached; ignoring");
                    continue;
                }
                let socket = match UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        drop(map);
                        tracing::debug!(error = %e, "failed to bind egress udp socket");
                        continue;
                    }
                };
                let token = shutdown.child_token();
                let idle = IdleGuard::spawn(egress.idle_timeout, token.clone());
                map.insert(
                    association_id,
                    UdpEntry {
                        socket: socket.clone(),
                        idle: idle.clone(),
                        shutdown: token.clone(),
                    },
                );
                drop(map);
                tokio::spawn(udp_recv_loop(
                    association_id,
                    socket,
                    sink.clone(),
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
                    match egress.authorize(&destination, EgressTransport::Udp).await {
                        Ok(resolved) => {
                            let _ = socket.send_to(&bytes, resolved.selected).await;
                        }
                        Err(e) => {
                            tracing::debug!(association_id, error = %e, "udp egress denied");
                        }
                    }
                }
            }
            TunnelFrame::CloseUdp { association_id } => {
                if let Some(entry) = udp.lock().await.remove(&association_id) {
                    entry.shutdown.cancel();
                }
            }
            TunnelFrame::Ping { nonce } => {
                sink.send(TunnelFrame::Pong { nonce }).await;
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

    // Peer gone: tear everything down.
    for (_, entry) in tcp.lock().await.drain() {
        entry.send_credit.close();
        entry.shutdown.cancel();
    }
    for (_, entry) in udp.lock().await.drain() {
        entry.shutdown.cancel();
    }
    writer_handle.abort();
    tracing::debug!(?client_key, "tunnel server relay: peer session ended");
}

/// Mirrors the client mux's control task: probe RTT on the download direction
/// (from the server's perspective) with our own periodic `Ping`s, then drive
/// the carrier's `WindowController` + pacing rate from the freshest sample. The
/// `Ping` arm in `run_server_relay` already answers the client's pings, which
/// is how the client measures the upload direction; the `Pong` arm records our
/// own probes' samples into `rtt`.
///
/// Stops on shutdown, or once the sink is gone — which happens shortly after
/// `run_server_relay` aborts the writer task on peer disconnect, since that
/// closes the channel `sink.send` writes to.
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
            _ = shutdown.cancelled() => break,
            _ = interval.tick() => {}
        }
        let nonce = next_nonce;
        next_nonce = next_nonce.wrapping_add(1);
        {
            let mut map = inflight.lock().unwrap();
            record_ping_sent(&mut map, nonce, Instant::now(), PING_NONCE_MAP_CAP);
        }
        if !sink.send(TunnelFrame::Ping { nonce }).await {
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
    sink: FrameSink,
    tcp: TcpMap,
    to_dest_rx: mpsc::Receiver<PeerToDest>,
    send_credit: SendCredit,
    idle: IdleGuard,
    token: CancellationToken,
) {
    let result = open_and_pump(
        stream_id,
        host,
        port,
        &egress,
        &sink,
        to_dest_rx,
        &send_credit,
        &idle,
        &token,
    )
    .await;

    if let Err(code) = result {
        sink.send(TunnelFrame::TcpReset { stream_id, code }).await;
    }

    // Deregister the stream (unless it was already replaced).
    if let Some(entry) = tcp.lock().await.remove(&stream_id) {
        entry.send_credit.close();
        entry.shutdown.cancel();
    }
}

/// Authorize + connect the destination, then pump both directions until the
/// stream ends. On any pre-connect failure returns `Err(code)` so the caller
/// sends a single `TcpReset`.
#[allow(clippy::too_many_arguments)]
async fn open_and_pump(
    stream_id: u64,
    host: String,
    port: u16,
    egress: &EgressPolicy,
    sink: &FrameSink,
    mut to_dest_rx: mpsc::Receiver<PeerToDest>,
    send_credit: &SendCredit,
    idle: &IdleGuard,
    token: &CancellationToken,
) -> Result<(), TunnelErrorCode> {
    let destination = parse_destination(&host, port);
    let resolved = egress
        .authorize(&destination, EgressTransport::Tcp)
        .await
        .map_err(|e| e.to_error_code())?;

    let dest = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(resolved.selected))
        .await
    {
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

    if !sink
        .send(TunnelFrame::TcpOpened {
            stream_id,
            bind_addr,
        })
        .await
    {
        return Ok(());
    }

    let (mut dest_read, mut dest_write) = dest.into_split();

    // peer → destination: write received data, then grant the peer credit for
    // exactly what we drained so it may send that much more.
    let pd_token = token.clone();
    let pd_sink = sink.clone();
    let pd_idle = idle.clone();
    let peer_to_dest: JoinHandle<()> = tokio::spawn(async move {
        loop {
            let msg = tokio::select! {
                _ = pd_token.cancelled() => break,
                m = to_dest_rx.recv() => m,
            };
            match msg {
                Some(PeerToDest::Data(bytes)) => {
                    let n = bytes.len();
                    if dest_write.write_all(&bytes).await.is_err() {
                        break;
                    }
                    pd_idle.poke();
                    if !pd_sink
                        .send(TunnelFrame::Credit {
                            stream_id,
                            bytes: n as u32,
                        })
                        .await
                    {
                        break;
                    }
                }
                Some(PeerToDest::Fin) | None => {
                    let _ = dest_write.shutdown().await;
                    break;
                }
            }
        }
    });

    // destination → peer (runs in this task). Reserve send credit before each
    // chunk so we never overrun the peer's receive window.
    let mut buf = vec![0u8; READ_CHUNK];
    let mut result_code: Option<TunnelErrorCode> = None;
    loop {
        let read = tokio::select! {
            _ = token.cancelled() => { break; }
            r = dest_read.read(&mut buf) => r,
        };
        match read {
            Ok(0) => {
                // Destination closed: half-close toward the peer.
                sink.send(TunnelFrame::TcpFin { stream_id }).await;
                break;
            }
            Ok(n) => {
                let reserved = tokio::select! {
                    _ = token.cancelled() => false,
                    ok = send_credit.reserve(n) => ok,
                };
                if !reserved {
                    break;
                }
                idle.poke();
                if !sink
                    .send(TunnelFrame::TcpData {
                        stream_id,
                        bytes: Bytes::copy_from_slice(&buf[..n]),
                    })
                    .await
                {
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

    token.cancel();
    peer_to_dest.abort();

    match result_code {
        // TcpOpened was already sent, so surface late errors as a reset here
        // rather than via the caller's Err path (which would double-signal).
        Some(code) => {
            sink.send(TunnelFrame::TcpReset { stream_id, code }).await;
            Ok(())
        }
        None => Ok(()),
    }
}

// ── Per-UDP-association egress ──────────────────────────────────────────────

async fn udp_recv_loop(
    association_id: u64,
    socket: Arc<UdpSocket>,
    sink: FrameSink,
    idle: IdleGuard,
    token: CancellationToken,
) {
    let mut buf = vec![0u8; UDP_READ_BUF];
    loop {
        let recv = tokio::select! {
            _ = token.cancelled() => break,
            r = socket.recv_from(&mut buf) => r,
        };
        match recv {
            Ok((n, src)) => {
                idle.poke();
                // Lossy: drop under congestion rather than stall other streams.
                let alive = sink.try_send_lossy(TunnelFrame::UdpDatagram {
                    association_id,
                    destination: TunnelDestination::Ip(src),
                    bytes: Bytes::copy_from_slice(&buf[..n]),
                });
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
    use std::collections::HashSet;

    use tokio::io::AsyncReadExt;

    use super::super::config::PACING_DEFAULT_RATE;
    use super::super::crypto::{
        generate_keypair, initiator_complete, initiator_start, responder_accept,
    };
    use super::super::frame::TunnelPublicKey;
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

    /// Run the real writer task over a real Noise transport, send `n` frames
    /// each carrying `payload_len` bytes, and return (wall-clock elapsed,
    /// total on-wire bytes written, the shared `paced` flag) by draining the
    /// raw length-prefixed frames on the other end of an in-memory duplex pipe.
    /// The returned `paced` Arc is the EXACT one handed to the writer, so a test
    /// can prove the writer sets it when (and only when) it actually throttles.
    async fn run_writer_and_measure(
        rate_bytes_per_s: u64,
        n_frames: usize,
        payload_len: usize,
    ) -> (Duration, u64, Arc<AtomicBool>) {
        let (client_transport, _server_transport) = handshake_pair();
        // Sized generously so `write_all` never blocks on the reader side —
        // this test only cares about the writer's own internal pacing delay,
        // not pipe backpressure.
        let (write_half, mut read_half) = tokio::io::duplex(8 * 1024 * 1024);

        let shutdown = CancellationToken::new();
        let pacing_rate = Arc::new(AtomicU64::new(rate_bytes_per_s));
        let paced = Arc::new(AtomicBool::new(false));
        let (sink, _handle) = spawn_frame_writer(
            Arc::new(Mutex::new(client_transport)),
            Box::new(write_half),
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

        // Drain exactly `n_frames` length-prefixed blobs off the wire; this
        // only completes once the (possibly paced) writer has actually
        // written every byte, so `start.elapsed()` below captures the full
        // pacing delay, not just enqueue time.
        let mut total_bytes: u64 = 0;
        for _ in 0..n_frames {
            let mut len_buf = [0u8; 2];
            read_half.read_exact(&mut len_buf).await.unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut blob = vec![0u8; len];
            read_half.read_exact(&mut blob).await.unwrap();
            total_bytes += (2 + len) as u64;
        }
        let elapsed = start.elapsed();

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

        assert!(
            elapsed < Duration::from_millis(500),
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

        let (client_transport, mut server_transport) = handshake_pair();
        let (write_half, mut read_half) = tokio::io::duplex(8 * 1024 * 1024);
        let shutdown = CancellationToken::new();
        let pacing_rate = Arc::new(AtomicU64::new(LOW_RATE));
        let paced = Arc::new(AtomicBool::new(false));
        let (sink, _handle) = spawn_frame_writer(
            Arc::new(Mutex::new(client_transport)),
            Box::new(write_half),
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

        // Read + decrypt every frame in wire order.
        let mut frames = Vec::with_capacity(N_DATA + 1);
        for _ in 0..(N_DATA + 1) {
            let mut len_buf = [0u8; 2];
            read_half.read_exact(&mut len_buf).await.unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut blob = vec![0u8; len];
            read_half.read_exact(&mut blob).await.unwrap();
            frames.push(
                server_transport
                    .decrypt(&blob)
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
        let (write_half, _read_half) = tokio::io::duplex(64 * 1024);
        let shutdown = CancellationToken::new();
        let pacing_rate = Arc::new(AtomicU64::new(PACING_DEFAULT_RATE));
        let paced = Arc::new(AtomicBool::new(false));
        let (sink, handle) = spawn_frame_writer(
            Arc::new(Mutex::new(client_transport)),
            Box::new(write_half),
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
}
