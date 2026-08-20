// ── Client-side tunnel multiplexer ──────────────────────────────────────────
//
// A single authenticated `TunnelClient` connection carries many independent
// SOCKS streams and UDP associations. This mux runs ONE reader task that
// demultiplexes inbound frames by stream/association id to per-connection
// channels, and shares ONE writer task (via `FrameSink`) for all outbound
// frames.
//
// This replaces the previous per-connection `Arc<Mutex<TunnelClient>>` design,
// which dead-locked: a connection holding the client lock while blocked in
// `read_frame().await` prevented every other task — including its own sender —
// from ever writing.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use super::carrier_peer::{CoverMessage, TunnelCarrierPeer};
use super::carrier_wire::CarrierReadHalf;
use super::client::TunnelClient;
use super::config::{
    COVER_PEX_INTERVAL, COVER_PEX_PEERS_COUNT, COVER_REQUEST_BLOCK_LEN,
    COVER_REQUEST_BLOCKS_PER_PIECE, COVER_REQUEST_INTERVAL, COVER_REQUEST_PIECE_SPAN, OPEN_WINDOW,
    OUTBOUND_QUEUE, PACING_DEFAULT_RATE, PER_CONN_QUEUE, PING_INTERVAL, PING_NONCE_MAP_CAP,
};
use super::crypto::NoiseTransport;
use super::flow::{
    RttEstimator, SendCredit, WindowController, drive_flow_control, record_ping_sent,
};
use super::frame::{TunnelDestination, TunnelErrorCode, TunnelFrame};
use super::relay::{FrameSink, next_tunnel_frame, spawn_frame_writer};

/// Inbound event routed to a single TCP stream handler.
pub(crate) enum InboundTcp {
    Opened(SocketAddr),
    Data(Bytes),
    Fin,
    Reset(TunnelErrorCode),
}

/// Inbound event routed to a single UDP association handler.
pub(crate) enum InboundUdp {
    Datagram {
        destination: TunnelDestination,
        bytes: Bytes,
    },
}

/// Per-TCP-stream client state.
struct TcpRoute {
    inbound: mpsc::Sender<InboundTcp>,
    /// Credit for the local→tunnel direction, replenished by the server's
    /// `Credit` frames as it drains to the destination.
    send_credit: SendCredit,
}

type TcpRoutes = Arc<Mutex<HashMap<u64, TcpRoute>>>;
type UdpRoutes = Arc<Mutex<HashMap<u64, mpsc::Sender<InboundUdp>>>>;
/// Nonce → send-time for pings we've sent but not yet heard a `Pong` for.
type PingInflight = Arc<StdMutex<HashMap<u64, Instant>>>;

/// Multiplexer over a connected tunnel client.
pub(crate) struct ClientMux {
    sink: FrameSink,
    tcp: TcpRoutes,
    udp: UdpRoutes,
    next_stream_id: AtomicU64,
    next_assoc_id: AtomicU64,
    shutdown: CancellationToken,
    /// Count of currently-registered TCP streams + UDP associations.
    load: Arc<AtomicUsize>,
    /// Per-carrier RTT estimate fed by `Ping`/`Pong` round trips: the control
    /// task sends probes, `reader_loop`'s `Pong` arm records the samples.
    rtt: Arc<StdMutex<RttEstimator>>,
    /// Delay-adaptive in-flight controller. The control task steps it from the
    /// carrier's queuing delay + the writer's `paced` flag, and drives
    /// `pacing_rate` (target / rtt) — which bounds aggregate local→tunnel
    /// in-flight. `open_tcp` opens every stream with a fixed generous
    /// `OPEN_WINDOW`; pacing, not the window, is the in-flight control.
    controller: Arc<StdMutex<WindowController>>,
    /// The writer's "pace-throttled since the last tick" flag. The SAME `Arc` is
    /// handed to `spawn_frame_writer` (which sets it when a pacing sleep occurs)
    /// and the control task (which reads-and-resets it as its `utilized`
    /// signal), so growth only fires when pacing was genuinely the bottleneck.
    paced: Arc<AtomicBool>,
    /// The writer's pacing-rate cell (bytes/s). The SAME `Arc` is handed to
    /// `spawn_frame_writer` (which re-reads it per frame) and the control task
    /// (which drives it to `target / rtt`); kept here for the test accessor.
    pacing_rate: Arc<AtomicU64>,
    /// Test-only: the window (bytes) the most recent `open_tcp` seeded its
    /// `SendCredit` with, so a test can prove the generous fixed `OPEN_WINDOW`
    /// actually reaches `SendCredit::with_window`.
    #[cfg(test)]
    last_open_window: Arc<AtomicUsize>,
}

impl ClientMux {
    /// Split a connected client into shared transport + reader/writer tasks.
    pub(crate) fn new(client: TunnelClient, shutdown: CancellationToken) -> Arc<Self> {
        let (transport, read_half, write_half, carrier_peer) = client.into_carrier();
        let transport = Arc::new(Mutex::new(transport));
        // Cover lane: the reader funnels inbound piece Request→Piece cover here
        // and the writer task drains it (unpaced, below control priority).
        let (cover_tx, cover_rx) = mpsc::channel::<CoverMessage>(OUTBOUND_QUEUE);
        // Ongoing piece cover so the carrier exhibits CONTINUOUS BT
        // Request/Piece traffic for the whole session (Plan C Task 3), not a
        // one-shot startup burst. Cloned here, before `cover_tx` is moved into
        // `reader_loop` below.
        let cover_seed = cover_tx.clone();
        // ONE pacing-rate cell shared by the writer (which re-reads it per
        // frame) and the control task below (which drives it to `target / rtt`).
        // Seeded at the effectively-unlimited default until the first RTT
        // sample lands.
        let pacing_rate = Arc::new(AtomicU64::new(PACING_DEFAULT_RATE));
        // ONE "the writer pace-throttled since the last tick" flag, shared by
        // the writer (which sets it) and the control task (which reads-and-
        // resets it as its `utilized` signal). Same-Arc sharing is what makes
        // the signal live.
        let paced = Arc::new(AtomicBool::new(false));
        let (sink, _writer_handle) = spawn_frame_writer(
            transport.clone(),
            write_half,
            cover_rx,
            shutdown.clone(),
            pacing_rate.clone(),
            paced.clone(),
        );

        let tcp: TcpRoutes = Arc::new(Mutex::new(HashMap::new()));
        let udp: UdpRoutes = Arc::new(Mutex::new(HashMap::new()));
        let load = Arc::new(AtomicUsize::new(0));
        let rtt = Arc::new(StdMutex::new(RttEstimator::new()));
        let controller = Arc::new(StdMutex::new(WindowController::new()));
        let ping_inflight: PingInflight = Arc::new(StdMutex::new(HashMap::new()));

        let mux = Arc::new(Self {
            sink: sink.clone(),
            tcp: tcp.clone(),
            udp: udp.clone(),
            // Client-initiated stream ids are odd (1, 3, 5, …).
            next_stream_id: AtomicU64::new(1),
            next_assoc_id: AtomicU64::new(1),
            shutdown: shutdown.clone(),
            load: load.clone(),
            rtt: rtt.clone(),
            controller: controller.clone(),
            paced: paced.clone(),
            pacing_rate: pacing_rate.clone(),
            #[cfg(test)]
            last_open_window: Arc::new(AtomicUsize::new(0)),
        });

        tokio::spawn(reader_loop(
            transport,
            read_half,
            carrier_peer,
            cover_tx,
            tcp,
            udp,
            load,
            rtt.clone(),
            ping_inflight.clone(),
            sink.clone(),
            shutdown.clone(),
        ));
        let cover_shutdown = shutdown.clone();
        tokio::spawn(ping_and_control_task(
            sink,
            ping_inflight,
            rtt,
            controller,
            paced,
            pacing_rate,
            shutdown,
        ));

        // Ongoing piece-cover cadence so the carrier exhibits CONTINUOUS BT
        // Request/Piece exchange for the whole session — a real downloading peer
        // keeps a steady request pipeline, so a carrier that fired a couple of
        // requests at connect and then went BT-silent would have a tell. The
        // requests reference real pieces of the synthetic carrier torrent; the
        // (authenticated) server answers each with a validated Piece and, being
        // authenticated, never self-chokes on the pre-auth pieces cap.
        tokio::spawn(cover_request_cadence(cover_seed, cover_shutdown));

        mux
    }

    // ── TCP ──────────────────────────────────────────────────────────────

    /// Allocate a stream, register its inbound route, and send `OpenTcp`.
    ///
    /// Returns the stream id, the inbound event receiver, and the send-credit
    /// handle for the local→tunnel direction (the caller `reserve`s from it
    /// before sending data).
    pub(crate) async fn open_tcp(
        &self,
        destination: TunnelDestination,
    ) -> Option<(u64, mpsc::Receiver<InboundTcp>, SendCredit)> {
        let stream_id = self.next_stream_id.fetch_add(2, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(PER_CONN_QUEUE);
        // Open the local→tunnel send window at the fixed generous `OPEN_WINDOW`:
        // a backstop that never binds (aggregate in-flight is bounded by pacing
        // at `target / rtt`, not this window), while the receive queue
        // (`PER_CONN_QUEUE`, sized from OPEN_WINDOW) is guaranteed to hold a full
        // window — so a stalled peer can never head-of-line-block the reader.
        let window = OPEN_WINDOW;
        #[cfg(test)]
        self.last_open_window.store(window, Ordering::Relaxed);
        let send_credit = SendCredit::with_window(window);
        self.tcp.lock().await.insert(
            stream_id,
            TcpRoute {
                inbound: tx,
                send_credit: send_credit.clone(),
            },
        );

        let (host, port) = match destination {
            TunnelDestination::Ip(addr) => (addr.ip().to_string(), addr.port()),
            TunnelDestination::Domain(name, port) => (name, port),
        };
        if self
            .sink
            .send(TunnelFrame::OpenTcp {
                stream_id,
                host,
                port,
            })
            .await
        {
            self.load.fetch_add(1, Ordering::Relaxed);
            Some((stream_id, rx, send_credit))
        } else {
            self.tcp.lock().await.remove(&stream_id);
            None
        }
    }

    pub(crate) async fn send_tcp_data(&self, stream_id: u64, bytes: Bytes) -> bool {
        // The control task's utilization signal is the writer's `paced` flag
        // (set when pacing actually throttles a `TcpData` frame), so there's no
        // per-send counter to maintain here.
        self.sink
            .send(TunnelFrame::TcpData { stream_id, bytes })
            .await
    }

    /// Grant the server `n` bytes of credit for the dest→local direction after
    /// draining that much to the local SOCKS socket.
    pub(crate) async fn grant_credit(&self, stream_id: u64, n: usize) -> bool {
        self.sink
            .send(TunnelFrame::Credit {
                stream_id,
                bytes: n as u32,
            })
            .await
    }

    pub(crate) async fn fin_tcp(&self, stream_id: u64) -> bool {
        self.sink.send(TunnelFrame::TcpFin { stream_id }).await
    }

    pub(crate) async fn unregister_tcp(&self, stream_id: u64) {
        if let Some(route) = self.tcp.lock().await.remove(&stream_id) {
            route.send_credit.close();
            self.load.fetch_sub(1, Ordering::Relaxed);
        }
    }

    // ── UDP ──────────────────────────────────────────────────────────────

    pub(crate) async fn open_udp(&self) -> Option<(u64, mpsc::Receiver<InboundUdp>)> {
        let assoc_id = self.next_assoc_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(PER_CONN_QUEUE);
        self.udp.lock().await.insert(assoc_id, tx);

        if self
            .sink
            .send(TunnelFrame::OpenUdp {
                association_id: assoc_id,
            })
            .await
        {
            self.load.fetch_add(1, Ordering::Relaxed);
            Some((assoc_id, rx))
        } else {
            self.udp.lock().await.remove(&assoc_id);
            None
        }
    }

    /// Best-effort send of an outbound UDP datagram. Drops under congestion
    /// (correct UDP semantics); returns `false` only if the tunnel is gone.
    pub(crate) fn send_udp_datagram(
        &self,
        association_id: u64,
        destination: TunnelDestination,
        bytes: Bytes,
    ) -> bool {
        self.sink.try_send_lossy(TunnelFrame::UdpDatagram {
            association_id,
            destination,
            bytes,
        })
    }

    pub(crate) async fn close_udp(&self, association_id: u64) {
        self.sink
            .send(TunnelFrame::CloseUdp { association_id })
            .await;
        if self.udp.lock().await.remove(&association_id).is_some() {
            self.load.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn is_shutdown(&self) -> bool {
        self.shutdown.is_cancelled()
    }

    /// Number of currently-registered TCP streams + UDP associations.
    pub(crate) fn load(&self) -> usize {
        self.load.load(Ordering::Relaxed)
    }

    /// `(rtt_min, rtt_smooth)` from this carrier's `RttEstimator`. Test-only
    /// accessor proving the `Ping`/`Pong` wiring is actually live.
    #[cfg(test)]
    pub(crate) fn rtt_for_test(&self) -> (Duration, Duration) {
        let est = self.rtt.lock().unwrap();
        (est.rtt_min(), est.rtt_smooth())
    }

    /// Current controller in-flight target (bytes). Test-only accessor proving
    /// the control task actually steps the `WindowController`.
    #[cfg(test)]
    pub(crate) fn controller_target_for_test(&self) -> usize {
        self.controller.lock().unwrap().target()
    }

    /// Current value of the SHARED pacing-rate cell (bytes/s) — the exact cell
    /// `spawn_frame_writer` re-reads per frame. Test-only accessor proving the
    /// control task drove it off `PACING_DEFAULT_RATE` to `target / rtt`.
    #[cfg(test)]
    pub(crate) fn pacing_rate_for_test(&self) -> u64 {
        self.pacing_rate.load(Ordering::Relaxed)
    }

    /// The window (bytes) the most recent `open_tcp` seeded its `SendCredit`
    /// with. Test-only accessor proving the fixed generous `OPEN_WINDOW`
    /// actually reaches `SendCredit::with_window` at the open site.
    #[cfg(test)]
    pub(crate) fn last_open_window_for_test(&self) -> usize {
        self.last_open_window.load(Ordering::Relaxed)
    }
}

/// Periodic RTT probe + per-carrier control loop. Every `PING_INTERVAL`: send a
/// `Ping` carrying a monotonically increasing nonce and remember its send time
/// (so `reader_loop`'s `Pong` arm turns the round trip into an RTT sample),
/// then step the `WindowController` from the freshest sample and drive the
/// writer's pacing rate to `target / rtt` via `drive_flow_control`. Stops on
/// shutdown, or once the sink is gone (peer disconnected).
async fn ping_and_control_task(
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

/// Ongoing cover-request cadence for an active carrier (Plan C Task 3).
///
/// A real leeching BitTorrent peer keeps a steady pipeline of block `Request`s
/// in flight for the whole session. This task makes the masquerade carrier do
/// the same: every `COVER_REQUEST_INTERVAL` it enqueues one small block
/// `Request` for a rotating in-range piece/block, so a passive observer sees
/// CONTINUOUS `Request`/`Piece` exchange rather than a single startup burst
/// (the previous one-shot 2-request seed) followed by BT silence.
///
/// Cheap and strictly best-effort: it `try_send`s on the shared cover lane and
/// DROPS on a full lane (it's cover — never worth blocking real tunnel data or
/// the reader behind it). The rotating index stays below
/// `COVER_REQUEST_PIECE_SPAN`, which every synthetic carrier is guaranteed to
/// have, so a request is always in range without the client needing to know the
/// exact corpus size. Stops on shutdown, or once the cover lane is gone.
async fn cover_request_cadence(cover_tx: mpsc::Sender<CoverMessage>, shutdown: CancellationToken) {
    use peer_binary_protocol::extended::ut_pex::UtPex;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    // A real client that sees a peer advertise `ut_metadata` + `metadata_size`
    // and lacks the metadata fetches it ONCE, up front (BEP-9). Best-effort.
    let _ = cover_tx.try_send(CoverMessage::UtMetadataRequest(0));

    let pex_peers = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 6881),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 51413),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3)), 6000),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)), 49000),
    ];
    let mut pex_interval = tokio::time::interval(COVER_PEX_INTERVAL);
    let mut request_interval = tokio::time::interval(COVER_REQUEST_INTERVAL);
    let mut counter: u32 = 0;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = pex_interval.tick() => {
                let pex = UtPex::from_addrs(
                    pex_peers[..COVER_PEX_PEERS_COUNT.min(pex_peers.len())].iter().copied(),
                    std::iter::empty(),
                );
                match cover_tx.try_send(CoverMessage::UtPex(pex)) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
            _ = request_interval.tick() => {
                let index = counter % COVER_REQUEST_PIECE_SPAN;
                let block = (counter / COVER_REQUEST_PIECE_SPAN) % COVER_REQUEST_BLOCKS_PER_PIECE;
                let begin = block * COVER_REQUEST_BLOCK_LEN;
                match cover_tx.try_send(CoverMessage::Request {
                    index,
                    begin,
                    length: COVER_REQUEST_BLOCK_LEN,
                }) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
                counter = counter.wrapping_add(1);
            }
        }
    }
}

/// Central reader: decrypt inbound frames and route them to the owning handler.
/// Serves inbound piece cover (Request→Piece) via `cover_tx` along the way.
#[allow(clippy::too_many_arguments)]
async fn reader_loop(
    transport: Arc<Mutex<NoiseTransport>>,
    mut read_half: CarrierReadHalf,
    carrier_peer: TunnelCarrierPeer,
    cover_tx: mpsc::Sender<CoverMessage>,
    tcp: TcpRoutes,
    udp: UdpRoutes,
    load: Arc<AtomicUsize>,
    rtt: Arc<StdMutex<RttEstimator>>,
    ping_inflight: PingInflight,
    sink: FrameSink,
    shutdown: CancellationToken,
) {
    // Carrier read state (see `next_tunnel_frame`): the defragmenter reassembles
    // chunked Noise ciphertext, `pending` buffers multiple blobs a single `push`
    // can yield, and `carrier_peer` handles inbound piece cover.
    let mut defrag = super::carrier_chunk::CarrierDefragmenter::new(
        super::carrier_chunk::MAX_CARRIER_CIPHERTEXT,
    );
    let mut pending: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
    let mut carrier_peer = carrier_peer;

    loop {
        let frame = tokio::select! {
            _ = shutdown.cancelled() => break,
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
                    tracing::debug!("tunnel client reader ended");
                    break;
                }
            },
        };

        match frame {
            TunnelFrame::TcpOpened {
                stream_id,
                bind_addr,
            } => route_tcp(&tcp, stream_id, InboundTcp::Opened(bind_addr)).await,
            TunnelFrame::TcpData { stream_id, bytes } => {
                route_tcp(&tcp, stream_id, InboundTcp::Data(bytes)).await
            }
            TunnelFrame::TcpFin { stream_id } => route_tcp(&tcp, stream_id, InboundTcp::Fin).await,
            TunnelFrame::TcpReset { stream_id, code } => {
                route_tcp(&tcp, stream_id, InboundTcp::Reset(code)).await;
                if let Some(route) = tcp.lock().await.remove(&stream_id) {
                    route.send_credit.close();
                    // The route is gone now, so the SOCKS handler's later
                    // `unregister_tcp` will find nothing and no-op — decrement
                    // `load` here or every server-initiated reset (denied
                    // destination, refused connection, timeout) leaks +1.
                    load.fetch_sub(1, Ordering::Relaxed);
                }
            }
            TunnelFrame::Credit { stream_id, bytes } => {
                // The server drained `bytes` of local→tunnel data; replenish
                // our send credit for this stream.
                let map = tcp.lock().await;
                if let Some(route) = map.get(&stream_id) {
                    route.send_credit.grant(bytes as usize);
                }
            }
            TunnelFrame::UdpDatagram {
                association_id,
                destination,
                bytes,
            } => {
                let tx = udp.lock().await.get(&association_id).cloned();
                if let Some(tx) = tx {
                    // Lossy: drop under congestion so a slow UDP consumer never
                    // stalls the shared reader (and thus every TCP stream).
                    let _ = tx.try_send(InboundUdp::Datagram { destination, bytes });
                }
            }
            TunnelFrame::Pong { nonce } => {
                let sent_at = ping_inflight.lock().unwrap().remove(&nonce);
                if let Some(sent_at) = sent_at {
                    rtt.lock().unwrap().record(sent_at.elapsed());
                }
            }
            TunnelFrame::Ping { nonce } => {
                // Reply so the SERVER's own ping task can measure the upload
                // direction (its `Pong` arm mirrors this one).
                sink.send(TunnelFrame::Pong { nonce }).await;
            }
            // Other server-origin frames need no client action.
            _ => {}
        }
    }

    // Connection gone: dropping every sender makes each handler's `recv()`
    // return `None`, which they treat as a hard reset. Close credit pools so
    // any sender blocked on `reserve` also wakes.
    //
    // No `load` decrement here: the mux is shutting down (`shutdown.cancel()`
    // below sets `is_shutdown()`), and the pool ignores load on a shut-down
    // mux, so adjusting the counter on the way out is pointless.
    for (_, route) in tcp.lock().await.drain() {
        route.send_credit.close();
    }
    udp.lock().await.clear();
    shutdown.cancel();
}

async fn route_tcp(tcp: &TcpRoutes, stream_id: u64, event: InboundTcp) {
    let tx = tcp.lock().await.get(&stream_id).map(|r| r.inbound.clone());
    if let Some(tx) = tx {
        let _ = tx.send(event).await;
    }
}
