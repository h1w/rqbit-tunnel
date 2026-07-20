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

use super::client::TunnelClient;
use super::config::{
    OPEN_WINDOW, PACING_DEFAULT_RATE, PER_CONN_QUEUE, PING_INTERVAL, PING_NONCE_MAP_CAP,
};
use super::crypto::NoiseTransport;
use super::flow::{
    RttEstimator, SendCredit, WindowController, drive_flow_control, record_ping_sent,
};
use super::frame::{TunnelDestination, TunnelErrorCode, TunnelFrame};
use super::relay::{FrameSink, read_encrypted_frame, spawn_frame_writer};

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
        let (transport, reader, writer) = client.into_split();
        let transport = Arc::new(Mutex::new(transport));
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
            writer,
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
            reader,
            tcp,
            udp,
            load,
            rtt.clone(),
            ping_inflight.clone(),
            sink.clone(),
            shutdown.clone(),
        ));
        tokio::spawn(ping_and_control_task(
            sink,
            ping_inflight,
            rtt,
            controller,
            paced,
            pacing_rate,
            shutdown,
        ));

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

/// Central reader: decrypt inbound frames and route them to the owning handler.
#[allow(clippy::too_many_arguments)]
async fn reader_loop(
    transport: Arc<Mutex<NoiseTransport>>,
    mut reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    tcp: TcpRoutes,
    udp: UdpRoutes,
    load: Arc<AtomicUsize>,
    rtt: Arc<StdMutex<RttEstimator>>,
    ping_inflight: PingInflight,
    sink: FrameSink,
    shutdown: CancellationToken,
) {
    loop {
        let frame = tokio::select! {
            _ = shutdown.cancelled() => break,
            r = read_encrypted_frame(&transport, &mut reader) => match r {
                Ok(f) => f,
                Err(e) => {
                    tracing::debug!(error = %e, "tunnel client reader ended");
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
