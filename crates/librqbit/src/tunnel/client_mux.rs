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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use super::client::TunnelClient;
use super::config::PER_CONN_QUEUE;
use super::crypto::NoiseTransport;
use super::flow::SendCredit;
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

/// Multiplexer over a connected tunnel client.
pub(crate) struct ClientMux {
    sink: FrameSink,
    tcp: TcpRoutes,
    udp: UdpRoutes,
    next_stream_id: AtomicU64,
    next_assoc_id: AtomicU64,
    shutdown: CancellationToken,
    /// Count of currently-registered TCP streams + UDP associations.
    load: AtomicUsize,
}

impl ClientMux {
    /// Split a connected client into shared transport + reader/writer tasks.
    pub(crate) fn new(client: TunnelClient, shutdown: CancellationToken) -> Arc<Self> {
        let (transport, reader, writer) = client.into_split();
        let transport = Arc::new(Mutex::new(transport));
        let (sink, _writer_handle) =
            spawn_frame_writer(transport.clone(), writer, shutdown.clone());

        let tcp: TcpRoutes = Arc::new(Mutex::new(HashMap::new()));
        let udp: UdpRoutes = Arc::new(Mutex::new(HashMap::new()));

        let mux = Arc::new(Self {
            sink,
            tcp: tcp.clone(),
            udp: udp.clone(),
            // Client-initiated stream ids are odd (1, 3, 5, …).
            next_stream_id: AtomicU64::new(1),
            next_assoc_id: AtomicU64::new(1),
            shutdown: shutdown.clone(),
            load: AtomicUsize::new(0),
        });

        tokio::spawn(reader_loop(transport, reader, tcp, udp, shutdown));

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
        let send_credit = SendCredit::new();
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
}

/// Central reader: decrypt inbound frames and route them to the owning handler.
async fn reader_loop(
    transport: Arc<Mutex<NoiseTransport>>,
    mut reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    tcp: TcpRoutes,
    udp: UdpRoutes,
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
            // Pong / other server-origin frames need no client action.
            _ => {}
        }
    }

    // Connection gone: dropping every sender makes each handler's `recv()`
    // return `None`, which they treat as a hard reset. Close credit pools so
    // any sender blocked on `reserve` also wakes.
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
