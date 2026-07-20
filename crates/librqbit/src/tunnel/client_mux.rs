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
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use super::client::TunnelClient;
use super::crypto::NoiseTransport;
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

const PER_CONN_QUEUE: usize = 128;

type TcpRoutes = Arc<Mutex<HashMap<u64, mpsc::Sender<InboundTcp>>>>;
type UdpRoutes = Arc<Mutex<HashMap<u64, mpsc::Sender<InboundUdp>>>>;

/// Multiplexer over a connected tunnel client.
pub(crate) struct ClientMux {
    sink: FrameSink,
    tcp: TcpRoutes,
    udp: UdpRoutes,
    next_stream_id: AtomicU64,
    next_assoc_id: AtomicU64,
    shutdown: CancellationToken,
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
        });

        tokio::spawn(reader_loop(transport, reader, tcp, udp, shutdown));

        mux
    }

    // ── TCP ──────────────────────────────────────────────────────────────

    /// Allocate a stream, register its inbound route, and send `OpenTcp`.
    pub(crate) async fn open_tcp(
        &self,
        destination: TunnelDestination,
    ) -> Option<(u64, mpsc::Receiver<InboundTcp>)> {
        let stream_id = self.next_stream_id.fetch_add(2, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(PER_CONN_QUEUE);
        self.tcp.lock().await.insert(stream_id, tx);

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
            Some((stream_id, rx))
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

    pub(crate) async fn fin_tcp(&self, stream_id: u64) -> bool {
        self.sink.send(TunnelFrame::TcpFin { stream_id }).await
    }

    pub(crate) async fn unregister_tcp(&self, stream_id: u64) {
        self.tcp.lock().await.remove(&stream_id);
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
            Some((assoc_id, rx))
        } else {
            self.udp.lock().await.remove(&assoc_id);
            None
        }
    }

    pub(crate) async fn send_udp_datagram(
        &self,
        association_id: u64,
        destination: TunnelDestination,
        bytes: Bytes,
    ) -> bool {
        self.sink
            .send(TunnelFrame::UdpDatagram {
                association_id,
                destination,
                bytes,
            })
            .await
    }

    pub(crate) async fn close_udp(&self, association_id: u64) {
        self.sink
            .send(TunnelFrame::CloseUdp { association_id })
            .await;
        self.udp.lock().await.remove(&association_id);
    }

    pub(crate) fn is_shutdown(&self) -> bool {
        self.shutdown.is_cancelled()
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
                tcp.lock().await.remove(&stream_id);
            }
            TunnelFrame::UdpDatagram {
                association_id,
                destination,
                bytes,
            } => {
                let tx = udp.lock().await.get(&association_id).cloned();
                if let Some(tx) = tx {
                    let _ = tx.send(InboundUdp::Datagram { destination, bytes }).await;
                }
            }
            // Pong / other server-origin frames need no client action.
            _ => {}
        }
    }

    // Connection gone: dropping every sender makes each handler's `recv()`
    // return `None`, which they treat as a hard reset.
    tcp.lock().await.clear();
    udp.lock().await.clear();
    shutdown.cancel();
}

async fn route_tcp(tcp: &TcpRoutes, stream_id: u64, event: InboundTcp) {
    let tx = tcp.lock().await.get(&stream_id).cloned();
    if let Some(tx) = tx {
        let _ = tx.send(event).await;
    }
}
