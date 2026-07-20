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
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::type_aliases::BoxAsyncWrite;

use super::config::{
    CONNECT_TIMEOUT, OUTBOUND_QUEUE, PER_STREAM_QUEUE, PING_INTERVAL, PING_NONCE_MAP_CAP,
    READ_CHUNK, UDP_READ_BUF,
};
use super::crypto::{NoiseTransport, TunnelCryptoError};
use super::egress::{EgressPolicy, EgressTransport};
use super::flow::{IdleGuard, RttEstimator, SendCredit, record_ping_sent};
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
#[derive(Clone)]
pub(crate) struct FrameSink {
    tx: mpsc::Sender<TunnelFrame>,
}

impl FrameSink {
    /// Enqueue a frame for encryption+write. Returns `false` if the writer task
    /// has stopped (peer gone).
    pub(crate) async fn send(&self, frame: TunnelFrame) -> bool {
        self.tx.send(frame).await.is_ok()
    }

    /// Best-effort enqueue for lossy traffic (UDP datagrams). Drops the frame
    /// if the shared outbound queue is full instead of blocking the caller —
    /// which would head-of-line-block every other stream on this connection.
    /// Returns `false` only if the peer connection is gone.
    pub(crate) fn try_send_lossy(&self, frame: TunnelFrame) -> bool {
        use mpsc::error::TrySendError;
        match self.tx.try_send(frame) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => true, // dropped; connection still alive
            Err(TrySendError::Closed(_)) => false,
        }
    }
}

/// Spawn the single writer task. It owns the write half and the shared
/// transport, encrypting each queued frame and writing it in order.
pub(crate) fn spawn_frame_writer(
    transport: Arc<Mutex<NoiseTransport>>,
    mut writer: BoxAsyncWrite,
    shutdown: CancellationToken,
) -> (FrameSink, JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<TunnelFrame>(OUTBOUND_QUEUE);
    let handle = tokio::spawn(async move {
        loop {
            let frame = tokio::select! {
                _ = shutdown.cancelled() => break,
                f = rx.recv() => match f {
                    Some(f) => f,
                    None => break,
                },
            };
            let blob = {
                let mut t = transport.lock().await;
                match t.encrypt(&frame) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::debug!(error = %e, "tunnel writer encrypt failed");
                        break;
                    }
                }
            };
            let len = (blob.len() as u16).to_be_bytes();
            if writer.write_all(&len).await.is_err()
                || writer.write_all(&blob).await.is_err()
                || writer.flush().await.is_err()
            {
                break;
            }
        }
    });
    (FrameSink { tx }, handle)
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
    let (sink, writer_handle) = spawn_frame_writer(transport.clone(), writer, shutdown.clone());

    let tcp: TcpMap = Arc::new(Mutex::new(HashMap::new()));
    let udp: UdpMap = Arc::new(Mutex::new(HashMap::new()));

    // Per-carrier RTT measurement (§flow::RttEstimator): our own ping task
    // probes the download direction; the `Ping` arm below answers the
    // client's pings so it can measure the upload direction. Feeds the later
    // adaptive-window controller.
    let rtt = Arc::new(StdMutex::new(RttEstimator::new()));
    let ping_inflight: PingInflight = Arc::new(StdMutex::new(HashMap::new()));
    tokio::spawn(server_ping_task(
        sink.clone(),
        ping_inflight.clone(),
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
                let send_credit = SendCredit::new();
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

/// Mirrors the client mux's `ping_task`: probe RTT on the download direction
/// (from the server's perspective) with our own periodic `Ping`s. The
/// `Ping` arm in `run_server_relay` already answers the client's pings, which
/// is how the client measures the upload direction.
///
/// Stops on shutdown, or once the sink is gone — which happens shortly after
/// `run_server_relay` aborts the writer task on peer disconnect, since that
/// closes the channel `sink.send` writes to.
async fn server_ping_task(sink: FrameSink, inflight: PingInflight, shutdown: CancellationToken) {
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
