// ── Local SOCKS5 ingress for client tunnel mode ──────────────────────────────
//
// `SocksIngress` binds a loopback TCP listener and accepts SOCKS5 clients.
// It never resolves DNS — domain destinations are forwarded as-is through the
// tunnel (the server resolves).  `TCPBind` is rejected with
// `CommandNotSupported`.
//
// Each SOCKS connection multiplexes over a single shared `ClientMux`, which
// runs the tunnel's reader/writer tasks. Connections never block one another
// on tunnel I/O.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use fast_socks5::server::{AcceptAuthentication, Config, DenyAuthentication, Socks5Socket};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use super::client_mux::{ClientMux, InboundTcp, InboundUdp};
use super::frame::{TunnelDestination, TunnelErrorCode};
use super::socks_udp::{encode_socks_udp_datagram, parse_socks_udp_datagram};

/// How long to wait for the server's `TcpOpened`/`TcpReset` after `OpenTcp`.
const OPEN_TIMEOUT: Duration = Duration::from_secs(30);

/// Buffer size for reading the local SOCKS TCP stream.
const LOCAL_READ_BUF: usize = 16 * 1024;

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub(crate) enum SocksIngressError {
    #[error("SOCKS5 protocol error: {0}")]
    Socks(#[from] fast_socks5::SocksError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ── SOCKS5 reply helpers ────────────────────────────────────────────────────

fn socks_reply(code: u8, bind_addr: SocketAddr) -> Vec<u8> {
    let (atyp, ip_oct, port) = match bind_addr {
        SocketAddr::V4(sock) => (
            0x01u8,
            sock.ip().octets().to_vec(),
            sock.port().to_be_bytes().to_vec(),
        ),
        SocketAddr::V6(sock) => (
            0x04u8,
            sock.ip().octets().to_vec(),
            sock.port().to_be_bytes().to_vec(),
        ),
    };
    let mut reply = vec![0x05, code, 0x00, atyp];
    reply.extend_from_slice(&ip_oct);
    reply.extend_from_slice(&port);
    reply
}

fn reply_success(bind_addr: SocketAddr) -> Vec<u8> {
    socks_reply(0x00, bind_addr)
}

fn reply_command_not_supported() -> Vec<u8> {
    socks_reply(0x07, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
}

fn reply_general_failure() -> Vec<u8> {
    socks_reply(0x01, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
}

/// Map a tunnel error code to the closest SOCKS5 reply code.
fn reply_for_code(code: TunnelErrorCode) -> Vec<u8> {
    let rep = match code {
        TunnelErrorCode::DestinationDenied => 0x02, // connection not allowed by ruleset
        TunnelErrorCode::HostUnreachable => 0x04,   // host unreachable
        TunnelErrorCode::ConnectionRefused => 0x05, // connection refused
        TunnelErrorCode::TimedOut => 0x06,          // TTL expired
        _ => 0x01,                                  // general failure
    };
    socks_reply(rep, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
}

// ── Convert TargetAddr to TunnelDestination ─────────────────────────────────

fn target_to_destination(addr: &TargetAddr) -> TunnelDestination {
    match addr {
        TargetAddr::Ip(sock) => TunnelDestination::Ip(*sock),
        TargetAddr::Domain(name, port) => TunnelDestination::Domain(name.clone(), *port),
    }
}

// ── SocksIngress ────────────────────────────────────────────────────────────

/// Local SOCKS5 ingress that translates SOCKS5 requests into tunnel frames.
pub(crate) struct SocksIngress {
    listen_addr: SocketAddr,
}

impl SocksIngress {
    pub(crate) fn new(listen_addr: SocketAddr) -> Self {
        Self { listen_addr }
    }

    pub(crate) fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Run the SOCKS5 accept loop against a shared tunnel mux.
    pub(crate) async fn run(
        self,
        listener: TcpListener,
        mux: Arc<ClientMux>,
        shutdown: CancellationToken,
    ) {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            if mux.is_shutdown() {
                                tracing::debug!("tunnel gone; refusing SOCKS connection");
                                continue;
                            }
                            let mux = Arc::clone(&mux);
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, mux).await {
                                    tracing::debug!(
                                        client_addr = %addr, error = %e,
                                        "SOCKS5 connection closed"
                                    );
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "SOCKS5 accept error");
                        }
                    }
                }
                _ = shutdown.cancelled() => {
                    tracing::info!("SOCKS5 ingress shutting down");
                    break;
                }
            }
        }
    }
}

/// Handle a single SOCKS5 client connection.
async fn handle_connection(
    stream: TcpStream,
    mux: Arc<ClientMux>,
) -> Result<(), SocksIngressError> {
    let mut cfg: Config<DenyAuthentication> = Config::default();
    cfg.set_request_timeout(30);
    // Must perform the SOCKS5 method-negotiation handshake: real clients (curl,
    // browsers) send `VER NMETHODS METHODS` and block for the `VER METHOD`
    // reply. Skipping it desynchronizes the byte stream ("Unknown SOCKS5 mode").
    cfg.set_skip_auth(false);
    cfg.set_dns_resolve(false);
    cfg.set_execute_command(false);
    cfg.set_udp_support(true);
    cfg.set_allow_no_auth(true);
    let cfg: fast_socks5::server::Config<AcceptAuthentication> =
        std::clone::Clone::clone(&cfg).with_authentication(AcceptAuthentication::default());
    let config = Arc::new(cfg);

    let socket = Socks5Socket::new(stream, config);
    let socket = socket.upgrade_to_socks5().await?;

    let target = socket.target_addr().cloned();
    let is_udp_associate = matches!(socket.cmd(), Some(Socks5Command::UDPAssociate));
    let is_tcp_connect = matches!(socket.cmd(), Some(Socks5Command::TCPConnect));
    let is_tcp_bind = matches!(socket.cmd(), Some(Socks5Command::TCPBind));

    let mut inner = socket.into_inner();

    if is_tcp_connect {
        let target = target.ok_or_else(|| {
            SocksIngressError::Socks(fast_socks5::SocksError::ReplyError(
                ReplyError::GeneralFailure,
            ))
        })?;
        let destination = target_to_destination(&target);

        let (stream_id, mut inbound) = match mux.open_tcp(destination).await {
            Some(pair) => pair,
            None => {
                inner.write_all(&reply_general_failure()).await?;
                return Ok(());
            }
        };

        // Wait for the server's admission verdict for this stream.
        match tokio::time::timeout(OPEN_TIMEOUT, inbound.recv()).await {
            Ok(Some(InboundTcp::Opened(_bind))) => {
                let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
                inner.write_all(&reply_success(bind_addr)).await?;
                inner.flush().await?;
                pump_tcp(inner, mux, stream_id, inbound).await;
                Ok(())
            }
            Ok(Some(InboundTcp::Reset(code))) => {
                inner.write_all(&reply_for_code(code)).await?;
                mux.unregister_tcp(stream_id).await;
                Ok(())
            }
            Ok(Some(_)) | Ok(None) => {
                inner.write_all(&reply_general_failure()).await?;
                mux.unregister_tcp(stream_id).await;
                Ok(())
            }
            Err(_) => {
                inner
                    .write_all(&reply_for_code(TunnelErrorCode::TimedOut))
                    .await?;
                mux.unregister_tcp(stream_id).await;
                Ok(())
            }
        }
    } else if is_udp_associate {
        let udp_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let local_addr = udp_socket.local_addr()?;

        let (assoc_id, inbound) = match mux.open_udp().await {
            Some(pair) => pair,
            None => {
                inner.write_all(&reply_general_failure()).await?;
                return Ok(());
            }
        };

        inner.write_all(&reply_success(local_addr)).await?;
        inner.flush().await?;

        handle_udp(inner, udp_socket, mux, assoc_id, inbound).await;
        Ok(())
    } else if is_tcp_bind {
        inner.write_all(&reply_command_not_supported()).await?;
        Ok(())
    } else {
        inner.write_all(&reply_general_failure()).await?;
        Ok(())
    }
}

// ── TCP pump ────────────────────────────────────────────────────────────────

/// Bidirectional pump between a local SOCKS TCP stream and a tunnel stream.
async fn pump_tcp(
    local: TcpStream,
    mux: Arc<ClientMux>,
    stream_id: u64,
    mut inbound: tokio::sync::mpsc::Receiver<InboundTcp>,
) {
    let (mut local_read, mut local_write) = tokio::io::split(local);

    // local → tunnel
    let send_mux = Arc::clone(&mux);
    let send_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; LOCAL_READ_BUF];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    send_mux.fin_tcp(stream_id).await;
                    break;
                }
                Ok(n) => {
                    if !send_mux
                        .send_tcp_data(stream_id, Bytes::copy_from_slice(&buf[..n]))
                        .await
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // tunnel → local
    loop {
        match inbound.recv().await {
            Some(InboundTcp::Data(bytes)) => {
                if local_write.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            Some(InboundTcp::Fin) => {
                let _ = local_write.shutdown().await;
                break;
            }
            Some(InboundTcp::Reset(_)) => break,
            Some(InboundTcp::Opened(_)) => {} // already handled during setup
            None => break,                    // tunnel lost
        }
    }

    send_handle.abort();
    mux.unregister_tcp(stream_id).await;
}

// ── UDP relay ───────────────────────────────────────────────────────────────

/// Relay SOCKS5 UDP datagrams between the local associated socket and the
/// tunnel, until the control TCP connection closes.
async fn handle_udp(
    mut control: TcpStream,
    udp_socket: UdpSocket,
    mux: Arc<ClientMux>,
    assoc_id: u64,
    mut inbound: tokio::sync::mpsc::Receiver<InboundUdp>,
) {
    let udp_socket = Arc::new(udp_socket);
    // Learned from the first local datagram; needed to address replies.
    let client_addr: Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    // local → tunnel
    let l2t_sock = Arc::clone(&udp_socket);
    let l2t_addr = Arc::clone(&client_addr);
    let l2t_mux = Arc::clone(&mux);
    let l2t = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let (n, src) = match l2t_sock.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => break,
            };
            *l2t_addr.lock().await = Some(src);
            match parse_socks_udp_datagram(&buf[..n]) {
                Ok((destination, payload)) => {
                    if !l2t_mux
                        .send_udp_datagram(assoc_id, destination, Bytes::copy_from_slice(payload))
                        .await
                    {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "dropping malformed SOCKS UDP datagram");
                }
            }
        }
    });

    // tunnel → local
    let t2l_sock = Arc::clone(&udp_socket);
    let t2l_addr = Arc::clone(&client_addr);
    let t2l = tokio::spawn(async move {
        while let Some(InboundUdp::Datagram { destination, bytes }) = inbound.recv().await {
            let addr = *t2l_addr.lock().await;
            if let Some(addr) = addr {
                let mut out = Vec::with_capacity(bytes.len() + 22);
                encode_socks_udp_datagram(&destination, &bytes, &mut out);
                let _ = t2l_sock.send_to(&out, addr).await;
            }
        }
    });

    // The association lives as long as the control TCP connection. A read of
    // 0 bytes (EOF) or any error means the client closed it.
    let mut probe = [0u8; 1];
    let _ = control.read(&mut probe).await;

    l2t.abort();
    t2l.abort();
    mux.close_udp(assoc_id).await;
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_success_ipv4_format() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080);
        let reply = reply_success(addr);
        assert_eq!(reply[0], 0x05); // VER
        assert_eq!(reply[1], 0x00); // REP = succeeded
        assert_eq!(reply[2], 0x00); // RSV
        assert_eq!(reply[3], 0x01); // ATYP = IPv4
        assert_eq!(&reply[4..8], &[127, 0, 0, 1]); // BND.ADDR
        assert_eq!(&reply[8..10], &1080u16.to_be_bytes()); // BND.PORT
    }

    #[test]
    fn reply_command_not_supported_has_correct_code() {
        let reply = reply_command_not_supported();
        assert_eq!(reply[1], 0x07);
    }

    #[test]
    fn reply_for_code_maps_error_codes() {
        assert_eq!(reply_for_code(TunnelErrorCode::DestinationDenied)[1], 0x02);
        assert_eq!(reply_for_code(TunnelErrorCode::HostUnreachable)[1], 0x04);
        assert_eq!(reply_for_code(TunnelErrorCode::ConnectionRefused)[1], 0x05);
        assert_eq!(reply_for_code(TunnelErrorCode::TimedOut)[1], 0x06);
        assert_eq!(reply_for_code(TunnelErrorCode::ProtocolViolation)[1], 0x01);
    }

    #[test]
    fn target_to_destination_preserves_domain() {
        let addr = TargetAddr::Domain("example.org".into(), 443);
        let dest = target_to_destination(&addr);
        assert_eq!(dest, TunnelDestination::Domain("example.org".into(), 443));
    }

    #[test]
    fn target_to_destination_preserves_ipv4() {
        let addr = TargetAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8080,
        ));
        let dest = target_to_destination(&addr);
        assert_eq!(
            dest,
            TunnelDestination::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                8080
            ))
        );
    }
}
