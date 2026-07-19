// ── Local SOCKS5 ingress for client tunnel mode ──────────────────────────────
///
/// `SocksIngress` binds a loopback TCP listener and accepts SOCKS5 clients.
/// It never resolves DNS — domain destinations are forwarded as-is through
/// the tunnel.  `TCPBind` is rejected with `CommandNotSupported`.
///
/// The ingress uses `fast_socks5::server::Socks5Socket` with `skip_auth`,
/// `dns_resolve: false`, and `execute_command: false`.  Command handling
/// is performed manually by inspecting the socket's parsed state.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use fast_socks5::server::{AcceptAuthentication, Config, DenyAuthentication, Socks5Socket};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

use super::client::{TunnelClient, TunnelClientError};
use super::frame::TunnelDestination;

// ── Result type ─────────────────────────────────────────────────────────────

/// The result of processing a SOCKS5 command.
#[derive(Debug)]
pub(crate) enum SocksCommandResult {
    Tcp {
        stream_id: u64,
    },
    Udp {
        association_id: u64,
        relay_addr: SocketAddr,
    },
}

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub(crate) enum SocksIngressError {
    #[error("SOCKS5 protocol error: {0}")]
    Socks(#[from] fast_socks5::SocksError),

    #[error("tunnel error: {0}")]
    Tunnel(#[from] TunnelClientError),

    #[error("UDP error: {0}")]
    Udp(#[from] std::io::Error),

    #[error("command not supported: {0:?}")]
    CommandNotSupported(Socks5Command),

    #[error("unknown stream id: {0}")]
    UnknownStream(u64),

    #[error("unknown association id: {0}")]
    UnknownAssociation(u64),
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

// ── Convert TargetAddr to TunnelDestination ─────────────────────────────────

fn target_to_destination(addr: &TargetAddr) -> TunnelDestination {
    match addr {
        TargetAddr::Ip(sock) => TunnelDestination::Ip(*sock),
        TargetAddr::Domain(name, port) => TunnelDestination::Domain(name.clone(), *port),
    }
}

// ── SocksIngress ────────────────────────────────────────────────────────────

/// UDP association state: keeps the control TCP stream alive and holds
/// the bound UDP socket.
struct UdpAssociationState {
    udp_socket: Arc<UdpSocket>,
    _control: TcpStream,
}

/// Local SOCKS5 ingress that translates SOCKS5 requests into tunnel frames.
pub(crate) struct SocksIngress {
    listen_addr: SocketAddr,
}

impl SocksIngress {
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self { listen_addr }
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Run the SOCKS5 accept loop.
    ///
    /// `client` is the already-connected [`TunnelClient`], wrapped in
    /// `Arc<Mutex<>>` so every SOCKS5 connection can share it.
    pub async fn run(
        self,
        listener: TcpListener,
        client: Arc<Mutex<TunnelClient>>,
        shutdown: tokio_util::sync::CancellationToken,
    ) {
        let associations: Arc<Mutex<HashMap<u64, UdpAssociationState>>> =
            Arc::new(Mutex::new(HashMap::new()));

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let client = Arc::clone(&client);
                            let associations = Arc::clone(&associations);
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(
                                    stream,
                                    client,
                                    associations,
                                ).await
                                {
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

    /// Handle a single SOCKS5 client connection.
    async fn handle_connection(
        stream: TcpStream,
        client: Arc<Mutex<TunnelClient>>,
        associations: Arc<Mutex<HashMap<u64, UdpAssociationState>>>,
    ) -> Result<(), SocksIngressError> {
        let mut cfg: Config<DenyAuthentication> = Config::default();
        cfg.set_request_timeout(30);
        cfg.set_skip_auth(true);
        cfg.set_dns_resolve(false);
        cfg.set_execute_command(false);
        cfg.set_udp_support(true);
        cfg.set_allow_no_auth(true);
        let cfg: fast_socks5::server::Config<AcceptAuthentication> =
            std::clone::Clone::clone(&cfg).with_authentication(AcceptAuthentication::default());
        let config = Arc::new(cfg);

        let socket = Socks5Socket::new(stream, config);
        let socket = socket.upgrade_to_socks5().await?;

        // Extract what we need before consuming the socket.
        // We can't clone Socks5Command; instead we match by reference.
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

            let stream_id = {
                let mut c = client.lock().await;
                c.open_tcp(destination).await?
            };

            let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
            inner.write_all(&reply_success(bind_addr)).await?;
            inner.flush().await?;

            return pipe_tcp(inner, stream_id, Arc::clone(&client)).await;
        }

        if is_udp_associate {
            let udp_socket = UdpSocket::bind("127.0.0.1:0").await?;
            let local_addr = udp_socket.local_addr()?;

            let assoc_id = {
                let mut c = client.lock().await;
                c.open_udp().await?
            };

            inner.write_all(&reply_success(local_addr)).await?;
            inner.flush().await?;

            let mut assocs = associations.lock().await;
            assocs.insert(
                assoc_id,
                UdpAssociationState {
                    udp_socket: Arc::new(udp_socket),
                    _control: inner,
                },
            );
            return Ok(());
        }

        if is_tcp_bind {
            inner.write_all(&reply_command_not_supported()).await?;
            return Ok(());
        }

        inner.write_all(&reply_general_failure()).await?;
        Ok(())
    }
}

// ── TCP pipe ────────────────────────────────────────────────────────────────

/// Bidirectional pipe between a local TCP stream and a tunnel stream.
async fn pipe_tcp(
    local: TcpStream,
    stream_id: u64,
    client: Arc<Mutex<TunnelClient>>,
) -> Result<(), SocksIngressError> {
    let (mut local_read, mut local_write) = tokio::io::split(local);

    // Task: read from SOCKS5 local stream → tunnel
    let send_client = Arc::clone(&client);
    let send_id = stream_id;
    let send_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    // EOF → send FIN
                    let mut c = send_client.lock().await;
                    let _ = c.close_tcp(send_id).await;
                    break;
                }
                Ok(n) => {
                    let mut c = send_client.lock().await;
                    if let Err(e) = c
                        .send_tcp_data(send_id, Bytes::copy_from_slice(&buf[..n]))
                        .await
                    {
                        tracing::debug!(error = %e, stream_id = send_id, "tunnel send error");
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, stream_id = send_id, "local read error");
                    break;
                }
            }
        }
    });

    // Main task: read from tunnel → local write
    loop {
        let frame = {
            let mut c = client.lock().await;
            match c.read_frame().await {
                Ok(f) => f,
                Err(e) => {
                    tracing::debug!(error = %e, stream_id, "tunnel read error");
                    break;
                }
            }
        };

        match frame {
            super::frame::TunnelFrame::TcpData {
                stream_id: sid,
                bytes,
            } if sid == stream_id => {
                if let Err(e) = local_write.write_all(&bytes).await {
                    tracing::debug!(error = %e, stream_id, "local write error");
                    break;
                }
            }
            super::frame::TunnelFrame::TcpFin { stream_id: sid } if sid == stream_id => {
                let _ = local_write.shutdown().await;
                break;
            }
            super::frame::TunnelFrame::TcpReset { stream_id: sid, .. } if sid == stream_id => {
                break;
            }
            _ => {
                // Frames for other streams are ignored — they'll be
                // dispatched by their own pipe tasks.
            }
        }
    }

    send_handle.abort();
    Ok(())
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
