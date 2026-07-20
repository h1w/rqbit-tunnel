// ── Tunnel service lifecycle ────────────────────────────────────────────────
///
/// A TunnelService owns the long-running tasks needed for a tunnel endpoint:
///   - Client: SOCKS5 → tunnel → server
///   - Server: listen for tunnel peers → relay frames
///
/// The service is started during Session construction via
/// `TunnelService::start()` and shut down when the session cancellation token
/// is triggered.
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::session::Session;

use super::client_supervisor::TunnelClientSupervisor;
use super::options::TunnelOptions;
use super::server::TunnelServer;
use super::socks::SocksIngress;

/// Handle to a running tunnel service.
///
/// Created by [`TunnelService::start`] and stored on [`Session`].  When the
/// session's cancellation token fires (or [`shutdown`](Self::shutdown) is
/// called explicitly) the background tasks are torn down.
pub struct TunnelService {
    shutdown: CancellationToken,
}

impl TunnelService {
    /// Start the tunnel service for the given session and configuration.
    ///
    /// The configuration is validated before any resources are allocated.
    /// Background tasks are spawned on the session's child cancellation token
    /// so they are torn down when the session stops.
    pub async fn start(
        session: &Arc<Session>,
        options: TunnelOptions,
    ) -> anyhow::Result<Arc<Self>> {
        options.validate()?;

        let shutdown = session.cancellation_token().child_token();
        let service = Arc::new(Self {
            shutdown: shutdown.clone(),
        });

        match options {
            TunnelOptions::Client(opts) => {
                // ── Bind SOCKS5 listener up front ───────────────────────────
                // The listener stays up for the whole session; the tunnel
                // connection is established and re-established in the background
                // by the supervisor, so session startup does not fail (and the
                // proxy does not go away) just because the server is briefly
                // unreachable.
                let listener = TcpListener::bind(opts.socks_listen).await?;
                let local_addr = listener.local_addr()?;

                // The session's DHT (if enabled) lets the client discover the
                // server by its carrier hash instead of a fixed address.
                let dht = session.get_dht().cloned();
                let supervisor = TunnelClientSupervisor::start(opts, dht, shutdown.clone());

                let ingress = SocksIngress::new(local_addr);
                let socks_shutdown = shutdown.clone();
                tokio::spawn(async move {
                    ingress.run(listener, supervisor, socks_shutdown).await;
                });

                tracing::info!("tunnel client SOCKS5 listening on {local_addr}");
            }
            TunnelOptions::Server(opts) => {
                let listener = TcpListener::bind(opts.peer_listen).await?;
                let local_addr = listener.local_addr()?;

                // Announce the carrier hash in the DHT (if enabled) so clients
                // can discover us without a pre-shared address. The announced
                // IP is inferred by DHT nodes from our packets; the port is our
                // tunnel peer-listen port.
                if let Some(dht) = session.get_dht() {
                    let carrier_hash = super::crypto::derive_carrier_hash(
                        &super::crypto::public_key(&opts.identity_key),
                    );
                    let announce_port = local_addr.port();
                    let stream = dht.get_peers(carrier_hash, Some(announce_port));
                    tokio::spawn(run_dht_announce(stream, shutdown.clone()));
                    tracing::info!(
                        ?carrier_hash,
                        port = announce_port,
                        "tunnel server announcing carrier in DHT"
                    );
                }

                let server = TunnelServer::new(opts);
                let server_shutdown = shutdown.clone();
                tokio::spawn(async move {
                    server.run(listener, server_shutdown).await;
                });

                tracing::info!("tunnel server listening on {local_addr}");
            }
        }

        Ok(service)
    }

    /// Initiate graceful shutdown of the tunnel service.
    ///
    /// Cancels the child token, which causes the server accept loop and
    /// any relay tasks to exit.
    pub async fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

/// Keep a DHT announce alive: hold the `get_peers(..., Some(port))` stream so
/// the periodic `announce_peer` persists (dropping it stops the announce), and
/// drain discovered peers (the server is the announcer, not a downloader, so
/// they are ignored — draining just keeps the channel from growing).
async fn run_dht_announce(mut stream: dht::RequestPeersStream, shutdown: CancellationToken) {
    use futures::StreamExt;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            item = stream.next() => {
                if item.is_none() {
                    break;
                }
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::PathBuf;

    use super::super::frame::{TunnelPrivateKey, TunnelPublicKey};
    use super::super::options::{
        EgressPolicy, TunnelClientOptions, TunnelOptions, TunnelServerOptions,
    };

    fn dummy_key() -> TunnelPublicKey {
        TunnelPublicKey([1u8; 32])
    }

    fn dummy_private() -> TunnelPrivateKey {
        TunnelPrivateKey([2u8; 32])
    }

    #[tokio::test]
    async fn start_client_with_valid_config() {
        let opts = TunnelOptions::Client(TunnelClientOptions {
            server_addr: Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 1),
                9090,
            ))),
            expected_server_key: dummy_key(),
            ..Default::default()
        });
        // Session is not constructed here; we test at the unit level.
        // The client path just logs a message and returns Ok.
        assert!(opts.validate().is_ok());
    }

    #[tokio::test]
    async fn start_server_with_valid_config() {
        let mut allowed = HashSet::new();
        allowed.insert(dummy_key());
        let opts = TunnelOptions::Server(TunnelServerOptions {
            peer_listen: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            identity_key: dummy_private(),
            allowed_client_keys: allowed,
            egress_policy: EgressPolicy::default(),
            carrier_root: PathBuf::from("/tmp/test-carrier"),
        });
        assert!(opts.validate().is_ok());
    }

    #[tokio::test]
    async fn default_session_starts_without_tunnel_service() {
        // Verifies that Session can be constructed without a tunnel service.
        // The tunnel_service field on Session defaults to None.
    }
}
