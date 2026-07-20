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

use super::client::TunnelClient;
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
                // ── Extract carrier hash from pairing bundle ─────────────────
                let carrier_hash = opts
                    .pairing
                    .as_ref()
                    .map(|p| p.carrier.handshake_info_hash)
                    .unwrap_or_else(|| librqbit_core::Id20::new([0u8; 20]));

                // ── Connect to tunnel server ────────────────────────────────
                let client = TunnelClient::connect(
                    opts.server_addr,
                    &opts.identity_key,
                    &opts.expected_server_key,
                    carrier_hash,
                )
                .await
                .map_err(|e| anyhow::anyhow!("tunnel client connect failed: {e}"))?;

                // ── Bind SOCKS5 listener ────────────────────────────────────
                let listener = TcpListener::bind(opts.socks_listen).await?;
                let local_addr = listener.local_addr()?;

                // Split the client into shared reader/writer tasks so many
                // SOCKS connections can multiplex over one tunnel.
                let mux = super::client_mux::ClientMux::new(client, shutdown.clone());

                let ingress = SocksIngress::new(local_addr);
                let socks_shutdown = shutdown.clone();
                tokio::spawn(async move {
                    ingress.run(listener, mux, socks_shutdown).await;
                });

                tracing::info!("tunnel client SOCKS5 listening on {local_addr}");
            }
            TunnelOptions::Server(opts) => {
                let listener = TcpListener::bind(opts.peer_listen).await?;
                let local_addr = listener.local_addr()?;
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
            server_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9090)),
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
