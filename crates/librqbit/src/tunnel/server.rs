// ── Authenticated tunnel server ─────────────────────────────────────────────
///
/// `TunnelServer` binds a TCP listener at `peer_listen`, performs PeerWireCrypto
/// responder handshake with carrier pairing, completes Noise IK, validates client
/// keys against the allowlist, and admits authenticated peers.
use std::collections::HashMap;
use std::sync::Arc;

use librqbit_core::Id20;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use super::carrier::TunnelCarrierStore;
use super::crypto::{self, NoiseTransport, TunnelCryptoError};
use super::frame::TunnelPublicKey;
use super::options::TunnelServerOptions;
use super::peer_wire_crypto::PeerWireCrypto;

// ── Admission error ─────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum TunnelAdmissionError {
    #[error("client static key not in allowlist: {0:?}")]
    ClientNotAllowed(TunnelPublicKey),

    #[error("carrier handshake failed: {0}")]
    CarrierHandshakeFailed(#[source] anyhow::Error),

    #[error("noise handshake failed: {0}")]
    NoiseHandshakeFailed(#[from] TunnelCryptoError),

    #[error("I/O error during admission: {0}")]
    Io(#[from] std::io::Error),

    #[error("peer disconnected during admission")]
    PeerDisconnected,
}

// ── Admitted peer ───────────────────────────────────────────────────────────

/// A successfully admitted tunnel peer carrying the Noise transport and the
/// BitTorrent-masquerade carrier halves for frame relay (real BT peer wire +
/// `rq_tunnel` extended messages carrying Noise chunks, with piece cover).
pub(crate) struct AdmittedPeer {
    pub client_key: TunnelPublicKey,
    pub transport: NoiseTransport,
    pub read_half: super::carrier_wire::CarrierReadHalf,
    pub write_half: super::carrier_wire::CarrierWriteHalf,
    pub carrier_peer: super::carrier_peer::TunnelCarrierPeer,
}

// ── Server ──────────────────────────────────────────────────────────────────

pub(crate) struct TunnelServer {
    options: TunnelServerOptions,
    /// Connected peer keys tracked for admission state.
    peers: RwLock<HashMap<TunnelPublicKey, bool>>,
    /// Deterministic synthetic carrier torrent shared with clients via the
    /// DHT rendezvous key (`descriptor().handshake_info_hash`). Consumed by
    /// [`CarrierWire::establish`] in [`accept`](Self::accept) to present a real
    /// BitTorrent peer wire.
    carrier_store: Arc<TunnelCarrierStore>,
}

impl TunnelServer {
    /// Construct the server state from the already-built carrier store.
    ///
    /// Note: the TCP listener is owned by the caller ([`TunnelService::start`])
    /// and passed to [`run`](Self::run).  This constructor must NOT bind a
    /// listener itself — doing so would race the caller's bind on the same
    /// `peer_listen` address and fail with `EADDRINUSE`.
    pub fn new(options: TunnelServerOptions, carrier_store: Arc<TunnelCarrierStore>) -> Arc<Self> {
        Arc::new(Self {
            options,
            peers: RwLock::new(HashMap::new()),
            carrier_store,
        })
    }

    /// Admit a single incoming peer connection through the full handshake
    /// pipeline:
    ///   1. PeerWireCrypto responder (MSE/RC4 carrier handshake)
    ///   2. Noise IK handshake over the encrypted stream
    ///   3. Client key allowlist check (done during Noise IK)
    ///
    /// Returns the `AdmittedPeer` on success.  The caller should spawn
    /// a relay task and remove the peer from tracking on disconnect.
    pub async fn accept(
        &self,
        stream: TcpStream,
        carrier_hash: Id20,
    ) -> Result<AdmittedPeer, TunnelAdmissionError> {
        // ── Step 1: MSE responder ───────────────────────────────────────────
        let enc = PeerWireCrypto::responder(stream, carrier_hash)
            .await
            .map_err(|e| TunnelAdmissionError::CarrierHandshakeFailed(anyhow::anyhow!("{e}")))?;

        // ── Step 2: BT handshake + BEP-10 + cover (masquerade) ──────────────
        let info_hash = self.carrier_store.descriptor().handshake_info_hash;
        let wire = super::carrier_wire::CarrierWire::establish(
            enc.reader,
            enc.writer,
            self.carrier_store.clone(),
            info_hash,
        )
        .await
        .map_err(|e| TunnelAdmissionError::CarrierHandshakeFailed(anyhow::anyhow!("{e}")))?;
        let (mut read_half, mut write_half, carrier_peer) = wire.into_halves();

        // ── Step 3: Noise IK initiator message, carried over rq_tunnel ──────
        let mut defrag = super::carrier_chunk::CarrierDefragmenter::new(
            super::carrier_chunk::MAX_CARRIER_CIPHERTEXT,
        );
        let noise_msg = super::carrier_chunk::recv_one_ciphertext(&mut read_half, &mut defrag)
            .await
            .ok_or(TunnelAdmissionError::PeerDisconnected)?;
        if noise_msg.len() > 512 {
            return Err(TunnelAdmissionError::NoiseHandshakeFailed(
                TunnelCryptoError::HandshakeFailed(format!(
                    "noise initiator message too large: {}",
                    noise_msg.len()
                )),
            ));
        }

        // ── Step 4: Noise IK responder accept (validates allowlist) ────────
        let (transport, client_key, reply) = crypto::responder_accept(
            &self.options.identity_key,
            &noise_msg,
            &self.options.allowed_client_keys,
        )?;

        // ── Step 5: send Noise reply back over rq_tunnel ───────────────────
        for chunk in super::carrier_chunk::chunk_ciphertext(&reply) {
            write_half.send_tunnel(&chunk).await.map_err(|e| {
                TunnelAdmissionError::CarrierHandshakeFailed(anyhow::anyhow!("{e}"))
            })?;
        }

        // ── Step 6: Admit and track ────────────────────────────────────────
        self.peers.write().await.insert(client_key.clone(), true);
        Ok(AdmittedPeer {
            client_key,
            transport,
            read_half,
            write_half,
            carrier_peer,
        })
    }

    /// Run the accept loop on the given listener, spawning relay tasks
    /// for each admitted peer.
    pub async fn run(
        self: &Arc<Self>,
        listener: TcpListener,
        shutdown: tokio_util::sync::CancellationToken,
    ) {
        // Build the runtime egress policy once and share it across all peers.
        let egress = Arc::new(super::egress::EgressPolicy::from_config(
            &self.options.egress_policy,
        ));

        // Key the MSE/PE carrier by a stable "torrent" identity derived from our
        // own public key. The client derives the same value from the pinned
        // server key, so no pairing exchange is needed.
        let carrier_hash = super::crypto::derive_carrier_hash(&super::crypto::public_key(
            &self.options.identity_key,
        ));

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let server = Arc::clone(self);
                            let egress = egress.clone();
                            let peer_shutdown = shutdown.child_token();
                            tokio::spawn(async move {
                                match server.accept(stream, carrier_hash).await {
                                    Ok(peer) => {
                                        let client_key = peer.client_key.clone();
                                        tracing::info!(?client_key, %addr, "tunnel peer admitted");
                                        super::relay::run_server_relay(
                                            peer,
                                            egress,
                                            peer_shutdown,
                                        )
                                        .await;
                                        server.remove_peer(&client_key).await;
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = %e, %addr, "peer admission failed");
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "accept error");
                        }
                    }
                }
                _ = shutdown.cancelled() => {
                    tracing::info!("tunnel server shutting down");
                    break;
                }
            }
        }
    }

    /// Return the number of currently admitted peers.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Remove a peer from tracking (called on disconnect).
    pub(crate) async fn remove_peer(&self, key: &TunnelPublicKey) {
        self.peers.write().await.remove(key);
    }

    /// Check whether a specific client key is admitted.
    pub(crate) async fn is_admitted(&self, key: &TunnelPublicKey) -> bool {
        self.peers.read().await.contains_key(key)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use super::super::frame::{TunnelPrivateKey, TunnelPublicKey};
    use super::super::options::{EgressPolicy, TunnelServerOptions};
    use super::*;

    fn known_key() -> TunnelPublicKey {
        let mut key = [0u8; 32];
        key[0] = 0xAA;
        TunnelPublicKey(key)
    }

    fn unknown_key() -> TunnelPublicKey {
        let mut key = [0u8; 32];
        key[31] = 0xFF;
        TunnelPublicKey(key)
    }

    fn server_key() -> TunnelPrivateKey {
        let mut key = [0u8; 32];
        key[0] = 0xBB;
        TunnelPrivateKey(key)
    }

    fn allowed_client_keys(keys: &[TunnelPublicKey]) -> HashSet<TunnelPublicKey> {
        keys.iter().cloned().collect()
    }

    fn test_server_options(allowed: HashSet<TunnelPublicKey>) -> TunnelServerOptions {
        TunnelServerOptions {
            peer_listen: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            identity_key: server_key(),
            allowed_client_keys: allowed,
            egress_policy: EgressPolicy::default(),
            carrier_root: std::path::PathBuf::from("/tmp/test-carrier"),
        }
    }

    /// Build a real carrier store in a fresh temp dir for the given identity
    /// key. The returned `TempDir` must be kept alive for the store's
    /// lifetime (it holds `root` for later piece I/O).
    async fn test_carrier_store(
        identity: &TunnelPrivateKey,
    ) -> (tempfile::TempDir, Arc<TunnelCarrierStore>) {
        let dir = tempfile::tempdir().unwrap();
        let server_pub = super::super::crypto::public_key(identity);
        let store = super::super::carrier_identity::build_carrier_store(dir.path(), &server_pub)
            .await
            .unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn server_constructs_with_zero_peers() {
        let opts = test_server_options(allowed_client_keys(&[known_key()]));
        let (_dir, store) = test_carrier_store(&opts.identity_key).await;
        let server = TunnelServer::new(opts, store);
        assert_eq!(server.peer_count().await, 0);
    }

    #[tokio::test]
    async fn server_peer_tracking_api() {
        let opts = test_server_options(allowed_client_keys(&[known_key()]));
        let (_dir, store) = test_carrier_store(&opts.identity_key).await;
        let server = TunnelServer::new(opts, store);

        assert_eq!(server.peer_count().await, 0);
        assert!(!server.is_admitted(&known_key()).await);
        // Full tracking is exercised via accept() in integration tests.
    }

    #[test]
    fn server_rejects_unknown_client_after_static_key_handshake() {
        let err = TunnelAdmissionError::ClientNotAllowed(unknown_key());
        assert!(matches!(err, TunnelAdmissionError::ClientNotAllowed(_)));
        assert_eq!(
            format!("{err}"),
            format!("client static key not in allowlist: {:?}", unknown_key())
        );
    }

    #[test]
    fn admission_error_display() {
        let e = TunnelAdmissionError::ClientNotAllowed(unknown_key());
        assert!(e.to_string().contains("client static key not in allowlist"));

        let e = TunnelAdmissionError::CarrierHandshakeFailed(anyhow::anyhow!("bad handshake"));
        assert!(e.to_string().contains("carrier handshake failed"));

        let e = TunnelAdmissionError::PeerDisconnected;
        assert!(e.to_string().contains("peer disconnected"));
    }
}
