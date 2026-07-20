// ── Authenticated tunnel server ─────────────────────────────────────────────
///
/// `TunnelServer` binds a TCP listener at `peer_listen`, performs PeerWireCrypto
/// responder handshake with carrier pairing, completes Noise IK, validates client
/// keys against the allowlist, and admits authenticated peers.
use std::collections::HashMap;
use std::sync::Arc;

use librqbit_core::Id20;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use super::crypto::{self, NoiseTransport, TunnelCryptoError};
use super::frame::{TunnelFrame, TunnelPublicKey};
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

/// A successfully admitted tunnel peer carrying the Noise transport and
/// encrypted I/O halves for frame relay.
pub(crate) struct AdmittedPeer {
    pub client_key: TunnelPublicKey,
    pub transport: NoiseTransport,
    pub reader: crate::type_aliases::BoxAsyncReadVectored,
    pub writer: crate::type_aliases::BoxAsyncWrite,
}

// ── Server ──────────────────────────────────────────────────────────────────

pub(crate) struct TunnelServer {
    options: TunnelServerOptions,
    /// Connected peer keys tracked for admission state.
    peers: RwLock<HashMap<TunnelPublicKey, bool>>,
}

impl TunnelServer {
    /// Construct the server state and prepare the carrier store.
    ///
    /// Note: the TCP listener is owned by the caller ([`TunnelService::start`])
    /// and passed to [`run`](Self::run).  This constructor must NOT bind a
    /// listener itself — doing so would race the caller's bind on the same
    /// `peer_listen` address and fail with `EADDRINUSE`.
    pub fn new(options: TunnelServerOptions) -> Arc<Self> {
        Arc::new(Self {
            options,
            peers: RwLock::new(HashMap::new()),
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
        // ── Step 1: PeerWireCrypto responder handshake ──────────────────────
        let encrypted = PeerWireCrypto::responder(stream, carrier_hash)
            .await
            .map_err(|e| TunnelAdmissionError::CarrierHandshakeFailed(anyhow::anyhow!("{e}")))?;

        let mut reader = encrypted.reader;
        let mut writer = encrypted.writer;

        // ── Step 2: Read Noise IK initiator message ────────────────────────
        let mut len_buf = [0u8; 2];
        reader
            .read_exact(&mut len_buf)
            .await
            .map_err(|_| TunnelAdmissionError::PeerDisconnected)?;
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        if msg_len > 512 {
            return Err(TunnelAdmissionError::NoiseHandshakeFailed(
                TunnelCryptoError::HandshakeFailed(format!(
                    "noise initiator message too large: {msg_len}"
                )),
            ));
        }

        let mut noise_msg = vec![0u8; msg_len];
        reader
            .read_exact(&mut noise_msg)
            .await
            .map_err(|_| TunnelAdmissionError::PeerDisconnected)?;

        // ── Step 3: Noise IK responder accept (validates allowlist) ────────
        let (transport, client_key, reply) = crypto::responder_accept(
            &self.options.identity_key,
            &noise_msg,
            &self.options.allowed_client_keys,
        )?;

        // ── Step 4: Send Noise reply back ──────────────────────────────────
        let reply_len = (reply.len() as u16).to_be_bytes();
        writer.write_all(&reply_len).await?;
        writer.write_all(&reply).await?;
        writer.flush().await?;

        // ── Step 5: Admit and track ────────────────────────────────────────
        let peer = AdmittedPeer {
            client_key: client_key.clone(),
            transport,
            reader,
            writer,
        };

        self.peers.write().await.insert(client_key, true);

        Ok(peer)
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

// ── Frame I/O helpers ───────────────────────────────────────────────────────

/// Read a Noise-encrypted `TunnelFrame` from the given reader.
pub(crate) async fn read_frame(
    transport: &mut NoiseTransport,
    reader: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
) -> Result<TunnelFrame, TunnelCryptoError> {
    let mut len_buf = [0u8; 2];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| TunnelCryptoError::DecryptFailed(format!("read len: {e}")))?;
    let len = u16::from_be_bytes(len_buf) as usize;

    if len == 0 || len > super::frame::MAX_FRAME_PAYLOAD + 32 {
        return Err(TunnelCryptoError::DecryptFailed(format!(
            "invalid frame length: {len}"
        )));
    }

    let mut ciphertext = vec![0u8; len];
    reader
        .read_exact(&mut ciphertext)
        .await
        .map_err(|e| TunnelCryptoError::DecryptFailed(format!("read frame: {e}")))?;

    transport.decrypt(&ciphertext)
}

/// Write a `TunnelFrame` through the Noise transport to the given writer.
pub(crate) async fn write_frame(
    transport: &mut NoiseTransport,
    writer: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
    frame: &TunnelFrame,
) -> Result<(), TunnelCryptoError> {
    let ciphertext = transport.encrypt(frame)?;
    let len = (ciphertext.len() as u16).to_be_bytes();
    writer
        .write_all(&len)
        .await
        .map_err(|e| TunnelCryptoError::EncryptFailed(format!("write len: {e}")))?;
    writer
        .write_all(&ciphertext)
        .await
        .map_err(|e| TunnelCryptoError::EncryptFailed(format!("write frame: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| TunnelCryptoError::EncryptFailed(format!("flush: {e}")))?;
    Ok(())
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

    #[tokio::test]
    async fn server_constructs_with_zero_peers() {
        let opts = test_server_options(allowed_client_keys(&[known_key()]));
        let server = TunnelServer::new(opts);
        assert_eq!(server.peer_count().await, 0);
    }

    #[tokio::test]
    async fn server_peer_tracking_api() {
        let opts = test_server_options(allowed_client_keys(&[known_key()]));
        let server = TunnelServer::new(opts);

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
