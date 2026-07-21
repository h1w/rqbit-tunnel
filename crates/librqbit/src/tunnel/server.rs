// ── Authenticated tunnel server ─────────────────────────────────────────────
///
/// `TunnelServer` binds a TCP listener at `peer_listen`, performs PeerWireCrypto
/// responder handshake with carrier pairing, completes Noise IK, validates client
/// keys against the allowlist, and admits authenticated peers.
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use librqbit_core::Id20;
use peer_binary_protocol::{Message, extended::ExtendedMessage};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use super::carrier::TunnelCarrierStore;
use super::crypto::{self, NoiseTransport, TunnelCryptoError};
use super::frame::{TunnelPrivateKey, TunnelPublicKey};
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

// ── Accept outcome ───────────────────────────────────────────────────────────

/// Result of [`TunnelServer::accept`]'s full pre-auth pipeline.
///
/// Active-probe resistance (Plan B): a peer that never completes a valid
/// allowlisted Noise handshake is never distinguishable from an ordinary
/// BitTorrent peer that connected, exchanged some cover traffic, and left —
/// it is always [`Seeded`](Self::Seeded), never an admission error. Only a
/// valid, allowlisted Noise handshake promotes a connection to
/// [`Admitted`](Self::Admitted).
pub(crate) enum AcceptOutcome {
    /// A valid, allowlisted Noise handshake landed — hand off to the relay.
    /// Boxed: `Seeded` (the common, no-tell outcome for every unauthenticated
    /// probe/BT-churn connection) carries no data, so leaving `AdmittedPeer`
    /// unboxed would size every `AcceptOutcome` — including every `Seeded`
    /// one — to the ~376-byte `Admitted` payload.
    Admitted(Box<AdmittedPeer>),
    /// The peer never authenticated (idle timeout, disconnect, bad/foreign
    /// Noise traffic, or oversized/malformed framing) and was served plain
    /// BitTorrent cover the whole time. Treat exactly like a normal BT peer
    /// that came and went: close the socket, no error, no tell.
    Seeded,
}

// ── Seeder loop (pre-auth active-probe resistance) ──────────────────────────

/// Serve plausible BitTorrent cover to a not-yet-authenticated peer while
/// watching for an `rq_tunnel` Noise handshake, promoting only on a valid,
/// allowlisted key. Never drops the connection on bad input — a censor
/// probing the public rendezvous must not be able to tell "this peer
/// completed a BT handshake and then went silent / got disconnected" apart
/// from ordinary BT peer churn.
///
/// Returns:
///   - `Ok(Some((transport, client_key)))` — a valid allowlisted Noise
///     handshake landed; promote to a tunnel relay.
///   - `Ok(None)` — the peer never authenticated (idle timeout, clean
///     disconnect/read error, or an oversized/malformed `rq_tunnel` frame);
///     treat exactly like a normal BT peer that came and went.
///   - `Err(_)` — a real I/O error writing the Noise reply to an otherwise
///     freshly-authenticated peer. This is the one case genuinely worth
///     surfacing as an admission error (it happens strictly AFTER the peer
///     already proved a valid key, so it reveals nothing to a prober).
async fn seed_until_promoted(
    read_half: &mut super::carrier_wire::CarrierReadHalf,
    write_half: &mut super::carrier_wire::CarrierWriteHalf,
    carrier_peer: &mut super::carrier_peer::TunnelCarrierPeer,
    identity_key: &TunnelPrivateKey,
    allowed: &HashSet<TunnelPublicKey>,
    idle: Duration,
) -> Result<Option<(NoiseTransport, TunnelPublicKey)>, TunnelAdmissionError> {
    let mut defrag = super::carrier_chunk::CarrierDefragmenter::new(
        super::carrier_chunk::MAX_CARRIER_CIPHERTEXT,
    );

    loop {
        let msg = match tokio::time::timeout(idle, read_half.recv_message()).await {
            Err(_elapsed) => return Ok(None), // idle disconnect: normal BT churn, no tell
            Ok(Ok(Some(m))) => m,
            Ok(_) => return Ok(None), // peer closed / read error
        };

        match msg {
            Message::Extended(ExtendedMessage::RqTunnel(rq)) => {
                let blobs = match defrag.push(rq.as_bytes()) {
                    Ok(b) => b,
                    Err(_) => return Ok(None), // oversized: drop like a misbehaving peer
                };
                for ciphertext in blobs {
                    if ciphertext.len() > 512 {
                        // Not a plausible Noise IK initiator message; ignore
                        // and keep seeding rather than tell a prober anything.
                        continue;
                    }
                    match crypto::responder_accept(identity_key, &ciphertext, allowed) {
                        Ok((transport, key, reply)) => {
                            for chunk in super::carrier_chunk::chunk_ciphertext(&reply) {
                                write_half.send_tunnel(&chunk).await.map_err(|e| {
                                    TunnelAdmissionError::CarrierHandshakeFailed(anyhow::anyhow!(
                                        "{e}"
                                    ))
                                })?;
                            }
                            return Ok(Some((transport, key))); // PROMOTE
                        }
                        Err(_) => {
                            // Bad Noise / non-allowlisted key: no reply, no
                            // drop — keep seeding, no tell.
                        }
                    }
                }
            }
            other => {
                // Serve cover exactly like the pre-establish early-cover path.
                match carrier_peer.on_message(other).await {
                    Ok(actions) => {
                        for action in actions {
                            if let super::carrier_peer::CarrierAction::OutgoingMessage(m) = action {
                                // Best-effort: a serialize failure just drops
                                // one cover message, never the connection.
                                let _ = write_half.send_message(&m.to_message()).await;
                            }
                        }
                    }
                    Err(_) => {
                        // Invalid cover request from the peer: ignore, keep seeding.
                    }
                }
            }
        }
    }
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
    ///   2. BT handshake + BEP-10 + cover (masquerade)
    ///   3. Seed BitTorrent cover (Request→Piece) while watching for an
    ///      `rq_tunnel` Noise handshake, promoting only on a valid
    ///      allowlisted key ([`seed_until_promoted`])
    ///
    /// Returns [`AcceptOutcome::Admitted`] on a valid allowlisted Noise
    /// handshake, or [`AcceptOutcome::Seeded`] for everything else (idle
    /// timeout, disconnect, bad/foreign Noise, oversized framing) — the
    /// latter is a normal outcome, not an error: this is the active-probe
    /// resistance (Plan B). The caller should spawn a relay task on
    /// `Admitted` and just close the socket on `Seeded`.
    pub async fn accept(
        &self,
        stream: TcpStream,
        carrier_hash: Id20,
    ) -> Result<AcceptOutcome, TunnelAdmissionError> {
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
        let (mut read_half, mut write_half, mut carrier_peer) = wire.into_halves();

        // ── Step 3: seed cover until a valid allowlisted Noise promotes ─────
        match seed_until_promoted(
            &mut read_half,
            &mut write_half,
            &mut carrier_peer,
            &self.options.identity_key,
            &self.options.allowed_client_keys,
            super::config::SEEDER_IDLE,
        )
        .await?
        {
            Some((transport, client_key)) => {
                self.peers.write().await.insert(client_key.clone(), true);
                Ok(AcceptOutcome::Admitted(Box::new(AdmittedPeer {
                    client_key,
                    transport,
                    read_half,
                    write_half,
                    carrier_peer,
                })))
            }
            None => Ok(AcceptOutcome::Seeded),
        }
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
                                    Ok(AcceptOutcome::Admitted(peer)) => {
                                        let client_key = peer.client_key.clone();
                                        tracing::info!(?client_key, %addr, "tunnel peer admitted");
                                        super::relay::run_server_relay(
                                            *peer,
                                            egress,
                                            peer_shutdown,
                                        )
                                        .await;
                                        server.remove_peer(&client_key).await;
                                    }
                                    Ok(AcceptOutcome::Seeded) => {
                                        // Never authenticated: served plain BT
                                        // cover, then went idle/disconnected.
                                        // A normal BT churn event — the whole
                                        // point of active-probe resistance is
                                        // that this is NOT an error, and looks
                                        // identical to a real peer leaving.
                                        tracing::debug!(%addr, "tunnel peer seeded (never authenticated), closing");
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

    // ── Seeder loop: cover + promote-only-on-valid-Noise (Plan B, Task 1) ────
    //
    // These drive `seed_until_promoted` directly over a real in-process
    // `tokio::io::duplex` carrier connection (real MSE + BT/BEP10 establish,
    // exactly like production), rather than a scripted fake — the same
    // pattern `tests/tunnel.rs::build_real_relay_pair` uses for the
    // post-promotion relay.

    #[tokio::test]
    async fn seed_until_promoted_keeps_seeding_after_invalid_noise_no_drop_tell() {
        use super::super::carrier_chunk::chunk_ciphertext;
        use super::super::carrier_wire::CarrierWire;
        use peer_binary_protocol::{Message, Request};

        let identity_key = server_key();
        let (_dir, store) = test_carrier_store(&identity_key).await;
        let info_hash = store.descriptor().handshake_info_hash;
        let carrier_hash = Id20::new([0xCD; 20]);
        let allowed = allowed_client_keys(&[known_key()]);

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server_store = store.clone();

        let server_task = tokio::spawn(async move {
            let enc = PeerWireCrypto::responder(server_io, carrier_hash)
                .await
                .expect("server MSE responder");
            let wire = CarrierWire::establish(enc.reader, enc.writer, server_store, info_hash)
                .await
                .expect("server carrier establish");
            let (mut read_half, mut write_half, mut carrier_peer) = wire.into_halves();
            seed_until_promoted(
                &mut read_half,
                &mut write_half,
                &mut carrier_peer,
                &identity_key,
                &allowed,
                std::time::Duration::from_millis(500),
            )
            .await
        });

        let enc = PeerWireCrypto::initiator(client_io, carrier_hash)
            .await
            .expect("client MSE initiator");
        let wire = CarrierWire::establish(enc.reader, enc.writer, store.clone(), info_hash)
            .await
            .expect("client carrier establish");
        let (mut read_half, mut write_half, _client_carrier_peer) = wire.into_halves();

        // A plain BT Request must be served with a Piece while the server
        // waits for the client's Noise handshake — the first removed tell
        // (previously cover Requests were ignored during this wait).
        write_half
            .send_message(&Message::Request(Request::new(0, 0, 16384)))
            .await
            .expect("send Request");
        let got_piece = loop {
            match read_half.recv_message().await.expect("recv") {
                Some(Message::Piece(_)) => break true,
                Some(_) => continue,
                None => break false,
            }
        };
        assert!(got_piece, "expected a Piece cover response to Request");

        // An invalid (garbage) rq_tunnel payload — not a real Noise IK
        // initiator message — must NOT drop the connection. The second
        // removed tell (previously bad Noise dropped the connection).
        let garbage = vec![0x42u8; 64];
        for chunk in chunk_ciphertext(&garbage) {
            write_half.send_tunnel(&chunk).await.expect("send garbage");
        }

        // The server must still be seeding: another Request still gets a Piece.
        write_half
            .send_message(&Message::Request(Request::new(0, 0, 16384)))
            .await
            .expect("send second Request");
        let still_seeding = loop {
            match read_half.recv_message().await.expect("recv") {
                Some(Message::Piece(_)) => break true,
                Some(_) => continue,
                None => break false,
            }
        };
        assert!(
            still_seeding,
            "server must keep seeding cover after invalid Noise payload (no drop tell)"
        );

        // Now the client disconnects; the server must treat this as ordinary
        // BT churn (Seeded), not surface an admission error.
        drop(read_half);
        drop(write_half);

        let outcome = server_task
            .await
            .expect("server task join")
            .expect("seed_until_promoted must not error");
        assert!(
            outcome.is_none(),
            "expected no promotion after client disconnect, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn seed_until_promoted_promotes_on_valid_allowlisted_noise() {
        use super::super::carrier_chunk::{
            CarrierDefragmenter, MAX_CARRIER_CIPHERTEXT, chunk_ciphertext, recv_one_ciphertext,
        };
        use super::super::carrier_wire::CarrierWire;

        let identity_key = server_key();
        let server_pub = crypto::public_key(&identity_key);
        let (client_sk, client_pk) = crypto::generate_keypair();
        let (_dir, store) = test_carrier_store(&identity_key).await;
        let info_hash = store.descriptor().handshake_info_hash;
        let carrier_hash = Id20::new([0xCE; 20]);
        let allowed = allowed_client_keys(std::slice::from_ref(&client_pk));

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server_store = store.clone();

        let server_task = tokio::spawn(async move {
            let enc = PeerWireCrypto::responder(server_io, carrier_hash)
                .await
                .expect("server MSE responder");
            let wire = CarrierWire::establish(enc.reader, enc.writer, server_store, info_hash)
                .await
                .expect("server carrier establish");
            let (mut read_half, mut write_half, mut carrier_peer) = wire.into_halves();
            seed_until_promoted(
                &mut read_half,
                &mut write_half,
                &mut carrier_peer,
                &identity_key,
                &allowed,
                std::time::Duration::from_secs(5),
            )
            .await
        });

        let enc = PeerWireCrypto::initiator(client_io, carrier_hash)
            .await
            .expect("client MSE initiator");
        let wire = CarrierWire::establish(enc.reader, enc.writer, store.clone(), info_hash)
            .await
            .expect("client carrier establish");
        let (mut read_half, mut write_half, _client_carrier_peer) = wire.into_halves();

        let (handshake, noise_msg) =
            crypto::initiator_start(&client_sk, &server_pub).expect("initiator_start");
        for chunk in chunk_ciphertext(&noise_msg) {
            write_half
                .send_tunnel(&chunk)
                .await
                .expect("send noise init");
        }

        let mut defrag = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
        let reply = recv_one_ciphertext(&mut read_half, &mut defrag)
            .await
            .expect("noise reply");
        let _client_transport =
            crypto::initiator_complete(handshake, &reply).expect("initiator_complete");

        let outcome = server_task
            .await
            .expect("server task join")
            .expect("seed_until_promoted must not error");
        match outcome {
            Some((_transport, key)) => assert_eq!(key, client_pk, "promoted client key mismatch"),
            None => panic!("expected promotion for a valid allowlisted Noise handshake"),
        }
    }
}
