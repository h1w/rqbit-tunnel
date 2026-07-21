// ── Authenticated tunnel server ─────────────────────────────────────────────
///
/// `TunnelServer` binds a TCP listener at `peer_listen`, performs PeerWireCrypto
/// responder handshake with carrier pairing, completes Noise IK, validates client
/// keys against the allowlist, and admits authenticated peers.
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use peer_binary_protocol::{Message, extended::ExtendedMessage};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Semaphore};

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
///   - `Ok(None)` — the peer never authenticated (idle timeout, overall
///     deadline elapsed, clean disconnect/read error, or an
///     oversized/malformed `rq_tunnel` frame); treat exactly like a normal BT
///     peer that came and went.
///   - `Err(_)` — a real I/O error writing the Noise reply to an otherwise
///     freshly-authenticated peer. This is the one case genuinely worth
///     surfacing as an admission error (it happens strictly AFTER the peer
///     already proved a valid key, so it reveals nothing to a prober).
///
/// `idle` resets on every message (an inactivity timeout); `deadline` does
/// NOT — it bounds the WHOLE seed window regardless of activity, mirroring
/// `carrier_wire::ESTABLISH_DEADLINE`'s reasoning exactly: a peer that streams
/// `Request`s (each driving a 256 KiB disk read + `Piece` write) just fast
/// enough to never go idle could otherwise stay in the pre-auth seed loop
/// indefinitely, driving unbounded disk/CPU/bandwidth use. On `deadline`
/// elapsing this returns `Ok(None)` — an ordinary idle disconnect, not an
/// error, so a censor probing the rendezvous learns nothing from it.
async fn seed_until_promoted(
    read_half: &mut super::carrier_wire::CarrierReadHalf,
    write_half: &mut super::carrier_wire::CarrierWriteHalf,
    carrier_peer: &mut super::carrier_peer::TunnelCarrierPeer,
    identity_key: &TunnelPrivateKey,
    allowed: &HashSet<TunnelPublicKey>,
    idle: Duration,
    deadline: Duration,
) -> Result<Option<(NoiseTransport, TunnelPublicKey)>, TunnelAdmissionError> {
    let seed = async {
        let mut defrag = super::carrier_chunk::CarrierDefragmenter::new(
            super::carrier_chunk::MAX_CARRIER_CIPHERTEXT,
        );
        // Per-connection Noise-attempt counter (Fix C1). Incremented ONLY when a
        // blob is actually handed to `responder_accept` (a fresh snow IK
        // responder + one X25519 DH). Persists across every inbound message for
        // the whole connection, hard-bounding total DH ops at
        // `MAX_NOISE_ATTEMPTS`.
        let mut noise_attempts: usize = 0;

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
                        // Cheap length gate (Fix C1): a real Noise IK initiator
                        // message with an empty payload is a small fixed size (96
                        // bytes for Noise_IK_25519_ChaChaPoly_SHA256). A blob
                        // outside this tight band cannot be one, so skip it
                        // WITHOUT building a snow responder / doing a DH — and
                        // WITHOUT counting it against the attempt cap (it is
                        // cheap-rejected on length alone). Keep seeding, no tell.
                        if ciphertext.len() < super::config::NOISE_INIT_MIN
                            || ciphertext.len() > super::config::NOISE_INIT_MAX
                        {
                            continue;
                        }
                        // Attempt cap (Fix C1): once we have spent
                        // `MAX_NOISE_ATTEMPTS` real `responder_accept` calls on
                        // this connection, stop calling it entirely for the rest
                        // of the connection but KEEP SEEDING — no drop, no tell. A
                        // legitimate client authenticates on its FIRST blob, so
                        // this never rejects a real client.
                        if noise_attempts >= super::config::MAX_NOISE_ATTEMPTS {
                            continue;
                        }
                        noise_attempts += 1;
                        match crypto::responder_accept(identity_key, &ciphertext, allowed) {
                            Ok((transport, key, reply)) => {
                                for chunk in super::carrier_chunk::chunk_ciphertext(&reply) {
                                    write_half.send_tunnel(&chunk).await.map_err(|e| {
                                        TunnelAdmissionError::CarrierHandshakeFailed(
                                            anyhow::anyhow!("{e}"),
                                        )
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
                Message::Piece(_) => {
                    // A seeder that already has the whole torrent needs no
                    // uploads (Fix I1): ignore inbound Piece pre-auth — no
                    // `verify_block` (no 256 KiB alloc, no corpus disk read), no
                    // drop, no tell. Keep seeding.
                }
                other => {
                    // Serve cover exactly like the pre-establish early-cover path.
                    match carrier_peer.on_message(other).await {
                        Ok(actions) => {
                            for action in actions {
                                if let super::carrier_peer::CarrierAction::OutgoingMessage(m) =
                                    action
                                {
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
    };

    match tokio::time::timeout(deadline, seed).await {
        Ok(result) => result,
        Err(_elapsed) => Ok(None), // overall seed-window elapsed: normal idle disconnect, no tell
    }
}

// ── Pre-auth connection admission caps (Plan B, Task 2) ─────────────────────
//
// A real seeder also bounds how many peers it will even keep a TCP connection
// open for concurrently — distinct from `SEEDER_UPLOAD_SLOTS` (how many of
// those admitted connections it actually SERVES `Piece`s to, see `accept`).
// Checked in `run`'s accept loop, before the MSE/BT handshake even starts, so
// an over-cap connection costs nothing beyond the `TcpListener::accept()`
// itself.

/// RAII guard for one admitted pre-auth seeder connection. Decrements the
/// per-IP and global in-flight counts on drop — covering every exit path
/// (promoted, seeded-out/timed-out, admission error, or the spawned task
/// simply ending) with the SAME code path, so a missed decrement can never
/// permanently wedge a cap closed.
struct SeederConnGuard {
    counts: Arc<StdMutex<HashMap<IpAddr, usize>>>,
    total: Arc<AtomicUsize>,
    ip: IpAddr,
}

impl Drop for SeederConnGuard {
    fn drop(&mut self) {
        // Recover from a poisoned lock (matching the admit path) so a prior
        // panic elsewhere can never leak this IP's per-connection count.
        let mut map = match self.counts.lock() {
            Ok(m) => m,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(n) = map.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
        drop(map);
        self.total.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Try to admit one more pre-auth seeder connection from `ip`, enforcing both
/// `MAX_SEEDER_CONNS_PER_IP` and `MAX_SEEDER_CONNS_TOTAL`. `None` means the
/// caller must drop the connection immediately without touching the socket
/// further — completely ordinary behavior for a busy seeder, never a tell.
fn try_admit_seeder_conn(
    counts: &Arc<StdMutex<HashMap<IpAddr, usize>>>,
    total: &Arc<AtomicUsize>,
    ip: IpAddr,
) -> Option<SeederConnGuard> {
    // Reserve the global slot first via a CAS loop: if the per-IP check below
    // then rejects, give it back — but never briefly over-book the global
    // count in the meantime.
    loop {
        let cur = total.load(Ordering::Relaxed);
        if cur >= super::config::MAX_SEEDER_CONNS_TOTAL {
            return None;
        }
        if total
            .compare_exchange(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
    }

    let mut map = match counts.lock() {
        Ok(m) => m,
        Err(poisoned) => poisoned.into_inner(),
    };
    let slot = map.entry(ip).or_insert(0);
    if *slot >= super::config::MAX_SEEDER_CONNS_PER_IP {
        drop(map);
        total.fetch_sub(1, Ordering::Relaxed);
        return None;
    }
    *slot += 1;
    drop(map);

    Some(SeederConnGuard {
        counts: counts.clone(),
        total: total.clone(),
        ip,
    })
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
    /// Bounds how many peers we serve `Piece`s to concurrently (choke/upload
    /// slot semantics — Plan B Task 2). Acquired (non-blocking) in `accept`
    /// right after the carrier handshake; released as soon as `accept`
    /// returns (promoted or not) — see the comment there.
    upload_slots: Arc<Semaphore>,
    /// Per-IP in-flight pre-auth seeder connection counts, for
    /// `MAX_SEEDER_CONNS_PER_IP` (checked in `run`'s accept loop).
    seeder_conns: Arc<StdMutex<HashMap<IpAddr, usize>>>,
    /// Global in-flight pre-auth seeder connection count, for
    /// `MAX_SEEDER_CONNS_TOTAL`.
    seeder_conns_total: Arc<AtomicUsize>,
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
            upload_slots: Arc::new(Semaphore::new(super::config::SEEDER_UPLOAD_SLOTS)),
            seeder_conns: Arc::new(StdMutex::new(HashMap::new())),
            seeder_conns_total: Arc::new(AtomicUsize::new(0)),
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
    pub async fn accept(&self, stream: TcpStream) -> Result<AcceptOutcome, TunnelAdmissionError> {
        // ── Step 1: MSE responder ───────────────────────────────────────────
        //
        // The MSE/PE SKEY is the carrier torrent's public `handshake_info_hash`
        // — exactly the info hash a real BitTorrent peer requesting this torrent
        // would key its MSE handshake by. The client derives the SAME value from
        // its independently-built (deterministic) carrier store, so both ends
        // agree with no exchange. A wall-clock deadline bounds the whole MSE
        // handshake so a peer that sends `Ya` then stalls can't pin this accept
        // task on a blocking `read_exact`; on elapse we drop exactly like any
        // other failed carrier handshake (no tell).
        let info_hash = self.carrier_store.descriptor().handshake_info_hash;
        let enc = match tokio::time::timeout(
            super::config::MSE_HANDSHAKE_DEADLINE,
            PeerWireCrypto::responder(stream, info_hash),
        )
        .await
        {
            Ok(res) => res.map_err(|e| {
                TunnelAdmissionError::CarrierHandshakeFailed(anyhow::anyhow!("{e}"))
            })?,
            Err(_elapsed) => {
                return Err(TunnelAdmissionError::CarrierHandshakeFailed(
                    anyhow::anyhow!("MSE handshake timed out"),
                ));
            }
        };

        // ── Step 2: BT handshake + BEP-10 + cover (masquerade) ──────────────
        let wire = super::carrier_wire::CarrierWire::establish(
            enc.reader,
            enc.writer,
            self.carrier_store.clone(),
            info_hash,
        )
        .await
        .map_err(|e| TunnelAdmissionError::CarrierHandshakeFailed(anyhow::anyhow!("{e}")))?;
        let (mut read_half, mut write_half, mut carrier_peer) = wire.into_halves();

        // ── Step 2.5: upload-slot admission (choke/unchoke, Plan B Task 2) ──
        //
        // `establish()` just unconditionally sent this peer an optimistic
        // `Unchoke` (see `carrier_peer::TunnelCarrierPeer::initial_messages`;
        // unchanged from before this task). A real seeder doesn't actually
        // SERVE everyone it optimistically unchokes: `SEEDER_UPLOAD_SLOTS`
        // bounds how many peers we serve `Piece`s to concurrently, SERVER-WIDE
        // (distinct from the per-connection pieces cap enforced below inside
        // `on_request` — this one caps aggregate concurrency across ALL
        // connections). If no slot is free we immediately re-choke — sending
        // an explicit `Choke` is a completely ordinary "reconsidered the
        // optimistic unchoke" BT pattern — so `on_request` refuses to serve.
        //
        // The permit is held only for the rest of THIS function call (through
        // `seed_until_promoted`): it is dropped as soon as `accept` returns,
        // whether the peer promoted, timed out, or disconnected, freeing the
        // slot immediately. Post-auth cover traffic is two `Request`s total
        // (see `client_mux.rs`) and doesn't need the same pre-auth resource
        // bound reasoning, so the slot needn't be held through the relay.
        let _upload_permit = match self.upload_slots.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                carrier_peer.set_local_choked(true);
                // Best-effort: if the peer already vanished, `seed_until_promoted`
                // observes that on its next read regardless.
                let _ = write_half.send_message(&Message::Choke).await;
                None
            }
        };

        // ── Step 3: seed cover until a valid allowlisted Noise promotes,
        // bounded by the overall (non-resetting) seed-window deadline ───────
        match seed_until_promoted(
            &mut read_half,
            &mut write_half,
            &mut carrier_peer,
            &self.options.identity_key,
            &self.options.allowed_client_keys,
            super::config::SEEDER_IDLE,
            super::config::SEED_WINDOW_DEADLINE,
        )
        .await?
        {
            Some((transport, client_key)) => {
                // Clear any transient pre-auth choke (from losing the optimistic
                // upload-slot race) so the now-authenticated connection serves
                // its post-auth cover Request/Piece traffic normally in the
                // relay — the pre-auth slot bound does not apply post-promotion.
                carrier_peer.set_local_choked(false);
                // Reset the pre-auth pieces-served counter (Fix M1) so the
                // pre-auth cap (`MAX_SEEDER_PIECES_PER_CONN`) never carries into
                // the authenticated relay and self-chokes cover mid-session.
                carrier_peer.reset_pieces_served();
                // Mark the connection authenticated so `on_request` skips the
                // pre-auth pieces self-choke entirely (Plan C Task 3): the
                // ongoing post-auth piece-cover cadence must run for the whole
                // session without ever hitting the cap.
                carrier_peer.set_authenticated(true);
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

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            // Per-IP + global in-flight connection caps: an
                            // over-cap connection is dropped immediately,
                            // before the MSE/BT handshake even starts —
                            // exactly what a busy real seeder does, not a
                            // tell to a censor.
                            let guard = match try_admit_seeder_conn(
                                &self.seeder_conns,
                                &self.seeder_conns_total,
                                addr.ip(),
                            ) {
                                Some(guard) => guard,
                                None => {
                                    tracing::debug!(
                                        %addr,
                                        "seeder connection cap reached; dropping"
                                    );
                                    continue;
                                }
                            };
                            let server = Arc::clone(self);
                            let egress = egress.clone();
                            let peer_shutdown = shutdown.child_token();
                            tokio::spawn(async move {
                                // Held for the task's whole lifetime; its Drop
                                // decrements the per-IP/global counts on every
                                // exit path (promoted, seeded-out, error).
                                let _guard = guard;
                                match server.accept(stream).await {
                                    Ok(AcceptOutcome::Admitted(peer)) => {
                                        // Authenticated (allowlisted): release the
                                        // pre-auth seeder slot BEFORE relaying. The
                                        // per-IP/global caps bound pre-auth probers,
                                        // not trusted long-lived carriers — a legit
                                        // client opens up to MAX_CARRIERS from one IP,
                                        // and circumvention users routinely share a
                                        // CGNAT/VPN egress IP, so counting authenticated
                                        // carriers against the per-IP cap would lock out
                                        // legitimate users.
                                        drop(_guard);
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
    use librqbit_core::Id20;

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

    /// A peer that completes the TCP connect but never sends `Ya` would, without
    /// a bound, pin the accept task on the MSE responder's `read_exact` forever.
    /// `MSE_HANDSHAKE_DEADLINE` bounds the whole handshake: on elapse `accept`
    /// returns `CarrierHandshakeFailed` (the connection is then just dropped —
    /// the same normal MSE rejection as any bad carrier handshake, no tell).
    /// Uses paused virtual time so the real 30 s deadline resolves instantly.
    #[tokio::test(start_paused = true)]
    async fn accept_times_out_on_stalled_mse_peer() {
        let opts = test_server_options(allowed_client_keys(&[known_key()]));
        let (_dir, store) = test_carrier_store(&opts.identity_key).await;
        let server = TunnelServer::new(opts, store);

        let listener = tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().unwrap();

        // Connect but send NOTHING — the MSE responder blocks on `read_exact(Ya)`.
        let _stall = tokio::net::TcpStream::connect(addr)
            .await
            .expect("stall connect");
        let (stream, _) = listener.accept().await.expect("listener accept");

        let accept_task = tokio::spawn(async move { server.accept(stream).await });

        // Let the accept task poll to its blocking read and ARM the MSE deadline
        // timer, then blow past the deadline in virtual time.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        tokio::time::advance(
            super::super::config::MSE_HANDSHAKE_DEADLINE + std::time::Duration::from_secs(1),
        )
        .await;

        let res = accept_task.await.expect("accept task join");
        assert!(
            matches!(res, Err(TunnelAdmissionError::CarrierHandshakeFailed(_))),
            "a stalled MSE peer must hit the handshake deadline (CarrierHandshakeFailed)",
        );
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
                std::time::Duration::from_secs(30),
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

    // ── Pre-auth Noise-attempt bound + size band (Plan B, Fix C1) ────────────

    /// The real Noise IK initiator message (empty payload) must fall inside the
    /// `[NOISE_INIT_MIN, NOISE_INIT_MAX]` band, or the cheap length gate in
    /// `seed_until_promoted` would reject a legitimate client. Also pins the
    /// measured length so a future crypto change that alters it can't silently
    /// drift a real init out of the band.
    #[test]
    fn noise_init_length_falls_within_seed_band() {
        let server_pub = crypto::public_key(&server_key());
        let (client_sk, _client_pk) = crypto::generate_keypair();
        let (_handshake, noise_msg) =
            crypto::initiator_start(&client_sk, &server_pub).expect("initiator_start");
        assert_eq!(
            noise_msg.len(),
            96,
            "Noise_IK_25519_ChaChaPoly_SHA256 init with empty payload must be 96 bytes"
        );
        assert!(
            noise_msg.len() >= super::super::config::NOISE_INIT_MIN
                && noise_msg.len() <= super::super::config::NOISE_INIT_MAX,
            "real Noise init ({} bytes) must fall inside the seed band [{}, {}]",
            noise_msg.len(),
            super::super::config::NOISE_INIT_MIN,
            super::super::config::NOISE_INIT_MAX,
        );
    }

    /// Out-of-band blobs (too short to be a Noise init) are cheap-rejected on
    /// length alone and MUST NOT consume the per-connection attempt cap: after a
    /// flood of them, a valid Noise init sent afterwards still promotes.
    #[tokio::test]
    async fn seed_until_promoted_out_of_band_blobs_do_not_consume_attempt_cap() {
        use super::super::carrier_chunk::{
            CarrierDefragmenter, MAX_CARRIER_CIPHERTEXT, chunk_ciphertext, recv_one_ciphertext,
        };
        use super::super::carrier_wire::CarrierWire;

        let identity_key = server_key();
        let server_pub = crypto::public_key(&identity_key);
        let (client_sk, client_pk) = crypto::generate_keypair();
        let (_dir, store) = test_carrier_store(&identity_key).await;
        let info_hash = store.descriptor().handshake_info_hash;
        let carrier_hash = Id20::new([0xE1; 20]);
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
                std::time::Duration::from_secs(30),
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

        // Flood many blobs just UNDER the band's minimum — well more than
        // MAX_NOISE_ATTEMPTS of them. Each must be skipped without consuming an
        // attempt.
        let short = vec![0x11u8; super::super::config::NOISE_INIT_MIN - 1];
        for _ in 0..(super::super::config::MAX_NOISE_ATTEMPTS * 4) {
            for chunk in chunk_ciphertext(&short) {
                write_half
                    .send_tunnel(&chunk)
                    .await
                    .expect("send short blob");
            }
        }

        // A valid Noise init afterwards must STILL promote (the cap was never
        // touched by the out-of-band flood).
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
        let _ = crypto::initiator_complete(handshake, &reply).expect("initiator_complete");

        let outcome = server_task
            .await
            .expect("server task join")
            .expect("seed_until_promoted must not error");
        match outcome {
            Some((_t, key)) => assert_eq!(key, client_pk, "promoted client key mismatch"),
            None => panic!("a valid init after an out-of-band flood must still promote"),
        }
    }

    /// In-band blobs (plausible size, but garbage) DO consume the attempt cap.
    /// Once `MAX_NOISE_ATTEMPTS` are spent, `responder_accept` is no longer
    /// called for the rest of the connection — even a subsequent VALID init is
    /// ignored — but the server KEEPS SEEDING (no drop, no tell). A legitimate
    /// client is unaffected because it authenticates on its FIRST blob.
    #[tokio::test]
    async fn seed_until_promoted_bounds_in_band_noise_attempts() {
        use super::super::carrier_chunk::chunk_ciphertext;
        use super::super::carrier_wire::CarrierWire;
        use peer_binary_protocol::{Message, Request};

        let identity_key = server_key();
        let server_pub = crypto::public_key(&identity_key);
        let (client_sk, client_pk) = crypto::generate_keypair();
        let (_dir, store) = test_carrier_store(&identity_key).await;
        let info_hash = store.descriptor().handshake_info_hash;
        let carrier_hash = Id20::new([0xE2; 20]);
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
                std::time::Duration::from_secs(30),
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

        // Exhaust the attempt cap with in-band (plausible-size) garbage — more
        // than MAX_NOISE_ATTEMPTS of them.
        let garbage = vec![0x42u8; super::super::config::NOISE_INIT_MIN + 16];
        for _ in 0..(super::super::config::MAX_NOISE_ATTEMPTS + 2) {
            for chunk in chunk_ciphertext(&garbage) {
                write_half
                    .send_tunnel(&chunk)
                    .await
                    .expect("send in-band garbage");
            }
        }

        // Now a VALID init — but the cap is already spent, so responder_accept
        // is never called for it: no promotion.
        let (_handshake, noise_msg) =
            crypto::initiator_start(&client_sk, &server_pub).expect("initiator_start");
        for chunk in chunk_ciphertext(&noise_msg) {
            write_half
                .send_tunnel(&chunk)
                .await
                .expect("send noise init");
        }

        // The server must still be seeding: a plain Request still gets a Piece.
        write_half
            .send_message(&Message::Request(Request::new(0, 0, 16384)))
            .await
            .expect("send Request");
        let still_seeding = loop {
            match read_half.recv_message().await.expect("recv") {
                Some(Message::Piece(_)) => break true,
                Some(_) => continue,
                None => break false,
            }
        };
        assert!(
            still_seeding,
            "server must keep seeding after the Noise-attempt cap is reached"
        );

        // Disconnect: the connection must end as ordinary churn (no promotion).
        drop(read_half);
        drop(write_half);
        let outcome = server_task
            .await
            .expect("server task join")
            .expect("seed_until_promoted must not error");
        assert!(
            outcome.is_none(),
            "a valid init sent AFTER the attempt cap is spent must not promote, got {outcome:?}"
        );
    }

    /// Inbound `Piece` messages pre-auth are ignored (Fix I1): a seeder needs no
    /// uploads, so it does no `verify_block` (no 256 KiB alloc, no corpus disk
    /// read) and — critically — never drops the connection. After a Piece, a
    /// following Request still gets served.
    #[tokio::test]
    async fn seed_until_promoted_ignores_inbound_piece_pre_auth() {
        use super::super::carrier_wire::CarrierWire;
        use peer_binary_protocol::{Message, Piece, Request};

        let identity_key = server_key();
        let (_dir, store) = test_carrier_store(&identity_key).await;
        let info_hash = store.descriptor().handshake_info_hash;
        let carrier_hash = Id20::new([0xE3; 20]);
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

        // Send an unsolicited Piece pre-auth. The server must ignore it (no
        // verify, no drop) rather than treat it as an upload.
        let junk = vec![0x42u8; 64];
        write_half
            .send_message(&Message::Piece(Piece::from_data(0, 0, &junk)))
            .await
            .expect("send Piece");

        // A Request afterwards must still be served — proof the connection was
        // neither dropped nor wedged by the inbound Piece.
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
        assert!(
            got_piece,
            "server must keep seeding after an ignored inbound Piece (no drop, no tell)"
        );

        drop(read_half);
        drop(write_half);
        let outcome = server_task
            .await
            .expect("server task join")
            .expect("seed_until_promoted must not error");
        assert!(outcome.is_none(), "no promotion expected, got {outcome:?}");
    }

    /// A promoted (authenticated) peer must have its PRE-AUTH pieces-served
    /// counter reset to 0 (Fix M1), so the pre-auth cap never carries into the
    /// authenticated relay. Drives the full `accept` path, serving one pre-auth
    /// Piece first, then promoting.
    #[tokio::test]
    async fn accept_resets_pieces_served_on_promotion() {
        use super::super::carrier_chunk::{
            CarrierDefragmenter, MAX_CARRIER_CIPHERTEXT, chunk_ciphertext, recv_one_ciphertext,
        };
        use super::super::carrier_wire::CarrierWire;
        use peer_binary_protocol::{Message, Request};
        use std::net::{Ipv4Addr, SocketAddrV4};

        let identity_key = server_key();
        let server_pub = crypto::public_key(&identity_key);
        let (client_sk, client_pk) = crypto::generate_keypair();
        let (_dir, store) = test_carrier_store(&identity_key).await;
        let info_hash = store.descriptor().handshake_info_hash;
        let opts = test_server_options(allowed_client_keys(std::slice::from_ref(&client_pk)));
        let server = TunnelServer::new(opts, store.clone());

        let listener = tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let listen_addr = listener.local_addr().unwrap();

        let server_clone = server.clone();
        let accept_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("listener accept");
            server_clone.accept(stream).await
        });

        let client_stream = tokio::net::TcpStream::connect(listen_addr)
            .await
            .expect("client connect");
        // MSE is keyed by the carrier's public `handshake_info_hash` — the same
        // value the server derives from its own store — so the client uses it too.
        let enc = PeerWireCrypto::initiator(client_stream, info_hash)
            .await
            .expect("client MSE initiator");
        let wire = CarrierWire::establish(enc.reader, enc.writer, store.clone(), info_hash)
            .await
            .expect("client carrier establish");
        let (mut read_half, mut write_half, _client_peer) = wire.into_halves();

        // Serve at least one pre-auth Piece so pieces_served becomes non-zero
        // on the server before promotion.
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
        assert!(got_piece, "expected a pre-auth Piece cover response");

        // Now promote with a valid allowlisted Noise init.
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
        let _ = crypto::initiator_complete(handshake, &reply).expect("initiator_complete");

        let outcome = accept_task
            .await
            .expect("accept task join")
            .expect("accept must not error");
        match outcome {
            AcceptOutcome::Admitted(peer) => {
                assert_eq!(
                    peer.carrier_peer.pieces_served(),
                    0,
                    "a promoted peer must have its pre-auth pieces-served counter reset to 0"
                );
                assert!(
                    peer.carrier_peer.is_authenticated(),
                    "a promoted peer must be marked authenticated so on_request skips the \
                     pre-auth pieces self-choke"
                );
            }
            AcceptOutcome::Seeded => panic!("a valid allowlisted client must be Admitted"),
        }
    }

    // ── Overall seed-window deadline (Plan B, Task 2) ────────────────────────

    /// THE bug this task closes: `idle` alone resets on every message, so a
    /// peer streaming `Request`s just fast enough to never go idle could stay
    /// in the pre-auth seed loop indefinitely (unbounded disk reads + `Piece`
    /// writes + a fresh snow responder per `rq_tunnel` blob). The overall
    /// `deadline` must cut the loop off REGARDLESS of that activity.
    #[tokio::test]
    async fn seed_until_promoted_overall_deadline_fires_despite_continuous_activity() {
        use super::super::carrier_wire::CarrierWire;
        use peer_binary_protocol::{Message, Request};

        let identity_key = server_key();
        let (_dir, store) = test_carrier_store(&identity_key).await;
        let info_hash = store.descriptor().handshake_info_hash;
        let carrier_hash = Id20::new([0xD1; 20]);
        let allowed = allowed_client_keys(&[known_key()]);

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server_store = store.clone();

        // Idle timeout is generous (10s) so it would never fire on its own;
        // the overall deadline (200ms) must still cut the loop off.
        let server_task = tokio::spawn(async move {
            let enc = PeerWireCrypto::responder(server_io, carrier_hash)
                .await
                .expect("server MSE responder");
            let wire = CarrierWire::establish(enc.reader, enc.writer, server_store, info_hash)
                .await
                .expect("server carrier establish");
            let (mut read_half, mut write_half, mut carrier_peer) = wire.into_halves();
            let start = std::time::Instant::now();
            let result = seed_until_promoted(
                &mut read_half,
                &mut write_half,
                &mut carrier_peer,
                &identity_key,
                &allowed,
                std::time::Duration::from_secs(10),
                std::time::Duration::from_millis(200),
            )
            .await;
            (result, start.elapsed())
        });

        let enc = PeerWireCrypto::initiator(client_io, carrier_hash)
            .await
            .expect("client MSE initiator");
        let wire = CarrierWire::establish(enc.reader, enc.writer, store.clone(), info_hash)
            .await
            .expect("client carrier establish");
        let (mut read_half, mut write_half, _client_carrier_peer) = wire.into_halves();

        // Stream Requests fast enough that the idle timeout (10s) never has a
        // chance to fire, for longer than the overall deadline (200ms).
        let sender = tokio::spawn(async move {
            for _ in 0..40 {
                if write_half
                    .send_message(&Message::Request(Request::new(0, 0, 16384)))
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        });
        // Drain the server's Piece cover so its writer never blocks.
        let drain = tokio::spawn(async move {
            loop {
                match read_half.recv_message().await {
                    Ok(Some(_)) => continue,
                    _ => break,
                }
            }
        });

        let (result, elapsed) = server_task.await.expect("server task join");
        let outcome = result.expect("seed_until_promoted must not error");
        assert!(
            outcome.is_none(),
            "expected no promotion (peer never authenticated), got {outcome:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "overall deadline (200ms) must cut the loop off despite continuous \
             activity keeping the idle timeout (10s) from ever firing; took {elapsed:?}"
        );

        let _ = sender.await;
        drain.abort();
    }

    // ── Upload slots (Plan B, Task 2) ────────────────────────────────────────

    /// With every `SEEDER_UPLOAD_SLOTS` permit already held elsewhere,
    /// `accept` must immediately re-choke a freshly-established peer (the
    /// `Unchoke` `establish` just sent it is reconsidered) — proof the
    /// server-wide upload-slot admission in `accept` actually fires.
    #[tokio::test]
    async fn accept_rechokes_when_upload_slots_exhausted() {
        use super::super::carrier_wire::CarrierWire;
        use peer_binary_protocol::Message;
        use std::net::{Ipv4Addr, SocketAddrV4};

        let identity_key = server_key();
        let (_dir, store) = test_carrier_store(&identity_key).await;
        let info_hash = store.descriptor().handshake_info_hash;
        let opts = test_server_options(allowed_client_keys(&[known_key()]));
        let server = TunnelServer::new(opts, store.clone());

        // Exhaust every upload slot up front, held for the whole test.
        let held_permits: Vec<_> = (0..super::super::config::SEEDER_UPLOAD_SLOTS)
            .map(|_| server.upload_slots.clone().try_acquire_owned().unwrap())
            .collect();

        let listener = tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let listen_addr = listener.local_addr().unwrap();

        let server_clone = server.clone();
        let accept_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("listener accept");
            server_clone.accept(stream).await
        });

        let client_stream = tokio::net::TcpStream::connect(listen_addr)
            .await
            .expect("client connect");
        let enc = PeerWireCrypto::initiator(client_stream, info_hash)
            .await
            .expect("client MSE initiator");
        let wire = CarrierWire::establish(enc.reader, enc.writer, store, info_hash)
            .await
            .expect("client carrier establish");
        let (mut read_half, write_half, _peer) = wire.into_halves();

        // The server's own `establish()` already sent Bitfield/Unchoke/
        // Interested; with every upload slot exhausted, `accept` must follow
        // up with an explicit Choke.
        let mut saw_choke = false;
        for _ in 0..8 {
            match read_half.recv_message().await.expect("recv") {
                Some(Message::Choke) => {
                    saw_choke = true;
                    break;
                }
                Some(_) => continue,
                None => break,
            }
        }
        assert!(
            saw_choke,
            "expected an explicit Choke once upload slots are exhausted"
        );

        drop(read_half);
        drop(write_half);
        let _ = accept_task.await;
        drop(held_permits);
    }

    #[tokio::test]
    async fn promotion_clears_pre_auth_choke_even_with_slots_exhausted() {
        // Regression (Task 2 review): a connection that lost the optimistic
        // upload-slot race is choked pre-auth, but once it promotes with a valid
        // allowlisted Noise handshake it MUST be unchoked so the authenticated
        // relay still serves its post-auth cover traffic.
        use super::super::carrier_chunk::{
            CarrierDefragmenter, MAX_CARRIER_CIPHERTEXT, chunk_ciphertext, recv_one_ciphertext,
        };
        use super::super::carrier_wire::CarrierWire;
        use std::net::{Ipv4Addr, SocketAddrV4};

        let identity_key = server_key();
        let server_pub = crypto::public_key(&identity_key);
        let (client_sk, client_pk) = crypto::generate_keypair();
        let (_dir, store) = test_carrier_store(&identity_key).await;
        let info_hash = store.descriptor().handshake_info_hash;
        let opts = test_server_options(allowed_client_keys(std::slice::from_ref(&client_pk)));
        let server = TunnelServer::new(opts, store.clone());

        // Exhaust every upload slot so `accept` re-chokes this peer pre-auth.
        let held: Vec<_> = (0..super::super::config::SEEDER_UPLOAD_SLOTS)
            .map(|_| server.upload_slots.clone().try_acquire_owned().unwrap())
            .collect();

        let listener = tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let listen_addr = listener.local_addr().unwrap();

        let server_clone = server.clone();
        let accept_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("listener accept");
            server_clone.accept(stream).await
        });

        let client_stream = tokio::net::TcpStream::connect(listen_addr)
            .await
            .expect("client connect");
        let enc = PeerWireCrypto::initiator(client_stream, info_hash)
            .await
            .expect("client MSE initiator");
        let wire = CarrierWire::establish(enc.reader, enc.writer, store.clone(), info_hash)
            .await
            .expect("client carrier establish");
        let (mut read_half, mut write_half, _client_peer) = wire.into_halves();

        // Promote with a valid allowlisted Noise init.
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
        let _ = crypto::initiator_complete(handshake, &reply).expect("initiator_complete");

        let outcome = accept_task
            .await
            .expect("accept task join")
            .expect("accept must not error");
        match outcome {
            AcceptOutcome::Admitted(peer) => assert!(
                !peer.carrier_peer.is_local_choked(),
                "a promoted (authenticated) peer must not stay choked even when \
                 upload slots were exhausted at connect time"
            ),
            AcceptOutcome::Seeded => panic!("a valid allowlisted client must be Admitted"),
        }
        drop(held);
    }

    // ── Pre-auth connection admission caps (Plan B, Task 2) ──────────────────
    //
    // Pure unit tests of the cap-counter logic in isolation (per the task
    // brief: "simpler to test, the cap counter logic in isolation") — no
    // networking, so these are plain `#[test]`s.

    #[test]
    fn seeder_conn_cap_rejects_beyond_per_ip_limit() {
        use std::net::Ipv4Addr;

        let counts: Arc<StdMutex<HashMap<IpAddr, usize>>> = Arc::new(StdMutex::new(HashMap::new()));
        let total = Arc::new(AtomicUsize::new(0));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let mut guards = Vec::new();
        for i in 0..super::super::config::MAX_SEEDER_CONNS_PER_IP {
            let g = try_admit_seeder_conn(&counts, &total, ip)
                .unwrap_or_else(|| panic!("connection {i} within the per-IP cap must be admitted"));
            guards.push(g);
        }

        assert!(
            try_admit_seeder_conn(&counts, &total, ip).is_none(),
            "connection beyond MAX_SEEDER_CONNS_PER_IP must be rejected"
        );

        // A different source IP is unaffected by the first IP's cap.
        let other_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        assert!(
            try_admit_seeder_conn(&counts, &total, other_ip).is_some(),
            "a different source IP must not be capped by the first IP's connections"
        );

        // Dropping a guard (RAII) must free a per-IP slot.
        guards.pop();
        assert!(
            try_admit_seeder_conn(&counts, &total, ip).is_some(),
            "dropping a guard must free a per-IP slot"
        );
    }

    #[test]
    fn seeder_conn_cap_rejects_beyond_global_limit() {
        use std::net::Ipv4Addr;

        let counts: Arc<StdMutex<HashMap<IpAddr, usize>>> = Arc::new(StdMutex::new(HashMap::new()));
        let total = Arc::new(AtomicUsize::new(0));

        // Spread connections across many distinct IPs (each well under its
        // own per-IP cap) so only the GLOBAL cap is exercised.
        let mut guards = Vec::new();
        for i in 0..super::super::config::MAX_SEEDER_CONNS_TOTAL {
            let ip = IpAddr::V4(Ipv4Addr::from(i as u32));
            let g = try_admit_seeder_conn(&counts, &total, ip)
                .unwrap_or_else(|| panic!("connection {i} within the global cap must be admitted"));
            guards.push(g);
        }

        let fresh_ip = IpAddr::V4(Ipv4Addr::from(
            super::super::config::MAX_SEEDER_CONNS_TOTAL as u32,
        ));
        assert!(
            try_admit_seeder_conn(&counts, &total, fresh_ip).is_none(),
            "connection beyond MAX_SEEDER_CONNS_TOTAL must be rejected even from a fresh IP"
        );
        assert_eq!(
            total.load(Ordering::Relaxed),
            super::super::config::MAX_SEEDER_CONNS_TOTAL
        );

        // Dropping a guard (RAII) must free a global slot.
        guards.pop();
        assert!(
            try_admit_seeder_conn(&counts, &total, fresh_ip).is_some(),
            "dropping a guard must free a global slot"
        );
    }
}
