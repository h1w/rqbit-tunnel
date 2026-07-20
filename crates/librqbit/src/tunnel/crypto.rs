// ── Noise IK transport for tunnel frames ────────────────────────────────────
//
// Uses `Noise_IK_25519_ChaChaPoly_SHA256`:
//   - Initiator pins the server's static public key.
//   - Responder inspects the remote static public key after handshake and
//     rejects keys absent from the allowlist.
//   - Sequence numbers are included in the authenticated plaintext and
//     validated on receipt (monotonically increasing, no duplicates or gaps).

use std::collections::HashSet;

use super::frame::{FrameError, TunnelFrame, TunnelPrivateKey, TunnelPublicKey};

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum TunnelCryptoError {
    #[error("client static key not in server allowlist: {0:?}")]
    ClientNotAllowed(TunnelPublicKey),

    #[error("noise handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("decryption failed: {0}")]
    DecryptFailed(String),

    #[error("encryption failed: {0}")]
    EncryptFailed(String),

    #[error("frame encoding error: {0:?}")]
    FrameEncode(#[from] FrameError),

    #[error("invalid sequence number: expected {expected}, got {got}")]
    SequenceNumberMismatch { expected: u64, got: u64 },

    #[error("message too large: {0}")]
    MessageTooLarge(usize),
}

// ── Transport state (post-handshake) ────────────────────────────────────────

/// The Noise transport state after a successful IK handshake.
#[derive(Debug)]
pub(crate) struct NoiseTransport {
    noise: snow::TransportState,
    /// Next inbound frame sequence number we expect to see.
    recv_seq: u64,
    /// Next outbound frame sequence number we will assign.
    send_seq: u64,
}

// ── Opaque initiator handshake state ────────────────────────────────────────

/// Opaque wrapper around the in-progress Noise IK handshake.
/// Created by `initiator_start()` and consumed by `initiator_complete()`.
pub(crate) struct InitiatorHandshake {
    state: snow::HandshakeState,
}

impl std::fmt::Debug for InitiatorHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitiatorHandshake").finish()
    }
}

// ── Sequence number constants ───────────────────────────────────────────────

/// Maximum frame plaintext (for frame + 8-byte sequence number).
const MAX_PLAINTEXT: usize = super::frame::MAX_FRAME_PAYLOAD + 16;
/// Maximum Noise ciphertext for a MAX_PLAINTEXT-sized message (with 16-byte auth tag).
const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 16;

// ── Noise params helper ─────────────────────────────────────────────────────

fn noise_params() -> snow::params::NoiseParams {
    "Noise_IK_25519_ChaChaPoly_SHA256"
        .parse()
        .expect("Noise_IK_25519_ChaChaPoly_SHA256 is a valid Noise protocol name")
}

// ── Initiator (two-phase) ───────────────────────────────────────────────────

/// Phase 1: Build the initiator and produce the first handshake message.
///
/// Returns the opaque `InitiatorHandshake` state and the bytes to send to the
/// responder. After receiving the responder's reply, call `initiator_complete()`
/// with the state and the reply bytes.
pub fn initiator_start(
    local_key: &TunnelPrivateKey,
    server_pubkey: &TunnelPublicKey,
) -> Result<(InitiatorHandshake, Vec<u8>), TunnelCryptoError> {
    let params = noise_params();

    let builder = snow::Builder::new(params).local_private_key(&local_key.0);

    let mut initiator = builder
        .remote_public_key(&server_pubkey.0)
        .build_initiator()
        .map_err(|e| TunnelCryptoError::HandshakeFailed(format!("initiator build: {e}")))?;

    let mut msg_buf = [0u8; 256];
    let len = initiator
        .write_message(&[], &mut msg_buf)
        .map_err(|e| TunnelCryptoError::HandshakeFailed(format!("initiator write: {e}")))?;

    Ok((
        InitiatorHandshake { state: initiator },
        msg_buf[..len].to_vec(),
    ))
}

/// Phase 2: Complete the initiator side by processing the responder's reply.
///
/// Consumes `InitiatorHandshake` and returns a ready-to-use `NoiseTransport`.
pub fn initiator_complete(
    handshake: InitiatorHandshake,
    server_reply: &[u8],
) -> Result<NoiseTransport, TunnelCryptoError> {
    let mut initiator = handshake.state;

    let mut read_buf = [0u8; 256];
    initiator
        .read_message(server_reply, &mut read_buf)
        .map_err(|e| TunnelCryptoError::HandshakeFailed(format!("initiator read: {e}")))?;

    let noise = initiator
        .into_transport_mode()
        .map_err(|e| TunnelCryptoError::HandshakeFailed(format!("initiator transport: {e}")))?;

    Ok(NoiseTransport {
        noise,
        recv_seq: 0,
        send_seq: 0,
    })
}

// ── Responder (single-phase) ────────────────────────────────────────────────

/// Accept an incoming Noise IK handshake as the responder.
///
/// Processes the initiator's first message, inspects the remote static public
/// key, rejects if absent from `allowed_clients`, and returns a ready-to-use
/// `NoiseTransport`, the remote public key, and the reply bytes to send back.
pub fn responder_accept(
    local_key: &TunnelPrivateKey,
    msg: &[u8],
    allowed_clients: &HashSet<TunnelPublicKey>,
) -> Result<(NoiseTransport, TunnelPublicKey, Vec<u8>), TunnelCryptoError> {
    let params = noise_params();

    let builder = snow::Builder::new(params).local_private_key(&local_key.0);

    let mut responder = builder
        .build_responder()
        .map_err(|e| TunnelCryptoError::HandshakeFailed(format!("responder build: {e}")))?;

    // Read the initiator's first message.
    let mut read_buf = [0u8; 256];
    responder
        .read_message(msg, &mut read_buf)
        .map_err(|e| TunnelCryptoError::HandshakeFailed(format!("responder read: {e}")))?;

    // Extract the remote static key (the initiator's public key).
    let remote_static: [u8; 32] = responder
        .get_remote_static()
        .ok_or_else(|| {
            TunnelCryptoError::HandshakeFailed("no remote static key after IK read".into())
        })?
        .try_into()
        .map_err(|_| TunnelCryptoError::HandshakeFailed("remote static key wrong length".into()))?;

    let remote_pub = TunnelPublicKey(remote_static);

    if !allowed_clients.contains(&remote_pub) {
        return Err(TunnelCryptoError::ClientNotAllowed(remote_pub));
    }

    // Write the responder's reply.
    let mut msg_buf = [0u8; 256];
    let len = responder
        .write_message(&[], &mut msg_buf)
        .map_err(|e| TunnelCryptoError::HandshakeFailed(format!("responder write: {e}")))?;

    let noise = responder
        .into_transport_mode()
        .map_err(|e| TunnelCryptoError::HandshakeFailed(format!("responder transport: {e}")))?;

    Ok((
        NoiseTransport {
            noise,
            recv_seq: 0,
            send_seq: 0,
        },
        remote_pub,
        msg_buf[..len].to_vec(),
    ))
}

// ── Noise transport encrypt / decrypt ───────────────────────────────────────

impl NoiseTransport {
    /// Encrypt a `TunnelFrame`, producing opaque ciphertext for one
    /// `RqTunnelMessage`.  The plaintext is `seq || encoded_frame` where
    /// `seq` is a big-endian `u64`.
    pub fn encrypt(&mut self, frame: &TunnelFrame) -> Result<Vec<u8>, TunnelCryptoError> {
        let encoded = frame.encode()?;

        // Build plaintext: 8-byte sequence number + frame bytes.
        let mut plain = Vec::with_capacity(8 + encoded.len());
        plain.extend_from_slice(&self.send_seq.to_be_bytes());
        plain.extend_from_slice(&encoded);

        if plain.len() > MAX_PLAINTEXT {
            return Err(TunnelCryptoError::MessageTooLarge(plain.len()));
        }

        let mut cipher = vec![0u8; plain.len() + 16]; // worst-case expansion
        let len = self
            .noise
            .write_message(&plain, &mut cipher)
            .map_err(|e| TunnelCryptoError::EncryptFailed(e.to_string()))?;

        cipher.truncate(len);
        self.send_seq = self.send_seq.wrapping_add(1);

        Ok(cipher)
    }

    /// Decrypt ciphertext and return the inner `TunnelFrame`.
    /// Validates the sequence number: must match the next expected value.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<TunnelFrame, TunnelCryptoError> {
        if ciphertext.len() > MAX_CIPHERTEXT {
            return Err(TunnelCryptoError::MessageTooLarge(ciphertext.len()));
        }

        let mut plain = vec![0u8; ciphertext.len() + 16]; // worst-case expansion
        let len = self
            .noise
            .read_message(ciphertext, &mut plain)
            .map_err(|e| TunnelCryptoError::DecryptFailed(e.to_string()))?;

        plain.truncate(len);

        if plain.len() < 8 {
            return Err(TunnelCryptoError::DecryptFailed(
                "plaintext too short for sequence number".into(),
            ));
        }

        let seq = u64::from_be_bytes([
            plain[0], plain[1], plain[2], plain[3], plain[4], plain[5], plain[6], plain[7],
        ]);

        if seq != self.recv_seq {
            return Err(TunnelCryptoError::SequenceNumberMismatch {
                expected: self.recv_seq,
                got: seq,
            });
        }

        self.recv_seq = self.recv_seq.wrapping_add(1);

        let frame_bytes = &plain[8..];
        let frame = TunnelFrame::decode(frame_bytes)?;

        Ok(frame)
    }
}

// ── Key generation ──────────────────────────────────────────────────────────

/// Generate a fresh Noise static keypair.
/// Returns `(private_key, public_key)`.
pub fn generate_keypair() -> (TunnelPrivateKey, TunnelPublicKey) {
    let keypair = snow::Builder::new(noise_params())
        .generate_keypair()
        .expect("generate_keypair should not fail for IK 25519");

    let private: [u8; 32] = keypair
        .private
        .try_into()
        .expect("Curve25519 private key is 32 bytes");
    let public: [u8; 32] = keypair
        .public
        .try_into()
        .expect("Curve25519 public key is 32 bytes");
    (TunnelPrivateKey(private), TunnelPublicKey(public))
}

// ── Carrier hash derivation ─────────────────────────────────────────────────

/// Derive the x25519 public key from a private key (Curve25519 base-point
/// multiplication with standard clamping).
pub(crate) fn public_key(private: &TunnelPrivateKey) -> TunnelPublicKey {
    let point = curve25519_dalek::MontgomeryPoint::mul_base_clamped(private.0);
    TunnelPublicKey(point.0)
}

/// Derive a stable, random-looking carrier "info hash" (`Id20`) from the
/// server's public key. Both peers compute it independently — the client from
/// the pinned server key, the server from its own key — so the MSE/PE carrier
/// is keyed by a plausible per-server torrent identity instead of an all-zero
/// hash, with no pairing exchange required.
pub(crate) fn derive_carrier_hash(server_pub: &TunnelPublicKey) -> librqbit_core::Id20 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"rqbit-tunnel-carrier-v1");
    hasher.update(server_pub.0);
    let digest = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    librqbit_core::Id20::new(out)
}

// ── Full handshake convenience (test helper) ────────────────────────────────

/// Complete an authenticated IK handshake (both directions in-process).
#[cfg(test)]
fn complete_handshake(
    client_key: &TunnelPrivateKey,
    server_key: &TunnelPrivateKey,
    server_pub: &TunnelPublicKey,
    allowed_clients: &HashSet<TunnelPublicKey>,
) -> Result<(NoiseTransport, NoiseTransport), TunnelCryptoError> {
    // Step 1: initiator produces first message.
    let (handshake, init_msg) = initiator_start(client_key, server_pub)?;

    // Step 2: responder processes initiator message, checks allowlist, produces reply.
    let (resp_transport, _remote_key, resp_msg) =
        responder_accept(server_key, &init_msg, allowed_clients)?;

    // Step 3: initiator processes reply.
    let init_transport = initiator_complete(handshake, &resp_msg)?;

    Ok((init_transport, resp_transport))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::frame::{TunnelDestination, TunnelErrorCode};
    use super::*;
    use bytes::Bytes;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    /// Linchpin: our `public_key` derivation MUST match the public key snow
    /// produced for the same private key, otherwise the client (deriving the
    /// carrier hash from the pinned server *public* key) and the server
    /// (deriving it from its own *private* key) would disagree and the MSE
    /// handshake would fail.
    #[test]
    fn public_key_matches_generated_keypair() {
        for _ in 0..16 {
            let (priv_key, pub_key) = generate_keypair();
            assert_eq!(
                public_key(&priv_key),
                pub_key,
                "derived public key must equal snow's public key"
            );
        }
    }

    #[test]
    fn carrier_hash_is_stable_and_nonzero() {
        let (_priv, pub_key) = generate_keypair();
        let h1 = derive_carrier_hash(&pub_key);
        let h2 = derive_carrier_hash(&pub_key);
        assert_eq!(h1, h2, "carrier hash must be deterministic");
        assert_ne!(h1.0, [0u8; 20], "carrier hash must not be all zeros");
    }

    // ── Key helpers ─────────────────────────────────────────────────────────

    fn server_keys() -> (TunnelPrivateKey, TunnelPublicKey) {
        use std::sync::OnceLock;
        static KP: OnceLock<(TunnelPrivateKey, TunnelPublicKey)> = OnceLock::new();
        KP.get_or_init(generate_keypair).clone()
    }

    fn client_keys() -> (TunnelPrivateKey, TunnelPublicKey) {
        use std::sync::OnceLock;
        static KP: OnceLock<(TunnelPrivateKey, TunnelPublicKey)> = OnceLock::new();
        KP.get_or_init(generate_keypair).clone()
    }

    fn unknown_client_keys() -> (TunnelPrivateKey, TunnelPublicKey) {
        use std::sync::OnceLock;
        static KP: OnceLock<(TunnelPrivateKey, TunnelPublicKey)> = OnceLock::new();
        KP.get_or_init(generate_keypair).clone()
    }

    fn allowed_clients() -> HashSet<TunnelPublicKey> {
        let mut set = HashSet::new();
        set.insert(client_keys().1.clone());
        set
    }

    fn authenticated_pair() -> (NoiseTransport, NoiseTransport) {
        let (ck, _cp) = client_keys();
        let (sk, sp) = server_keys();
        complete_handshake(&ck, &sk, &sp, &allowed_clients()).expect("handshake should succeed")
    }

    // ── Step 1 tests ────────────────────────────────────────────────────────

    #[test]
    fn rejects_a_client_not_in_the_server_allowlist() {
        let (uk, _up) = unknown_client_keys();
        let (sk, sp) = server_keys();
        let result = complete_handshake(&uk, &sk, &sp, &allowed_clients());
        assert!(
            matches!(result, Err(TunnelCryptoError::ClientNotAllowed(_))),
            "expected ClientNotAllowed, got {result:?}"
        );
    }

    #[test]
    fn encrypted_frame_round_trips_without_exposing_destination() {
        let (mut client, mut server) = authenticated_pair();
        let ciphertext = client
            .encrypt(&TunnelFrame::OpenTcp {
                stream_id: 1,
                host: "example.test".into(),
                port: 443,
            })
            .unwrap();

        // Destination MUST NOT appear in ciphertext.
        assert!(
            !ciphertext
                .windows(b"example.test".len())
                .any(|w| w == b"example.test"),
            "destination leaked into ciphertext"
        );

        let frame = server.decrypt(&ciphertext).unwrap();
        assert!(
            matches!(&frame, TunnelFrame::OpenTcp { stream_id: 1, .. }),
            "expected OpenTcp with stream_id=1, got {frame:?}"
        );
        if let TunnelFrame::OpenTcp { host, port, .. } = &frame {
            assert_eq!(host, "example.test");
            assert_eq!(*port, 443);
        }
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let (mut client, mut server) = authenticated_pair();
        let mut ciphertext = client.encrypt(&TunnelFrame::Ping { nonce: 1 }).unwrap();

        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0x01;
        }

        let result = server.decrypt(&ciphertext);
        assert!(
            matches!(result, Err(TunnelCryptoError::DecryptFailed(_))),
            "expected DecryptFailed, got {result:?}"
        );
    }

    #[test]
    fn rejects_replayed_ciphertext() {
        let (mut client, mut server) = authenticated_pair();

        let ct = client.encrypt(&TunnelFrame::Ping { nonce: 1 }).unwrap();

        server.decrypt(&ct).unwrap();

        let result = server.decrypt(&ct);
        // AEAD nonce reuse may cause DecryptFailed before we reach the
        // sequence-number check; either error is acceptable.
        assert!(
            matches!(
                result,
                Err(TunnelCryptoError::SequenceNumberMismatch { .. })
                    | Err(TunnelCryptoError::DecryptFailed(_))
            ),
            "expected SequenceNumberMismatch or DecryptFailed, got {result:?}"
        );
    }

    #[test]
    fn rejects_replayed_ciphertext_initiator_side() {
        let (mut client, mut server) = authenticated_pair();

        let ct = server.encrypt(&TunnelFrame::Pong { nonce: 1 }).unwrap();

        client.decrypt(&ct).unwrap();

        let result = client.decrypt(&ct);
        // AEAD nonce reuse may cause DecryptFailed before we reach the
        // sequence-number check; either error is acceptable.
        assert!(
            matches!(
                result,
                Err(TunnelCryptoError::SequenceNumberMismatch { .. })
                    | Err(TunnelCryptoError::DecryptFailed(_))
            ),
            "expected SequenceNumberMismatch or DecryptFailed, got {result:?}"
        );
    }

    #[test]
    fn rejects_oversized_plaintext() {
        let (mut client, _server) = authenticated_pair();

        // Frame payload is capped at u16::MAX (65535), and the ClientHello
        // payload is encoded directly.  Choose a size that passes the frame
        // encoder but exceeds the overall plaintext limit.
        let big = vec![0x42u8; MAX_PLAINTEXT - 8]; // -8 for sequence number
        let result = client.encrypt(&TunnelFrame::ClientHello(big));
        assert!(
            matches!(
                result,
                Err(TunnelCryptoError::MessageTooLarge(_)) | Err(TunnelCryptoError::FrameEncode(_))
            ),
            "expected MessageTooLarge or FrameEncode, got {result:?}"
        );
    }

    #[test]
    fn tcp_data_round_trip_encrypted() {
        let (mut client, mut server) = authenticated_pair();

        let ct = client
            .encrypt(&TunnelFrame::TcpData {
                stream_id: 7,
                bytes: Bytes::from_static(b"secret payload"),
            })
            .unwrap();

        let frame = server.decrypt(&ct).unwrap();
        assert_eq!(
            frame,
            TunnelFrame::TcpData {
                stream_id: 7,
                bytes: Bytes::from_static(b"secret payload"),
            }
        );
    }

    #[test]
    fn all_frame_types_encrypt_decrypt() {
        let (mut client, mut server) = authenticated_pair();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1234));

        let frames: Vec<TunnelFrame> = vec![
            TunnelFrame::ClientHello(b"hello".to_vec()),
            TunnelFrame::ServerHello(b"world".to_vec()),
            TunnelFrame::OpenTcp {
                stream_id: 1,
                host: "example.test".into(),
                port: 80,
            },
            TunnelFrame::TcpOpened {
                stream_id: 1,
                bind_addr: addr,
            },
            TunnelFrame::TcpData {
                stream_id: 1,
                bytes: Bytes::from_static(b"data"),
            },
            TunnelFrame::TcpFin { stream_id: 1 },
            TunnelFrame::TcpReset {
                stream_id: 2,
                code: TunnelErrorCode::TimedOut,
            },
            TunnelFrame::OpenUdp { association_id: 3 },
            TunnelFrame::UdpDatagram {
                association_id: 3,
                destination: TunnelDestination::Domain("dns.test".into(), 53),
                bytes: Bytes::from_static(b"query"),
            },
            TunnelFrame::CloseUdp { association_id: 3 },
            TunnelFrame::Credit {
                stream_id: 4,
                bytes: 8192,
            },
            TunnelFrame::Ping { nonce: 42 },
            TunnelFrame::Pong { nonce: 42 },
        ];

        for frame in &frames {
            let ct = client.encrypt(frame).unwrap();
            let dec = server.decrypt(&ct).unwrap();
            assert_eq!(&dec, frame, "mismatch for {frame:?}");
        }
    }

    #[test]
    fn sequence_numbers_increment_correctly() {
        let (mut client, mut server) = authenticated_pair();

        for i in 0u64..10 {
            let ct = client.encrypt(&TunnelFrame::Ping { nonce: i }).unwrap();
            let dec = server.decrypt(&ct).unwrap();
            assert_eq!(dec, TunnelFrame::Ping { nonce: i });
        }
    }

    #[test]
    fn keypair_generation_produces_different_keys() {
        let (a_priv, a_pub) = generate_keypair();
        let (b_priv, b_pub) = generate_keypair();
        assert_ne!(a_priv.0, b_priv.0);
        assert_ne!(a_pub.0, b_pub.0);
    }

    #[test]
    fn generated_keypair_has_correct_lengths() {
        let (private, public) = generate_keypair();
        assert_eq!(private.0.len(), 32);
        assert_eq!(public.0.len(), 32);
    }
}
