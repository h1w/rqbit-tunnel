use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use librqbit_core::Id20;
use num_bigint::BigUint;
use rand::Rng;
use rc4::{Key, KeyInit, Rc4, StreamCipher};
use sha1w::{ISha1, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    type_aliases::{BoxAsyncReadVectored, BoxAsyncWrite},
    vectored_traits::AsyncReadVectoredIntoCompat,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// 768-bit safe prime for MSE Diffie-Hellman (BEP 6, group 2)
const MSE_PRIME: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A63A36210000000000090563",
);

/// DH public key width in bytes (768 bits -> 96 bytes)
const DH_KEY_BYTES: usize = 96;
/// RC4 key length in bytes (20-byte SHA1 output)
const RC4_KEY_LEN: usize = 20;

/// Number of RC4 output bytes to discard after initialization (both directions)
const RC4_DISCARD: usize = 1024;

/// Maximum random padding bytes in handshake messages
const MAX_PADDING: usize = 512;

/// Verification constant length in bytes
const VC_LEN: usize = 8;

/// The verification constant value (all zeros as per MSE spec)
const VC_VALUE: [u8; VC_LEN] = [0u8; VC_LEN];

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub(crate) enum TunnelCryptoError {
    #[error("invalid DH public value")]
    InvalidDhPublic,
    #[error("padding length too large: {0}")]
    PaddingTooLarge(usize),
    #[error("verification constant mismatch")]
    VerificationFailed,
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

pub(crate) enum PeerWireCryptoRole {
    Initiator,
    Responder,
}

pub(crate) struct EncryptedPeerIo {
    pub reader: BoxAsyncReadVectored,
    pub writer: BoxAsyncWrite,
}

pub(crate) struct PeerWireCrypto;

impl PeerWireCrypto {
    pub async fn initiator<S>(
        stream: S,
        carrier_hash: Id20,
    ) -> Result<EncryptedPeerIo, TunnelCryptoError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        do_handshake(stream, carrier_hash, PeerWireCryptoRole::Initiator).await
    }

    pub async fn responder<S>(
        stream: S,
        expected_carrier_hash: Id20,
    ) -> Result<EncryptedPeerIo, TunnelCryptoError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        do_handshake(stream, expected_carrier_hash, PeerWireCryptoRole::Responder).await
    }
}

// ===========================================================================
// DH helpers
// ===========================================================================

fn mse_prime() -> BigUint {
    BigUint::parse_bytes(MSE_PRIME.as_bytes(), 16).expect("MSE prime is valid hex")
}

fn mse_generator() -> BigUint {
    BigUint::from(2u32)
}

/// Generate a DH keypair: (private_key, public_key)
fn generate_dh_keypair() -> (BigUint, BigUint) {
    let p = mse_prime();
    let g = mse_generator();
    let mut rng = rand::rng();
    // Generate 20 random bytes (160 bits) for the private key
    let mut private_bytes = [0u8; 20];
    rng.fill(&mut private_bytes);
    let private = BigUint::from_bytes_be(&private_bytes);
    let public = g.modpow(&private, &p);
    (private, public)
}
/// Pad a biguint to exactly `DH_KEY_BYTES` bytes (big-endian, zero-left-padded).
fn dh_public_to_bytes(value: &BigUint) -> [u8; DH_KEY_BYTES] {
    let raw = value.to_bytes_be();
    let mut buf = [0u8; DH_KEY_BYTES];
    let start = DH_KEY_BYTES.saturating_sub(raw.len());
    buf[start..].copy_from_slice(&raw);
    buf
}

/// Parse a DH public value from exactly 96 big-endian bytes.
fn bytes_to_dh_public(bytes: &[u8; DH_KEY_BYTES]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// Validate that a DH public value is in the valid range [2, P-2].
fn validate_dh_public(value: &BigUint) -> Result<(), TunnelCryptoError> {
    let p = mse_prime();
    let two = BigUint::from(2u32);
    if value < &two || value >= &(p.clone() - two) {
        return Err(TunnelCryptoError::InvalidDhPublic);
    }
    Ok(())
}

/// Compute the DH shared secret S = peer_public^private mod P, returned as
/// a 96-byte big-endian buffer.
fn compute_shared_secret(private: &BigUint, peer_public: &BigUint) -> [u8; DH_KEY_BYTES] {
    let p = mse_prime();
    let s = peer_public.modpow(private, &p);
    dh_public_to_bytes(&s)
}

// ===========================================================================
// SHA1 helpers
// ===========================================================================

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finish()
}

/// Derive directional RC4 keys from the shared secret and carrier hash.
///
/// Returns `(encrypt_key, decrypt_key)` — each 20 bytes.
/// For the initiator: `encrypt_key` encrypts data TO the responder.
/// For the responder: `encrypt_key` encrypts data TO the initiator.
fn derive_rc4_keys(
    shared_secret: &[u8; DH_KEY_BYTES],
    carrier_hash: &Id20,
    is_initiator: bool,
) -> ([u8; RC4_KEY_LEN], [u8; RC4_KEY_LEN]) {
    // SKEY = SHA1(S)
    let skey = sha1(shared_secret);

    // req_seed = SHA1(SKEY || info_hash)
    let mut req_input = Vec::with_capacity(40);
    req_input.extend_from_slice(&skey);
    req_input.extend_from_slice(&carrier_hash.0);
    let req_seed = sha1(&req_input);

    // Directional keys using "keyA" / "keyB" markers
    let (local_marker, remote_marker) = if is_initiator {
        (b"keyB", b"keyA") // Initiator: local=encrypt=keyB, remote=decrypt=keyA
    } else {
        (b"keyA", b"keyB") // Responder:  local=encrypt=keyA, remote=decrypt=keyB
    };

    let mut encrypt_input = req_seed.to_vec();
    encrypt_input.extend_from_slice(local_marker);
    let encrypt_key = sha1(&encrypt_input);

    let mut decrypt_input = req_seed.to_vec();
    decrypt_input.extend_from_slice(remote_marker);
    let decrypt_key = sha1(&decrypt_input);

    (encrypt_key, decrypt_key)
}

// ===========================================================================
// RC4 helpers
// ===========================================================================

type Rc4Cipher = Rc4<rc4::consts::U20>;

fn new_rc4(key: &[u8; RC4_KEY_LEN]) -> Rc4Cipher {
    let k = Key::<rc4::consts::U20>::from_slice(key);
    Rc4::new(k)
}

fn rc4_apply(cipher: &mut Rc4Cipher, data: &mut [u8]) {
    cipher.apply_keystream(data);
}

fn rc4_discard(cipher: &mut Rc4Cipher, n: usize) {
    let mut discard = vec![0u8; n];
    cipher.apply_keystream(&mut discard);
}

// ===========================================================================
// I/O helpers
// ===========================================================================

/// Read exactly `N` bytes or 0-length padding from stream.
async fn read_padding<S>(stream: &mut S, pad_len: usize) -> Result<(), TunnelCryptoError>
where
    S: AsyncRead + Unpin,
{
    if pad_len > MAX_PADDING {
        return Err(TunnelCryptoError::PaddingTooLarge(pad_len));
    }
    if pad_len > 0 {
        let mut discard = vec![0u8; pad_len];
        stream.read_exact(&mut discard).await?;
    }
    Ok(())
}

/// Write padding with a 2-byte big-endian length prefix.
async fn write_padding<S>(stream: &mut S) -> Result<(), TunnelCryptoError>
where
    S: AsyncWrite + Unpin,
{
    let pad_len = rand::rng().random_range(0..=MAX_PADDING);
    let pad_bytes = (pad_len as u16).to_be_bytes();
    stream.write_all(&pad_bytes).await?;
    if pad_len > 0 {
        let padding: Vec<u8> = (0..pad_len).map(|_| rand::rng().random()).collect();
        stream.write_all(&padding).await?;
    }
    Ok(())
}

/// Read a 2-byte big-endian length prefix, then read that many bytes as padding.
async fn read_padding_prefixed<S>(stream: &mut S) -> Result<(), TunnelCryptoError>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let pad_len = u16::from_be_bytes(len_buf) as usize;
    read_padding(stream, pad_len).await
}

// ===========================================================================
// Encrypted I/O wrappers
// ===========================================================================

/// An `AsyncRead` wrapper that decrypts with RC4 on the fly.
struct EncryptedReader<R> {
    inner: R,
    cipher: Rc4Cipher,
}

impl<R: AsyncRead + Unpin> AsyncRead for EncryptedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let inner = Pin::new(&mut self.inner);
        match inner.poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled_mut();
                let new_data = &mut filled[before..];
                rc4_apply(&mut self.cipher, new_data);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

/// An `AsyncWrite` wrapper that encrypts with RC4 on the fly.
struct EncryptedWriter<W> {
    inner: W,
    cipher: Rc4Cipher,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for EncryptedWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut encrypted = buf.to_vec();
        rc4_apply(&mut self.cipher, &mut encrypted);
        Pin::new(&mut self.inner).poll_write(cx, &encrypted)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ===========================================================================
// Handshake
// ===========================================================================

/// Perform the full MSE handshake, returning encrypted reader/writer halves.
async fn do_handshake<S>(
    mut stream: S,
    carrier_hash: Id20,
    role: PeerWireCryptoRole,
) -> Result<EncryptedPeerIo, TunnelCryptoError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match role {
        PeerWireCryptoRole::Initiator => {
            // --- Initiator: Step 1 ---
            let (private, public) = generate_dh_keypair();
            let public_bytes = dh_public_to_bytes(&public);

            // Send Xa (96 bytes) + padding (with length prefix)
            stream.write_all(&public_bytes).await?;
            write_padding(&mut stream).await?;

            // --- Initiator: Step 2 ---
            // Read Yb (96 bytes) + padding (with length prefix)
            let mut peer_public_bytes = [0u8; DH_KEY_BYTES];
            stream.read_exact(&mut peer_public_bytes).await?;
            let peer_public = bytes_to_dh_public(&peer_public_bytes);
            validate_dh_public(&peer_public)?;
            read_padding_prefixed(&mut stream).await?;

            // Compute shared secret
            let secret = compute_shared_secret(&private, &peer_public);

            // Derive keys
            let (encrypt_key, decrypt_key) = derive_rc4_keys(&secret, &carrier_hash, true);
            let mut encrypt_cipher = new_rc4(&encrypt_key);
            let mut decrypt_cipher = new_rc4(&decrypt_key);

            // Discard first 1024 bytes in both directions
            rc4_discard(&mut encrypt_cipher, RC4_DISCARD);
            rc4_discard(&mut decrypt_cipher, RC4_DISCARD);

            // --- Initiator: Steps 3-4 (VC exchange) ---
            // Read and verify VC (encrypted)
            let mut vc = [0u8; VC_LEN];
            stream.read_exact(&mut vc).await?;
            rc4_apply(&mut decrypt_cipher, &mut vc);
            if vc != VC_VALUE {
                return Err(TunnelCryptoError::VerificationFailed);
            }

            // Send VC back (encrypted)
            let mut vc = VC_VALUE;
            rc4_apply(&mut encrypt_cipher, &mut vc);
            stream.write_all(&vc).await?;

            // Split and wrap
            let (read_half, write_half) = tokio::io::split(stream);
            let reader: BoxAsyncReadVectored = Box::new(
                EncryptedReader {
                    inner: read_half,
                    cipher: decrypt_cipher,
                }
                .into_vectored_compat(),
            );
            let writer: BoxAsyncWrite = Box::new(EncryptedWriter {
                inner: write_half,
                cipher: encrypt_cipher,
            });
            return Ok(EncryptedPeerIo { reader, writer });
        }
        PeerWireCryptoRole::Responder => {
            // --- Responder: Step 1 ---
            // Read Xa (96 bytes) + padding (with length prefix)
            let mut initiator_public_bytes = [0u8; DH_KEY_BYTES];
            stream.read_exact(&mut initiator_public_bytes).await?;
            let initiator_public = bytes_to_dh_public(&initiator_public_bytes);
            validate_dh_public(&initiator_public)?;
            read_padding_prefixed(&mut stream).await?;

            // --- Responder: Step 2 ---
            let (private, public) = generate_dh_keypair();
            let secret = compute_shared_secret(&private, &initiator_public);

            // Derive keys
            let (encrypt_key, decrypt_key) = derive_rc4_keys(&secret, &carrier_hash, false);
            let mut encrypt_cipher = new_rc4(&encrypt_key);
            let mut decrypt_cipher = new_rc4(&decrypt_key);

            // Discard first 1024 bytes in both directions
            rc4_discard(&mut encrypt_cipher, RC4_DISCARD);
            rc4_discard(&mut decrypt_cipher, RC4_DISCARD);

            // Send Yb (96 bytes) + padding (with length prefix)
            let public_bytes = dh_public_to_bytes(&public);
            stream.write_all(&public_bytes).await?;
            write_padding(&mut stream).await?;

            // --- Responder: Step 3 ---
            // Send VC (encrypted)
            let mut vc = VC_VALUE;
            rc4_apply(&mut encrypt_cipher, &mut vc);
            stream.write_all(&vc).await?;

            // --- Responder: Step 4 ---
            // Read and verify VC (encrypted)
            let mut vc = [0u8; VC_LEN];
            stream.read_exact(&mut vc).await?;
            rc4_apply(&mut decrypt_cipher, &mut vc);
            if vc != VC_VALUE {
                return Err(TunnelCryptoError::VerificationFailed);
            }

            // Split and wrap
            let (read_half, write_half) = tokio::io::split(stream);
            let reader: BoxAsyncReadVectored = Box::new(
                EncryptedReader {
                    inner: read_half,
                    cipher: decrypt_cipher,
                }
                .into_vectored_compat(),
            );
            let writer: BoxAsyncWrite = Box::new(EncryptedWriter {
                inner: write_half,
                cipher: encrypt_cipher,
            });
            return Ok(EncryptedPeerIo { reader, writer });
        }
    };
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn requires_encrypted_peer_wire_and_recovers_handshake_bytes() {
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let carrier_hash = Id20::new([7; 20]);
        let (client, server) = tokio::join!(
            PeerWireCrypto::initiator(client_io, carrier_hash),
            PeerWireCrypto::responder(server_io, carrier_hash),
        );
        let client = client.unwrap();
        let server = server.unwrap();
        let _client_read = client.reader;
        let mut client_write = client.writer;
        let mut server_read = server.reader;
        let _server_write = server.writer;

        // Write through encrypted wrapper
        client_write
            .write_all(b"BitTorrent protocol")
            .await
            .unwrap();
        let mut plain = [0; 19];
        let mut server_mut = Pin::new(&mut *server_read);
        AsyncReadExt::read_exact(&mut server_mut, &mut plain)
            .await
            .unwrap();
        assert_eq!(&plain, b"BitTorrent protocol");
    }

    #[tokio::test]
    async fn encrypts_and_decrypts_bidirectional_stream() {
        let (client_io, server_io) = tokio::io::duplex(32 * 1024);
        let carrier_hash = Id20::new([0xAB; 20]);
        let (client, server) = tokio::join!(
            PeerWireCrypto::initiator(client_io, carrier_hash),
            PeerWireCrypto::responder(server_io, carrier_hash),
        );
        let client = client.unwrap();
        let server = server.unwrap();
        let mut client_read = client.reader;
        let mut client_write = client.writer;
        let mut server_read = server.reader;
        let mut server_write = server.writer;

        // Client -> Server
        let msg = b"Hello from client!";
        client_write.write_all(msg).await.unwrap();
        let mut buf = [0u8; 18];
        let mut server_mut = Pin::new(&mut *server_read);
        AsyncReadExt::read_exact(&mut server_mut, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, msg);

        // Server -> Client
        let msg = b"Hello from server!";
        server_write.write_all(msg).await.unwrap();
        let mut buf = [0u8; 18];
        let mut client_mut = Pin::new(&mut *client_read);
        AsyncReadExt::read_exact(&mut client_mut, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, msg);
    }

    #[tokio::test]
    async fn rejects_mismatched_carrier_hash() {
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let client_hash = Id20::new([1; 20]);
        let server_hash = Id20::new([2; 20]);

        let (client_res, server_res) = tokio::join!(
            PeerWireCrypto::initiator(client_io, client_hash),
            PeerWireCrypto::responder(server_io, server_hash),
        );

        // With mismatched hashes, derived keys differ => VC verification fails.
        assert!(client_res.is_err() || server_res.is_err());
    }

    #[tokio::test]
    async fn rejects_invalid_dh_public_value() {
        let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);
        let carrier_hash = Id20::new([7; 20]);

        // Spawn initiator
        let client_task =
            tokio::spawn(async move { PeerWireCrypto::initiator(client_io, carrier_hash).await });

        // Read initiator's DH public key (96 bytes) + padding
        let mut buf = [0u8; DH_KEY_BYTES];
        server_io.read_exact(&mut buf).await.unwrap();
        // Read padding length and bytes
        let mut pad_len_buf = [0u8; 2];
        server_io.read_exact(&mut pad_len_buf).await.unwrap();
        let pad_len = u16::from_be_bytes(pad_len_buf) as usize;
        if pad_len > 0 {
            let mut discard = vec![0u8; pad_len];
            server_io.read_exact(&mut discard).await.unwrap();
        }

        // Send invalid DH public (all zeros = 0, which is < 2)
        let invalid_dh = [0u8; DH_KEY_BYTES];
        server_io.write_all(&invalid_dh).await.unwrap();

        let result = client_task.await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_truncated_padding() {
        let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);
        let carrier_hash = Id20::new([7; 20]);

        let client_task =
            tokio::spawn(async move { PeerWireCrypto::initiator(client_io, carrier_hash).await });

        // Read initiator's DH public + padding
        let mut buf = [0u8; DH_KEY_BYTES];
        server_io.read_exact(&mut buf).await.unwrap();
        let mut pad_len_buf = [0u8; 2];
        server_io.read_exact(&mut pad_len_buf).await.unwrap();
        let pad_len = u16::from_be_bytes(pad_len_buf) as usize;
        if pad_len > 0 {
            let mut discard = vec![0u8; pad_len];
            server_io.read_exact(&mut discard).await.unwrap();
        }

        // Compute shared secret and keys for valid response
        let initiator_public = bytes_to_dh_public(buf.as_slice().try_into().unwrap());
        validate_dh_public(&initiator_public).unwrap();
        let (private, public) = generate_dh_keypair();
        let public_bytes = dh_public_to_bytes(&public);

        // Send DH public
        server_io.write_all(&public_bytes).await.unwrap();

        // Send padding length prefix claiming 10 bytes, but only send 5
        server_io.write_all(&10u16.to_be_bytes()).await.unwrap();
        server_io.write_all(&[0u8; 5]).await.unwrap();

        // Drop the entire server side to trigger EOF
        drop(server_io);

        let result = client_task.await.unwrap();
        assert!(result.is_err(), "should reject truncated padding");
    }

    #[tokio::test]
    async fn large_transfer_through_encrypted_tunnel() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let carrier_hash = Id20::new([42; 20]);
        let (client, server) = tokio::join!(
            PeerWireCrypto::initiator(client_io, carrier_hash),
            PeerWireCrypto::responder(server_io, carrier_hash),
        );
        let client = client.unwrap();
        let server = server.unwrap();
        let _client_read = client.reader;
        let mut client_write = client.writer;
        let mut server_read = server.reader;
        let _server_write = server.writer;

        // Client sends 64KB
        let data: Vec<u8> = (0..65536).map(|i| (i & 0xFF) as u8).collect();
        let data_clone = data.clone();
        let client_send = tokio::spawn(async move {
            client_write.write_all(&data_clone).await.unwrap();
        });

        let mut received = vec![0u8; 65536];
        let mut server_mut = Pin::new(&mut *server_read);
        AsyncReadExt::read_exact(&mut server_mut, &mut received)
            .await
            .unwrap();

        client_send.await.unwrap();
        assert_eq!(received, data);
    }
}
