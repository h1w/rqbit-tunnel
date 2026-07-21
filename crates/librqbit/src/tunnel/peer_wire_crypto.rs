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

/// MSE crypto-method bit for RC4.
const CRYPTO_RC4: u32 = 0x0000_0002;
/// `crypto_provide` advertised by our initiator: plaintext (0x01) | RC4 (0x02).
const CRYPTO_PROVIDE: u32 = 0x0000_0003;
/// `crypto_select` chosen by our responder: RC4.
const CRYPTO_SELECT: u32 = 0x0000_0002;

/// Length of the SHA1 sync markers (`req1`, `sync_marker`) in bytes.
const MARKER_LEN: usize = 20;

/// Extra slack over `MAX_PADDING + marker.len()` for the bounded resync scan.
const RESYNC_SLACK: usize = 16;

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
    #[error("sync marker mismatch (unknown SKEY)")]
    MarkerMismatch,
    #[error("resync marker not found within scan bound")]
    ResyncNotFound,
    #[error("crypto negotiation failed: no mutually supported method")]
    CryptoNegotiationFailed,
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

/// Spec-accurate MSE/PE key derivation.
///
/// `keyA = SHA1("keyA" || S || SKEY)` and `keyB = SHA1("keyB" || S || SKEY)`,
/// where `S` is the 96-byte DH shared secret and `SKEY` is the 20-byte torrent
/// info hash. Returns `(keyA, keyB)`.
///
/// Per the MSE spec the initiator (A) encrypts A->B with `keyA` and decrypts
/// B->A with `keyB`; the responder (B) mirrors this (encrypt with `keyB`,
/// decrypt with `keyA`).
fn mse_keys(
    s: &[u8; DH_KEY_BYTES],
    skey: &[u8; RC4_KEY_LEN],
) -> ([u8; RC4_KEY_LEN], [u8; RC4_KEY_LEN]) {
    let derive = |tag: &[u8; 4]| -> [u8; RC4_KEY_LEN] {
        let mut input = Vec::with_capacity(tag.len() + DH_KEY_BYTES + RC4_KEY_LEN);
        input.extend_from_slice(tag);
        input.extend_from_slice(s);
        input.extend_from_slice(skey);
        sha1(&input)
    };
    (derive(b"keyA"), derive(b"keyB"))
}

/// `req1 = SHA1("req1" || S)` — the 20-byte hash of the shared secret.
fn req1(s: &[u8; DH_KEY_BYTES]) -> [u8; 20] {
    let mut input = Vec::with_capacity(4 + DH_KEY_BYTES);
    input.extend_from_slice(b"req1");
    input.extend_from_slice(s);
    sha1(&input)
}

/// `req2 = SHA1("req2" || SKEY)` — the 20-byte hash of the info hash.
fn req2(skey: &[u8; RC4_KEY_LEN]) -> [u8; 20] {
    let mut input = Vec::with_capacity(4 + RC4_KEY_LEN);
    input.extend_from_slice(b"req2");
    input.extend_from_slice(skey);
    sha1(&input)
}

/// `req3 = SHA1("req3" || S)` — the 20-byte hash of the shared secret.
fn req3(s: &[u8; DH_KEY_BYTES]) -> [u8; 20] {
    let mut input = Vec::with_capacity(4 + DH_KEY_BYTES);
    input.extend_from_slice(b"req3");
    input.extend_from_slice(s);
    sha1(&input)
}

/// The MSE sync marker sent in the handshake: `req2(SKEY) xor req3(S)`.
///
/// A responder recovers `req2(SKEY)` from a received marker as
/// `marker xor req3(S)`.
fn sync_marker(skey: &[u8; RC4_KEY_LEN], s: &[u8; DH_KEY_BYTES]) -> [u8; 20] {
    let a = req2(skey);
    let b = req3(s);
    let mut out = [0u8; 20];
    for (o, (x, y)) in out.iter_mut().zip(a.iter().zip(b.iter())) {
        *o = x ^ y;
    }
    out
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

/// Write a raw MSE padding field (`PadA`/`PadB`): a random `0..=MAX_PADDING`
/// bytes, with **NO** length prefix. The receiver locates the following protocol
/// element via [`resync_on`], not via a declared length.
async fn write_raw_pad<S>(stream: &mut S) -> Result<(), TunnelCryptoError>
where
    S: AsyncWrite + Unpin,
{
    let pad_len = rand::rng().random_range(0..=MAX_PADDING);
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        rand::rng().fill(&mut pad[..]);
        stream.write_all(&pad).await?;
    }
    Ok(())
}

/// Bounded resync: read one byte at a time into a sliding `marker.len()`-wide
/// window and return `Ok(())` the instant the window equals `marker` — at which
/// point the stream is positioned **immediately after** the marker (no over-read,
/// since we read exactly one byte at a time).
///
/// Fails closed with [`TunnelCryptoError::ResyncNotFound`] once `max_scan` bytes
/// have been consumed without a match. NEVER reads unboundedly, so a peer that
/// floods bytes without ever sending the marker cannot hang or OOM us. A short
/// read before a match surfaces as an IO error.
async fn resync_on<S>(
    stream: &mut S,
    marker: &[u8],
    max_scan: usize,
) -> Result<(), TunnelCryptoError>
where
    S: AsyncRead + Unpin,
{
    let mut window: Vec<u8> = Vec::with_capacity(marker.len());
    let mut scanned = 0usize;
    while scanned < max_scan {
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).await?;
        scanned += 1;
        if window.len() == marker.len() {
            window.remove(0);
        }
        window.push(b[0]);
        if window.len() == marker.len() && window.as_slice() == marker {
            return Ok(());
        }
    }
    Err(TunnelCryptoError::ResyncNotFound)
}

/// Read exactly `n` bytes and decrypt them in place with `cipher`, advancing the
/// RC4 keystream by exactly `n`. Returns the decrypted plaintext.
async fn read_exact_decrypt<S>(
    stream: &mut S,
    cipher: &mut Rc4Cipher,
    n: usize,
) -> Result<Vec<u8>, TunnelCryptoError>
where
    S: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; n];
    if n > 0 {
        stream.read_exact(&mut buf).await?;
        rc4_apply(cipher, &mut buf);
    }
    Ok(buf)
}

// ===========================================================================
// Encrypted I/O wrappers
// ===========================================================================

/// An `AsyncRead` wrapper that decrypts with RC4 on the fly.
struct EncryptedReader<R> {
    inner: R,
    cipher: Rc4Cipher,
    /// Already-decrypted bytes (the MSE `IA` initial payload) to surface before
    /// reading further from `inner`. Empty in our own handshakes (`len(IA) == 0`).
    prefix: Vec<u8>,
}

impl<R: AsyncRead + Unpin> AsyncRead for EncryptedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain any buffered `IA` payload first — it is already decrypted, so it
        // must not pass through the RC4 cipher again.
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            let rest = self.prefix.split_off(n);
            let head = std::mem::replace(&mut self.prefix, rest);
            buf.put_slice(&head);
            return Poll::Ready(Ok(()));
        }
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
///
/// RC4 is a stream cipher: its keystream advances by exactly the number of
/// bytes encrypted, and both peers must consume the keystream in lockstep. The
/// underlying writer may accept fewer bytes than offered (a partial or
/// would-block write), so we must NOT re-encrypt the same plaintext twice.
/// Instead, we encrypt each input once and buffer any ciphertext the inner
/// writer did not accept, draining it before encrypting anything new.
struct EncryptedWriter<W> {
    inner: W,
    cipher: Rc4Cipher,
    /// Ciphertext already advanced through the keystream but not yet written.
    pending: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> EncryptedWriter<W> {
    /// Push buffered ciphertext to `inner`; `Ready(Ok(()))` once fully drained.
    fn drain_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => {
                    self.pending.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for EncryptedWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();

        // Never encrypt new plaintext while ciphertext from a previous partial
        // write is still pending — that would reorder the keystream.
        match this.drain_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut encrypted = buf.to_vec();
        rc4_apply(&mut this.cipher, &mut encrypted);
        match Pin::new(&mut this.inner).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(n)) => {
                if n < encrypted.len() {
                    this.pending.extend_from_slice(&encrypted[n..]);
                }
                // The whole input has been encrypted and is now either written
                // or buffered, so it is fully consumed from the caller's view.
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                // Already advanced the keystream; buffer everything so it is
                // neither lost nor re-encrypted, and report it consumed.
                this.pending.extend_from_slice(&encrypted);
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        match this.drain_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        match this.drain_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
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
    // `SKEY` is the 20-byte carrier/torrent hash driving req2/key derivation.
    let skey = carrier_hash.0;
    match role {
        // ===================================================================
        // Initiator (A). Wire order: send 1, recv 2, send 3, recv 4.
        // ===================================================================
        PeerWireCryptoRole::Initiator => {
            // --- Step 1: A -> B :  Ya ‖ PadA (raw pad, NO length prefix) ---
            let (private, public) = generate_dh_keypair();
            stream.write_all(&dh_public_to_bytes(&public)).await?;
            write_raw_pad(&mut stream).await?;

            // --- Step 2: B -> A :  read Yb (96). PadB is skipped by resync. ---
            let mut yb = [0u8; DH_KEY_BYTES];
            stream.read_exact(&mut yb).await?;
            let peer_public = bytes_to_dh_public(&yb);
            validate_dh_public(&peer_public)?;
            let secret = compute_shared_secret(&private, &peer_public);

            // Keys: A encrypts A->B with keyA, decrypts B->A with keyB.
            let (key_a, key_b) = mse_keys(&secret, &skey);
            let mut encrypt_cipher = new_rc4(&key_a);
            let mut decrypt_cipher = new_rc4(&key_b);
            rc4_discard(&mut encrypt_cipher, RC4_DISCARD);
            rc4_discard(&mut decrypt_cipher, RC4_DISCARD);

            // --- Step 3: A -> B ---
            //   req1(S) ‖ sync_marker(SKEY,S)          (cleartext, no cipher)
            //   RC4_keyA[ VC ‖ crypto_provide ‖ len(PadC) ‖ PadC ‖ len(IA)=0 ]
            let pad_c_len = rand::rng().random_range(0..=MAX_PADDING);
            let pad_c = {
                let mut v = vec![0u8; pad_c_len];
                if pad_c_len > 0 {
                    rand::rng().fill(&mut v[..]);
                }
                v
            };
            let mut block = Vec::with_capacity(VC_LEN + 4 + 2 + pad_c_len + 2);
            block.extend_from_slice(&VC_VALUE);
            block.extend_from_slice(&CRYPTO_PROVIDE.to_be_bytes());
            block.extend_from_slice(&(pad_c_len as u16).to_be_bytes());
            block.extend_from_slice(&pad_c);
            block.extend_from_slice(&0u16.to_be_bytes()); // len(IA) = 0
            rc4_apply(&mut encrypt_cipher, &mut block);
            // encrypt_cipher is now advanced by (16 + pad_c_len) past the discard;
            // that is exactly where the A->B payload keystream must resume.

            let mut step3 = Vec::with_capacity(2 * MARKER_LEN + block.len());
            step3.extend_from_slice(&req1(&secret));
            step3.extend_from_slice(&sync_marker(&skey, &secret));
            step3.extend_from_slice(&block);
            stream.write_all(&step3).await?;

            // --- Step 4: B -> A ---
            // Skip PadB by resyncing on ENCRYPT(keyB, VC). Since VC is all-zero,
            // that ciphertext equals the keyB keystream at position 1024..1032, so
            // computing it here advances decrypt_cipher by exactly the 8 VC bytes.
            // A successful match is *also* an implicit VC==0 verification.
            let mut vc_marker = VC_VALUE;
            rc4_apply(&mut decrypt_cipher, &mut vc_marker);
            let max_scan = MAX_PADDING + vc_marker.len() + RESYNC_SLACK;
            resync_on(&mut stream, &vc_marker, max_scan).await?;

            // Continue the keyB stream (now at position 1032): crypto_select,
            // len(PadD), PadD.
            let cs = read_exact_decrypt(&mut stream, &mut decrypt_cipher, 4).await?;
            let crypto_select = u32::from_be_bytes([cs[0], cs[1], cs[2], cs[3]]);
            if crypto_select & CRYPTO_RC4 == 0 {
                // We only run RC4 post-handshake; a non-RC4 selection is rejected.
                return Err(TunnelCryptoError::CryptoNegotiationFailed);
            }
            let pd = read_exact_decrypt(&mut stream, &mut decrypt_cipher, 2).await?;
            let pad_d_len = u16::from_be_bytes([pd[0], pd[1]]) as usize;
            if pad_d_len > MAX_PADDING {
                return Err(TunnelCryptoError::PaddingTooLarge(pad_d_len));
            }
            read_exact_decrypt(&mut stream, &mut decrypt_cipher, pad_d_len).await?;
            // decrypt_cipher is now at 1024 + 14 + pad_d_len — exactly where B's
            // keyB payload keystream resumes. Reader/writer take over seamlessly.

            let (read_half, write_half) = tokio::io::split(stream);
            let reader: BoxAsyncReadVectored = Box::new(
                EncryptedReader {
                    inner: read_half,
                    cipher: decrypt_cipher,
                    prefix: Vec::new(),
                }
                .into_vectored_compat(),
            );
            let writer: BoxAsyncWrite = Box::new(EncryptedWriter {
                inner: write_half,
                cipher: encrypt_cipher,
                pending: Vec::new(),
            });
            Ok(EncryptedPeerIo { reader, writer })
        }

        // ===================================================================
        // Responder (B). Wire order: recv 1, send 2, recv 3, send 4.
        // ===================================================================
        PeerWireCryptoRole::Responder => {
            // --- Step 1: A -> B :  read Ya (96). PadA is skipped by resync. ---
            let mut ya = [0u8; DH_KEY_BYTES];
            stream.read_exact(&mut ya).await?;
            let initiator_public = bytes_to_dh_public(&ya);
            validate_dh_public(&initiator_public)?;

            let (private, public) = generate_dh_keypair();
            let secret = compute_shared_secret(&private, &initiator_public);

            // Keys: B encrypts B->A with keyB, decrypts A->B with keyA.
            let (key_a, key_b) = mse_keys(&secret, &skey);
            let mut encrypt_cipher = new_rc4(&key_b);
            let mut decrypt_cipher = new_rc4(&key_a);
            rc4_discard(&mut encrypt_cipher, RC4_DISCARD);
            rc4_discard(&mut decrypt_cipher, RC4_DISCARD);

            // --- Step 2: B -> A :  Yb ‖ PadB (raw pad) ---
            // Sent now: the initiator withholds step 3 until it has Yb, so we must
            // not block on reading req1 before emitting our own key.
            stream.write_all(&dh_public_to_bytes(&public)).await?;
            write_raw_pad(&mut stream).await?;

            // --- Step 3: A -> B ---
            // Skip PadA and lock onto req1(S) (cleartext — ciphers untouched).
            let expected_req1 = req1(&secret);
            let max_scan = MAX_PADDING + expected_req1.len() + RESYNC_SLACK;
            resync_on(&mut stream, &expected_req1, max_scan).await?;

            // Read + verify the sync marker (folds in SKEY). A mismatch means this
            // is not our carrier — reject, exactly as MSE ignores unknown torrents.
            let mut marker = [0u8; MARKER_LEN];
            stream.read_exact(&mut marker).await?;
            if marker != sync_marker(&skey, &secret) {
                return Err(TunnelCryptoError::MarkerMismatch);
            }

            // Decrypt the keyA block: VC ‖ crypto_provide ‖ len(PadC) ‖ PadC ‖
            // len(IA) ‖ IA. decrypt_cipher advances byte-for-byte from position
            // 1024, mirroring the initiator's encrypt_cipher over the same block.
            let vc = read_exact_decrypt(&mut stream, &mut decrypt_cipher, VC_LEN).await?;
            if vc != VC_VALUE {
                return Err(TunnelCryptoError::VerificationFailed);
            }
            let cp = read_exact_decrypt(&mut stream, &mut decrypt_cipher, 4).await?;
            let crypto_provide = u32::from_be_bytes([cp[0], cp[1], cp[2], cp[3]]);
            if crypto_provide & CRYPTO_RC4 == 0 {
                // Initiator offered only plaintext — reject (documented choice; our
                // own initiator always offers RC4, so this only rejects foreigners).
                return Err(TunnelCryptoError::CryptoNegotiationFailed);
            }
            let pc = read_exact_decrypt(&mut stream, &mut decrypt_cipher, 2).await?;
            let pad_c_len = u16::from_be_bytes([pc[0], pc[1]]) as usize;
            if pad_c_len > MAX_PADDING {
                return Err(TunnelCryptoError::PaddingTooLarge(pad_c_len));
            }
            read_exact_decrypt(&mut stream, &mut decrypt_cipher, pad_c_len).await?;
            let ia_len_buf = read_exact_decrypt(&mut stream, &mut decrypt_cipher, 2).await?;
            let ia_len = u16::from_be_bytes([ia_len_buf[0], ia_len_buf[1]]) as usize;
            // `IA` is 0 for our own initiator; a foreign peer never reaches here
            // (marker check). If present it is the decrypted lead of the payload.
            let ia = read_exact_decrypt(&mut stream, &mut decrypt_cipher, ia_len).await?;

            // --- Step 4: B -> A :  RC4_keyB[ VC ‖ crypto_select ‖ len(PadD) ‖ PadD ] ---
            let pad_d_len = rand::rng().random_range(0..=MAX_PADDING);
            let pad_d = {
                let mut v = vec![0u8; pad_d_len];
                if pad_d_len > 0 {
                    rand::rng().fill(&mut v[..]);
                }
                v
            };
            let mut block = Vec::with_capacity(VC_LEN + 4 + 2 + pad_d_len);
            block.extend_from_slice(&VC_VALUE);
            block.extend_from_slice(&CRYPTO_SELECT.to_be_bytes());
            block.extend_from_slice(&(pad_d_len as u16).to_be_bytes());
            block.extend_from_slice(&pad_d);
            rc4_apply(&mut encrypt_cipher, &mut block);
            stream.write_all(&block).await?;
            // encrypt_cipher is now at 1024 + 14 + pad_d_len — where the B->A
            // payload keystream resumes, matching the initiator's decrypt_cipher.

            let (read_half, write_half) = tokio::io::split(stream);
            let reader: BoxAsyncReadVectored = Box::new(
                EncryptedReader {
                    inner: read_half,
                    cipher: decrypt_cipher,
                    prefix: ia,
                }
                .into_vectored_compat(),
            );
            let writer: BoxAsyncWrite = Box::new(EncryptedWriter {
                inner: write_half,
                cipher: encrypt_cipher,
                pending: Vec::new(),
            });
            Ok(EncryptedPeerIo { reader, writer })
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    // ---- MSE key-derivation / marker conformance vectors -------------------

    #[test]
    fn mse_keys_match_spec_formula() {
        let s = [0x11u8; DH_KEY_BYTES];
        let skey = [0x22u8; RC4_KEY_LEN];

        let (key_a, key_b) = mse_keys(&s, &skey);

        // keyA = SHA1("keyA" || S || SKEY), rebuilt independently in the test.
        let mut input_a = Vec::new();
        input_a.extend_from_slice(b"keyA");
        input_a.extend_from_slice(&s);
        input_a.extend_from_slice(&skey);
        assert_eq!(
            key_a,
            sha1(&input_a),
            "keyA must equal SHA1(keyA || S || SKEY)"
        );

        // keyB = SHA1("keyB" || S || SKEY).
        let mut input_b = Vec::new();
        input_b.extend_from_slice(b"keyB");
        input_b.extend_from_slice(&s);
        input_b.extend_from_slice(&skey);
        assert_eq!(
            key_b,
            sha1(&input_b),
            "keyB must equal SHA1(keyB || S || SKEY)"
        );

        assert_ne!(key_a, key_b, "keyA and keyB must differ");

        // Deterministic.
        let (key_a2, key_b2) = mse_keys(&s, &skey);
        assert_eq!(key_a, key_a2);
        assert_eq!(key_b, key_b2);
    }

    #[test]
    fn req_hashes_match_spec_and_are_distinct() {
        let s = [0x33u8; DH_KEY_BYTES];
        let skey = [0x44u8; RC4_KEY_LEN];

        let r1 = req1(&s);
        let r2 = req2(&skey);
        let r3 = req3(&s);

        // Each equals SHA1(tag || arg), rebuilt in the test.
        let mut i1 = Vec::new();
        i1.extend_from_slice(b"req1");
        i1.extend_from_slice(&s);
        assert_eq!(r1, sha1(&i1), "req1 must equal SHA1(req1 || S)");

        let mut i2 = Vec::new();
        i2.extend_from_slice(b"req2");
        i2.extend_from_slice(&skey);
        assert_eq!(r2, sha1(&i2), "req2 must equal SHA1(req2 || SKEY)");

        let mut i3 = Vec::new();
        i3.extend_from_slice(b"req3");
        i3.extend_from_slice(&s);
        assert_eq!(r3, sha1(&i3), "req3 must equal SHA1(req3 || S)");

        // Distinct.
        assert_ne!(r1, r2);
        assert_ne!(r1, r3);
        assert_ne!(r2, r3);

        // Deterministic.
        assert_eq!(r1, req1(&s));
        assert_eq!(r2, req2(&skey));
        assert_eq!(r3, req3(&s));
    }

    #[test]
    fn sync_marker_is_req2_xor_req3_and_recoverable() {
        let s = [0x55u8; DH_KEY_BYTES];
        let skey = [0x66u8; RC4_KEY_LEN];

        let marker = sync_marker(&skey, &s);
        let r2 = req2(&skey);
        let r3 = req3(&s);

        // marker == req2 xor req3, byte-for-byte.
        let mut expected = [0u8; 20];
        for i in 0..20 {
            expected[i] = r2[i] ^ r3[i];
        }
        assert_eq!(marker, expected, "sync_marker must be req2 XOR req3");

        // Responder recovery: marker xor req3(S) == req2(SKEY).
        let mut recovered = [0u8; 20];
        for i in 0..20 {
            recovered[i] = marker[i] ^ r3[i];
        }
        assert_eq!(recovered, r2, "marker XOR req3 must recover req2");
    }

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
        let skey = Id20::new([7; 20]);
        let client_task =
            tokio::spawn(async move { PeerWireCrypto::initiator(client_io, skey).await });

        // Read the initiator's Ya (96). The trailing raw PadA is left unread — the
        // initiator's read of Yb does not depend on us consuming it.
        let mut ya = [0u8; DH_KEY_BYTES];
        server_io.read_exact(&mut ya).await.unwrap();

        // Respond with an invalid Yb (all zeros => value 0, outside [2, P-2]).
        server_io.write_all(&[0u8; DH_KEY_BYTES]).await.unwrap();
        drop(server_io);

        let result = client_task.await.unwrap();
        assert!(matches!(result, Err(TunnelCryptoError::InvalidDhPublic)));
    }

    #[tokio::test]
    async fn rejects_truncated_handshake() {
        let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);
        let skey = Id20::new([7; 20]);
        let client_task =
            tokio::spawn(async move { PeerWireCrypto::initiator(client_io, skey).await });

        // Read Ya (96).
        let mut ya = [0u8; DH_KEY_BYTES];
        server_io.read_exact(&mut ya).await.unwrap();

        // Send a valid Yb, then drop without ever sending the step-4 VC block.
        let (_xb, yb) = generate_dh_keypair();
        server_io.write_all(&dh_public_to_bytes(&yb)).await.unwrap();
        drop(server_io); // EOF: the initiator's step-3 write / resync fails closed.

        let result = client_task.await.unwrap();
        assert!(
            result.is_err(),
            "truncated handshake (no VC block) must be rejected",
        );
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

    // ---- Spec-accurate MSE/PE choreography ---------------------------------

    /// The crux test: a full self-interop over duplex, then multi-KB payload in
    /// BOTH directions after the handshake. A one-byte keystream misalignment in
    /// the handshake byte-accounting silently corrupts payload — this catches it.
    #[tokio::test]
    async fn self_interop_roundtrip_multi_kb_bidirectional() {
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let skey = Id20::new([0x77; 20]);
        let (client, server) = tokio::join!(
            PeerWireCrypto::initiator(client_io, skey),
            PeerWireCrypto::responder(server_io, skey),
        );
        let client = client.expect("initiator handshake");
        let server = server.expect("responder handshake");
        let mut client_read = client.reader;
        let mut client_write = client.writer;
        let mut server_read = server.reader;
        let mut server_write = server.writer;

        // Distinct, structured multi-KB patterns each direction.
        let c2s: Vec<u8> = (0..32_768u32).map(|i| (i.wrapping_mul(31)) as u8).collect();
        let s2c: Vec<u8> = (0..40_000u32)
            .map(|i| (i.wrapping_mul(17).wrapping_add(7)) as u8)
            .collect();
        let c2s2 = c2s.clone();
        let s2c2 = s2c.clone();

        // Concurrent writers so neither direction blocks the other.
        let cw = tokio::spawn(async move {
            client_write.write_all(&c2s2).await.unwrap();
            client_write.flush().await.unwrap();
        });
        let sw = tokio::spawn(async move {
            server_write.write_all(&s2c2).await.unwrap();
            server_write.flush().await.unwrap();
        });

        let mut got_s = vec![0u8; c2s.len()];
        let mut server_mut = Pin::new(&mut *server_read);
        AsyncReadExt::read_exact(&mut server_mut, &mut got_s)
            .await
            .unwrap();
        assert_eq!(got_s, c2s, "client->server payload corrupted (keystream)");

        let mut got_c = vec![0u8; s2c.len()];
        let mut client_mut = Pin::new(&mut *client_read);
        AsyncReadExt::read_exact(&mut client_mut, &mut got_c)
            .await
            .unwrap();
        assert_eq!(got_c, s2c, "server->client payload corrupted (keystream)");

        cw.await.unwrap();
        sw.await.unwrap();
    }

    /// Structural: capture the initiator's raw first bytes and assert `Ya` (96),
    /// then raw padding with NO 2-byte length prefix, then `req1(S)` followed by
    /// the sync marker. Proves the spec wire format (old code emits neither).
    #[tokio::test]
    async fn initiator_wire_is_spec_mse_structural() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let skey = Id20::new([0x5A; 20]);
        let client_task =
            tokio::spawn(async move { PeerWireCrypto::initiator(client_io, skey).await });

        // Ya (96) must be a valid DH public value.
        let mut ya = [0u8; DH_KEY_BYTES];
        server_io.read_exact(&mut ya).await.unwrap();
        let ya_pub = bytes_to_dh_public(&ya);
        validate_dh_public(&ya_pub).expect("Ya must be a valid DH public value");

        // Send our Yb so the initiator proceeds to emit step 3.
        let (xb, yb) = generate_dh_keypair();
        server_io.write_all(&dh_public_to_bytes(&yb)).await.unwrap();

        // S = Ya^Xb; compute expected markers.
        let secret = compute_shared_secret(&xb, &ya_pub);
        let expected_req1 = req1(&secret);
        let expected_marker = sync_marker(&skey.0, &secret);

        // Collect everything after Ya: PadA (already buffered) ‖ req1 ‖ marker ‖ …
        let mut collected: Vec<u8> = Vec::new();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let mut buf = [0u8; 1024];
            let n = tokio::time::timeout_at(deadline, server_io.read(&mut buf))
                .await
                .expect("timed out collecting step-3 bytes")
                .unwrap();
            if n == 0 {
                panic!("stream ended before req1(S) appeared");
            }
            collected.extend_from_slice(&buf[..n]);
            if let Some(p) = collected
                .windows(expected_req1.len())
                .position(|w| w == expected_req1)
            {
                if collected.len() >= p + 40 {
                    // Bytes between Ya-end and req1 == raw PadA (0..=512), no prefix.
                    assert!(
                        p <= MAX_PADDING,
                        "PadA must be 0..=512 raw bytes with NO length prefix, got {p}",
                    );
                    assert_eq!(
                        &collected[p + 20..p + 40],
                        &expected_marker[..],
                        "sync_marker(SKEY,S) must immediately follow req1(S)",
                    );
                    drop(server_io);
                    let _ = client_task.await;
                    return;
                }
            }
            assert!(
                collected.len() <= MAX_PADDING + 40 + 128,
                "req1(S) not found after Ya + bounded pad — wrong wire format",
            );
        }
    }

    /// A mismatched SKEY: `S` matches (DH ok) so `req1(S)` resync succeeds, but the
    /// sync marker (which folds in SKEY) fails — the responder rejects, no panic.
    #[tokio::test]
    async fn responder_rejects_mismatched_skey() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client_skey = Id20::new([1; 20]);
        let server_skey = Id20::new([2; 20]);
        let (_client_res, server_res) = tokio::join!(
            PeerWireCrypto::initiator(client_io, client_skey),
            PeerWireCrypto::responder(server_io, server_skey),
        );
        assert!(
            server_res.is_err(),
            "responder must reject a foreign SKEY (marker mismatch)",
        );
    }

    /// Bounded resync: a peer that sends `Ya` then bytes that never contain the
    /// marker must cause the responder to fail within `max_scan`, not hang/OOM.
    #[tokio::test]
    async fn responder_resync_is_bounded() {
        let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
        let skey = Id20::new([0x11; 20]);
        let server_task =
            tokio::spawn(async move { PeerWireCrypto::responder(server_io, skey).await });

        // Valid Ya so the responder gets past DH...
        let (_xa, ya) = generate_dh_keypair();
        client_io.write_all(&dh_public_to_bytes(&ya)).await.unwrap();
        // ...then a flood that can never match req1(S) (constant byte can't equal
        // a 20-byte SHA1 marker). Bounded amount, larger than any legal scan.
        let _ = client_io.write_all(&[0xACu8; 4096]).await;

        let res = tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
            .await
            .expect("responder resync must terminate (bounded), not hang")
            .unwrap();
        assert!(
            matches!(res, Err(TunnelCryptoError::ResyncNotFound)),
            "expected bounded ResyncNotFound",
        );
    }
}
