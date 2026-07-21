use std::sync::Arc;

use bitvec::{boxed::BitBox, order::Msb0};
use buffers::ByteBuf;
use bytes::Bytes;
use librqbit_core::{Id32, torrent_metainfo_v2::torrent_v2_from_bytes};
use peer_binary_protocol::{Message, Piece, Request};
use sha2::{Digest, Sha256};

use super::carrier::{TunnelCarrierStore, ValidPieceIndex};

// ── Error Type ────────────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub(crate) enum TunnelCarrierError {
    #[error("piece hash mismatch at index {index}: expected {expected}, got {actual}")]
    PieceHashMismatch {
        index: u32,
        expected: String,
        actual: String,
    },

    #[error("invalid request: {reason}")]
    InvalidRequest { reason: String },

    #[error("invalid bitfield: expected {expected} bytes, got {actual}")]
    InvalidBitfield { expected: usize, actual: usize },

    #[error("carrier store error: {0}")]
    Store(#[from] anyhow::Error),
}

// ── Cover message (owned) ────────────────────────────────────────────────────

/// An OWNED cover-traffic peer message.
///
/// The carrier serves plausible BitTorrent cover (Bitfield/Piece/…) on the LIVE
/// path — on every inbound `Request`, and during the pre-Noise early-cover loop
/// in [`CarrierWire::establish`]. Carrying a borrowed `Message<'static>` there
/// forced a permanent heap leak to synthesize the `'static` lifetime,
/// leaking the block bytes on every request (an unbounded, amplifiable leak).
///
/// Instead we carry this owned value across the action/cover channels and turn
/// it into a borrowed [`Message<'_>`] only at the serialize site via
/// [`CoverMessage::to_message`] — no leaked `'static` bytes.
#[derive(Debug)]
pub(crate) enum CoverMessage {
    Bitfield(bytes::Bytes),
    Unchoke,
    Interested,
    Choke,
    NotInterested,
    Have(u32),
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        data: bytes::Bytes,
    },
    KeepAlive,
}

impl CoverMessage {
    /// Borrow this owned cover message as a wire [`Message`] for serialization.
    pub(crate) fn to_message(&self) -> peer_binary_protocol::Message<'_> {
        use buffers::ByteBuf;
        use peer_binary_protocol::{Message, Piece, Request};
        match self {
            CoverMessage::Bitfield(b) => Message::Bitfield(ByteBuf(b)),
            CoverMessage::Unchoke => Message::Unchoke,
            CoverMessage::Interested => Message::Interested,
            CoverMessage::Choke => Message::Choke,
            CoverMessage::NotInterested => Message::NotInterested,
            CoverMessage::Have(i) => Message::Have(*i),
            CoverMessage::Request {
                index,
                begin,
                length,
            } => Message::Request(Request::new(*index, *begin, *length)),
            CoverMessage::Piece { index, begin, data } => {
                Message::Piece(Piece::from_data(*index, *begin, data))
            }
            CoverMessage::KeepAlive => Message::KeepAlive,
        }
    }
}

// ── Action Type ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub(crate) enum CarrierAction {
    OutgoingMessage(CoverMessage),
    // Reserved for a future graceful-disconnect signal distinct from a hard
    // protocol error (every `on_message` violation currently surfaces as an
    // `Err(TunnelCarrierError)`, which callers already treat as terminal); no
    // handler constructs this yet.
    #[allow(dead_code)]
    Disconnect(String),
}

// ── Cached Piece-Layer Metadata ──────────────────────────────────────────────

struct CarrierPieceLayer {
    // Retained for future diagnostics (e.g. logging the root on a validation
    // failure); only used as a local lookup key during construction today.
    #[allow(dead_code)]
    pieces_root: Id32,
    leaf_hashes: Vec<Id32>,
    piece_length: u32,
    bitfield_bytes: usize,
}

impl CarrierPieceLayer {
    fn from_descriptor(metainfo: &Bytes) -> Result<Self, TunnelCarrierError> {
        let parsed = torrent_v2_from_bytes(metainfo).map_err(|e| {
            TunnelCarrierError::Store(anyhow::anyhow!("parse carrier metainfo: {e}"))
        })?;

        let validated = parsed
            .info
            .data
            .validate(&parsed.piece_layers)
            .map_err(|e| {
                TunnelCarrierError::Store(anyhow::anyhow!("validate carrier metainfo: {e}"))
            })?;

        let files = validated.files();
        let pieces_root = files.iter().find_map(|f| f.pieces_root).ok_or_else(|| {
            TunnelCarrierError::Store(anyhow::anyhow!("carrier metainfo has no pieces_root"))
        })?;

        let raw_hashes = parsed.piece_layers.get(&pieces_root).ok_or_else(|| {
            TunnelCarrierError::Store(anyhow::anyhow!(
                "carrier piece layers missing root {}",
                hex::encode(pieces_root.0),
            ))
        })?;

        let piece_length = validated.info().piece_length;
        let raw = raw_hashes.as_ref();
        if raw.len() % 32 != 0 {
            return Err(TunnelCarrierError::Store(anyhow::anyhow!(
                "carrier piece layer bytes not aligned to 32: len={}",
                raw.len(),
            )));
        }

        let leaf_hashes: Vec<Id32> = raw
            .chunks(32)
            .map(|chunk| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(chunk);
                Id32::new(arr)
            })
            .collect();

        let bitfield_bytes = leaf_hashes.len().div_ceil(8);

        Ok(Self {
            pieces_root,
            leaf_hashes,
            piece_length,
            bitfield_bytes,
        })
    }

    fn npieces(&self) -> usize {
        self.leaf_hashes.len()
    }
}

// ── Carrier Peer ─────────────────────────────────────────────────────────────

pub(crate) struct TunnelCarrierPeer {
    carrier: Arc<TunnelCarrierStore>,
    remote_have: BitBox<u8, Msb0>,
    /// Whether WE are choking this peer — i.e. refusing to answer its
    /// `Request`s with `Piece`s. Gates `on_request` (Plan B Task 2: seeder
    /// realism + a pre-auth resource bound). Starts choked; `initial_messages`
    /// optimistically unchokes (matching real BT clients, which commonly
    /// extend an initial optimistic unchoke before deciding whether to keep
    /// serving), and `server.rs`'s upload-slot admission may immediately
    /// re-choke right after if no slot is free. `on_request` also forces this
    /// back to `true` once `MAX_SEEDER_PIECES_PER_CONN` is reached, mimicking
    /// a real overloaded seeder.
    local_choked: bool,
    remote_choked: bool,
    /// Count of `Piece`s served to this peer's `Request`s this connection.
    /// Capped at `MAX_SEEDER_PIECES_PER_CONN` — see `local_choked`.
    pieces_served: usize,
    layer: CarrierPieceLayer,
}

impl TunnelCarrierPeer {
    pub fn new(carrier: Arc<TunnelCarrierStore>) -> Result<Self, TunnelCarrierError> {
        let layer = CarrierPieceLayer::from_descriptor(&carrier.descriptor().metainfo)?;
        Ok(Self {
            remote_have: bitvec::bitbox![u8, Msb0; 0; layer.npieces()],
            local_choked: true,
            remote_choked: true,
            pieces_served: 0,
            carrier,
            layer,
        })
    }

    // ── Choke state (Plan B Task 2: upload slots) ─────────────────────────

    /// Set whether we are choking this peer. `false` (unchoked) lets
    /// `on_request` actually serve `Piece`s; `true` makes it a silent no-op —
    /// exactly real BT choke semantics (a choked peer's `Request`s just go
    /// unanswered, no explicit rejection). Called by `server.rs`'s
    /// upload-slot admission.
    pub(crate) fn set_local_choked(&mut self, choked: bool) {
        self.local_choked = choked;
    }

    /// Whether we are currently choking this peer. Test-only: production code
    /// only ever SETS this (`set_local_choked`); the enforcement itself lives
    /// in `on_request`.
    #[cfg(test)]
    pub(crate) fn is_local_choked(&self) -> bool {
        self.local_choked
    }

    /// Reset the per-connection pieces-served counter (Plan B, Fix M1). Called
    /// by `server.rs`'s `accept` on promotion so the PRE-AUTH pieces cap
    /// (`MAX_SEEDER_PIECES_PER_CONN`) never carries into the authenticated relay
    /// and self-chokes post-auth cover mid-session if its cadence ever grows.
    pub(crate) fn reset_pieces_served(&mut self) {
        self.pieces_served = 0;
    }

    /// The number of `Piece`s served to this peer this connection. Test-only:
    /// used to assert the pre-auth counter is reset on promotion (Fix M1).
    #[cfg(test)]
    pub(crate) fn pieces_served(&self) -> usize {
        self.pieces_served
    }

    // ── Initial messages ──────────────────────────────────────────────────

    pub fn initial_messages(&mut self) -> Vec<CoverMessage> {
        let have = self.carrier.have_bitfield();
        let bitfield_bytes = have.len().div_ceil(8);
        let mut buf = vec![0u8; bitfield_bytes];

        // Copy bitfield bits into byte buffer (Msb0 → network-order bitfield)
        for (i, bit) in have.iter().by_vals().enumerate() {
            if bit {
                let byte_idx = i / 8;
                let bit_idx = 7 - (i % 8); // Msb0: piece 0 → MSB of byte 0
                buf[byte_idx] |= 1 << bit_idx;
            }
        }

        // Optimistic unchoke at connect (see `local_choked`'s doc comment).
        self.local_choked = false;

        vec![
            CoverMessage::Bitfield(bytes::Bytes::from(buf)),
            CoverMessage::Unchoke,
        ]
    }

    // ── Message dispatch ──────────────────────────────────────────────────

    pub async fn on_message(
        &mut self,
        message: Message<'_>,
    ) -> Result<Vec<CarrierAction>, TunnelCarrierError> {
        match message {
            Message::Request(req) => self.on_request(req).await,
            Message::Piece(piece) => self.on_piece(piece).await,
            Message::Bitfield(bf) => self.on_bitfield(bf),
            Message::Have(index) => Ok(self.on_have(index)),
            Message::Choke => Ok(self.on_choke()),
            Message::Unchoke => Ok(self.on_unchoke()),
            Message::Interested | Message::NotInterested => Ok(vec![]),
            Message::KeepAlive => Ok(vec![]),
            Message::Extended(_) => Ok(vec![]),
            Message::Cancel(_) => Ok(vec![]),
        }
    }

    // ── Handlers ──────────────────────────────────────────────────────────

    async fn on_request(&mut self, req: Request) -> Result<Vec<CarrierAction>, TunnelCarrierError> {
        // A choked peer's `Request`s go unanswered — real BT choke semantics
        // (silence, not an explicit rejection) and the primary pre-auth
        // resource bound here: no disk read, no `Piece` write, no serialize.
        if self.local_choked {
            return Ok(vec![]);
        }

        let idx = req.index;
        let begin = req.begin;
        let length = req.length;

        // Validate range
        if idx as usize >= self.layer.npieces() {
            return Err(TunnelCarrierError::InvalidRequest {
                reason: format!(
                    "request index {idx} out of range (max {})",
                    self.layer.npieces().saturating_sub(1),
                ),
            });
        }

        if begin.saturating_add(length) > self.layer.piece_length {
            return Err(TunnelCarrierError::InvalidRequest {
                reason: format!(
                    "request range overflow: begin={begin} + length={length} > piece_length={}",
                    self.layer.piece_length,
                ),
            });
        }

        if length == 0 {
            return Err(TunnelCarrierError::InvalidRequest {
                reason: "zero-length request".into(),
            });
        }

        // Read the piece data
        let piece_len = self.layer.piece_length as usize;
        let mut buf = vec![0u8; piece_len];
        self.carrier
            .read_piece(ValidPieceIndex(idx), &mut buf)
            .await
            .map_err(TunnelCarrierError::Store)?;

        let block = if (begin as usize) + (length as usize) <= buf.len() {
            &buf[(begin as usize)..][..(length as usize)]
        } else {
            return Err(TunnelCarrierError::InvalidRequest {
                reason: format!(
                    "request range [{begin}, {}+{}) = [{}, {}) exceeds piece_len {piece_len}",
                    begin,
                    length,
                    begin,
                    begin + length,
                ),
            });
        };

        let piece_msg = CoverMessage::Piece {
            index: idx,
            begin,
            data: bytes::Bytes::copy_from_slice(block),
        };
        let mut actions = vec![CarrierAction::OutgoingMessage(piece_msg)];

        // Per-connection pieces-served cap (Plan B Task 2): after serving
        // `MAX_SEEDER_PIECES_PER_CONN` pieces to this peer, self-choke — a
        // real overloaded seeder stops serving rather than serving forever.
        // A legitimate client authenticates almost immediately and never
        // comes close to this cap.
        self.pieces_served += 1;
        if self.pieces_served >= super::config::MAX_SEEDER_PIECES_PER_CONN {
            self.local_choked = true;
            actions.push(CarrierAction::OutgoingMessage(CoverMessage::Choke));
        }

        Ok(actions)
    }

    async fn on_piece(
        &mut self,
        piece: Piece<ByteBuf<'_>>,
    ) -> Result<Vec<CarrierAction>, TunnelCarrierError> {
        let (block_0, block_1) = piece.data();

        // Validate block_0
        if !block_0.is_empty() {
            self.verify_block(piece.index, piece.begin, block_0).await?;
        }

        // Validate block_1
        if !block_1.is_empty() {
            self.verify_block(piece.index, piece.begin + block_0.len() as u32, block_1)
                .await?;
        }

        // Mark piece as available on the remote
        if let Some(mut bit) = self.remote_have.get_mut(piece.index as usize) {
            *bit = true;
        }

        Ok(vec![])
    }

    /// Verify an incoming piece BLOCK against the local copy of the carrier
    /// corpus. The carrier is a synthetic torrent both endpoints generate (or
    /// open) deterministically from the same seed, so a received block can be
    /// checked directly against the corresponding byte range of the local
    /// piece.
    ///
    /// This is deliberately NOT a lookup against `self.layer.leaf_hashes`: the
    /// piece layer's hashes each cover a WHOLE `piece_length`-sized piece
    /// (see `carrier.rs::hash_piece`), while real BT peers — and the minimal
    /// piece cover wired into `ClientMux::new` — request/respond in
    /// individual blocks well below `piece_length` (bounded by `MAX_MSG_LEN`).
    /// Hashing a partial block and comparing it to a whole-piece hash would
    /// always mismatch whenever `piece_length` exceeds one block, which is
    /// the normal case (`CARRIER_PIECE_LENGTH` is 256 KiB).
    async fn verify_block(
        &self,
        piece_index: u32,
        begin: u32,
        block: &[u8],
    ) -> Result<(), TunnelCarrierError> {
        let idx = piece_index as usize;

        if idx >= self.layer.npieces() {
            return Err(TunnelCarrierError::InvalidRequest {
                reason: format!(
                    "piece index {piece_index} out of range (max {})",
                    self.layer.npieces().saturating_sub(1),
                ),
            });
        }

        // Compute the end of the block range in `usize` via checked arithmetic
        // so an attacker-controlled `begin` near `u32::MAX` cannot wrap the
        // bounds check (as plain u32 addition would) and then panic on the
        // out-of-range slice below.
        let begin_usize = begin as usize;
        let end = begin_usize.checked_add(block.len()).ok_or_else(|| {
            TunnelCarrierError::InvalidRequest {
                reason: format!(
                    "block overflow: begin={begin} + length={} overflows usize",
                    block.len(),
                ),
            }
        })?;

        if end > self.layer.piece_length as usize {
            return Err(TunnelCarrierError::InvalidRequest {
                reason: format!(
                    "block overflow: begin={begin} + length={} > piece_length={}",
                    block.len(),
                    self.layer.piece_length,
                ),
            });
        }

        let piece_len = self.layer.piece_length as usize;
        let mut local = vec![0u8; piece_len];
        self.carrier
            .read_piece(ValidPieceIndex(piece_index), &mut local)
            .await
            .map_err(TunnelCarrierError::Store)?;

        let expected = &local[begin_usize..end];
        if expected != block {
            return Err(TunnelCarrierError::PieceHashMismatch {
                index: piece_index,
                expected: hex::encode(sha256_hash(expected).0),
                actual: hex::encode(sha256_hash(block).0),
            });
        }

        Ok(())
    }

    fn on_bitfield(&mut self, bf: ByteBuf<'_>) -> Result<Vec<CarrierAction>, TunnelCarrierError> {
        let data = bf.as_ref();
        let expected = self.layer.bitfield_bytes;

        if data.len() != expected {
            return Err(TunnelCarrierError::InvalidBitfield {
                expected,
                actual: data.len(),
            });
        }

        // Copy bitfield bits into remote_have (Msb0 ordering)
        for byte_idx in 0..data.len() {
            let byte = data[byte_idx];
            for bit_idx in 0..8 {
                let piece_idx = byte_idx * 8 + bit_idx;
                if piece_idx >= self.layer.npieces() {
                    break;
                }
                if (byte >> (7 - bit_idx)) & 1 == 1 {
                    if let Some(mut bit) = self.remote_have.get_mut(piece_idx) {
                        *bit = true;
                    }
                }
            }
        }

        Ok(vec![])
    }

    fn on_have(&mut self, index: u32) -> Vec<CarrierAction> {
        if let Some(mut bit) = self.remote_have.get_mut(index as usize) {
            *bit = true;
        }
        vec![]
    }

    fn on_choke(&mut self) -> Vec<CarrierAction> {
        self.remote_choked = true;
        vec![]
    }

    fn on_unchoke(&mut self) -> Vec<CarrierAction> {
        self.remote_choked = false;
        vec![]
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn sha256_hash(data: &[u8]) -> Id32 {
    let mut digest = Sha256::new();
    digest.update(data);
    let mut hash = [0; 32];
    hash.copy_from_slice(&digest.finalize());
    Id32::new(hash)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::carrier::TunnelCarrierConfig;
    use super::*;

    const TEST_CORPUS: u64 = 65536;
    const TEST_PIECE_LEN: u32 = 16384;

    fn test_config() -> TunnelCarrierConfig {
        TunnelCarrierConfig {
            corpus_bytes: TEST_CORPUS,
            piece_length: TEST_PIECE_LEN,
            display_name: "peer-test".into(),
            seed: [0u8; 32],
        }
    }
    async fn test_store() -> (Arc<TunnelCarrierStore>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = TunnelCarrierStore::open_or_initialize(dir.path(), &test_config())
            .await
            .unwrap();
        (Arc::new(store), dir)
    }

    /// Builds an UNCHOKED peer (as if it had already been granted an upload
    /// slot) — the request-handling / bitfield / piece tests below are about
    /// validation and cover-serving logic, not the new choke gating (Plan B
    /// Task 2, covered separately below), so they need a peer that actually
    /// serves. `TunnelCarrierPeer::new` alone now starts CHOKED (a real
    /// seeder's default) — see the "Local choke gating" tests below for that.
    async fn test_peer() -> (TunnelCarrierPeer, tempfile::TempDir) {
        let (store, dir) = test_store().await;
        let mut peer = TunnelCarrierPeer::new(store).unwrap();
        peer.set_local_choked(false);
        (peer, dir)
    }

    // ── Initial messages ──────────────────────────────────────────────────

    #[tokio::test]
    async fn initial_messages_sends_bitfield_and_unchoke() {
        let (mut peer, _dir) = test_peer().await;
        let msgs = peer.initial_messages();

        assert_eq!(msgs.len(), 2, "expected bitfield + unchoke");

        // First message should be Bitfield
        let bitfield = match &msgs[0] {
            CoverMessage::Bitfield(bf) => bf.as_ref(),
            other => panic!("expected Bitfield, got {other:?}"),
        };

        let npieces = (TEST_CORPUS / TEST_PIECE_LEN as u64) as usize; // 4 pieces
        let expected_bytes = npieces.div_ceil(8); // 1 byte
        assert_eq!(bitfield.len(), expected_bytes, "bitfield size mismatch");

        // All four pieces set (0xF0 in Msb0)
        assert_eq!(
            bitfield[0], 0xF0,
            "all pieces should be set (got {:#04x})",
            bitfield[0]
        );

        // Second message should be Unchoke
        assert!(matches!(msgs[1], CoverMessage::Unchoke), "expected Unchoke");
    }

    // ── Request handling ──────────────────────────────────────────────────

    #[tokio::test]
    async fn serves_requested_block() {
        let (mut peer, _dir) = test_peer().await;

        let actions = peer
            .on_message(Message::Request(Request::new(0, 0, 16384)))
            .await
            .unwrap();

        assert_eq!(actions.len(), 1, "expected one Piece action");
        match &actions[0] {
            CarrierAction::OutgoingMessage(CoverMessage::Piece { index, begin, data }) => {
                assert_eq!(*index, 0);
                assert_eq!(*begin, 0);
                // Full 16KiB piece
                assert_eq!(data.len(), 16384, "expected 16384-byte piece");
            }
            other => panic!("expected Piece, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_request_out_of_range() {
        let (mut peer, _dir) = test_peer().await;

        // 4 pieces (0..3), piece 4 is out of range
        let result = peer
            .on_message(Message::Request(Request::new(4, 0, 16384)))
            .await;

        assert!(
            matches!(result, Err(TunnelCarrierError::InvalidRequest { .. })),
            "expected InvalidRequest, got {result:?}",
        );
    }

    #[tokio::test]
    async fn rejects_request_with_begin_exceeding_piece_length() {
        let (mut peer, _dir) = test_peer().await;

        // begin >= piece_length is invalid
        let result = peer
            .on_message(Message::Request(Request::new(0, 32768, 1)))
            .await;

        assert!(
            matches!(result, Err(TunnelCarrierError::InvalidRequest { .. })),
            "expected InvalidRequest, got {result:?}",
        );
    }

    #[tokio::test]
    async fn rejects_request_with_overflowing_range() {
        let (mut peer, _dir) = test_peer().await;

        // begin + length > piece_length
        let result = peer
            .on_message(Message::Request(Request::new(0, 16000, 1024)))
            .await;

        assert!(
            matches!(result, Err(TunnelCarrierError::InvalidRequest { .. })),
            "expected InvalidRequest, got {result:?}",
        );
    }

    #[tokio::test]
    async fn rejects_zero_length_request() {
        let (mut peer, _dir) = test_peer().await;

        let result = peer
            .on_message(Message::Request(Request::new(0, 0, 0)))
            .await;

        assert!(
            matches!(result, Err(TunnelCarrierError::InvalidRequest { .. })),
            "expected InvalidRequest, got {result:?}",
        );
    }

    // ── Piece handling ────────────────────────────────────────────────────

    #[tokio::test]
    async fn accepts_valid_piece() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            TunnelCarrierStore::open_or_initialize(dir.path(), &test_config())
                .await
                .unwrap(),
        );
        let mut peer = TunnelCarrierPeer::new(store.clone()).unwrap();

        // Read piece 0 from the store to get valid data
        let mut piece_data = vec![0u8; TEST_PIECE_LEN as usize];
        store
            .read_piece(ValidPieceIndex(0), &mut piece_data)
            .await
            .unwrap();

        // Send the valid piece
        let result = peer
            .on_message(Message::Piece(Piece::from_data(0, 0, &piece_data)))
            .await
            .unwrap();

        assert!(
            result.is_empty(),
            "accepting valid piece should produce no actions"
        );
        assert!(
            peer.remote_have[0],
            "piece 0 should be marked as have on remote"
        );
        drop(store);
        drop(dir);
    }

    #[tokio::test]
    async fn rejects_piece_whose_v2_root_does_not_match() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            TunnelCarrierStore::open_or_initialize(dir.path(), &test_config())
                .await
                .unwrap(),
        );
        let mut peer = TunnelCarrierPeer::new(store.clone()).unwrap();

        // Read piece 0, then flip a byte
        let mut piece_data = vec![0u8; TEST_PIECE_LEN as usize];
        store
            .read_piece(ValidPieceIndex(0), &mut piece_data)
            .await
            .unwrap();
        piece_data[42] ^= 0xFF;

        let result = peer
            .on_message(Message::Piece(Piece::from_data(0, 0, &piece_data)))
            .await;
        assert!(
            matches!(result, Err(TunnelCarrierError::PieceHashMismatch { .. })),
            "expected PieceHashMismatch, got {result:?}",
        );
        drop(store);
        drop(dir);
    }

    #[tokio::test]
    async fn rejects_piece_with_out_of_range_index() {
        let (mut peer, _dir) = test_peer().await;

        // Piece index out of range
        let dummy = [0u8; 64];
        let result = peer
            .on_message(Message::Piece(Piece::from_data(99, 0, &dummy)))
            .await;

        assert!(
            matches!(result, Err(TunnelCarrierError::InvalidRequest { .. })),
            "expected InvalidRequest for out-of-range piece, got {result:?}",
        );
    }

    #[tokio::test]
    async fn rejects_piece_with_overflowing_begin_without_panicking() {
        let (mut peer, _dir) = test_peer().await;
        let block = [0u8; 16];
        let result = peer
            .on_message(Message::Piece(Piece::from_data(0, u32::MAX - 4, &block)))
            .await;
        assert!(
            matches!(result, Err(TunnelCarrierError::InvalidRequest { .. })),
            "expected InvalidRequest, got {result:?}",
        );
    }

    // ── Bitfield handling ─────────────────────────────────────────────────

    #[tokio::test]
    async fn accepts_correct_sized_bitfield() {
        let (mut peer, _dir) = test_peer().await;

        // 4 pieces → 1 byte bitfield, bits for pieces 0 and 2 set
        let bitfield_byte = 0b1010_0000u8; // Msb0: pieces 0 and 2
        let result = peer
            .on_message(Message::Bitfield(ByteBuf(&[bitfield_byte])))
            .await
            .unwrap();

        assert!(result.is_empty(), "bitfield should produce no actions");
        assert!(peer.remote_have[0], "piece 0 should be set");
        assert!(!peer.remote_have[1], "piece 1 should not be set");
        assert!(peer.remote_have[2], "piece 2 should be set");
        assert!(!peer.remote_have[3], "piece 3 should not be set");
    }

    #[tokio::test]
    async fn rejects_wrong_sized_bitfield() {
        let (mut peer, _dir) = test_peer().await;

        let result = peer.on_message(Message::Bitfield(ByteBuf(&[0u8; 3]))).await;

        assert!(
            matches!(result, Err(TunnelCarrierError::InvalidBitfield { .. })),
            "expected InvalidBitfield, got {result:?}",
        );
    }

    // ── Have handling ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn have_sets_remote_bit() {
        let (mut peer, _dir) = test_peer().await;

        let actions = peer.on_message(Message::Have(2)).await.unwrap();
        assert!(actions.is_empty());
        assert!(peer.remote_have[2], "piece 2 should be set");
        assert!(!peer.remote_have[0], "piece 0 should not be set");
    }

    // ── Choke / Unchoke ───────────────────────────────────────────────────

    #[tokio::test]
    async fn choke_sets_remote_choked() {
        let (mut peer, _dir) = test_peer().await;

        assert!(peer.remote_choked, "initial remote_choked should be true");

        let actions = peer.on_message(Message::Unchoke).await.unwrap();
        assert!(actions.is_empty());
        assert!(!peer.remote_choked);

        let actions = peer.on_message(Message::Choke).await.unwrap();
        assert!(actions.is_empty());
        assert!(peer.remote_choked);
    }

    // ── No-ops ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn interested_and_keepalive_are_no_ops() {
        let (mut peer, _dir) = test_peer().await;

        let actions = peer.on_message(Message::Interested).await.unwrap();
        assert!(actions.is_empty());

        let actions = peer.on_message(Message::NotInterested).await.unwrap();
        assert!(actions.is_empty());

        let actions = peer.on_message(Message::KeepAlive).await.unwrap();
        assert!(actions.is_empty());
    }

    // ── Local choke gating (Plan B Task 2: upload slots) ───────────────────
    //
    // Distinct from `remote_choked` above (which tracks whether the REMOTE
    // peer is choking US): `local_choked` gates whether WE serve `Piece`s to
    // THEIR `Request`s — the seeder-realism + pre-auth resource bound this
    // task adds.

    #[tokio::test]
    async fn choked_peer_request_yields_no_piece_until_unchoked() {
        let (store, _dir) = test_store().await;
        let mut peer = TunnelCarrierPeer::new(store).unwrap();

        // A brand-new peer starts choked: a real seeder's default.
        assert!(peer.is_local_choked(), "new peer must start locally choked");

        let actions = peer
            .on_message(Message::Request(Request::new(0, 0, 16384)))
            .await
            .unwrap();
        assert!(
            actions.is_empty(),
            "a choked peer's Request must yield NO Piece, got {actions:?}"
        );

        // Grant an upload slot (what `server.rs`'s admission does on success).
        peer.set_local_choked(false);
        assert!(!peer.is_local_choked());

        let actions = peer
            .on_message(Message::Request(Request::new(0, 0, 16384)))
            .await
            .unwrap();
        assert_eq!(actions.len(), 1, "expected one Piece action once unchoked");
        assert!(
            matches!(
                &actions[0],
                CarrierAction::OutgoingMessage(CoverMessage::Piece { .. })
            ),
            "expected Piece, got {actions:?}"
        );
    }

    #[tokio::test]
    async fn rechoking_stops_further_service() {
        let (mut peer, _dir) = test_peer().await; // starts unchoked

        let actions = peer
            .on_message(Message::Request(Request::new(0, 0, 16384)))
            .await
            .unwrap();
        assert_eq!(actions.len(), 1, "expected a Piece while unchoked");

        peer.set_local_choked(true);
        let actions = peer
            .on_message(Message::Request(Request::new(0, 0, 16384)))
            .await
            .unwrap();
        assert!(
            actions.is_empty(),
            "expected no Piece once re-choked, got {actions:?}"
        );
    }

    // ── Per-connection pieces-served cap (Plan B Task 2) ───────────────────

    #[tokio::test]
    async fn pieces_cap_self_chokes_after_max_served() {
        use super::super::config::MAX_SEEDER_PIECES_PER_CONN;

        let (mut peer, _dir) = test_peer().await; // starts unchoked

        // Serve exactly the cap's worth of pieces; every one must be served.
        for n in 0..MAX_SEEDER_PIECES_PER_CONN {
            let actions = peer
                .on_message(Message::Request(Request::new(0, 0, 16384)))
                .await
                .unwrap();
            let has_piece = actions.iter().any(|a| {
                matches!(
                    a,
                    CarrierAction::OutgoingMessage(CoverMessage::Piece { .. })
                )
            });
            assert!(has_piece, "request {n} (within cap) must be served");
        }

        // The cap must have flipped local_choked and emitted an explicit
        // Choke somewhere along the way (on the Nth, cap-reaching request).
        assert!(
            peer.is_local_choked(),
            "peer must be self-choked once the pieces cap is reached"
        );

        // The (N+1)th Request must NOT be served.
        let actions = peer
            .on_message(Message::Request(Request::new(0, 0, 16384)))
            .await
            .unwrap();
        assert!(
            actions.is_empty(),
            "request beyond the pieces cap must not be served, got {actions:?}"
        );
    }

    #[tokio::test]
    async fn pieces_cap_reaching_request_emits_explicit_choke() {
        use super::super::config::MAX_SEEDER_PIECES_PER_CONN;

        let (mut peer, _dir) = test_peer().await; // starts unchoked

        let mut saw_choke = false;
        for _ in 0..MAX_SEEDER_PIECES_PER_CONN {
            let actions = peer
                .on_message(Message::Request(Request::new(0, 0, 16384)))
                .await
                .unwrap();
            if actions
                .iter()
                .any(|a| matches!(a, CarrierAction::OutgoingMessage(CoverMessage::Choke)))
            {
                saw_choke = true;
            }
        }
        assert!(
            saw_choke,
            "the request that reaches the pieces cap must emit an explicit Choke"
        );
    }
}
