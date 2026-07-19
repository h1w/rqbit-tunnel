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

// ── Action Type ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub(crate) enum CarrierAction {
    OutgoingMessage(Message<'static>),
    Disconnect(String),
}

// ── Cached Piece-Layer Metadata ──────────────────────────────────────────────

struct CarrierPieceLayer {
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

    fn verify_block(
        &self,
        piece_index: u32,
        begin: u32,
        block: &[u8],
    ) -> Result<(), TunnelCarrierError> {
        let idx = piece_index as usize;
        let block_len = block.len() as u32;

        if idx >= self.npieces() {
            return Err(TunnelCarrierError::InvalidRequest {
                reason: format!(
                    "piece index {piece_index} out of range (max {})",
                    self.npieces().saturating_sub(1),
                ),
            });
        }

        if begin + block_len > self.piece_length {
            return Err(TunnelCarrierError::InvalidRequest {
                reason: format!(
                    "block overflow: begin={begin} + length={block_len} > piece_length={}",
                    self.piece_length,
                ),
            });
        }

        let leaf_hash = sha256_hash(block);

        let expected = &self.leaf_hashes[idx];
        if leaf_hash != *expected {
            return Err(TunnelCarrierError::PieceHashMismatch {
                index: piece_index,
                expected: hex::encode(expected.0),
                actual: hex::encode(leaf_hash.0),
            });
        }

        Ok(())
    }
}

// ── Carrier Peer ─────────────────────────────────────────────────────────────

pub(crate) struct TunnelCarrierPeer {
    carrier: Arc<TunnelCarrierStore>,
    remote_have: BitBox<u8, Msb0>,
    local_choked: bool,
    remote_choked: bool,
    layer: CarrierPieceLayer,
}

impl TunnelCarrierPeer {
    pub fn new(carrier: Arc<TunnelCarrierStore>) -> Result<Self, TunnelCarrierError> {
        let layer = CarrierPieceLayer::from_descriptor(&carrier.descriptor().metainfo)?;
        Ok(Self {
            remote_have: bitvec::bitbox![u8, Msb0; 0; layer.npieces()],
            local_choked: false,
            remote_choked: true,
            carrier,
            layer,
        })
    }

    // ── Initial messages ──────────────────────────────────────────────────

    pub fn initial_messages(&self) -> Vec<Message<'static>> {
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

        let leaked: &'static [u8] = Box::leak(buf.into_boxed_slice());
        vec![Message::Bitfield(ByteBuf(leaked)), Message::Unchoke]
    }

    // ── Message dispatch ──────────────────────────────────────────────────

    pub async fn on_message(
        &mut self,
        message: Message<'_>,
    ) -> Result<Vec<CarrierAction>, TunnelCarrierError> {
        match message {
            Message::Request(req) => self.on_request(req).await,
            Message::Piece(piece) => self.on_piece(piece),
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

        let leaked: &'static [u8] = Box::leak(block.to_vec().into_boxed_slice());
        let piece_msg = Message::Piece(Piece::from_data(idx, begin, leaked));

        Ok(vec![CarrierAction::OutgoingMessage(piece_msg)])
    }

    fn on_piece(
        &mut self,
        piece: Piece<ByteBuf<'_>>,
    ) -> Result<Vec<CarrierAction>, TunnelCarrierError> {
        let (block_0, block_1) = piece.data();

        // Validate block_0
        if !block_0.is_empty() {
            self.layer.verify_block(piece.index, piece.begin, block_0)?;
        }

        // Validate block_1
        if !block_1.is_empty() {
            self.layer
                .verify_block(piece.index, piece.begin + block_0.len() as u32, block_1)?;
        }

        // Mark piece as available on the remote
        if let Some(mut bit) = self.remote_have.get_mut(piece.index as usize) {
            *bit = true;
        }

        Ok(vec![])
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
        }
    }
    async fn test_store() -> (Arc<TunnelCarrierStore>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = TunnelCarrierStore::open_or_initialize(dir.path(), &test_config())
            .await
            .unwrap();
        (Arc::new(store), dir)
    }

    async fn test_peer() -> (TunnelCarrierPeer, tempfile::TempDir) {
        let (store, dir) = test_store().await;
        (TunnelCarrierPeer::new(store).unwrap(), dir)
    }

    // ── Initial messages ──────────────────────────────────────────────────

    #[tokio::test]
    async fn initial_messages_sends_bitfield_and_unchoke() {
        let (peer, _dir) = test_peer().await;
        let msgs = peer.initial_messages();

        assert_eq!(msgs.len(), 2, "expected bitfield + unchoke");

        // First message should be Bitfield
        let bitfield = match &msgs[0] {
            Message::Bitfield(bf) => bf.as_ref(),
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
        assert!(matches!(msgs[1], Message::Unchoke), "expected Unchoke");
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
            CarrierAction::OutgoingMessage(Message::Piece(piece)) => {
                assert_eq!(piece.index, 0);
                assert_eq!(piece.begin, 0);
                // Full 16KiB piece
                let (b0, b1) = piece.data();
                let total = b0.len() + b1.len();
                assert_eq!(total, 16384, "expected 16384-byte piece");
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
}
