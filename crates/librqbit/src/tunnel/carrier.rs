use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use bitvec::{boxed::BitBox, order::Msb0, slice::BitSlice};
use bytes::Bytes;
use librqbit_core::{
    Id20, Id32,
    torrent_metainfo_v2::{info_hash_v2, merkle_root, torrent_v2_from_bytes},
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use sha2::Digest;

// ── Config & Public Types ────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub(crate) struct TunnelCarrierConfig {
    pub corpus_bytes: u64,
    pub piece_length: u32,
    pub display_name: String,
    /// Deterministic seed for the corpus RNG. Both endpoints derive this from
    /// the shared carrier hash so they generate byte-identical torrents.
    pub seed: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelCarrierDescriptor {
    pub info_hash: Id32,
    pub handshake_info_hash: Id20,
    #[serde(with = "serde_bytes_helpers")]
    pub metainfo: Bytes,
}

/// A validated piece index that is guaranteed to be in-range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidPieceIndex(pub u32);

// ── Serde helpers for `Bytes` ────────────────────────────────────────────────

mod serde_bytes_helpers {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Bytes, D::Error> {
        let v: Vec<u8> = Vec::deserialize(deserializer)?;
        Ok(Bytes::from(v))
    }
}

// ── Constants ────────────────────────────────────────────────────────────────

const DESCRIPTOR_FILENAME: &str = "carrier-descriptor.bin";
const CORPUS_FILENAME: &str = "carrier-corpus";

// ── Bencode helpers ──────────────────────────────────────────────────────────

fn bencode_bytes(w: &mut Vec<u8>, data: &[u8]) {
    write!(w, "{}:", data.len()).expect("infallible: write to Vec");
    w.extend_from_slice(data);
}

fn bencode_int(w: &mut Vec<u8>, n: i64) {
    write!(w, "i{}e", n).expect("infallible: write to Vec");
}

fn bencode_dict_start(w: &mut Vec<u8>) {
    w.push(b'd');
}

fn bencode_dict_end(w: &mut Vec<u8>) {
    w.push(b'e');
}

fn piece_count(size: u64, piece_length: u32) -> usize {
    size.div_ceil(u64::from(piece_length)) as usize
}

fn hash_piece(data: &[u8]) -> Id32 {
    let digest = sha2::Sha256::digest(data);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Id32::new(bytes)
}

// ── Build v2 metainfo bytes (bencode) ────────────────────────────────────────

/// Returns `(info_dict_bytes, full_metainfo_bytes)`.
fn build_metainfo(
    display_name: &str,
    corpus_bytes: u64,
    piece_length: u32,
    pieces_root: Id32,
    leaf_hashes: &[Id32],
) -> (Vec<u8>, Vec<u8>) {
    let name_bytes = display_name.as_bytes();
    let empty: &[u8] = b"";

    // Piece layers value: all leaf hashes concatenated
    let mut piece_layers_value = Vec::new();
    for h in leaf_hashes {
        piece_layers_value.extend_from_slice(&h.0);
    }

    // File tree: { name: { "": { length, pieces root } } }
    let mut file_tree = Vec::new();
    bencode_dict_start(&mut file_tree);
    {
        bencode_bytes(&mut file_tree, name_bytes);
        bencode_dict_start(&mut file_tree);
        {
            bencode_bytes(&mut file_tree, empty);
            bencode_dict_start(&mut file_tree);
            {
                bencode_bytes(&mut file_tree, b"length");
                bencode_int(&mut file_tree, corpus_bytes as i64);
                bencode_bytes(&mut file_tree, b"pieces root");
                bencode_bytes(&mut file_tree, &pieces_root.0);
            }
            bencode_dict_end(&mut file_tree);
        }
        bencode_dict_end(&mut file_tree);
    }
    bencode_dict_end(&mut file_tree);

    // Info dict
    let mut info = Vec::new();
    bencode_dict_start(&mut info);
    {
        bencode_bytes(&mut info, b"file tree");
        info.extend_from_slice(&file_tree);
        bencode_bytes(&mut info, b"meta version");
        bencode_int(&mut info, 2);
        bencode_bytes(&mut info, b"name");
        bencode_bytes(&mut info, name_bytes);
        bencode_bytes(&mut info, b"piece length");
        bencode_int(&mut info, piece_length as i64);
    }
    bencode_dict_end(&mut info);

    // Piece layers dict
    let mut piece_layers_dict = Vec::new();
    bencode_dict_start(&mut piece_layers_dict);
    {
        bencode_bytes(&mut piece_layers_dict, &pieces_root.0);
        bencode_bytes(&mut piece_layers_dict, &piece_layers_value);
    }
    bencode_dict_end(&mut piece_layers_dict);

    // Full metainfo
    let mut metainfo = Vec::new();
    bencode_dict_start(&mut metainfo);
    {
        bencode_bytes(&mut metainfo, b"info");
        metainfo.extend_from_slice(&info);
        bencode_bytes(&mut metainfo, b"piece layers");
        metainfo.extend_from_slice(&piece_layers_dict);
    }
    bencode_dict_end(&mut metainfo);

    (info, metainfo)
}

fn atomic_write(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, data)
        .with_context(|| format!("writing temp file {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} -> {}", tmp_path.display(), path.display()))?;
    Ok(())
}

// ── Carrier Store ────────────────────────────────────────────────────────────

pub(crate) struct TunnelCarrierStore {
    descriptor: TunnelCarrierDescriptor,
    root: PathBuf,
    have: BitBox<u8, Msb0>,
}

impl TunnelCarrierStore {
    pub async fn open_or_initialize(
        root: &Path,
        config: &TunnelCarrierConfig,
    ) -> anyhow::Result<Self> {
        tokio::fs::create_dir_all(root)
            .await
            .with_context(|| format!("creating carrier dir {}", root.display()))?;

        let desc_path = root.join(DESCRIPTOR_FILENAME);
        let corpus_path = root.join(CORPUS_FILENAME);

        if desc_path.exists() {
            // A descriptor exists: try to reopen it. If reopen fails for a
            // RECOVERABLE local-state mismatch (corpus size / piece-hash /
            // merkle-root mismatch, a corrupt or partially-written descriptor, or
            // a leftover dir generated from a DIFFERENT config), self-heal by
            // regenerating from `config` rather than propagating a hard error to
            // the caller — the carrier is deterministic local state, so
            // regenerating is always safe and yields the correct torrent.
            match Self::reopen(root, config, &desc_path, &corpus_path).await {
                Ok(store) => Ok(store),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        dir = %root.display(),
                        "carrier store reopen failed; regenerating from config (self-heal)"
                    );
                    Self::initialize(root, config, &desc_path, &corpus_path).await
                }
            }
        } else {
            Self::initialize(root, config, &desc_path, &corpus_path).await
        }
    }

    async fn reopen(
        root: &Path,
        config: &TunnelCarrierConfig,
        desc_path: &Path,
        corpus_path: &Path,
    ) -> anyhow::Result<Self> {
        // Descriptor file contains just the raw metainfo bytes
        let metainfo_bytes = tokio::fs::read(desc_path)
            .await
            .with_context(|| format!("reading descriptor {}", desc_path.display()))?;
        let metainfo = Bytes::from(metainfo_bytes);

        // Re-validate metainfo
        let metainfo_for_parse = metainfo.clone();
        let meta = torrent_v2_from_bytes(&metainfo_for_parse)
            .with_context(|| "re-validating carrier metainfo")?;

        let descriptor = TunnelCarrierDescriptor {
            info_hash: meta.info_hash,
            handshake_info_hash: meta.handshake_info_hash(),
            metainfo,
        };

        let corpus = tokio::fs::read(corpus_path)
            .await
            .with_context(|| format!("reading carrier corpus {}", corpus_path.display()))?;
        if corpus.len() as u64 != config.corpus_bytes {
            bail!(
                "carrier corpus size mismatch: expected {}, got {}",
                config.corpus_bytes,
                corpus.len()
            );
        }

        let piece_len = config.piece_length as usize;
        let npieces = piece_count(config.corpus_bytes, config.piece_length);

        let piece_layers = &meta.piece_layers;
        let validated = meta
            .info
            .data
            .validate(piece_layers)
            .with_context(|| "validating carrier metainfo v2 info")?;

        // Compute piece hashes from stored corpus
        let mut computed_hashes = Vec::with_capacity(npieces);
        for i in 0..npieces {
            let start = i * piece_len;
            let end = ((i + 1) * piece_len).min(corpus.len());
            computed_hashes.push(hash_piece(&corpus[start..end]));
        }

        // Get the expected root from the file tree
        let files = validated.files();
        let pieces_root = files
            .iter()
            .find_map(|f| f.pieces_root)
            .ok_or_else(|| anyhow::anyhow!("carrier has no pieces_root"))?;

        // Get stored piece layer hashes and compare
        let stored_bytes = piece_layers
            .get(&pieces_root)
            .ok_or_else(|| anyhow::anyhow!("carrier piece layers missing root"))?;
        let stored_bytes_ref = stored_bytes.as_ref();
        // Return a recoverable error (not panic) on a misaligned stored layer so
        // `open_or_initialize`'s self-heal path can re-initialize a corrupt dir.
        let stored_hashes: Vec<Id32> = stored_bytes_ref
            .chunks(32)
            .map(|chunk| {
                if chunk.len() != 32 {
                    bail!(
                        "carrier piece layer has trailing bytes: {} total, {} remainder",
                        stored_bytes_ref.len(),
                        stored_bytes_ref.len() % 32
                    );
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(chunk);
                Ok(Id32::new(arr))
            })
            .collect::<anyhow::Result<Vec<Id32>>>()?;

        if computed_hashes != stored_hashes {
            bail!("carrier piece hash mismatch on reopen");
        }

        let verified_root = merkle_root(&computed_hashes, config.piece_length);
        if verified_root != pieces_root {
            bail!("carrier merkle root mismatch on reopen");
        }

        let have = bitvec::bitbox![u8, Msb0; 1; npieces];

        Ok(Self {
            descriptor,
            root: root.to_path_buf(),
            have,
        })
    }

    async fn initialize(
        root: &Path,
        config: &TunnelCarrierConfig,
        desc_path: &Path,
        corpus_path: &Path,
    ) -> anyhow::Result<Self> {
        let piece_len = config.piece_length as usize;
        let corpus_len = config.corpus_bytes as usize;
        let npieces = piece_count(config.corpus_bytes, config.piece_length);

        // Deterministic corpus so both endpoints agree on the torrent.
        let mut rng = StdRng::from_seed(config.seed);
        let mut corpus = vec![0u8; corpus_len];
        rng.fill(&mut corpus[..]);

        // Hash each piece
        let mut leaf_hashes = Vec::with_capacity(npieces);
        for i in 0..npieces {
            let start = i * piece_len;
            let end = ((i + 1) * piece_len).min(corpus_len);
            leaf_hashes.push(hash_piece(&corpus[start..end]));
        }

        // Compute pieces root via Merkle tree
        let pieces_root = merkle_root(&leaf_hashes, config.piece_length);

        // Build metainfo
        let (info_bytes, metainfo_bytes) = build_metainfo(
            &config.display_name,
            config.corpus_bytes,
            config.piece_length,
            pieces_root,
            &leaf_hashes,
        );

        let metainfo = Bytes::from(metainfo_bytes);
        let info_hash = info_hash_v2(&info_bytes);

        // Parse to validate and get handshake_info_hash
        let parsed = torrent_v2_from_bytes(&metainfo)
            .with_context(|| "validating generated carrier metainfo")?;
        assert_eq!(parsed.info_hash, info_hash);

        let descriptor = TunnelCarrierDescriptor {
            info_hash,
            handshake_info_hash: parsed.handshake_info_hash(),
            metainfo: metainfo.clone(),
        };

        // Persist corpus and descriptor atomically
        atomic_write(corpus_path, &corpus).with_context(|| "writing carrier corpus")?;
        atomic_write(desc_path, &metainfo).with_context(|| "writing carrier descriptor")?;

        let have = bitvec::bitbox![u8, Msb0; 1; npieces];

        Ok(Self {
            descriptor,
            root: root.to_path_buf(),
            have,
        })
    }

    pub fn descriptor(&self) -> &TunnelCarrierDescriptor {
        &self.descriptor
    }

    pub fn have_bitfield(&self) -> &BitSlice<u8, Msb0> {
        &self.have
    }

    pub async fn read_piece(&self, piece: ValidPieceIndex, out: &mut [u8]) -> anyhow::Result<()> {
        let piece_len = out.len();
        let corpus_path = self.root.join(CORPUS_FILENAME);

        let corpus_len = {
            let meta = std::fs::metadata(&corpus_path)
                .with_context(|| format!("stat corpus {}", corpus_path.display()))?;
            meta.len() as usize
        };

        let idx = piece.0 as usize;
        let start = idx * piece_len;

        if start >= corpus_len {
            bail!(
                "piece index {} out of range (corpus has {} bytes)",
                idx,
                corpus_len
            );
        }

        let read_len = piece_len.min(corpus_len - start);

        // Random-access read — avoids loading the entire corpus into memory
        let mut file = tokio::fs::File::open(&corpus_path)
            .await
            .with_context(|| format!("opening corpus for read {}", corpus_path.display()))?;
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        file.seek(std::io::SeekFrom::Start(start as u64))
            .await
            .with_context(|| format!("seeking to piece {} in corpus", idx))?;
        file.read_exact(&mut out[..read_len])
            .await
            .with_context(|| format!("reading piece {} from corpus", idx))?;

        // If the last piece is shorter than piece_len, zero-pad the rest
        if read_len < piece_len {
            out[read_len..].fill(0);
        }

        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> TunnelCarrierConfig {
        TunnelCarrierConfig {
            corpus_bytes: 65536,
            piece_length: 16384,
            display_name: "carrier-test".into(),
            seed: [0u8; 32],
        }
    }

    #[tokio::test]
    async fn initializes_then_reopens_the_same_carrier() {
        let dir = tempfile::tempdir().unwrap();
        let first = TunnelCarrierStore::open_or_initialize(dir.path(), &test_config())
            .await
            .unwrap();
        let descriptor = first.descriptor().clone();
        drop(first);

        let reopened = TunnelCarrierStore::open_or_initialize(dir.path(), &test_config())
            .await
            .unwrap();
        assert_eq!(reopened.descriptor(), &descriptor);
        assert!(reopened.have_bitfield().all());
    }

    #[tokio::test]
    async fn rejects_invalid_piece_index() {
        let dir = tempfile::tempdir().unwrap();
        let store = TunnelCarrierStore::open_or_initialize(dir.path(), &test_config())
            .await
            .unwrap();
        let mut buf = vec![0u8; test_config().piece_length as usize];

        // 4 pieces for 65536/16384 — piece 4 is out of range
        let result = store.read_piece(ValidPieceIndex(4), &mut buf).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn read_piece_roundtrip_produces_valid_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let store = TunnelCarrierStore::open_or_initialize(dir.path(), &test_config())
            .await
            .unwrap();
        let piece_len = test_config().piece_length as usize;

        let mut buf = vec![0u8; piece_len];
        store
            .read_piece(ValidPieceIndex(0), &mut buf)
            .await
            .unwrap();
        assert_ne!(buf, vec![0u8; piece_len], "piece 0 should not be all zeros");

        store
            .read_piece(ValidPieceIndex(1), &mut buf)
            .await
            .unwrap();
        assert_ne!(buf, vec![0u8; piece_len], "piece 1 should not be all zeros");
    }

    #[tokio::test]
    async fn self_heals_reopen_with_mismatched_config() {
        let dir = tempfile::tempdir().unwrap();
        TunnelCarrierStore::open_or_initialize(dir.path(), &test_config())
            .await
            .unwrap();

        // A config whose seed AND size differ from what's on disk. `reopen`
        // cannot validate the stale corpus against it, so `open_or_initialize`
        // must SELF-HEAL: regenerate from `bad_config` and return ITS descriptor
        // (not the stale one), rather than propagating an error.
        let bad_config = TunnelCarrierConfig {
            corpus_bytes: 32768, // different size
            seed: [5u8; 32],     // different seed
            ..test_config()
        };
        let healed = TunnelCarrierStore::open_or_initialize(dir.path(), &bad_config)
            .await
            .expect("mismatched existing dir must self-heal, not error");

        // The healed store must reflect `bad_config`. Compare against a fresh
        // store built from `bad_config` in a clean dir.
        let clean = tempfile::tempdir().unwrap();
        let expected = TunnelCarrierStore::open_or_initialize(clean.path(), &bad_config)
            .await
            .unwrap();
        assert_eq!(
            healed.descriptor(),
            expected.descriptor(),
            "self-healed store must match a fresh store built from the new config"
        );

        // And a subsequent reopen with the SAME (healed) config now succeeds
        // cleanly — the on-disk state was rewritten to match.
        let reopened = TunnelCarrierStore::open_or_initialize(dir.path(), &bad_config)
            .await
            .expect("reopen after self-heal must succeed");
        assert_eq!(reopened.descriptor(), expected.descriptor());
    }

    #[tokio::test]
    async fn self_heals_reopen_with_corrupt_corpus() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config();
        let original = TunnelCarrierStore::open_or_initialize(dir.path(), &cfg)
            .await
            .unwrap();
        let original_desc = original.descriptor().clone();
        drop(original);

        // Corrupt the corpus in place WITHOUT changing its size: the size check
        // passes, but the piece-hash / merkle-root check fails on reopen — a
        // different recoverable failure path than a size/config mismatch.
        let corpus_path = dir.path().join(CORPUS_FILENAME);
        let mut bytes = std::fs::read(&corpus_path).unwrap();
        bytes[0] ^= 0xFF;
        std::fs::write(&corpus_path, &bytes).unwrap();

        // Self-heal: reopen must SUCCEED and regenerate the correct torrent
        // (identical to the original, since the seed is unchanged).
        let healed = TunnelCarrierStore::open_or_initialize(dir.path(), &cfg)
            .await
            .expect("corrupt corpus must self-heal, not error");
        assert_eq!(
            healed.descriptor(),
            &original_desc,
            "self-healed store must match the original (same seed regenerates identically)"
        );

        // A subsequent clean reopen now succeeds: the on-disk corpus was rewritten
        // consistent with the descriptor.
        let reopened = TunnelCarrierStore::open_or_initialize(dir.path(), &cfg)
            .await
            .expect("reopen after self-heal must succeed");
        assert_eq!(reopened.descriptor(), &original_desc);
    }

    #[tokio::test]
    async fn same_seed_produces_identical_descriptor_in_different_dirs() {
        let mut cfg = test_config();
        cfg.seed = [7u8; 32];

        let dir_a = tempfile::tempdir().unwrap();
        let a = TunnelCarrierStore::open_or_initialize(dir_a.path(), &cfg)
            .await
            .unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let b = TunnelCarrierStore::open_or_initialize(dir_b.path(), &cfg)
            .await
            .unwrap();

        assert_eq!(a.descriptor(), b.descriptor(), "same seed → same torrent");

        let mut pa = vec![0u8; cfg.piece_length as usize];
        let mut pb = vec![0u8; cfg.piece_length as usize];
        a.read_piece(ValidPieceIndex(0), &mut pa).await.unwrap();
        b.read_piece(ValidPieceIndex(0), &mut pb).await.unwrap();
        assert_eq!(pa, pb, "same seed → identical piece bytes");
    }

    #[tokio::test]
    async fn different_seed_produces_different_info_hash() {
        let mut cfg1 = test_config();
        cfg1.seed = [1u8; 32];
        let mut cfg2 = test_config();
        cfg2.seed = [2u8; 32];

        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let s1 = TunnelCarrierStore::open_or_initialize(d1.path(), &cfg1)
            .await
            .unwrap();
        let s2 = TunnelCarrierStore::open_or_initialize(d2.path(), &cfg2)
            .await
            .unwrap();
        assert_ne!(s1.descriptor().info_hash, s2.descriptor().info_hash);
    }
}
