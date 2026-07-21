// ── Deterministic carrier-torrent identity ──────────────────────────────────
//
// Both endpoints derive an IDENTICAL `TunnelCarrierConfig` from the shared
// carrier hash, so the synthetic v2 torrent (and thus its info_hash / piece
// data) is the same on both sides with no exchange.

use librqbit_core::Id20;
use sha2::{Digest, Sha256};

use super::carrier::TunnelCarrierConfig;
use super::config::{
    CARRIER_CORPUS_MAX, CARRIER_CORPUS_MIN, CARRIER_DISPLAY_NAMES, CARRIER_PIECE_LENGTH,
};

fn tagged_hash(tag: &[u8], carrier_hash: &Id20) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag);
    h.update(carrier_hash.0);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Deterministic corpus RNG seed for this carrier.
fn carrier_corpus_seed(carrier_hash: &Id20) -> [u8; 32] {
    tagged_hash(b"rqbit-tunnel-corpus-v1", carrier_hash)
}

/// Build the identical carrier-torrent config both endpoints use.
pub(crate) fn carrier_config_for(carrier_hash: &Id20) -> TunnelCarrierConfig {
    let selector = tagged_hash(b"rqbit-tunnel-shape-v1", carrier_hash);

    // Display name: pick one deterministically.
    let name_idx = (selector[0] as usize) % CARRIER_DISPLAY_NAMES.len();
    let display_name = CARRIER_DISPLAY_NAMES[name_idx].to_string();

    // Corpus size: map 2 selector bytes into [MIN, MAX].
    let span = CARRIER_CORPUS_MAX - CARRIER_CORPUS_MIN;
    let r = u64::from(u16::from_be_bytes([selector[1], selector[2]]));
    let corpus_bytes = CARRIER_CORPUS_MIN + (r * span) / u64::from(u16::MAX);

    TunnelCarrierConfig {
        corpus_bytes,
        piece_length: CARRIER_PIECE_LENGTH,
        display_name,
        seed: carrier_corpus_seed(carrier_hash),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use librqbit_core::Id20;

    #[test]
    fn config_is_deterministic_for_a_hash() {
        let h = Id20::new([9u8; 20]);
        let a = carrier_config_for(&h);
        let b = carrier_config_for(&h);
        assert_eq!(a.seed, b.seed);
        assert_eq!(a.corpus_bytes, b.corpus_bytes);
        assert_eq!(a.piece_length, b.piece_length);
        assert_eq!(a.display_name, b.display_name);
    }

    #[test]
    fn different_hashes_differ() {
        let a = carrier_config_for(&Id20::new([1u8; 20]));
        let b = carrier_config_for(&Id20::new([2u8; 20]));
        // At least one identity input differs.
        assert!(a.seed != b.seed || a.display_name != b.display_name);
    }

    #[test]
    fn corpus_size_is_in_band_and_piece_aligned_is_not_required() {
        let cfg = carrier_config_for(&Id20::new([42u8; 20]));
        assert!(cfg.corpus_bytes >= super::super::config::CARRIER_CORPUS_MIN);
        assert!(cfg.corpus_bytes <= super::super::config::CARRIER_CORPUS_MAX);
    }
}
