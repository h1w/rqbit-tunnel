// ── Deterministic carrier-torrent identity ──────────────────────────────────
//
// Both endpoints derive an IDENTICAL `TunnelCarrierConfig` from the shared
// carrier hash, so the synthetic v2 torrent (and thus its info_hash / piece
// data) is the same on both sides with no exchange.

use std::path::Path;
use std::sync::Arc;

use librqbit_core::Id20;
use sha2::{Digest, Sha256};

use super::carrier::{TunnelCarrierConfig, TunnelCarrierStore};
use super::config::{
    CARRIER_CORPUS_MAX, CARRIER_CORPUS_MIN, CARRIER_DISPLAY_NAMES, CARRIER_PIECE_LENGTH,
};
use super::crypto::derive_carrier_hash;
use super::frame::TunnelPublicKey;

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

/// Open-or-initialize the deterministic carrier store for a given server key.
///
/// Both endpoints call this with the same `server_pub` (the server derives it
/// from its own identity key; the client uses the pinned `expected_server_key`),
/// so they build byte-identical synthetic v2 torrents with no exchange. The
/// resulting store's `descriptor().handshake_info_hash` is BOTH the shared DHT
/// rendezvous key AND the MSE/PE SKEY (see `server.rs::accept` /
/// `client.rs::connect`) — exactly as a real BitTorrent peer keys both by the
/// public info hash. `derive_carrier_hash` here is used ONLY as the private
/// seed that shapes the synthetic corpus (display name, size, piece data); it
/// is NOT the MSE key and never goes on the wire.
pub(crate) async fn build_carrier_store(
    root: &Path,
    server_pub: &TunnelPublicKey,
) -> anyhow::Result<Arc<TunnelCarrierStore>> {
    let carrier_hash = derive_carrier_hash(server_pub);
    let config = carrier_config_for(&carrier_hash);
    // Namespace the on-disk store per server key so two different servers never
    // collide in the same `root`. Without this, a stale dir left by server A —
    // whose corpus happens to match B's size — would `reopen` cleanly and
    // silently hand back A's (wrong) torrent for B. A distinct `server_pub` maps
    // to a distinct subdir, hence B's own (correct) seed.
    let store_dir = root.join(hex::encode(server_pub.0));
    let store = TunnelCarrierStore::open_or_initialize(&store_dir, &config).await?;
    Ok(Arc::new(store))
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

    #[tokio::test]
    async fn different_server_keys_get_different_subdirs_and_descriptors() {
        let root = tempfile::tempdir().unwrap();

        let key_a = TunnelPublicKey([1u8; 32]);
        let key_b = TunnelPublicKey([2u8; 32]);

        let store_a = build_carrier_store(root.path(), &key_a).await.unwrap();
        let store_b = build_carrier_store(root.path(), &key_b).await.unwrap();

        // Two different server keys must NOT collide in the same root: each maps
        // to a distinct per-key subdir with its own descriptor on disk.
        let dir_a = root.path().join(hex::encode(key_a.0));
        let dir_b = root.path().join(hex::encode(key_b.0));
        assert_ne!(dir_a, dir_b, "per-key subdirs must differ");
        assert!(
            dir_a.join("carrier-descriptor.bin").exists(),
            "server A descriptor must live under its own subdir"
        );
        assert!(
            dir_b.join("carrier-descriptor.bin").exists(),
            "server B descriptor must live under its own subdir"
        );

        // And each store carries its OWN (correct) torrent, not the other's.
        assert_ne!(
            store_a.descriptor().info_hash,
            store_b.descriptor().info_hash,
            "different server keys must yield different carrier torrents"
        );
        assert_ne!(
            store_a.descriptor().handshake_info_hash,
            store_b.descriptor().handshake_info_hash,
        );
    }

    #[tokio::test]
    async fn both_sides_derive_same_handshake_info_hash() {
        use super::super::crypto::{derive_carrier_hash, generate_keypair, public_key};

        let (server_priv, server_pub) = generate_keypair();

        // Server derives from its own key; client from the pinned server pub key.
        let server_pub_from_priv = public_key(&server_priv);
        assert_eq!(server_pub_from_priv, server_pub);

        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let server_store = build_carrier_store(d1.path(), &server_pub_from_priv)
            .await
            .unwrap();
        let client_store = build_carrier_store(d2.path(), &server_pub).await.unwrap();

        assert_eq!(
            server_store.descriptor().handshake_info_hash,
            client_store.descriptor().handshake_info_hash,
            "DHT rendezvous key must match on both sides"
        );
        // Sanity: the private corpus seed (`derive_carrier_hash`) is a distinct
        // value from the public `handshake_info_hash` — it shapes the synthetic
        // torrent but is neither the DHT key nor (now) the MSE SKEY.
        let carrier_hash = derive_carrier_hash(&server_pub);
        assert_ne!(carrier_hash, server_store.descriptor().handshake_info_hash);
    }
}
