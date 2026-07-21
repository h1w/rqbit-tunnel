# Plan A — Live BitTorrent Masquerade Carrier — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route the tunnel's Noise-encrypted frames through the (currently dead) BitTorrent peer-wire carrier so on-wire traffic is a real BT handshake + BEP-10 + `rq_tunnel` extended messages with piece cover, instead of raw length-prefixed Noise frames.

**Architecture:** Keep MSE (`PeerWireCrypto`) and Noise IK (`NoiseTransport`) exactly as-is. After MSE, both endpoints run `CarrierWire::establish` (BT handshake + BEP-10 + Bitfield/Unchoke/Interested cover). Noise ciphertext blobs are split into ≤16 KiB chunks and carried as `rq_tunnel` extended messages; incoming `Request`s are answered with `Piece`s from a **deterministic** synthetic v2 torrent whose `handshake_info_hash` is shared by both ends and is what the DHT announces. The existing two-task split (reader task + paced writer task, sharing `Arc<Mutex<NoiseTransport>>`) is preserved; a new `cover` channel carries reader-produced cover messages (Piece responses) to the writer task.

**Tech Stack:** Rust, tokio, `snow` (Noise), `peer_binary_protocol` (BT messages + `rq_tunnel` BEP-10 extension), `librqbit_core` (`Id20`/`Id32`, v2 metainfo), `bitvec`, `sha2`.

## Global Constraints

- BEP 52 (v2) structures only for any torrent/info-dict work — never v1.
- `rq_tunnel` extended-message payload cap is `MAX_RQ_TUNNEL_MESSAGE_LEN = 16 * 1024` (`crates/peer_binary_protocol/src/lib.rs:58`). Every chunk written via `send_tunnel` MUST be ≤ this.
- Tunnel frame payload cap is `MAX_FRAME_PAYLOAD = u16::MAX` (`frame.rs:22`); a single Noise ciphertext blob is up to `MAX_FRAME_PAYLOAD + 32` bytes.
- Inner Noise framing (`seq(8 BE u64) || encoded_frame`, `crypto.rs:205-227`) is UNCHANGED. `NoiseTransport::encrypt`/`decrypt` stay exactly as-is; the migration replaces only the OUTER `[u16 len][ciphertext]` wire framing.
- Prefer typed errors over `anyhow` on verification paths (project rule).
- After every Rust change run `cargo check` and `cargo clippy --all-targets` before declaring a task done.
- Run `cargo fmt --all` before each commit.
- The MSE key stays `derive_carrier_hash(server_pub)` (`crypto.rs:304`). Only the DHT rendezvous key and the BT-handshake info_hash change to the carrier's `handshake_info_hash`.

---

## File Structure

Created:
- `crates/librqbit/src/tunnel/carrier_identity.rs` — deterministic seed + `TunnelCarrierConfig` derivation from the carrier hash; the single source of truth both endpoints use to build an identical torrent.
- `crates/librqbit/src/tunnel/carrier_chunk.rs` — chunk a Noise ciphertext blob into ≤16 KiB `rq_tunnel` payloads and reassemble them (`CarrierDefragmenter`).

Modified:
- `carrier.rs` — deterministic corpus (seed the RNG).
- `carrier_wire.rs` — split post-establish `CarrierWire` into `CarrierReadHalf` / `CarrierWriteHalf`; add chunked send + a cover channel.
- `options.rs` — add `carrier_root` to `TunnelClientOptions`.
- `config.rs` — carrier identity constants (piece length, corpus size band, distro name list).
- `service.rs` — server announces on `handshake_info_hash`, builds the carrier store.
- `client_pool.rs` / `client_supervisor.rs` — client builds the store, discovers via `handshake_info_hash`, threads the store into the mux.
- `client.rs` — `connect` runs `CarrierWire::establish` and the Noise handshake over the carrier.
- `client_mux.rs` — `reader_loop` reads via the carrier read half + defrag; writer + cover plumbing.
- `server.rs` — `accept` runs `CarrierWire::establish` and Noise over the carrier.
- `relay.rs` — `spawn_frame_writer` writes chunks via the carrier write half + drains the cover lane; `run_server_relay` reads via the carrier read half.
- `mod.rs` — declare new modules; narrow the `#![allow(dead_code)]`.
- `crates/librqbit/src/tests/tunnel.rs` — E2E capture gate.

---

## Task 1: Deterministic carrier corpus

Two endpoints must generate byte-identical torrents (same `info_hash`, same piece data) so the BT handshake `info_hash` matches and served `Piece`s validate. Today the corpus is random (`carrier.rs:310`).

**Files:**
- Modify: `crates/librqbit/src/tunnel/carrier.rs:17-22` (config), `:299-312` (initialize)
- Test: `crates/librqbit/src/tunnel/carrier.rs` (tests module)

**Interfaces:**
- Produces: `TunnelCarrierConfig { corpus_bytes: u64, piece_length: u32, display_name: String, seed: [u8; 32] }`

- [ ] **Step 1: Write the failing test**

Add to `carrier.rs` `mod tests`:

```rust
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
    let s1 = TunnelCarrierStore::open_or_initialize(d1.path(), &cfg1).await.unwrap();
    let s2 = TunnelCarrierStore::open_or_initialize(d2.path(), &cfg2).await.unwrap();
    assert_ne!(s1.descriptor().info_hash, s2.descriptor().info_hash);
}
```

Update the existing `test_config()` helper in `carrier.rs` tests to set a seed:

```rust
fn test_config() -> TunnelCarrierConfig {
    TunnelCarrierConfig {
        corpus_bytes: 65536,
        piece_length: 16384,
        display_name: "carrier-test".into(),
        seed: [0u8; 32],
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p librqbit tunnel::carrier::tests::same_seed 2>&1 | tail -20`
Expected: FAIL to compile — `TunnelCarrierConfig` has no field `seed`.

- [ ] **Step 3: Add the `seed` field and use it**

In `carrier.rs:17-22` change the config struct:

```rust
#[derive(Clone, Debug)]
pub(crate) struct TunnelCarrierConfig {
    pub corpus_bytes: u64,
    pub piece_length: u32,
    pub display_name: String,
    /// Deterministic seed for the corpus RNG. Both endpoints derive this from
    /// the shared carrier hash so they generate byte-identical torrents.
    pub seed: [u8; 32],
}
```

In `carrier.rs:310` replace the RNG construction inside `initialize`:

```rust
        // Deterministic corpus so both endpoints agree on the torrent.
        let mut rng = StdRng::from_seed(config.seed);
        let mut corpus = vec![0u8; corpus_len];
        rng.fill(&mut corpus[..]);
```

(`StdRng::from_seed` is already importable — `rand::{Rng, SeedableRng, rngs::StdRng}` is imported at `carrier.rs:11`.)

Fix every other `TunnelCarrierConfig { .. }` literal in the crate to add `seed`. Known sites to update (compiler will list any others):
- `carrier_wire.rs` test `test_carrier()` (`carrier_wire.rs:284-288`) — add `seed: [0u8; 32],`
- `carrier_peer.rs` test `test_config()` (`carrier_peer.rs:365-370`) — add `seed: [0u8; 32],`

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p librqbit tunnel::carrier 2>&1 | tail -20`
Expected: PASS (including `same_seed_...` and `different_seed_...`).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add crates/librqbit/src/tunnel/carrier.rs crates/librqbit/src/tunnel/carrier_wire.rs crates/librqbit/src/tunnel/carrier_peer.rs
git commit -m "feat(tunnel): deterministic carrier corpus via config seed"
```

---

## Task 2: Carrier identity derivation (seed + config from carrier hash)

Both endpoints must derive the SAME `TunnelCarrierConfig` from the shared carrier hash, so `display_name`, `corpus_bytes`, `piece_length`, and `seed` (all inputs to the info-hash) match without any exchange.

**Files:**
- Create: `crates/librqbit/src/tunnel/carrier_identity.rs`
- Modify: `crates/librqbit/src/tunnel/mod.rs` (add `pub(crate) mod carrier_identity;`), `config.rs` (constants)
- Test: in `carrier_identity.rs`

**Interfaces:**
- Consumes: `librqbit_core::Id20` (the carrier hash from `crypto::derive_carrier_hash`)
- Produces:
  - `pub(crate) fn carrier_config_for(carrier_hash: &Id20) -> super::carrier::TunnelCarrierConfig`

- [ ] **Step 1: Add identity constants to `config.rs`**

Append to `config.rs`:

```rust
// ── Carrier identity (masquerade torrent shape) ──────────────────────────────

/// Piece length for the synthetic carrier torrent. 256 KiB is a common real
/// value for GiB-scale single-file torrents.
pub(crate) const CARRIER_PIECE_LENGTH: u32 = 256 * 1024;

/// Corpus size band (bytes). The concrete size is chosen deterministically per
/// carrier hash within [MIN, MAX] so different servers look like different
/// torrents while staying cheap to generate/store.
pub(crate) const CARRIER_CORPUS_MIN: u64 = 8 * 1024 * 1024;
pub(crate) const CARRIER_CORPUS_MAX: u64 = 24 * 1024 * 1024;

/// Plausible display names; one is chosen deterministically per carrier hash.
pub(crate) const CARRIER_DISPLAY_NAMES: &[&str] = &[
    "debian-12.7.0-amd64-netinst.iso",
    "ubuntu-24.04.1-desktop-amd64.iso",
    "archlinux-2024.09.01-x86_64.iso",
    "Fedora-Workstation-Live-x86_64-40.iso",
    "linuxmint-22-cinnamon-64bit.iso",
    "manjaro-kde-24.0-240513-linux69.iso",
    "openSUSE-Leap-15.6-DVD-x86_64.iso",
    "pop-os_22.04_amd64_intel.iso",
];
```

- [ ] **Step 2: Write the failing test**

Create `carrier_identity.rs` with only the test first:

```rust
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p librqbit tunnel::carrier_identity 2>&1 | tail -20`
Expected: FAIL to compile — `carrier_config_for` not found / module not declared.

- [ ] **Step 4: Implement `carrier_identity.rs` and declare the module**

Prepend to `carrier_identity.rs` (above the test module):

```rust
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
```

In `mod.rs`, add after `pub(crate) mod carrier;` (line 17):

```rust
pub(crate) mod carrier_identity;
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p librqbit tunnel::carrier_identity 2>&1 | tail -20`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add crates/librqbit/src/tunnel/carrier_identity.rs crates/librqbit/src/tunnel/mod.rs crates/librqbit/src/tunnel/config.rs
git commit -m "feat(tunnel): deterministic carrier identity from carrier hash"
```

---

## Task 3: Chunk / defragment layer

`rq_tunnel` messages cap at 16 KiB but Noise ciphertext blobs can be larger (UDP datagrams; also a 16 KiB `READ_CHUNK` TcpData blob is 16 KiB + ~30 bytes). Carry a length-prefixed ciphertext byte-stream split across `rq_tunnel` messages. Delivery under `rq_tunnel` is reliable + ordered (TCP + MSE + BT message order), so a simple length-prefix stream is sufficient.

**Files:**
- Create: `crates/librqbit/src/tunnel/carrier_chunk.rs`
- Modify: `mod.rs` (`pub(crate) mod carrier_chunk;`)
- Test: in `carrier_chunk.rs`

**Interfaces:**
- Produces:
  - `pub(crate) const CHUNK_MAX: usize` (= `MAX_RQ_TUNNEL_MESSAGE_LEN`)
  - `pub(crate) fn chunk_ciphertext(blob: &[u8]) -> Vec<Vec<u8>>`
  - `pub(crate) struct CarrierDefragmenter` with `pub(crate) fn push(&mut self, chunk: &[u8]) -> Vec<Vec<u8>>` and `pub(crate) fn new() -> Self`

- [ ] **Step 1: Write the failing test**

Create `carrier_chunk.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(blob: Vec<u8>) {
        let chunks = chunk_ciphertext(&blob);
        for c in &chunks {
            assert!(c.len() <= CHUNK_MAX, "chunk {} > CHUNK_MAX", c.len());
        }
        let mut d = CarrierDefragmenter::new();
        let mut out = Vec::new();
        for c in chunks {
            out.extend(d.push(&c));
        }
        assert_eq!(out.len(), 1, "exactly one message reassembled");
        assert_eq!(out[0], blob);
    }

    #[test]
    fn roundtrips_small() {
        roundtrip(vec![0xAB; 10]);
    }

    #[test]
    fn roundtrips_empty() {
        roundtrip(Vec::new());
    }

    #[test]
    fn roundtrips_larger_than_chunk() {
        roundtrip((0..40_000u32).map(|i| i as u8).collect());
    }

    #[test]
    fn reassembles_multiple_messages_from_one_stream() {
        let a = vec![1u8; 100];
        let b = vec![2u8; 20_000];
        let mut stream = chunk_ciphertext(&a);
        stream.extend(chunk_ciphertext(&b));

        let mut d = CarrierDefragmenter::new();
        let mut out = Vec::new();
        for c in stream {
            out.extend(d.push(&c));
        }
        assert_eq!(out, vec![a, b]);
    }

    #[test]
    fn handles_chunk_split_across_length_prefix() {
        // Feed one byte at a time; a message must only appear once complete.
        let blob = vec![9u8; 5000];
        let chunks = chunk_ciphertext(&blob);
        let joined: Vec<u8> = chunks.into_iter().flatten().collect();
        let mut d = CarrierDefragmenter::new();
        let mut out = Vec::new();
        for byte in joined {
            out.extend(d.push(&[byte]));
        }
        assert_eq!(out, vec![blob]);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p librqbit tunnel::carrier_chunk 2>&1 | tail -20`
Expected: FAIL to compile — items not defined / module not declared.

- [ ] **Step 3: Implement the chunker/defragmenter**

Prepend to `carrier_chunk.rs`:

```rust
// ── Chunk a Noise ciphertext blob across rq_tunnel messages ──────────────────
//
// Wire form is a length-prefixed byte stream: for each blob we emit
// `u32-BE length || blob`, then slice that stream into <= CHUNK_MAX pieces.
// Delivery under rq_tunnel is reliable + ordered, so the receiver just
// accumulates bytes and drains complete `length || payload` messages.

use peer_binary_protocol::MAX_RQ_TUNNEL_MESSAGE_LEN;

pub(crate) const CHUNK_MAX: usize = MAX_RQ_TUNNEL_MESSAGE_LEN;

/// Split one ciphertext blob into ordered <= CHUNK_MAX chunks (with a 4-byte
/// length prefix on the logical message).
pub(crate) fn chunk_ciphertext(blob: &[u8]) -> Vec<Vec<u8>> {
    let mut framed = Vec::with_capacity(4 + blob.len());
    framed.extend_from_slice(&(blob.len() as u32).to_be_bytes());
    framed.extend_from_slice(blob);

    framed
        .chunks(CHUNK_MAX)
        .map(|c| c.to_vec())
        .collect()
}

/// Reassembles the length-prefixed ciphertext stream produced by
/// `chunk_ciphertext`.
pub(crate) struct CarrierDefragmenter {
    buf: Vec<u8>,
}

impl CarrierDefragmenter {
    pub(crate) fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Push one received rq_tunnel payload; return zero or more complete
    /// ciphertext messages now available.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 4 {
                break;
            }
            let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]])
                as usize;
            if self.buf.len() < 4 + len {
                break;
            }
            let msg = self.buf[4..4 + len].to_vec();
            self.buf.drain(..4 + len);
            out.push(msg);
        }
        out
    }
}
```

In `mod.rs`, add after `carrier_chunk` alphabetical neighbours (near line 17):

```rust
pub(crate) mod carrier_chunk;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p librqbit tunnel::carrier_chunk 2>&1 | tail -20`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add crates/librqbit/src/tunnel/carrier_chunk.rs crates/librqbit/src/tunnel/mod.rs
git commit -m "feat(tunnel): rq_tunnel chunk/defrag layer for Noise blobs"
```

---

## Task 4: Client `carrier_root` option

The client needs a place to persist its copy of the carrier torrent (to present the correct `info_hash` and serve piece cover). The server already has `carrier_root`; add the mirror to the client. **Design revision (approved):** there is NO dual-mode flag — the masquerade carrier wholly replaces the raw-Noise path. Isolation is preserved by unit tests on the new modules (chunk/defrag/split), not by keeping a second relay path.

**Files:**
- Modify: `crates/librqbit/src/tunnel/options.rs` (client struct + defaults)
- Test: `options.rs` tests

**Interfaces:**
- Produces: `TunnelClientOptions.carrier_root: PathBuf`

- [ ] **Step 1: Write the failing test**

Add to `options.rs` tests:

```rust
#[test]
fn client_has_carrier_root_default() {
    let o = super::TunnelClientOptions::default();
    assert!(!o.carrier_root.as_os_str().is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p librqbit tunnel::options 2>&1 | tail -20`
Expected: FAIL to compile — no field `carrier_root` on `TunnelClientOptions`.

- [ ] **Step 3: Add the field**

Add to `TunnelClientOptions` (struct at `options.rs:38`):

```rust
    /// Root dir for this client's copy of the carrier torrent store.
    pub carrier_root: PathBuf,
```

Update the `TunnelClientOptions` `Default` impl (around `options.rs:64-70`) to include:

```rust
            carrier_root: std::env::temp_dir().join("rqbit-tunnel-carrier-client"),
```

Ensure `use std::path::PathBuf;` is present in `options.rs` (the server struct already uses `PathBuf`, so it is imported).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p librqbit tunnel::options 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add crates/librqbit/src/tunnel/options.rs
git commit -m "feat(tunnel): client carrier_root option"
```

---

## Task 5: Build the carrier store on both endpoints; unify DHT rendezvous on `handshake_info_hash`

Both endpoints build the deterministic store from `carrier_config_for(carrier_hash)`. The server announces on and the client discovers by the store's `handshake_info_hash`, and that same value is passed to `CarrierWire::establish`. The MSE key stays `carrier_hash`.

**Files:**
- Modify: `service.rs:80-92` (server announce), `service.rs` (build store, pass to `TunnelServer`)
- Modify: `client_pool.rs`, `client_supervisor.rs` (build store, discover by `handshake_info_hash`, thread store into mux)
- Modify: `server.rs` (`TunnelServer` holds `Arc<TunnelCarrierStore>`)
- Test: new unit test in `carrier_identity.rs` proving both sides derive the same DHT key

**Interfaces:**
- Consumes: `carrier_identity::carrier_config_for`, `crypto::derive_carrier_hash`, `crypto::public_key`, `carrier::TunnelCarrierStore::open_or_initialize`, `TunnelCarrierStore::descriptor().handshake_info_hash: Id20`
- Produces: `pub(crate) async fn build_carrier_store(root: &Path, server_pub: &TunnelPublicKey) -> anyhow::Result<Arc<TunnelCarrierStore>>` in `carrier_identity.rs`

- [ ] **Step 1: Write the failing test**

Add to `carrier_identity.rs` tests:

```rust
#[tokio::test]
async fn both_sides_derive_same_handshake_info_hash() {
    use super::super::crypto::{derive_carrier_hash, generate_keypair, public_key};

    let (server_priv, server_pub) = generate_keypair();

    // Server derives from its own key; client from the pinned server pub key.
    let server_pub_from_priv = public_key(&server_priv);
    assert_eq!(server_pub_from_priv, server_pub);

    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let server_store = build_carrier_store(d1.path(), &server_pub_from_priv).await.unwrap();
    let client_store = build_carrier_store(d2.path(), &server_pub).await.unwrap();

    assert_eq!(
        server_store.descriptor().handshake_info_hash,
        client_store.descriptor().handshake_info_hash,
        "DHT rendezvous key must match on both sides"
    );
    // Sanity: carrier hash (MSE key) is a different value.
    let carrier_hash = derive_carrier_hash(&server_pub);
    assert_ne!(carrier_hash, server_store.descriptor().handshake_info_hash);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p librqbit tunnel::carrier_identity::tests::both_sides 2>&1 | tail -20`
Expected: FAIL to compile — `build_carrier_store` not found.

- [ ] **Step 3: Implement `build_carrier_store`**

Add to `carrier_identity.rs` (imports + fn):

```rust
use std::path::Path;
use std::sync::Arc;

use super::carrier::TunnelCarrierStore;
use super::crypto::derive_carrier_hash;
use super::frame::TunnelPublicKey;

/// Open-or-initialize the deterministic carrier store for a given server key.
pub(crate) async fn build_carrier_store(
    root: &Path,
    server_pub: &TunnelPublicKey,
) -> anyhow::Result<Arc<TunnelCarrierStore>> {
    let carrier_hash = derive_carrier_hash(server_pub);
    let config = carrier_config_for(&carrier_hash);
    let store = TunnelCarrierStore::open_or_initialize(root, &config).await?;
    Ok(Arc::new(store))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p librqbit tunnel::carrier_identity::tests::both_sides 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Wire the server side (build store, announce on handshake hash)**

In `service.rs`, in the `TunnelOptions::Server(opts)` arm, before constructing `TunnelServer`, build the store and use its handshake hash for the announce. Replace `service.rs:80-98` with:

```rust
                let server_pub = super::crypto::public_key(&opts.identity_key);
                let carrier_store =
                    super::carrier_identity::build_carrier_store(&opts.carrier_root, &server_pub)
                        .await?;
                let announce_hash = carrier_store.descriptor().handshake_info_hash;

                if let Some(dht) = session.get_dht() {
                    let announce_port = local_addr.port();
                    let stream = dht.get_peers(announce_hash, Some(announce_port));
                    tokio::spawn(run_dht_announce(stream, shutdown.clone()));
                    tracing::info!(
                        ?announce_hash,
                        port = announce_port,
                        "tunnel server announcing carrier in DHT"
                    );
                }

                let server = TunnelServer::new(opts, carrier_store);
                let server_shutdown = shutdown.clone();
                tokio::spawn(async move {
                    server.run(listener, server_shutdown).await;
                });
```

Update `TunnelServer::new` (in `server.rs`) to accept and store `carrier_store: Arc<TunnelCarrierStore>` as a field. Find the current `TunnelServer` struct and `new`:

```rust
// server.rs — struct: add field
    carrier_store: Arc<super::carrier::TunnelCarrierStore>,

// server.rs — new(): add param and initializer
    pub fn new(
        options: TunnelServerOptions,
        carrier_store: Arc<super::carrier::TunnelCarrierStore>,
    ) -> Arc<Self> {
        Arc::new(Self {
            // ...existing fields...
            carrier_store,
        })
    }
```

(Keep the existing fields exactly; only add `carrier_store`. If `new` currently returns `Self` not `Arc<Self>`, keep its existing return type and just add the field + param.)

- [ ] **Step 6: Wire the client side (build store, discover by handshake hash)**

In `client_pool.rs` / `client_supervisor.rs`, where the supervisor computes the DHT lookup key (currently `derive_carrier_hash`), build the store once at pool/supervisor start and use `descriptor().handshake_info_hash` for `dht.get_peers(...)`. Thread the `Arc<TunnelCarrierStore>` into each `TunnelClientSupervisor` so it can pass it to `ClientMux::new` (Task 9) and to `TunnelClient::connect` (Task 9).

Concretely, in `CarrierPool::start` (`client_pool.rs`), build the store before spawning supervisors:

```rust
    // Build the deterministic carrier store once; share across supervisors.
    let carrier_store = super::carrier_identity::build_carrier_store(
        &opts.carrier_root,
        &opts.expected_server_key,
    )
    .await?;   // NOTE: make CarrierPool::start async, or block_on at the call site in service.rs
    let discover_hash = carrier_store.descriptor().handshake_info_hash;
```

Replace the client-side `derive_carrier_hash(...)` used for `dht.get_peers` (in `client_supervisor.rs`, around the `spawn_dht_drainer` call) with `discover_hash` threaded in from the pool. Keep `derive_carrier_hash(&expected_server_key)` ONLY for the MSE `carrier_hash` passed to `PeerWireCrypto::initiator`.

Since `CarrierPool::start` becomes `async`, update its call site in `service.rs:62` to `.await` it and propagate the error (the client arm of `TunnelService::start` is already `async` and returns `anyhow::Result`).

- [ ] **Step 7: Verify build + run the identity test suite**

Run: `cargo check -p librqbit 2>&1 | tail -30`
Expected: compiles (there will be unused-var warnings for `carrier_store` on the client until Task 9 consumes it — acceptable this task).
Run: `cargo test -p librqbit tunnel::carrier_identity 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
cargo fmt --all
git add crates/librqbit/src/tunnel/
git commit -m "feat(tunnel): build deterministic carrier store on both ends; DHT rendezvous on handshake_info_hash"
```

---

## Task 6: Split `CarrierWire` into read/write halves + cover channel

The relay uses two tasks (reader + paced writer) sharing `Arc<Mutex<NoiseTransport>>`. `CarrierWire` bundles both halves and writes piece cover inline. Split it after `establish` so the writer half is owned solely by the writer task, and cover messages produced while reading are sent to the writer via a channel.

**Files:**
- Modify: `crates/librqbit/src/tunnel/carrier_wire.rs`
- Test: `carrier_wire.rs` tests

**Interfaces:**
- Produces:
  - `pub(crate) struct CarrierWriteHalf { writer: BoxAsyncWrite, peer_ids: PeerExtendedMessageIds }`
    - `pub(crate) async fn send_tunnel(&mut self, payload: &[u8]) -> Result<(), CarrierWireError>` (writes ONE rq_tunnel message; caller pre-chunks)
    - `pub(crate) async fn send_message(&mut self, msg: &Message<'_>) -> Result<(), CarrierWireError>`
  - `pub(crate) struct CarrierReadHalf { reader: BoxAsyncReadVectored, read_buf: ReadBuf }`
    - `pub(crate) async fn recv_message(&mut self) -> Result<Option<Message<'_>>, CarrierWireError>` — returns a message BORROWING `self` (no owned clone; `Message` does not implement `CloneToOwned`). The caller processes it inline before the next call, exactly as `recv_tunnel` does today.
  - `CarrierWire::into_halves(self) -> (CarrierReadHalf, CarrierWriteHalf, TunnelCarrierPeer)`

- [ ] **Step 1: Write the failing test**

Replace the existing `bt_masquerade_handshake_and_tunnel_roundtrip` test body's steady-state part to drive the split halves. Add a new test:

```rust
#[tokio::test]
async fn split_halves_carry_tunnel_and_cover() {
    let carrier = test_carrier().await;
    let info_hash = carrier.descriptor().handshake_info_hash;
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);

    let server_carrier = carrier.clone();
    let server = tokio::spawn(async move {
        let enc = PeerWireCrypto::responder(server_io, info_hash).await.unwrap();
        let wire = CarrierWire::establish(enc.reader, enc.writer, server_carrier, info_hash)
            .await
            .unwrap();
        let (mut r, mut w, _peer) = wire.into_halves();
        // Read one tunnel payload, echo it back as a tunnel payload.
        loop {
            match r.recv_message().await.unwrap() {
                Some(Message::Extended(ExtendedMessage::RqTunnel(rq))) => {
                    let payload = rq.as_bytes().to_vec();
                    w.send_tunnel(&payload).await.unwrap();
                    break payload;
                }
                Some(_) => continue,
                None => panic!("server disconnected early"),
            }
        }
    });

    let enc = PeerWireCrypto::initiator(client_io, info_hash).await.unwrap();
    let wire = CarrierWire::establish(enc.reader, enc.writer, carrier, info_hash)
        .await
        .unwrap();
    let (mut r, mut w, _peer) = wire.into_halves();

    let payload = b"noise-blob".to_vec();
    w.send_tunnel(&payload).await.unwrap();
    let echoed = loop {
        match r.recv_message().await.unwrap() {
            Some(Message::Extended(ExtendedMessage::RqTunnel(rq))) => break rq.as_bytes().to_vec(),
            Some(_) => continue,
            None => panic!("client disconnected early"),
        }
    };
    assert_eq!(echoed, payload);
    assert_eq!(server.await.unwrap(), payload);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p librqbit tunnel::carrier_wire::tests::split_halves 2>&1 | tail -20`
Expected: FAIL to compile — `into_halves` / halves not defined.

- [ ] **Step 3: Implement the split**

In `carrier_wire.rs`, add below the `CarrierWire` impl:

```rust
/// Owns the carrier writer half. All outbound BT messages (tunnel chunks and
/// piece cover) go through this single owner, preserving Noise sequence order.
pub(crate) struct CarrierWriteHalf {
    writer: BoxAsyncWrite,
    peer_ids: PeerExtendedMessageIds,
    scratch: Vec<u8>,
}

impl CarrierWriteHalf {
    /// Write one already-chunked tunnel payload as an `rq_tunnel` message.
    pub(crate) async fn send_tunnel(&mut self, payload: &[u8]) -> Result<(), CarrierWireError> {
        let msg = Message::Extended(ExtendedMessage::RqTunnel(RqTunnelMessage::from_bytes(payload)));
        write_message(&mut self.writer, &mut self.scratch, &msg, self.peer_ids).await
    }

    /// Write an arbitrary BT peer message (cover: Piece/Have/KeepAlive/…).
    pub(crate) async fn send_message(&mut self, msg: &Message<'_>) -> Result<(), CarrierWireError> {
        write_message(&mut self.writer, &mut self.scratch, msg, self.peer_ids).await
    }
}

/// Owns the carrier reader half. Yields decoded BT messages one at a time; the
/// caller routes `rq_tunnel` payloads and feeds other messages to
/// `TunnelCarrierPeer`.
pub(crate) struct CarrierReadHalf {
    reader: BoxAsyncReadVectored,
    read_buf: ReadBuf,
}

impl CarrierReadHalf {
    /// Read exactly one BT peer message, BORROWING the internal read buffer.
    /// `Ok(None)` on clean disconnect. The returned message borrows `self`, so
    /// the caller must finish using it before the next call (streaming pattern,
    /// identical to `recv_tunnel`'s internal loop). `Message` does NOT implement
    /// `CloneToOwned`, so we do not attempt to return an owned `Message<'static>`.
    pub(crate) async fn recv_message(
        &mut self,
    ) -> Result<Option<Message<'_>>, CarrierWireError> {
        match self
            .read_buf
            .read_message(&mut self.reader, WIRE_TIMEOUT)
            .await
        {
            Ok(m) => Ok(Some(m)),
            Err(e) => {
                tracing::debug!(error = %e, "carrier wire read ended");
                Ok(None)
            }
        }
    }
}

impl CarrierWire {
    /// Consume a post-establish `CarrierWire` into independently-owned halves
    /// plus the `TunnelCarrierPeer` cover state machine.
    pub(crate) fn into_halves(self) -> (CarrierReadHalf, CarrierWriteHalf, TunnelCarrierPeer) {
        (
            CarrierReadHalf {
                reader: self.reader,
                read_buf: self.read_buf,
            },
            CarrierWriteHalf {
                writer: self.writer,
                peer_ids: self.peer_ids,
                scratch: vec![0u8; MAX_MSG_LEN],
            },
            self.carrier_peer,
        )
    }
}
```

Resolved API note (controller-verified): `peer_binary_protocol::Message` does NOT implement `CloneToOwned` (only `Piece` does), so there is no owned-`Message<'static>` conversion. `recv_message` therefore returns a BORROWED `Message<'_>`, and callers process it inline — `rq_tunnel` payloads are copied to `Bytes`, and cover messages are handed to `carrier_peer.on_message(msg)` (which takes `Message<'_>` and returns already-`'static` `CarrierAction::OutgoingMessage`). No `clone_to_owned` call is used anywhere in this task.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p librqbit tunnel::carrier_wire 2>&1 | tail -20`
Expected: PASS (`split_halves_carry_tunnel_and_cover` + existing roundtrip).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add crates/librqbit/src/tunnel/carrier_wire.rs
git commit -m "feat(tunnel): split CarrierWire into read/write halves"
```

---

## Task 7: Server relay through the carrier

> **⚠️ EXECUTION RE-DECOMPOSITION (applied during execution).** During execution this section was split: the **defrag length-cap hardening** (the "Security hardening" block below) shipped independently as its own task/commit (`865546c8`, `fix(tunnel): bound CarrierDefragmenter declared length`) — `CarrierDefragmenter` is now `new(MAX_CARRIER_CIPHERTEXT)` with `push(...) -> Result<_, CarrierChunkError>`. The **server-relay migration steps** in the rest of this section were executed **atomically together with Task 8's client migration** as one task, because `spawn_frame_writer` and `read_encrypted_frame` are shared by both client and server and changing their signatures cannot compile split across two tasks. Read the rest of Task 7 + all of Task 8 as a single atomic unit whose gate is the full `cargo test -p librqbit tunnel` integration suite passing through the carrier.

Rewire `server.rs::accept` and `relay.rs` so the server runs `CarrierWire::establish` after MSE, does Noise over the carrier, and the relay reads/writes frames through the carrier halves (with piece cover).

**Security hardening (REQUIRED — added after Task 3 review).** `CarrierDefragmenter` (from Task 3) currently trusts the declared `u32` length with no upper bound. This task wires it to a live socket where the rendezvous `info_hash` is public (DHT-discoverable), so a peer that completes MSE + BT handshake but fails Noise auth can still feed the defragmenter. Harden it so an oversized declared length cannot cause unbounded buffering:
- Change `CarrierDefragmenter::new()` → `CarrierDefragmenter::new(max_msg_len: usize)` and store the cap. Callers pass `crypto::MAX_CIPHERTEXT`-equivalent: the max valid Noise ciphertext is `MAX_FRAME_PAYLOAD + 32` (frame payload 65535 + 8-byte seq + 16-byte tag + small frame header ⇒ use a constant `MAX_CARRIER_CIPHERTEXT = MAX_FRAME_PAYLOAD + 64` for slack). Define this constant in `carrier_chunk.rs`.
- Change `push(&mut self, chunk: &[u8]) -> Vec<Vec<u8>>` → `push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, CarrierChunkError>` where `CarrierChunkError::MessageTooLarge { declared, max }` is a typed error (thiserror). Return it BEFORE buffering when the decoded `len > max_msg_len` (check right after reading the 4-byte prefix, before the `< 4 + len` wait).
- Update Task 3's tests to the new signatures, and add one test: a declared length `> max` returns `MessageTooLarge` without buffering.
- In `next_tunnel_frame` / `recv_one_ciphertext`, treat a `push` error as a disconnect (return `None`), logging at debug.

Do this hardening as the FIRST step of this task (before the server rewire), committed separately (`fix(tunnel): bound CarrierDefragmenter declared length`).

**Files:**
- Modify: `server.rs:80-139` (accept), `relay.rs:226-385` (writer), `relay.rs:428-672` (server relay), `relay.rs:51-73` (reader helper)
- Test: `crates/librqbit/src/tests/tunnel.rs` (existing server-side E2E must pass in masquerade mode)

**Interfaces:**
- Consumes: `CarrierWire::establish`, `into_halves`, `CarrierReadHalf::recv_message`, `CarrierWriteHalf::{send_tunnel, send_message}`, `carrier_chunk::{chunk_ciphertext, CarrierDefragmenter}`, `TunnelCarrierPeer::{initial_messages(done in establish), on_message}`, `CarrierAction`
- Produces: `AdmittedPeer` carries carrier halves instead of raw MSE halves when `carrier_mode == BtMasquerade`

- [ ] **Step 1: Extend `AdmittedPeer` to carry the carrier**

`AdmittedPeer` (`server.rs:43-48`) currently holds raw `reader`/`writer`. Replace them with a carrier bundle so the relay is carrier-native:

```rust
pub(crate) struct AdmittedPeer {
    pub client_key: TunnelPublicKey,
    pub transport: NoiseTransport,
    pub read_half: super::carrier_wire::CarrierReadHalf,
    pub write_half: super::carrier_wire::CarrierWriteHalf,
    pub carrier_peer: super::carrier_peer::TunnelCarrierPeer,
}
```

- [ ] **Step 2: Rewrite `accept` to establish the carrier and do Noise over it**

Replace `server.rs:85-138` (after acquiring `carrier_hash` param) wholesale — the raw-Noise body is removed entirely:

```rust
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
        let (mut read_half, mut write_half, carrier_peer) = wire.into_halves();

        // ── Step 3: Noise IK initiator message, carried over rq_tunnel ──────
        let mut defrag = super::carrier_chunk::CarrierDefragmenter::new();
        let noise_msg = recv_one_ciphertext(&mut read_half, &mut defrag)
            .await
            .ok_or(TunnelAdmissionError::PeerDisconnected)?;
        if noise_msg.len() > 512 {
            return Err(TunnelAdmissionError::NoiseHandshakeFailed(
                TunnelCryptoError::HandshakeFailed(format!(
                    "noise initiator message too large: {}",
                    noise_msg.len()
                )),
            ));
        }

        let (transport, client_key, reply) = crypto::responder_accept(
            &self.options.identity_key,
            &noise_msg,
            &self.options.allowed_client_keys,
        )?;

        // ── Step 4: send Noise reply back over rq_tunnel ────────────────────
        for chunk in super::carrier_chunk::chunk_ciphertext(&reply) {
            write_half
                .send_tunnel(&chunk)
                .await
                .map_err(|e| TunnelAdmissionError::CarrierHandshakeFailed(anyhow::anyhow!("{e}")))?;
        }

        self.peers.write().await.insert(client_key.clone(), true);
        Ok(AdmittedPeer {
            client_key,
            transport,
            read_half,
            write_half,
            carrier_peer,
        })
```

Add a small helper in `server.rs` (module scope), which pumps carrier messages until a complete ciphertext is available (handling early cover inline via the writer would require the write half; during handshake we only expect the peer's rq_tunnel messages, so route non-rq_tunnel cover to `carrier_peer` is deferred — for the handshake, ignore non-rq_tunnel messages except to keep the connection alive):

```rust
/// Pump carrier messages until one full defragmented ciphertext is available.
async fn recv_one_ciphertext(
    read_half: &mut super::carrier_wire::CarrierReadHalf,
    defrag: &mut super::carrier_chunk::CarrierDefragmenter,
) -> Option<Vec<u8>> {
    use peer_binary_protocol::{Message, extended::ExtendedMessage};
    loop {
        match read_half.recv_message().await.ok()?? {
            Message::Extended(ExtendedMessage::RqTunnel(rq)) => {
                let mut done = defrag.push(rq.as_bytes());
                if !done.is_empty() {
                    return Some(done.remove(0));
                }
            }
            _ => continue,
        }
    }
}
```

- [ ] **Step 3: Rewrite the writer task to write chunks + drain a cover lane**

In `relay.rs`, change `spawn_frame_writer` to own a `CarrierWriteHalf` instead of a `BoxAsyncWrite`, add a `cover_rx: mpsc::Receiver<Message<'static>>` lane, and replace the inner `write_frame` seam.

Signature change:

```rust
pub(crate) fn spawn_frame_writer(
    transport: Arc<Mutex<NoiseTransport>>,
    mut write_half: super::carrier_wire::CarrierWriteHalf,
    mut cover_rx: mpsc::Receiver<Message<'static>>,
    shutdown: CancellationToken,
    pacing_rate: Arc<AtomicU64>,
    paced: Arc<AtomicBool>,
) -> (FrameSink, JoinHandle<()>)
```

Replace the inner `write_frame` (`relay.rs:252-271`) with a carrier version:

```rust
    async fn write_frame(
        write_half: &mut super::carrier_wire::CarrierWriteHalf,
        transport: &Mutex<NoiseTransport>,
        frame: &TunnelFrame,
    ) -> bool {
        let blob = {
            let mut t = transport.lock().await;
            match t.encrypt(frame) {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(error = %e, "encrypt failed");
                    return false;
                }
            }
        };
        for chunk in super::carrier_chunk::chunk_ciphertext(&blob) {
            if write_half.send_tunnel(&chunk).await.is_err() {
                return false;
            }
        }
        true
    }
```

In the `biased` select loop (`relay.rs:291-375`), add a cover branch AFTER the control branch and BEFORE the data branch (cover is unpaced, lower priority than control):

```rust
            msg = cover_rx.recv() => {
                match msg {
                    Some(m) => {
                        // A cover message that fails to SERIALIZE (e.g. an
                        // oversized Piece a malicious peer tried to request) must
                        // NOT kill the tunnel — skip it. Only a real write/IO
                        // failure breaks the writer.
                        match write_half.send_message(&m).await {
                            Ok(()) => {}
                            Err(super::carrier_wire::CarrierWireError::Serialize(_)) => {
                                tracing::debug!("skipping unserializable cover message");
                            }
                            Err(_) => break,
                        }
                    }
                    None => { /* cover lane closed; keep serving data/control */ }
                }
            }
```

All existing `write_frame(&mut writer, ...)` call sites become `write_frame(&mut write_half, ...)`. The token-bucket pacing (`bucket.take`, `relay.rs:352`) is unchanged — it still gates only `TcpData` before the `write_frame` call.

- [ ] **Step 4: Rewrite the server relay read path to use the carrier + cover**

In `run_server_relay` (`relay.rs:428-672`):
- Destructure `AdmittedPeer { client_key, transport, read_half, write_half, carrier_peer }`.
- Create the cover channel: `let (cover_tx, cover_rx) = mpsc::channel::<Message<'static>>(OUTBOUND_QUEUE);`
- Pass `write_half` + `cover_rx` to `spawn_frame_writer`.
- Replace the read loop's `read_encrypted_frame(&transport, &mut reader)` with a carrier read helper that returns decrypted `TunnelFrame`s AND drives cover:

```rust
    let mut defrag = super::carrier_chunk::CarrierDefragmenter::new();
    let mut carrier_peer = carrier_peer;
    // ... in the loop:
    let frame = match next_tunnel_frame(
        &mut read_half,
        &mut defrag,
        &transport,
        &mut carrier_peer,
        &cover_tx,
    ).await {
        Some(f) => f,
        None => break, // disconnect
    };
    // ... existing match on `frame` unchanged ...
```

Add the shared helper to `relay.rs` (module scope) — this REPLACES `read_encrypted_frame` for the carrier path and is reused by the client (Task 8):

```rust
/// Read carrier messages until one decrypted tunnel `TunnelFrame` is available,
/// serving piece cover (Request→Piece) via `cover_tx` along the way.
/// Returns `None` on disconnect or a hard decrypt/sequence error.
pub(crate) async fn next_tunnel_frame(
    read_half: &mut super::carrier_wire::CarrierReadHalf,
    defrag: &mut super::carrier_chunk::CarrierDefragmenter,
    transport: &Mutex<NoiseTransport>,
    carrier_peer: &mut super::carrier_peer::TunnelCarrierPeer,
    cover_tx: &mpsc::Sender<Message<'static>>,
) -> Option<TunnelFrame> {
    use peer_binary_protocol::{Message, extended::ExtendedMessage};
    loop {
        let msg = read_half.recv_message().await.ok()??;
        match msg {
            Message::Extended(ExtendedMessage::RqTunnel(rq)) => {
                for blob in defrag.push(rq.as_bytes()) {
                    let mut t = transport.lock().await;
                    match t.decrypt(&blob) {
                        Ok(frame) => return Some(frame),
                        Err(e) => {
                            tracing::debug!(error = %e, "carrier frame decrypt failed");
                            return None;
                        }
                    }
                }
            }
            Message::KeepAlive => {}
            other => {
                match carrier_peer.on_message(other).await {
                    Ok(actions) => {
                        for a in actions {
                            match a {
                                super::carrier_peer::CarrierAction::OutgoingMessage(m) => {
                                    let _ = cover_tx.send(m).await;
                                }
                                super::carrier_peer::CarrierAction::Disconnect(reason) => {
                                    tracing::debug!(%reason, "carrier peer requested disconnect");
                                    return None;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "carrier cover error");
                        return None;
                    }
                }
            }
        }
    }
}
```

Note: `defrag.push` returning multiple blobs in one call is possible; `next_tunnel_frame` returns the first and would drop the rest. To avoid loss, hoist `defrag` outside and, before reading a new message, first drain any already-buffered blob. Implement by having `next_tunnel_frame` keep a small `pending: &mut Vec<Vec<u8>>` passed in, or (simpler) change the loop to decrypt-and-return the first blob while pushing the remainder into a `VecDeque` field on the caller. For correctness, thread a `pending: &mut std::collections::VecDeque<Vec<u8>>` argument and check it at the top of the loop:

```rust
    if let Some(blob) = pending.pop_front() {
        let mut t = transport.lock().await;
        return match t.decrypt(&blob) { Ok(f) => Some(f), Err(_) => None };
    }
```

and in the rq_tunnel arm push extras: `for blob in defrag.push(...) { pending.push_back(blob); }` then `continue` the loop so the `pending` drain at the top handles them one at a time.

- [ ] **Step 5: Run the server-side E2E tests in masquerade mode**

Ensure the test harness constructs server options with a `carrier_root` tempdir. Run the existing SOCKS-through-tunnel tests:

Run: `cargo test -p librqbit tunnel:: 2>&1 | tail -40`
Expected: the existing E2E tests (`socks_connect_reaches_server_side_tcp_echo_only_through_tunnel`, `udp_associate_echoes_datagram_through_tunnel`, `real_relay_transfers_large_payload_with_flow_control`, …) PASS through the carrier once Task 8 lands the client. Until then, run only server-focused unit tests and `cargo check`.

Run: `cargo check -p librqbit 2>&1 | tail -30`
Expected: compiles.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add crates/librqbit/src/tunnel/server.rs crates/librqbit/src/tunnel/relay.rs
git commit -m "feat(tunnel): server relay over BT masquerade carrier with piece cover"
```

---

## Task 8: Client connect + mux through the carrier

> **⚠️ EXECUTION NOTE.** Executed as ONE atomic task together with Task 7's server-relay migration steps (shared `spawn_frame_writer`/`read_encrypted_frame`/`next_tunnel_frame` plumbing). Defrag API is now `CarrierDefragmenter::new(carrier_chunk::MAX_CARRIER_CIPHERTEXT)` + `push -> Result<_, CarrierChunkError>`; in `next_tunnel_frame`/`recv_one_ciphertext` treat `Err(MessageTooLarge)` as a disconnect (return `None`, debug-log). Cover-lane `send_message` serialize errors are non-fatal (skip, don't break). Gate: the full `cargo test -p librqbit tunnel` suite passes through the carrier.

Mirror Task 7 on the client: `TunnelClient::connect` runs `CarrierWire::establish` and Noise over the carrier; `ClientMux` reader loop uses `next_tunnel_frame`; the writer uses the carrier write half + cover lane.

**Files:**
- Modify: `client.rs:50-257` (struct fields, `connect`, `into_split`), `client_mux.rs:104-171` (`ClientMux::new`), `client_mux.rs:383-474` (`reader_loop`)
- Test: `crates/librqbit/src/tests/tunnel.rs`

**Interfaces:**
- Consumes: everything produced in Tasks 6–7. `TunnelClient::connect` gains a `carrier_store: Arc<TunnelCarrierStore>` param (threaded from the pool in Task 5).
- Produces: `TunnelClient::into_carrier(self) -> (NoiseTransport, CarrierReadHalf, CarrierWriteHalf, TunnelCarrierPeer)`

- [ ] **Step 1: Change `TunnelClient` fields to carrier halves**

Replace `reader`/`writer` fields (`client.rs:53-56`) with:

```rust
    read_half: super::carrier_wire::CarrierReadHalf,
    write_half: super::carrier_wire::CarrierWriteHalf,
    carrier_peer: super::carrier_peer::TunnelCarrierPeer,
```

- [ ] **Step 2: Rewrite `connect` to establish the carrier and Noise over it**

Add `carrier_store: Arc<super::carrier::TunnelCarrierStore>` param to `connect` (`client.rs:68-73`) and replace steps 2–3 (`client.rs:77-106`) with:

```rust
        // ── Step 2: MSE initiator ────────────────────────────────────────
        let enc = PeerWireCrypto::initiator(stream, carrier_hash)
            .await
            .map_err(|e| TunnelClientError::CarrierHandshake(e.to_string()))?;

        // ── Step 3: BT handshake + BEP-10 + cover ────────────────────────
        let info_hash = carrier_store.descriptor().handshake_info_hash;
        let wire = super::carrier_wire::CarrierWire::establish(
            enc.reader, enc.writer, carrier_store, info_hash,
        )
        .await
        .map_err(|e| TunnelClientError::CarrierHandshake(e.to_string()))?;
        let (mut read_half, mut write_half, carrier_peer) = wire.into_halves();

        // ── Step 4: Noise IK over rq_tunnel ──────────────────────────────
        let (handshake, noise_msg) = crypto::initiator_start(identity_key, expected_server_key)?;
        for chunk in super::carrier_chunk::chunk_ciphertext(&noise_msg) {
            write_half
                .send_tunnel(&chunk)
                .await
                .map_err(|e| TunnelClientError::CarrierHandshake(e.to_string()))?;
        }

        let mut defrag = super::carrier_chunk::CarrierDefragmenter::new();
        let reply = super::server::recv_one_ciphertext(&mut read_half, &mut defrag)
            .await
            .ok_or(TunnelClientError::ConnectionLost)?;
        let transport = crypto::initiator_complete(handshake, &reply)?;
```

(Expose `recv_one_ciphertext` from Task 7 as `pub(crate)` in `server.rs`, or move it to `carrier_chunk.rs` as a free helper `pub(crate) async fn recv_one_ciphertext(read_half, defrag)`. Prefer moving it to `carrier_chunk.rs` so both `client.rs` and `server.rs` share it without a cross-module dependency.)

Then build `Self { transport, read_half, write_half, carrier_peer, next_stream_id, next_assoc_id, .. }`.

- [ ] **Step 3: Replace `into_split` with `into_carrier`**

Replace `TunnelClient::into_split` (`client.rs:249-257`) with:

```rust
    pub(crate) fn into_carrier(
        self,
    ) -> (
        NoiseTransport,
        super::carrier_wire::CarrierReadHalf,
        super::carrier_wire::CarrierWriteHalf,
        super::carrier_peer::TunnelCarrierPeer,
    ) {
        (self.transport, self.read_half, self.write_half, self.carrier_peer)
    }
```

Note: the blocking `TunnelClient::read_frame`/`send_frame` API (`client.rs:226`) used `server::read_frame`/`write_frame`. Migrate those helpers to send/recv over `write_half`/`read_half` via chunking, OR gate the whole blocking API behind `#[cfg(test)]` if it is test-only. Confirm callers with `rg -n "into_split|\.read_frame\(|\.send_frame\(" crates/librqbit/src` and update each.

- [ ] **Step 4: Rewrite `ClientMux::new` and `reader_loop`**

In `ClientMux::new` (`client_mux.rs:104-171`): call `client.into_carrier()`; create `let (cover_tx, cover_rx) = mpsc::channel::<Message<'static>>(OUTBOUND_QUEUE);`; pass `write_half` + `cover_rx` to `spawn_frame_writer`; spawn `reader_loop` with `read_half`, `carrier_peer`, `cover_tx`, the shared `Arc<Mutex<NoiseTransport>>`, and the existing routing args.

In `reader_loop` (`client_mux.rs:383-474`): replace the signature's `reader`/adds `read_half`, `carrier_peer`, `cover_tx`; replace the `read_encrypted_frame(&transport, &mut reader)` call (`client_mux.rs:397`) with:

```rust
    let mut defrag = super::carrier_chunk::CarrierDefragmenter::new();
    let mut pending: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
    let mut carrier_peer = carrier_peer;
    loop {
        let frame = match super::relay::next_tunnel_frame(
            &mut read_half, &mut defrag, &mut pending, &transport, &mut carrier_peer, &cover_tx,
        ).await {
            Some(f) => f,
            None => break,
        };
        // ... existing per-frame demux/routing unchanged ...
    }
```

(Adjust `next_tunnel_frame`'s signature to include `pending: &mut VecDeque<Vec<u8>>` per Task 7 Step 4's correctness note, and update the server caller the same way.)

- [ ] **Step 5: Run the full tunnel E2E suite in masquerade mode**

Update the test harness (`build_real_relay_pair`, `start_live_carrier_pool`, and any option builders in `tests/tunnel.rs`) to set `carrier_root` tempdirs on BOTH client and server options.

Run: `cargo test -p librqbit tunnel 2>&1 | tail -60`
Expected: ALL existing tunnel E2E tests PASS through the masquerade carrier — specifically:
- `socks_connect_reaches_server_side_tcp_echo_only_through_tunnel`
- `udp_associate_echoes_datagram_through_tunnel`
- `multiple_concurrent_tcp_streams_through_tunnel`
- `real_relay_transfers_large_payload_with_flow_control`
- `client_rejects_wrong_server_key_before_sending_frames`
- `carrier_pool_distributes_streams_across_live_carriers`

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add crates/librqbit/src/tunnel/client.rs crates/librqbit/src/tunnel/client_mux.rs crates/librqbit/src/tunnel/carrier_chunk.rs crates/librqbit/src/tunnel/server.rs
git commit -m "feat(tunnel): client connect + mux over BT masquerade carrier"
```

---

## Task 9: Narrow `dead_code`; capture-harness E2E gate

Now that the carrier is live, remove the blanket dead-code suppression for the wired modules and add the E2E gate proving real BT events appear on the wire.

**Files:**
- Modify: `mod.rs:1-15` (narrow allows)
- Test: `crates/librqbit/src/tests/tunnel.rs` (new capture test using `test_capture.rs`)

**Interfaces:**
- Consumes: `test_capture::{RawCapture, CarrierTrace, CarrierEvent}` (`test_capture.rs`)

- [ ] **Step 1: Write the failing E2E capture test**

Add to `tests/tunnel.rs`. Use the existing real-relay harness but wrap the client↔server transport in `RawCapture`/`CarrierTrace` (see `test_capture.rs` for the exact wrapper constructor; it wraps a transport stream and records normalized `CarrierEvent`s). Assert the trace contains real BT events:

```rust
#[tokio::test]
async fn wire_shows_real_bittorrent_events() {
    // Build a masquerade-mode relay pair whose server<->client byte stream is
    // observed by a CarrierTrace (records ExtendedHandshake/Bitfield/Piece/…).
    let (trace, harness) = build_traced_masquerade_pair().await;

    // Drive a small SOCKS request through the tunnel so cover Request/Piece flow.
    harness.socks_get_echo(b"ping").await.unwrap();

    let events = trace.events();
    assert!(events.contains(&CarrierEvent::ExtendedHandshake), "no BEP-10 handshake on wire");
    assert!(events.contains(&CarrierEvent::Bitfield), "no bitfield on wire");
    assert!(
        events.contains(&CarrierEvent::Piece) || events.contains(&CarrierEvent::Request),
        "no piece cover on wire: {events:?}"
    );
}
```

Implement `build_traced_masquerade_pair` / `socks_get_echo` in the test module by extending the existing `build_real_relay_pair` (`tests/tunnel.rs:595`) to insert the `CarrierTrace` wrapper (from `test_capture.rs`) around the server's accepted `TcpStream` before MSE. Follow the wrapping pattern the `test_capture.rs` doc comments describe; a `CarrierTrace` must observe the DECRYPTED-BT layer, so wrap at the point where BT `Message`s are serialized — i.e. instrument `CarrierWriteHalf`/`CarrierReadHalf` in a `#[cfg(test)]` tap, or decode the post-MSE stream in the trace. If a message-level tap is not already available, add a `#[cfg(test)]` hook on `write_message`/`read_message` in `carrier_wire.rs` that feeds a `CarrierTrace`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p librqbit tunnel::wire_shows_real_bittorrent_events 2>&1 | tail -30`
Expected: FAIL (helpers missing / assertion fails because cover not yet flowing).

- [ ] **Step 3: Ensure cover Request/Piece actually flow**

For the assertion to hold, at least one side must send `Request`s. `establish` advertises the full bitfield (all pieces) via `initial_messages()` (`carrier_peer.rs:174-190`), so neither side requests. Add a minimal cover-request trigger: after `into_halves`, have the client enqueue a few `Request`s for real pieces onto its `cover_tx` at mux start (the server answers with `Piece`s via `on_message`). Concretely, in `ClientMux::new`, after spawning the reader/writer, send:

```rust
    // Minimal piece cover so the connection exhibits real BT Request/Piece
    // traffic (Plan C elaborates the cadence).
    let cover_seed = cover_tx.clone();
    tokio::spawn(async move {
        for idx in 0u32..2 {
            let _ = cover_seed
                .send(peer_binary_protocol::Message::Request(
                    peer_binary_protocol::Request::new(idx, 0, 16384),
                ))
                .await;
        }
    });
```

The server's `next_tunnel_frame` routes the returned `Piece` to `carrier_peer.on_message` (validates + no-op) — the wire now carries Request (client→server) and Piece (server→client). The `CarrierTrace` records both.

- [ ] **Step 4: Narrow the dead-code allow**

In `mod.rs:1-15`, remove the blanket `#![allow(dead_code)]` and `#![allow(unused_variables)]`. Replace with per-item `#[allow(dead_code)]` only where genuinely still-unused code remains (run `cargo check 2>&1` to get the exact list, then annotate those items). The wired modules (`carrier`, `carrier_wire`, `carrier_peer`, `carrier_identity`, `carrier_chunk`) must compile with NO blanket suppression.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p librqbit tunnel 2>&1 | tail -40`
Expected: PASS including `wire_shows_real_bittorrent_events`.
Run: `cargo clippy -p librqbit --all-targets 2>&1 | tail -30`
Expected: no new warnings from the wired modules.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add crates/librqbit/src/tunnel/mod.rs crates/librqbit/src/tests/tunnel.rs crates/librqbit/src/tunnel/client_mux.rs
git commit -m "test(tunnel): E2E gate asserts real BT events on wire; narrow dead_code"
```

---

## Task 10: Milestone pcap review (manual E2E gate)

Automated gates prove protocol structure; the milestone pcap confirms it against a real capture as the spec's verification strategy requires.

**Files:** none (verification only). Uses `scripts/tunnel/`.

- [ ] **Step 1: Build release binaries**

Run: `cargo build --release -p rqbit`

- [ ] **Step 2: Start a server and client tunnel locally**

Use `scripts/tunnel/server-quickstart.sh` and `scripts/tunnel/client-run.sh` (read them first for the exact flags/keys). Start the server, then the client, on loopback with a fixed `server_addr`.

- [ ] **Step 3: Capture the carrier connection**

Run (loopback, server peer port from the script, e.g. 9090):
`sudo tcpdump -i lo -w /tmp/rqbit-carrier.pcap 'tcp port 9090'`

Drive traffic through the client SOCKS proxy:
`curl -x socks5h://127.0.0.1:<socks_port> http://example.com/ -o /dev/null`

- [ ] **Step 4: Inspect and confirm BT shape**

Open the pcap (`tcpdump -r /tmp/rqbit-carrier.pcap -X | head -100` or Wireshark). Confirm:
- The first client→server bytes are the MSE DH exchange (96-byte high-entropy blob), NOT a plaintext BT handshake (MSE hides the pstr).
- Steady state is a single long-lived TCP flow with bidirectional data (no plaintext leaks of the destination).
- Message sizes/cadence are consistent with an encrypted BT peer (mix of ~16 KiB-ish records), not request/response HTTP shapes.

Record the observations in `docs/superpowers/specs/2026-07-21-full-bittorrent-masquerade-design.md` under a new "Results (Plan A)" section (mirroring how the multicarrier spec records results), then commit that doc note.

- [ ] **Step 5: Commit the results note**

```bash
git add docs/superpowers/specs/2026-07-21-full-bittorrent-masquerade-design.md
git commit -m "docs(tunnel): record Plan A pcap milestone results"
```

---

## Self-Review

**Spec coverage (Plan A rows of the master spec):**
- Deterministic fake corpus → Tasks 1–2. ✓
- info_hash unification (DHT ↔ handshake) → Tasks 5. ✓ (MSE key stays `carrier_hash`; DHT + handshake use `handshake_info_hash`.)
- 64 KiB → 16 KiB chunking → Task 3, consumed in 7–8. ✓
- Preserve flow control / pacing / control lane → Task 7 Step 3 (token bucket unchanged; control lane preserved; cover lane added below control, above data). ✓
- No wire compatibility (wholesale replacement, no dual mode — approved revision) → Tasks 4/7/8 replace the raw path outright; isolation preserved by unit tests on the new modules. ✓
- Remove `#![allow(dead_code)]` for wired modules → Task 9 Step 4. ✓
- E2E gate: capture harness sees Handshake/ExtendedHandshake/Bitfield/Piece/Request; existing integration tests pass; SOCKS TCP+UDP traverse; milestone pcap → Tasks 8 Step 5, 9, 10. ✓

**Placeholder scan:** No `TBD`/`TODO`. Two items require confirming an existing API before writing the exact call and are called out explicitly with the command to confirm: `Message::clone_to_owned` arity (Task 6 Step 3) and the `CarrierTrace` tap point (Task 9 Step 1). These are verification steps, not unfilled blanks.

**Type consistency:** `next_tunnel_frame` signature is defined once (Task 7 Step 4) and both callers (server relay, client `reader_loop`) use the same arg list including `pending: &mut VecDeque<Vec<u8>>`. `CarrierWriteHalf::send_tunnel` takes an already-chunked `&[u8]`; every caller chunks via `chunk_ciphertext` first. `recv_one_ciphertext` is defined once and shared (moved to `carrier_chunk.rs` per Task 8 Step 2). `AdmittedPeer` (Task 7 Step 1) and `TunnelClient` fields (Task 8 Step 1) both carry `read_half`/`write_half`/`carrier_peer` of the same carrier types.

**Known risk to watch during execution:** `CarrierReadHalf::recv_message` uses `ReadBuf::read_message` with `WIRE_TIMEOUT`. In the reader loops this is awaited directly (one message at a time) — it is NOT inside a `select!` here, so cancel-safety is not required. If a later plan puts it inside a `select!`, revisit. The writer task remains the sole writer (tunnel chunks + cover), preserving Noise sequence == wire order.
