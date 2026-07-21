# Plan C — Steady-State Cadence Realism — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development / executing-plans. Steps use `- [ ]`.

**Goal:** Make the carrier's steady-state behavior match a real BitTorrent client's, so a *protocol-aware* passive observer (rung 2, full) sees ordinary BT activity, not "handshake then only opaque extended messages." Add ut_metadata (BEP-9) advertise+serve, a keepalive cadence, and ongoing Request/Piece cover — beyond Plan A's handshake+bitfield and Plan B's seeder serving.

**Architecture:** Extend the BEP-10 extended handshake in `CarrierWire::establish` to advertise `ut_metadata` + `metadata_size` (like qBittorrent). Handle inbound `ut_metadata` `request` messages by serving the fake torrent's raw info-dict bytes in 16 KiB pieces (BEP-9). Add a keepalive timer to the carrier writer path (both endpoints) that emits `Message::KeepAlive` on idle. Add an ongoing cover cadence (periodic `Request` on the client mux; server answers with `Piece` as today). Everything rides the existing cover lane / `CoverMessage` machinery; tunnel data over `rq_tunnel` is unchanged.

**Tech Stack:** Rust, tokio, `peer_binary_protocol` (extended handshake, `UtMetadata` BEP-9 messages already supported — keys/ids at `lib.rs:51-52`), existing `carrier_wire`/`carrier_peer`/`relay`.

## Global Constraints
- BEP 52 (v2) info dict for the served metadata — the `ut_metadata` bytes MUST be the exact raw info-dict whose hash equals the advertised `handshake_info_hash`/`info_hash` (else a probing client detects a metadata/info-hash mismatch — a worse tell than not advertising).
- Preserve the Plan B pre-auth resource bounds: metadata serving is itself an amplification surface (info dict is small — a few KiB — but cap requests per connection); keep it choke/rate-bounded or bounded by the seed-window deadline. Metadata serving pre-auth is reachable by anyone knowing `server_pub` — do NOT introduce a new unbounded pre-auth disk/CPU/alloc path.
- Prefer typed errors over `anyhow`. Use repo-local `TMPDIR` for cargo. `cargo check`/`clippy --all-targets` clean; `cargo fmt`; full `cargo test -p librqbit tunnel` green after each task.
- Keepalive/cover cadence must not interfere with tunnel-data pacing or the control-priority lane (Plan A) — cover stays on the best-effort lane, below data.

## File Structure
- Modify: `carrier_wire.rs` — extended handshake advertises ut_metadata + metadata_size; expose the raw info-dict bytes/size.
- Modify: `carrier.rs` / `carrier_identity.rs` — persist/expose the raw info-dict bytes (`ut_metadata` serves these; `info_hash_v2(info_bytes)` must match the descriptor).
- Modify: `carrier_peer.rs` — handle inbound `ut_metadata` request → serve `data` pieces (bounded); a per-connection metadata-request cap.
- Modify: `relay.rs` / `client_mux.rs` — keepalive timer on the writer; ongoing cover-request cadence.
- Modify: `config.rs` — `KEEPALIVE_INTERVAL`, `COVER_REQUEST_INTERVAL`, `MAX_METADATA_REQUESTS_PER_CONN`.
- Test: `tests/tunnel.rs`, unit tests.

---

## Task 1: Advertise + serve ut_metadata (BEP-9)

**Files:** `carrier.rs`/`carrier_identity.rs` (expose raw info-dict bytes), `carrier_wire.rs` (advertise), `carrier_peer.rs` (serve), `config.rs` (cap), tests.

**Interfaces:**
- Produces: `TunnelCarrierDescriptor` (or store) exposes `info_bytes: Bytes` (the raw v2 info dict, `info_hash_v2(info_bytes) == info_hash`) and its length for `metadata_size`.
- `carrier_peer` handles `Message::Extended(ExtendedMessage::UtMetadata(...))` request → `data` responses, capped by `MAX_METADATA_REQUESTS_PER_CONN`.

- [ ] **Step 1: Expose the raw info-dict bytes.** `carrier.rs::build_metainfo` already returns `(info_bytes, metainfo_bytes)` but only persists metainfo. Persist/derive the raw info-dict bytes so the store can serve them. Either store `info_bytes` in the descriptor file, or re-extract them from the persisted metainfo by locating the `info` value's raw bencode span (bencode is deterministic; the info dict is a contiguous byte range). Add `TunnelCarrierStore::info_dict_bytes(&self) -> &[u8]`. TEST: `info_hash_v2(store.info_dict_bytes()) == store.descriptor().info_hash`.

- [ ] **Step 2: Advertise ut_metadata in the extended handshake.** In `carrier_wire.rs::establish`, before sending the `ExtendedHandshake`, set `ext.metadata_size = Some(info_dict_len as u32)` and advertise `ut_metadata` in `ext.m` (the outgoing `PeerExtendedMessageIds` must include `ut_metadata = Some(MY_EXTENDED_UT_METADATA=3)` alongside `rq_tunnel`). Match qBittorrent: advertise `ut_metadata` + `ut_pex` (pex handled as a no-op/accepted for now — Plan E serves it) so the `m` dict looks normal. Confirm what `ExtendedHandshake::new()` currently advertises and add the missing ids. TEST: a peer reading our extended handshake sees `ut_metadata` id + a non-zero `metadata_size`.

- [ ] **Step 3: Serve ut_metadata requests.** In `carrier_peer.rs::on_message`, handle inbound `UtMetadata` `request { piece }`: respond with `UtMetadata data { piece, total_size, <=16 KiB of info_dict_bytes }` (BEP-9 pieces the info dict into 16 KiB chunks). Reject out-of-range piece indices (typed error, no panic). Enforce `MAX_METADATA_REQUESTS_PER_CONN` (add to config.rs; small, e.g. `2 * ceil(metadata_size/16KiB) + 4`) — after the cap, ignore further metadata requests (no drop, no tell), bounding the pre-auth amplification. The `data` responses go through the existing `CoverMessage`/cover lane (add a `CoverMessage::UtMetadata` variant or reuse a raw extended-message cover path). TEST: a peer that sends a metadata `request` for each piece reassembles bytes equal to `info_dict_bytes`, and `info_hash_v2` of the reassembled bytes matches the advertised info hash; an out-of-range request is rejected without panic; the per-conn cap stops serving after N.

- [ ] **Step 4:** `cargo test -p librqbit tunnel` green; clippy/fmt clean. Commit: `feat(tunnel): advertise + serve ut_metadata (BEP-9) cover`

---

## Task 2: Keepalive cadence

**Files:** `relay.rs` (writer keepalive timer), `client_mux.rs` (client writer), `config.rs`.

- [ ] **Step 1:** Add `KEEPALIVE_INTERVAL` to config.rs (a real BT client sends a keepalive roughly every ~2 min of idle; use e.g. `Duration::from_secs(110)`). Write a failing test asserting a `KeepAlive` is emitted on an otherwise-idle carrier within the interval (observe via the message-level trace tap from Plan A's capture harness, or a unit test on the writer).
- [ ] **Step 2:** In the carrier writer task (both server relay and client mux writer), add a `tokio::time::interval(KEEPALIVE_INTERVAL)` branch in the `biased` select that sends `Message::KeepAlive` via the cover lane (best-effort; lowest priority, below data/cover). It must NOT reset on tunnel-data activity in a way that suppresses keepalives during long idle — a real client sends keepalives even on active connections periodically; simplest: emit on the interval tick regardless (a keepalive on a busy connection is harmless and realistic). Ensure it doesn't perturb Noise sequence order (KeepAlive is a plain BT message, not a tunnel frame — like Piece cover).
- [ ] **Step 3:** Full suite green; clippy/fmt. Commit: `feat(tunnel): periodic BT keepalive cadence on the carrier`

---

## Task 3: Ongoing cover-request cadence + E2E cadence gate

**Files:** `client_mux.rs` (replace the fixed 2-request seed with an ongoing cadence), `config.rs`, `tests/tunnel.rs`.

- [ ] **Step 1:** Replace the one-shot 2-`Request` cover seed in `ClientMux::new` (from Plan A) with a periodic cover-request task: every `COVER_REQUEST_INTERVAL` (config.rs, e.g. 2–5 s with jitter), send a `Request` for a plausible piece/block (rotating indices) so the carrier exhibits ongoing piece exchange, not just a one-time burst. Keep it best-effort (`try_send` on the cover lane) and bounded (it's cover; drop on full). The server answers with `Piece` as today (choke/pieces-cap gated from Plan B — note: the pieces cap is now per-connection; ongoing cover over a long-lived authenticated carrier must not self-choke — confirm `pieces_served` was reset on promotion in Plan B, and consider that ongoing cover over hours will hit `MAX_SEEDER_PIECES_PER_CONN`; for an AUTHENTICATED carrier, cover should not be capped by the pre-auth seeder bound — gate the cap on pre-auth only, or raise/disable it post-promotion).
- [ ] **Step 2 (E2E gate):** In `tests/tunnel.rs`, extend the Plan A capture harness (`CarrierTrace`) with a cadence test `carrier_cadence_matches_a_real_client_profile`: over a bounded window on a live tunnel, assert the wire shows (a) the extended handshake advertised `ut_metadata` + `metadata_size`; (b) at least one served `ut_metadata` data response when the peer requests metadata; (c) a `KeepAlive` within `KEEPALIVE_INTERVAL` on idle; (d) ongoing `Request`/`Piece` events across the window (not just at start). These are STRUCTURAL cadence properties (the full statistical/reference-pcap match is Plan F's job, not this gate).
- [ ] **Step 3:** Full suite green; clippy/fmt. Commit: `test(tunnel): steady-state cadence E2E gate; ongoing cover-request cadence`

---

## Self-Review checklist
- ut_metadata advertised + served with bytes matching the advertised info hash (no metadata/info-hash tell). ✓
- Metadata serving bounded per connection (no new pre-auth amplification). ✓
- Keepalive emitted on idle within interval; on the best-effort lane; no Noise-order perturbation. ✓
- Ongoing Request/Piece cover; authenticated carriers not self-choked by the pre-auth pieces cap. ✓
- E2E gate asserts structural cadence (extensions, metadata, keepalive, ongoing pieces). ✓
- ut_pex advertised (accepted/no-op) but full PEX deferred to Plan E. ✓
