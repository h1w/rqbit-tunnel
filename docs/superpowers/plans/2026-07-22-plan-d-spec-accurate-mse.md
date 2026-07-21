# Plan D — Spec-Accurate MSE/PE — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`. This is authorized defensive/interop crypto work on a censorship-circumvention tool. Use opus for implementers and reviewers — the code is security- and correctness-critical.

**Goal:** Rewrite the tunnel's `PeerWireCrypto` (currently an MSE-*flavoured* obfuscation with wire deviations) into a **spec-accurate MSE/PE handshake** (the de-facto Vuze/Azureus Message Stream Encryption), so the carrier's outer layer is indistinguishable from a real encrypted BitTorrent peer to an ACTIVE, MSE-aware probe — closing rung 4. This makes the "encrypted peer" identity (the current default) genuinely conformant.

**Why:** The current handshake (`peer_wire_crypto.rs`) matches MSE on DH group-2 (768-bit), RC4, the 1024-byte keystream discard, and an 8-zero VC — but deviates in three observable ways that a protocol-aware active probe can detect: (1) padding is sent with a **cleartext 2-byte length prefix** (real MSE sends raw random padding and the receiver **resynchronizes** on a marker); (2) it omits the `HASH('req1',S)` / `HASH('req2',SKEY) xor HASH('req3',S)` markers; (3) it omits the `crypto_provide`/`crypto_select` negotiation and uses a non-spec key derivation.

## The MSE handshake to implement (target wire format)
`S` = DH shared secret (96 bytes, big-endian). `SKEY` = the torrent info hash used to key the stream (see Global Constraints — we use the carrier's advertised `handshake_info_hash`). `VC` = 8 zero bytes.

- **1. A→B:** `Ya` (96 bytes, DH pubkey, zero-left-padded) ‖ `PadA` (0–512 random bytes, **NO length prefix**).
- **2. B→A:** `Yb` (96) ‖ `PadB` (0–512 random, no prefix).
- **3. A→B:** `HASH('req1',S)` (20) ‖ `HASH('req2',SKEY) xor HASH('req3',S)` (20) ‖ `ENCRYPT(keyA, VC(8) ‖ crypto_provide(4,BE) ‖ len(PadC)(2,BE) ‖ PadC ‖ len(IA)(2,BE)=0)`.
- **4. B→A:** `ENCRYPT(keyB, VC(8) ‖ crypto_select(4,BE) ‖ len(PadD)(2,BE) ‖ PadD)`.
- Payload after handshake continues the SAME RC4 streams: A→B under `keyA`, B→A under `keyB` (each already advanced by the 1024-byte discard **and** the handshake ciphertext above).

Key derivation (MSE spec): `keyA = SHA1('keyA' ‖ S ‖ SKEY)`, `keyB = SHA1('keyB' ‖ S ‖ SKEY)`. Initiator encrypts with keyA / decrypts with keyB; responder encrypts with keyB / decrypts with keyA. Each cipher discards 1024 keystream bytes before first use.

**Resynchronization (the hard part):** the receiver does not know the sender's pad length.
- **B**, after reading `Ya` (96 bytes), reads bytes and slides a 20-byte window looking for `HASH('req1',S)` (skips `PadA`); bounded scan (≤ 512 + 20 + slack). On match, reads the 20-byte marker, computes `HASH('req2',our_SKEY) xor HASH('req3',S)` and compares — mismatch ⇒ reject (not our torrent). Then decrypts with `keyA`, verifies `VC == 0`, reads `crypto_provide`, picks `crypto_select`, reads `PadC`/`len(IA)`.
- **A**, after reading `Yb` (96), computes the expected `ENCRYPT(keyB, VC)` (8 bytes, keystream position 0 after discard) and slides an 8-byte window looking for it (skips `PadB`); bounded scan. On match, continues decrypting `crypto_select`, `PadD`.

## Global Constraints
- **SKEY = the carrier's `handshake_info_hash`** (the fake torrent info hash we already advertise on DHT + in the BT handshake), NOT the current `carrier_hash`. Rationale: real MSE is keyed by the (public) info hash a peer requests; using it makes an active MSE probe that knows our DHT info hash see a real, matching handshake, and is consistent with Plan B (probers reach the seeder; the real authentication is the inner Noise IK + allowlist, unchanged). The client knows `handshake_info_hash` (it builds the deterministic carrier store). This OPENS the MSE gate from "needs server_pub" to "needs the public info hash" — that is correct and intended; the Plan B pre-auth bounds already protect the seeder.
- Preserve the inner layering: MSE (RC4) → BT/BEP-10 handshake → `rq_tunnel` → Noise IK. Only the OUTER MSE handshake changes; everything inside is untouched.
- **No unbounded pre-auth reads:** the resync scan MUST be bounded (≤ ~600 bytes) and fail closed — a peer streaming garbage must not cause an unbounded read/alloc. Fail = drop (a real MSE peer also drops on a malformed handshake; this is pre-auth and looks like normal MSE rejection).
- Typed errors (`TunnelCryptoError`), no panic on crafted input. RC4/DH primitives (`generate_dh_keypair`, `mse_prime`, `new_rc4`, `rc4_discard`, `EncryptedReader`/`EncryptedWriter`) are already correct — REUSE them; replace only the choreography + key derivation + add markers/negotiation/resync.
- Verify with repo-local `TMPDIR`. `cargo check`/`clippy --all-targets` clean; `cargo fmt`; full `cargo test -p librqbit tunnel` green after each task.
- **Interop caveat:** true interop against a real qBittorrent MSE peer can't be run in this environment (no external network). The gate is self-interop (our initiator ↔ our responder) + known-derivation conformance + structural wire assertions (marker offsets, no cleartext length prefix, encrypted VC). Real-client interop is a deployment-time verification — document it.

## File Structure
- Modify: `peer_wire_crypto.rs` — the whole handshake + key derivation; keep DH/RC4/wrapper primitives.
- Modify: `client.rs`, `server.rs` (+ `client_supervisor.rs`/`client_pool.rs` as needed) — pass `handshake_info_hash` as SKEY instead of `carrier_hash`.
- Test: `peer_wire_crypto.rs` unit + `tests/tunnel.rs` integration/conformance.

---

## Task 1: Spec-accurate key derivation + markers (pure functions + conformance vectors)

**Files:** `peer_wire_crypto.rs` (replace `derive_rc4_keys`; add `req1/req2/req3` + marker helpers), tests.

**Interfaces:**
- Produces (all pure): `mse_keys(s: &[u8;96], skey: &[u8;20]) -> (Rc4Key, Rc4Key)` returning `(keyA, keyB)` = `(SHA1('keyA'‖s‖skey), SHA1('keyB'‖s‖skey))`; `req1(s)->[u8;20]`, `req2(skey)->[u8;20]`, `req3(s)->[u8;20]`; `sync_marker(skey,s) = req2(skey) xor req3(s)`.

- [ ] **Step 1:** Write failing tests: (a) `keyA != keyB` and both deterministic; (b) `keyA == SHA1(b"keyA" ‖ s ‖ skey)` recomputed independently in the test (assert the EXACT formula, not a tautology — the test builds the SHA1 input itself); (c) `req1/req2/req3` distinct + deterministic; (d) `sync_marker` = xor of req2,req3, and `sync_marker xor req3(s) == req2(skey)` (the recovery a responder does). Run → fail.
- [ ] **Step 2:** Implement the helpers per the MSE formulas above (SHA1 = existing `sha1()` helper). Remove/replace the old `derive_rc4_keys` (`req_seed = SHA1(SKEY‖info_hash)`, keyA/keyB suffix markers) — the OLD derivation is non-spec and must go. Run → pass.
- [ ] **Step 3:** `cargo test -p librqbit tunnel::peer_wire_crypto` + clippy/fmt. Commit: `feat(tunnel): spec-accurate MSE key derivation + req1/req2/req3 markers`

---

## Task 2: Spec-accurate handshake choreography + resync + crypto negotiation

**Files:** `peer_wire_crypto.rs` (`do_handshake` rewrite; add a bounded resync helper; `PeerWireCrypto::initiator/responder` gain a `skey: Id20` param — see Task 3 for wiring, but the signature changes here).

- [ ] **Step 1:** Write a failing self-interop test: `PeerWireCrypto::initiator(client_io, skey)` ↔ `responder(server_io, skey)` over `tokio::io::duplex`, both with the SAME `skey`; after the handshake, write bytes through the initiator's encrypted writer and read them decrypted on the responder's reader (and vice-versa) — asserting round-trip. Also a MISMATCHED-skey test: responder with a different skey must REJECT (marker mismatch). Run → fail (signature/behavior).
- [ ] **Step 2:** Rewrite `do_handshake` to the 5-step MSE choreography above:
  - Replace `write_padding`/`read_padding_prefixed` (cleartext length prefix) with `write_raw_pad()` (random 0–512 bytes, NO prefix) and a bounded `resync_on(stream, marker: &[u8], max_scan)` helper that reads bytes into a rolling buffer, slides a window to find `marker`, returns the bytes consumed AFTER the marker (and errors if `max_scan` exceeded — fail closed).
  - Initiator: send Ya‖PadA; read Yb (96) then `resync_on(ENCRYPT(keyB,VC))`; verify; read/decrypt `crypto_select`‖len(PadD)‖PadD; send step-3 (req1 ‖ marker ‖ ENCRYPT(keyA, VC‖crypto_provide‖len(PadC)‖PadC‖0)). ORDER: A must send step 3 before it can read step 4 — follow the spec's exact ordering (A sends 1, receives 2, sends 3, receives 4). Re-derive the precise send/recv interleave from the target format above and implement it exactly.
  - Responder: read Ya (96) then `resync_on(req1(S))`; read marker, verify `== sync_marker(our_skey, S)` else reject; decrypt VC (keyA) verify zero; read crypto_provide; send Yb‖PadB; send step-4 (ENCRYPT(keyB, VC‖crypto_select‖len(PadD)‖PadD)). (Note: responder can compute S only after reading Ya, so it sends Yb after — matches the current code's structure.)
  - `crypto_provide = 0x0000_0003` (plaintext|RC4); `crypto_select = 0x0000_0002` (RC4). If a foreign initiator provides RC4 (bit 0x02 set), select RC4; if it provides ONLY plaintext (0x01), you MAY select plaintext (still conformant — the inner Noise protects) or reject — pick one, document it, and keep our own client always providing 0x03 so our own handshakes always negotiate RC4. `IA` (initial payload) is empty (`len(IA)=0`) — we send the BT handshake as normal post-MSE payload.
  - Keep the RC4 cipher continuity: the `EncryptedReader`/`EncryptedWriter` must wrap the stream with the RC4 ciphers positioned AFTER the 1024 discard AND the handshake-encrypted bytes each side wrote/read, so payload continues the keystream seamlessly. Verify the byte accounting carefully.
- [ ] **Step 3:** Make the tests pass. Add: a structural test capturing the initiator's raw first bytes and asserting `Ya` is 96 bytes then random pad with NO 2-byte length prefix, and that `req1(S)` appears (marker present); a bounded-resync test (a peer that never sends the marker → the scan fails within `max_scan`, not an unbounded read).
- [ ] **Step 4:** Full `cargo test -p librqbit tunnel` — note: this task changes the `PeerWireCrypto` signature (adds `skey`); update the call sites minimally to keep compiling (pass the existing `carrier_hash` as a placeholder skey here; Task 3 switches it to `handshake_info_hash`). Green + clippy/fmt. Commit: `feat(tunnel): spec-accurate MSE handshake (markers, crypto negotiation, resync)`

---

## Task 3: SKEY = handshake_info_hash; integration + conformance E2E

**Files:** `client.rs`, `server.rs`, `client_supervisor.rs`/`client_pool.rs`, `tests/tunnel.rs`.

- [ ] **Step 1:** Change the `skey` passed to `PeerWireCrypto::initiator`/`responder` from `carrier_hash` (`derive_carrier_hash`) to the carrier store's `descriptor().handshake_info_hash` — which the server and client already build (Plan A/5). The MSE key is now the public advertised info hash, exactly like a real torrent client. (`carrier_hash`/`derive_carrier_hash` may become unused for MSE — keep it only if still used elsewhere; remove the dead import if not.) Confirm both endpoints derive the SAME `handshake_info_hash` (already guaranteed by the deterministic carrier).
- [ ] **Step 2:** E2E: the FULL `cargo test -p librqbit tunnel` suite must pass over the new spec-accurate MSE (the whole stack — MSE → BT/BEP-10 → rq_tunnel → Noise, SOCKS TCP+UDP, flow control, active-probe gate, cadence gate — still works). Add a conformance integration test `mse_handshake_is_spec_shaped` that drives a real client↔server MSE and asserts the wire (via a raw capture at the TCP layer, or by inspecting the initiator's emitted bytes) shows: 96-byte DH, raw padding (no cleartext length field), the `req1(S)` marker at the correct resync point, and an encrypted VC — i.e. structurally a real MSE handshake. Document in a comment that true interop with a real qBittorrent MSE peer is a deployment-time check not runnable here.
- [ ] **Step 3:** Full suite green; clippy/fmt. Commit: `feat(tunnel): key MSE by handshake_info_hash; spec-MSE conformance E2E`

---

## Self-Review checklist
- Key derivation is the exact MSE formula (`SHA1('keyA'‖S‖SKEY)` etc.); old non-spec derivation removed. ✓
- Wire format matches MSE: raw (unprefixed) padding, req1/req2^req3 markers, crypto_provide/select, encrypted VC, 1024 discard, RC4 continuity. ✓
- Resync is bounded + fails closed (no unbounded pre-auth read). ✓
- SKEY = handshake_info_hash (public info hash); consistent with Plan B; both ends agree. ✓
- Full tunnel stack still works end-to-end over spec MSE; active-probe + cadence gates still pass. ✓
- No panic on crafted handshake input; typed errors. ✓
- Interop-with-real-client caveat documented. ✓
