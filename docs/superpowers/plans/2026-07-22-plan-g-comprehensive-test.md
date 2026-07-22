# Plan G — Comprehensive Test & Program Close-out — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Prove the whole A–D masquerade stack holds together in ONE end-to-end scenario (a regression guard against one feature breaking another), re-verify it in the real binary under emulated RTT, and record the final program state (A–D complete; E–F deferred to deployment, with rationale). This is the closing PR for the sandbox-implementable portion of the program.

**Context — what A–D delivered (all merged):**
- A (#7): live BitTorrent masquerade carrier (MSE → BT + BEP-10 handshake → `rq_tunnel` Noise frames → piece cover).
- B (#8): active-probe resistance (server seeds any peer, promotes only on valid allowlisted Noise, pre-auth DoS bounds).
- C (#9): steady-state cadence (ut_metadata serve, keepalive, ongoing cover).
- D (#10): spec-accurate MSE/PE handshake (markers, crypto negotiation, resync; SKEY = public `handshake_info_hash`).

Existing per-feature E2E gates already exist in `tests/tunnel.rs`: `socks_connect_reaches_server_side_tcp_echo_only_through_tunnel`, `udp_associate_echoes_datagram_through_tunnel`, `real_relay_transfers_large_payload_with_flow_control`, `wire_shows_real_bittorrent_events`, `active_probe_gets_seeded_and_stays_connected`, `carrier_cadence_matches_a_real_client_profile`, `mse_handshake_is_spec_shaped`. Plan G ties them into one combined assertion + a real-binary run.

## Global Constraints
- Additive only — do NOT change production behavior; this plan is tests + a controller-run milestone + docs. If the combined test reveals a real interaction bug between features, that IS a finding — fix the code, not the assertion.
- Prefer typed errors. Use repo-local `TMPDIR`. `cargo check`/`clippy --all-targets` clean; `cargo fmt`; full `cargo test -p librqbit tunnel` green.

## Task 1: Combined full-stack E2E gate

**Files:** `crates/librqbit/src/tests/tunnel.rs` (one new test, reusing the existing harness + the `CarrierTrace` tap + `tokio::time` pause/advance).

- [ ] **Step 1:** Write `full_stack_masquerade_holds_together` (current-thread `#[tokio::test]`): bring up a real client↔server tunnel with the `CarrierTrace` installed, then in ONE scenario assert, on the SAME live session, that ALL of these hold simultaneously:
  1. The MSE handshake was structurally spec-shaped (96-byte DH, raw padding without a cleartext length prefix, `req1` marker) — reuse the assertion from `mse_handshake_is_spec_shaped`.
  2. The wire shows real BT protocol: `ExtendedHandshake` (advertising `ut_metadata` + non-zero `metadata_size`), `Bitfield`, and ongoing `Request`/`Piece` cover — reuse `wire_shows_real_bittorrent_events` + cadence assertions.
  3. A served `ut_metadata` Data response after the peer requests metadata, and the reassembled bytes hash to the advertised info hash.
  4. A `KeepAlive` appears within `KEEPALIVE_INTERVAL` (advance paused time).
  5. Real application data traverses the tunnel intact: a SOCKS TCP request through the client's proxy reaches a server-side echo and returns byte-exact (and, if cheap, a UDP datagram round-trip).
  6. A CONCURRENT active probe (a stub BT peer on a second connection that never authenticates) is seeded a valid piece and NOT disconnected after sending garbage — reuse `active_probe_gets_seeded_and_stays_connected`'s mechanism.
  Factor shared setup into a helper if it reduces duplication, but keep the single test's assertions explicit. This is the regression guard that no feature silently broke another.
- [ ] **Step 2:** Run it; if any interaction fails, investigate (real bug vs. test timing) and fix the CODE if it's a real regression. Full `cargo test -p librqbit tunnel` green.
- [ ] **Step 3:** clippy/fmt. Commit: `test(tunnel): combined full-stack masquerade E2E gate (A–D hold together)`

## Task 2: Real-binary comprehensive milestone + program close-out docs (controller-run)

**Files:** `docs/superpowers/specs/2026-07-21-full-bittorrent-masquerade-design.md` (append a "Results (Plans B–D + close-out)" section).

- [ ] **Step 1 (controller-run):** Build the release `rqbit`; run a real loopback tunnel (server + client) and drive a large SOCKS download (a) direct and (b) through a userspace ~100 ms delay proxy; confirm byte-exact transfer + record throughput (mirrors Plan A's milestone, now over the full A–D stack incl. spec MSE + cadence + probe resistance). Confirm the server logs show `tunnel peer admitted`, DHT rendezvous on `handshake_info_hash`, and no errors.
- [ ] **Step 2 (docs):** Append a close-out section to the master spec recording: A–D complete + validated (test counts, the combined gate, the real-binary throughput); the indistinguishability ladder now covers rungs 1–4; and E–F **deferred to deployment** with the rationale — genuine swarm/DHT realism (multi-info_hash with consistent backing torrents, live diverse peers, PEX with real peers, reference-pcap statistical parity) requires real-network swarm participation and a reference client, and faking it in-sandbox would REINTRODUCE the exact announce/handshake fingerprints Plan D removed (a node that announces or PEXes things it can't consistently back up is MORE detectable). Note the concrete deployment-phase checklist for E/F/real-interop.
- [ ] **Step 3:** Commit: `docs(tunnel): record Plan G comprehensive results + A–D close-out; defer E/F to deployment`

## Self-Review checklist
- One combined test asserts all A–D properties on a single live session (regression guard). ✓
- Real-binary run confirms the full stack works outside the test harness, under emulated RTT, byte-exact. ✓
- Master spec records the honest final state: rungs 1–4 done + validated; E/F deferred with the fingerprint-consistency rationale + a deployment checklist. ✓
