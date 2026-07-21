# Tunnel: full BitTorrent masquerade design

Date: 2026-07-21
Status: approved (design), pending implementation plans
Area: `crates/librqbit/src/tunnel/`, `crates/peer_binary_protocol/src/extended/`

## Problem & evidence

The SOCKS-over-BitTorrent tunnel is advertised as "traffic fully masked as
BitTorrent". A code-level audit shows this is only **partly** true. Two wire
designs exist in the tree, and the convincing one is **dead code**.

**Live production path** (what actually runs):

- Client: `client.rs:74-117` — `TCP connect` → `PeerWireCrypto` (MSE/PE
  obfuscation) → Noise IK → length-prefixed opaque frames.
- Server: `server.rs:80-139` — MSE responder → read Noise IK → `responder_accept`
  (allowlist) → admit. On Noise failure the connection is dropped.
- DHT rendezvous is **genuine**: `service.rs:85`
  `dht.get_peers(carrier_hash, Some(port))` + `run_dht_announce`.

**Full BitTorrent masquerade** (present, fully unit-tested, **zero non-test
callers**):

- `carrier_wire.rs` / `carrier_peer.rs` / `carrier.rs` implement a real BT
  handshake (reserved bits `0x0000000000180005`, peer-id `-qB4650-`), BEP-10
  extended handshake advertising `rq_tunnel`, `Bitfield`/`Unchoke`/`Interested`
  cover, and steady-state `rq_tunnel` extended messages carrying Noise frames,
  with `Request`/`Piece` cover over a synthetic v2 torrent.
- Verified dead: grep for `CarrierWire` / `send_tunnel` / `TunnelCarrierPeer`
  finds only the modules and their tests; the live modules
  (`service`/`socks`/`relay`/`server`/`client`/`client_mux`/`client_supervisor`/
  `client_pool`) do **not** import `peer_binary_protocol` at all. Whole subsystem
  is under `#![allow(dead_code)]` (`mod.rs:1-3`).

**MSE layer is MSE-flavoured, not spec-accurate** (`peer_wire_crypto.rs`).
Matches: DH group-2 768-bit (`:24`), RC4 (`:209`), 1024-byte discard
(`:429-430`), 8-zero VC (`:46`). Deviates (fingerprints): padding carries a
**cleartext 2-byte length prefix** (`write_padding:249-251`); no `req1`/`req2`
info-hash markers; no `crypto_provide`/`crypto_select` negotiation; custom key
derivation (`req_seed = SHA1(SKEY‖info_hash)`, keyA/keyB markers).

### Verdict

Masked today: **(1)** "this is an encrypted stream, not plaintext BT" and
**(2)** rendezvous via real DHT. NOT masked: real BT protocol behaviour
(handshake / BEP-10 / piece exchange), spec-accurate encrypted-peer identity,
active-probe resistance, swarm/DHT node profile, and statistical/behavioural
shape. The strongest asset (full masquerade with piece cover) is implemented but
disabled.

## Goals / non-goals

**Goal:** make the tunnel's carrier traffic indistinguishable from real
BitTorrent to progressively stronger adversaries, verified end-to-end after each
increment.

**Non-goals:**

- WireGuard / other transport tunnelling (explicitly dropped for this program).
- Changing the SOCKS ingress contract (TCP CONNECT + UDP ASSOCIATE stay).
- Changing the Noise IK security model (inner authentication is unchanged).
- Perfect indistinguishability against a nation-state adversary with unlimited
  active + statistical capability — that is an asymptote; the layer-4 target is
  the measurable parity criterion defined below, not "unbreakable".

## Indistinguishability ladder (acceptance framework)

"Indistinguishable" is defined operationally per adversary class. Each plan
climbs one rung. A rung's acceptance criterion is its E2E gate.

| Rung | Adversary | Held today | Closed by |
|------|-----------|-----------|-----------|
| 1 | Passive entropy DPI ("encrypted vs plaintext?") | yes | — |
| 2 | Protocol-aware DPI (parses BT handshake / BEP-10 / pieces) | no | A, C |
| 3 | Active prober (connects, speaks BT) | no | B |
| 4 | Alternate identity (encrypted PE peer) | no | D |
| 5 | Swarm / DHT node profile | no | E |
| 6 | Statistical / ML traffic classifier (timing, sizes, symmetry) | no | F |

**Cover-identity decision (approved):** start with the full BitTorrent handshake
identity via `carrier_wire`; add a spec-accurate MSE/PE encrypted-peer identity
in Plan D; the finished node supports **both** identities, as a real swarm
contains both plaintext-handshake and MSE-encrypted peers.

## Architecture: the carrier seam

`CarrierWire` sits **on top of** the MSE-encrypted stream. Public surface
(verified, `carrier_wire.rs`):

- `CarrierWire::establish(reader, writer, carrier: Arc<TunnelCarrierStore>,
  info_hash) -> CarrierWire` — BT handshake + BEP-10 + initial cover.
- `send_tunnel(&mut self, payload: &[u8])` — emits payload as an `rq_tunnel`
  extended message.
- `recv_tunnel(&mut self) -> Option<Bytes>` — reads peer messages, handling
  `Request`/`Piece`/`KeepAlive` cover inline via `TunnelCarrierPeer`, until the
  next `rq_tunnel` payload.

**Target live path (from Plan A onward):**

```
TCP connect
  → PeerWireCrypto::initiator/responder(stream, carrier_hash)   [MSE, unchanged]
  → CarrierWire::establish(reader, writer, carrier_store, info_hash)  [NEW]
  → Noise IK handshake, carried as rq_tunnel payloads via send/recv_tunnel
  → steady state: every Noise frame chunked into rq_tunnel messages;
    Request/Piece cover interleaved by TunnelCarrierPeer
```

### Cross-cutting integration decisions (bind in Plan A, honoured by all)

1. **Deterministic fake corpus.** `TunnelCarrierStore` currently builds a
   *random* corpus (`carrier.rs`), so two endpoints would derive different
   info_hashes and piece hashes → handshake mismatch. The corpus MUST be
   deterministic from a shared seed (derived from `carrier_hash`) so both ends
   produce identical info_hash and valid piece content.
2. **info_hash unification (DHT ↔ handshake).** Today DHT announces
   `carrier_hash` while the BT handshake would present the fake torrent's
   info_hash — an observable rendezvous/handshake mismatch. Decision:
   `carrier_hash` stays the (invisible) MSE key; the **DHT announce and the BT
   handshake both use the fake torrent's info_hash**. Rendezvous derivation moves
   accordingly (client can still compute it from the pinned server key + the
   deterministic corpus rule).
3. **64 KiB → 16 KiB chunking.** `MAX_RQ_TUNNEL_MESSAGE_LEN` = 16 KiB
   (`peer_binary_protocol/src/lib.rs:58`); tunnel frames are up to 64 KiB
   (`frame.rs:22`). A chunk/reassembly layer sits between Noise frames and
   `rq_tunnel` messages.
4. **Preserve flow control.** Adaptive window, token-bucket pacing, and the
   unpaced control lane (Ping/Pong/Credit) must survive the move through the
   carrier; cover-piece interleaving must not reorder or unpace control frames.
5. **Feature flag, no wire compatibility.** No deployed peer must interoperate
   with the old raw-Noise path. The masquerade carrier becomes the default; the
   raw path is kept behind a test-only config flag for isolation tests, then
   removed once A is green.

## Plans

Seven plans. Order = by leverage and dependency. Each ends with its E2E gate.
Detailed implementation plans are produced incrementally (see Process), starting
with A.

### Plan A — Live BitTorrent masquerade carrier (rung 2, core)

Wire `carrier_wire`/`carrier_peer`/`carrier` into the live path
(`client.rs:78`, `server.rs:86`), replacing raw Noise frames. Implements the five
cross-cutting decisions above. Remove `#![allow(dead_code)]` for the wired
modules.

- E2E gate: capture harness observes real `Handshake` + `ExtendedHandshake` +
  `Bitfield` + `Piece`/`Request` events on the wire; all existing tunnel
  integration tests pass through the new carrier; SOCKS TCP + UDP still traverse
  end-to-end; milestone pcap review confirms a BT-shaped handshake.
- Acceptance: rung 2 handshake/protocol structure present; no throughput
  regression beyond an agreed budget.

### Plan B — Active-probe resistance (rung 3)

The rendezvous info_hash is public on DHT, so a censor can connect. The server
must behave as a real seeder to an unauthenticated prober (complete handshake,
serve valid pieces of the fake torrent), never drop right after obfuscation, and
switch to tunnel mode only after Noise authentication succeeds.

- E2E gate: automated prober test — a stub BT client connects with a real
  handshake, downloads and validates a piece, and observes no
  "obfuscation-then-disconnect" tell.
- Acceptance: an active BT-speaking probe cannot distinguish the node from a
  seeding peer without the client identity key.

### Plan C — Steady-state protocol realism (rung 2, full)

BT cadence: `keep-alive` ~every 2 min, periodic `have`, `choke`/`unchoke`
dynamics, `ut_pex`, `ut_metadata`, pipelined `Request`/`Piece` in 16 KiB blocks,
plausible cover/tunnel ratio.

- E2E gate: capture matches a reference client's cadence profile
  (message mix + inter-message timing within tolerance).

### Plan D — Spec-accurate MSE/PE identity (rung 4)

Rewrite `PeerWireCrypto` to real MSE: `req1`/`req2^req3` hashes,
`crypto_provide`/`crypto_select` negotiation, resync-based padding (no cleartext
length prefix), `HASH('keyA'/'keyB', S, SKEY)` key derivation. Adds the
"encrypted peer" identity alongside the Plan A handshake identity.

- E2E gate: interop against MSE spec vectors / a real client's expectations; an
  active MSE-aware probe cannot separate our handshake from a real one.

### Plan E — Swarm / DHT node profile (rung 5)

Multi-info_hash presence, participation in a couple of real public swarms,
diverse peer set, so the node's DHT/swarm footprint is not a single anomalous
hash with one high-volume peer.

- E2E gate: DHT profile check — the node announces/participates like an ordinary
  client, not a lone rendezvous hash.

### Plan F — Statistical / behavioural shaping (rung 6)

Swarm of several exit peers/IPs, decoy connections to real peers, up/down
symmetry shaping, block-shaped framing, interactive-traffic padding.

- E2E gate (approved criterion): **reference-capture parity** — capture a real
  qBittorrent-in-a-swarm pcap, extract a feature vector (block sizes,
  inter-packet timing, peer count, up/down symmetry, connection duration),
  require our traffic to match within tolerance, AND an off-the-shelf traffic
  classifier fails to separate our traffic from the reference.

### Plan G — Final comprehensive test (all rungs)

Full-system run with every layer enabled: external DPI/classifier gauntlet,
throughput/latency regression against a budget, all identities and cover
behaviours exercised together.

- Acceptance: rungs 1–6 all pass simultaneously in one end-to-end scenario; no
  regression outside budget.

## Verification strategy

Approved: automated gate every stage + manual pcap at milestones + final
comprehensive test.

- **Per stage (automated gate):** `cargo test` integration suite
  (`tests/tunnel.rs`) + `test_capture.rs` assertions on `CarrierEvent`
  (Piece/Request/ExtendedHandshake/cadence). Reproducible; run every increment.
- **Milestones (manual pcap):** real server+client run via `scripts/tunnel/`,
  `tcpdump`, compared against a reference capture; summarised back.
- **Layer-4 parity harness (reusable test asset):** captured reference pcap +
  feature-vector extractor + tolerance thresholds + an off-the-shelf classifier
  gate. Lives in the repo as a test fixture.
- **Plan G:** full gauntlet + throughput/latency regression budget.

## Sequencing & dependencies

- A is the foundation and gates capture-based verification for everything else.
- B depends on A (probe resistance needs the masquerade wired).
- C depends on A; refines cadence.
- D is largely independent (second identity); scheduled after C so the primary
  identity is solid first.
- E depends on A (info_hash unification) and informs F.
- F depends on A/C/E; highest cost, latency/throughput trade-offs.
- G depends on all.

## Risks

- **Corpus determinism vs. plausibility.** A deterministic corpus must still look
  like real torrent content (entropy, piece hashes valid). Seed derivation and
  content generation need care.
- **Throughput/latency cost of cover.** Piece cover + pacing + Plan-F shaping add
  overhead; each gate includes a regression budget so cost stays visible.
- **rq_tunnel 16 KiB cap** interacts with pacing; chunking must not create
  head-of-line stalls on the control lane.
- **Layer-4 is an arms race.** The parity criterion bounds it; "beats every
  future classifier" is explicitly out of scope.
- **Public rendezvous hash** is inherently probe-reachable; Plan B is what makes
  that safe, so A without B is a weaker interim state (document the interim).

## Process (how plans are produced)

This master spec covers architecture + all seven plans with acceptance criteria
and E2E gates. Detailed implementation plans are generated **incrementally** via
the writing-plans skill, one sub-project at a time, starting with Plan A, so that
F/G are not over-specified before earlier layers change the reality. Each plan
terminates in its E2E gate; G is the final comprehensive test.

## Open decisions (resolved defaults, revisit if needed)

- Fake-torrent display name / size profile: default to a plausible popular
  distro image (e.g. a Linux ISO ~ single-file, GiB-scale metadata) — finalise
  in Plan A.
- Multi-exit infrastructure for Plan F (several real exit IPs vs. decoys to real
  peers): default to decoys-to-real-peers first, multi-exit optional — finalise
  in Plan F.
