# rqbit tunnel: client/server SOCKS transport design

## Status

Approved architecture for a later implementation plan. This document defines the product boundary; it does not begin implementation.

## Goal

Add an opt-in tunnel subsystem to `rqbit` with two explicit roles:

- **client mode** runs a loopback SOCKS5 inbound for desktop applications, Xray, sing-box, and other local routing software;
- **server mode** runs on a VPS, accepts only authenticated tunnel peers, and is the TCP/UDP egress point.

The desktop-to-VPS leg carries all tunnel control and payload traffic through an encrypted BitTorrent peer-wire transport. Normal `rqbit` downloading and seeding remain available on both nodes.

## Visibility boundary

The protected transport leg is:

```text
local application → client-mode rqbit → VPS server-mode rqbit
```

The VPS-to-destination leg necessarily uses the destination protocol (for example HTTPS, QUIC, DNS, or application UDP). A single-hop SOCKS exit cannot make that final leg BitTorrent traffic and still communicate with the destination.

No client-side direct fallback to a destination is permitted. If the client-to-server tunnel is unavailable, SOCKS requests fail.

## Non-goals

- Public relay discovery through tracker or DHT.
- A public SOCKS server.
- Multi-hop routing in the first version.
- Web UI or HTTP API controls in the first version.
- Reusing `ConnectionOptions.proxy_url` / `--socks-url`; that existing setting is only an outgoing proxy for ordinary torrent peer connections.
- Claiming universal indistinguishability to every possible DPI implementation. Similarity is a measurable acceptance criterion against a defined observation suite, not an untestable absolute claim.

## Product configuration

`librqbit` exposes a typed `TunnelOptions` API. The `rqbit` binary exposes equivalent `--tunnel-*` flags and environment variables.

### Client mode

Required configuration:

- loopback SOCKS5 listen address;
- VPS tunnel peer address;
- client identity private key;
- expected VPS public key;
- pairing bundle containing the internal carrier identity and transport parameters.

The default SOCKS5 bind is loopback. The client manually handles SOCKS5 `CONNECT` and `UDP ASSOCIATE`; it does not use a helper that opens an upstream connection locally. A domain supplied by a SOCKS client remains unresolved until it reaches the VPS, preventing desktop-side DNS leakage.

### Server mode

Required configuration:

- public TCP and, when enabled, uTP tunnel listener address;
- server identity private key;
- allowlist of client public keys;
- egress destination policy;
- persistent internal carrier storage.

The server exposes no public SOCKS listener. It accepts tunnel peers, authenticates them, performs remote TCP connect or UDP association operations, and applies per-client connection, byte-rate, destination, and idle-time limits.

## Internal carrier swarm

A tunnel pair owns a private internal carrier swarm. The server initializes a persistent legal carrier corpus (or an operator provisions it once); a pairing bundle distributed out-of-band gives the client the metadata, identity, and VPS endpoint needed to join. The end user does not manage a separate `.torrent` per tunnel session.

The carrier is a real private **BEP 52 v2** torrent with valid metadata, bitfield, request, piece, and hash-verification behavior. It is not announced to a tracker or DHT because the VPS endpoint is explicitly configured.

The carrier retains ordinary BitTorrent state and genuine piece exchange while the tunnel is active. Its scheduler reserves a configured carrier bandwidth budget and emits only valid carrier messages. Tunnel payload is never substituted for a `piece`: piece content has precommitted hashes, while SOCKS traffic is live and arbitrary. Every tunnel byte remains an encrypted extension payload inside the peer-wire connection; no raw side channel exists.

### Foundational dependency

The current repository exposes v1-shaped types such as `TorrentMetaV1*` and `Id20`; no v2 torrent types were found during discovery. Implementing the carrier therefore requires a BEP 52 foundation before tunnel behavior can be completed. This is a hard prerequisite, not a configuration-only change.

## Transport layers

### 1. Peer-wire encryption layer

A stream wrapper is inserted before `ReadBuf::read_handshake`. It wraps the existing `BoxAsyncReadVectored` / `BoxAsyncWrite` boundary, so the existing parser consumes a decrypted peer-wire byte stream after transport negotiation.

The outer layer provides BitTorrent-compatible encrypted/obfuscated peer-wire behavior. Its initial key negotiation cannot itself be encrypted before keys exist; all tunnel payload and post-negotiation peer-wire bytes are protected. It is not the tunnel's authentication or cryptographic security boundary.

### 2. Normal BitTorrent carrier session

After transport negotiation, client and server perform the carrier's standard peer handshake and BEP 10 extended handshake. The carrier exchanges valid bitfield, interest, request, and piece messages according to its own BEP 52 metadata and scheduler.

### 3. `rq_tunnel` extension

A negotiated custom peer-wire extension carries tunnel frames. It is added to `peer_binary_protocol` as a typed, bounded message rather than treated as an unknown dynamic bencode value.

Each extension payload is protected by a modern authenticated-encryption session established from the client and server static keys. This inner session is the confidentiality, integrity, replay-protection, and endpoint-authentication boundary. It protects destination hostnames, ports, SOCKS status, TCP bytes, UDP datagrams, and tunnel errors.

The sender enforces a bounded frame size compatible with the current peer-wire receive and write buffers. It uses bounded queues and explicit flow-control credits; the existing unbounded torrent writer queue must not become an unbounded tunnel buffer.

## SOCKS5 semantics

Use `fast-socks5` as the SOCKS5 protocol parser/server foundation in manual mode. Its standard automatic proxy helpers are not used because they would create direct client-side outbound connections.

### TCP CONNECT

1. The client accepts a SOCKS5 `CONNECT` request.
2. It allocates a stream identifier and sends an encrypted `OpenTcp` request to the server.
3. The server enforces its egress policy, opens the TCP connection, and returns success or a SOCKS-mapped error.
4. Both directions use encrypted, flow-controlled data frames.
5. FIN, reset, timeout, and peer disconnect map to a deterministic SOCKS stream closure.

TCP streams do not transparently migrate across a lost peer connection. A reconnect creates a new tunnel session; affected TCP streams fail and their callers reconnect through normal SOCKS behavior.

### UDP ASSOCIATE

1. The client accepts `UDP ASSOCIATE` and creates an association identifier.
2. Each UDP datagram retains its destination address, port, and datagram boundary inside an encrypted frame.
3. The server creates and maintains the remote UDP socket/association, sends outgoing datagrams, and returns responses with the same association identifier.
4. Associations have explicit byte quotas, maximum datagram sizes, and idle expiry.

## Ordinary rqbit isolation

The tunnel is feature-gated and owns separate state, listener lifecycle, counters, and errors. It must not register a visible managed torrent in `Session::db`, mutate user torrent statistics, or change existing tracker/DHT behavior. The internal carrier belongs to `TunnelService`; it may reuse lower-level storage and peer-wire primitives only through its own namespace and lifecycle.

The server tunnel listener is separate because the current inbound path reads a peer handshake and routes it only to a live torrent whose `info_hash` matches. The tunnel admission path instead validates the pairing/carrier identity and client key before accepting tunnel work.

## Error handling and abuse controls

- Bind the client SOCKS listener to loopback by default.
- Reject unknown client public keys before accepting a tunnel session.
- Restrict server destinations by configurable address/port policy.
- Cap active TCP streams, UDP associations, queued bytes, frame size, and per-peer bandwidth.
- Never log payloads, destination content, private keys, or decrypted extension frames.
- Reject malformed, replayed, oversized, and authentication-failed frames without retaining their payload.
- Propagate explicit SOCKS reply codes for refused connections, unreachable hosts, timeouts, and unsupported commands.
- Disable direct egress fallback on the client.

## Verification strategy

### Protocol and security

- Unit-test peer-wire encryption negotiation, malformed input rejection, and no plaintext tunnel payload after negotiation.
- Unit-test static-key authentication, tamper rejection, replay rejection, key mismatch, and frame size limits.
- Test `rq_tunnel` extension negotiation with peers that do and do not support it.

### SOCKS behavior

- End-to-end TCP `CONNECT` echo and HTTP(S) tests through client mode and server mode.
- End-to-end UDP `ASSOCIATE` datagram echo, DNS-name destination, expiry, maximum-size, and error tests.
- Assert no desktop-side resolver call occurs for a SOCKS domain destination.
- Assert client mode opens no direct connection to the requested destination.

### Torrent regression and traffic contract

- Verify ordinary torrent download and seeding still work while each tunnel role is active.
- Verify carrier pieces have valid BEP 52 hash checks and normal request/piece transitions.
- Capture client-to-VPS traffic in controlled tests and verify that tunnel payload and destination metadata are absent in plaintext.
- Compare carrier-session traces with a declared baseline torrent client/session. The test suite reports divergence; it does not promise global DPI immunity.

## Delivery sequence

1. Add BEP 52 carrier primitives and tests.
2. Add peer-wire encryption wrapper at the stream boundary.
3. Add typed `rq_tunnel` extension and inner authenticated-encryption session.
4. Add server-mode admission, egress policy, TCP relay, and UDP relay.
5. Add client-mode local SOCKS5 inbound and tunnel multiplexer.
6. Add CLI/library configuration, regression tests, capture-based verification, and documentation.

## Sources and repository evidence

- [BEP 3 — BitTorrent Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html)
- [BEP 10 — Extension Protocol](https://www.bittorrent.org/beps/bep_0010.html)
- [BEP 52 — BitTorrent Protocol Specification v2](https://www.bittorrent.org/beps/bep_0052.html)
- [fast-socks5 documentation](https://context7.com/dizda/fast-socks5/llms.txt)
- `crates/peer_binary_protocol/src/lib.rs` and `extended/mod.rs`: current peer-wire and extension handling.
- `crates/librqbit/src/peer_connection.rs`: current handshake, writer, and message-dispatch path.
- `crates/librqbit/src/session.rs`: current inbound `info_hash` admission path.
- `crates/librqbit/src/type_aliases.rs`: stream-wrapper boundary.
- `crates/librqbit/src/stream_connect.rs`: existing outgoing-only SOCKS proxy configuration.
