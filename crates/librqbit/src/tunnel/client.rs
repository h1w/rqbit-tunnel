// ── Authenticated tunnel client ─────────────────────────────────────────────
///
/// `TunnelClient` connects to a tunnel server through TCP, performs the
/// PeerWireCrypto initiator handshake followed by a Noise IK initiator
/// handshake, then sends/receives encrypted `TunnelFrame`s.
///
/// All destination traffic goes through the tunnel — the client never opens
/// a direct connection to the requested destination.
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
#[cfg(test)]
use std::sync::atomic::Ordering;

#[cfg(test)]
use bytes::Bytes;
use tokio::net::TcpStream;

use crate::tunnel::carrier::TunnelCarrierStore;
use crate::tunnel::carrier_peer::TunnelCarrierPeer;
use crate::tunnel::carrier_wire::{CarrierReadHalf, CarrierWire, CarrierWriteHalf};
use crate::tunnel::crypto::{self, NoiseTransport, TunnelCryptoError};
#[cfg(test)]
use crate::tunnel::frame::{TunnelDestination, TunnelFrame};
use crate::tunnel::frame::{TunnelPrivateKey, TunnelPublicKey};
use crate::tunnel::peer_wire_crypto::PeerWireCrypto;

// ── Client error ────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub(crate) enum TunnelClientError {
    #[error("connection to server failed: {0}")]
    Connect(#[from] std::io::Error),

    #[error("carrier handshake failed: {0}")]
    CarrierHandshake(String),

    #[error("noise handshake failed: {0}")]
    NoiseHandshake(#[from] TunnelCryptoError),

    #[error("frame protocol error: {0}")]
    Frame(#[from] crate::tunnel::frame::FrameError),

    #[error("server connection lost")]
    ConnectionLost,

    #[error("unexpected frame: expected {expected:?}, got {got:?}")]
    UnexpectedFrame { expected: String, got: String },
}

// ── Client ──────────────────────────────────────────────────────────────────

/// Connected and authenticated tunnel client.
///
/// Created by [`TunnelClient::connect`].  Stream IDs and association IDs are
/// allocated monotonically starting at 1 on the client side.
pub(crate) struct TunnelClient {
    /// Noise transport state for encrypt/decrypt of frames.
    transport: NoiseTransport,
    /// BitTorrent-masquerade carrier reader half.
    read_half: CarrierReadHalf,
    /// BitTorrent-masquerade carrier writer half.
    write_half: CarrierWriteHalf,
    /// Cover state machine (serves piece Request→Piece traffic).
    carrier_peer: TunnelCarrierPeer,
    /// Reassembles chunked Noise ciphertext from `rq_tunnel` messages. Only used
    /// by the (test-only) blocking [`read_frame`](Self::read_frame); in
    /// production the client is consumed by [`into_carrier`](Self::into_carrier)
    /// immediately after connecting, so this field would otherwise be
    /// write-only in production builds.
    #[cfg(test)]
    defrag: super::carrier_chunk::CarrierDefragmenter,
    /// Decoded-but-not-yet-returned ciphertext blobs for the blocking reader.
    #[cfg(test)]
    pending: std::collections::VecDeque<Vec<u8>>,
    /// Next stream ID (even numbers for client-initiated).
    next_stream_id: AtomicU64,
    /// Next association ID.
    next_assoc_id: AtomicU64,
    /// Resolver call counter (test-only, never incremented in production).
    #[cfg(test)]
    local_resolver_calls: std::sync::atomic::AtomicUsize,
}

impl TunnelClient {
    /// Connect to the tunnel server and complete both handshake phases over the
    /// live BitTorrent masquerade carrier.
    pub async fn connect(
        server_addr: SocketAddr,
        identity_key: &TunnelPrivateKey,
        expected_server_key: &TunnelPublicKey,
        carrier_hash: librqbit_core::Id20,
        carrier_store: Arc<TunnelCarrierStore>,
    ) -> Result<Self, TunnelClientError> {
        // ── Step 1: TCP connect ──────────────────────────────────────────
        let stream = TcpStream::connect(server_addr).await?;

        // ── Step 2: MSE initiator ────────────────────────────────────────
        let enc = PeerWireCrypto::initiator(stream, carrier_hash)
            .await
            .map_err(|e| TunnelClientError::CarrierHandshake(e.to_string()))?;

        // ── Step 3: BT handshake + BEP-10 + cover ────────────────────────
        let info_hash = carrier_store.descriptor().handshake_info_hash;
        let wire = CarrierWire::establish(enc.reader, enc.writer, carrier_store, info_hash)
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

        let mut defrag = super::carrier_chunk::CarrierDefragmenter::new(
            super::carrier_chunk::MAX_CARRIER_CIPHERTEXT,
        );
        let reply = super::carrier_chunk::recv_one_ciphertext(&mut read_half, &mut defrag)
            .await
            .ok_or(TunnelClientError::ConnectionLost)?;
        let transport = crypto::initiator_complete(handshake, &reply)?;

        Ok(Self {
            transport,
            read_half,
            write_half,
            carrier_peer,
            #[cfg(test)]
            defrag,
            #[cfg(test)]
            pending: std::collections::VecDeque::new(),
            next_stream_id: AtomicU64::new(1),
            next_assoc_id: AtomicU64::new(1),
            #[cfg(test)]
            local_resolver_calls: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    // ── Accessors ────────────────────────────────────────────────────────

    /// Consume the client into its Noise transport and BitTorrent-masquerade
    /// carrier parts, for the multiplexer to drive shared reader/writer tasks.
    pub(crate) fn into_carrier(
        self,
    ) -> (
        NoiseTransport,
        CarrierReadHalf,
        CarrierWriteHalf,
        TunnelCarrierPeer,
    ) {
        (
            self.transport,
            self.read_half,
            self.write_half,
            self.carrier_peer,
        )
    }
}

// ── Blocking single-connection API (test-only) ───────────────────────────────
//
// The production path connects, then immediately hands the client to
// `ClientMux::new` via `into_carrier`. The direct request/response API below is
// exercised only by the in-process tunnel fixtures, so it is gated behind
// `#[cfg(test)]` — there is no dead non-test code carrying it.
#[cfg(test)]
impl TunnelClient {
    // ── Stream / association ID allocation ───────────────────────────────

    fn alloc_stream_id(&self) -> u64 {
        // Even numbers for client-initiated streams.
        let id = self.next_stream_id.fetch_add(2, Ordering::Relaxed);
        id
    }

    fn alloc_assoc_id(&self) -> u64 {
        let id = self.next_assoc_id.fetch_add(1, Ordering::Relaxed);
        id
    }

    // ── High-level operations ────────────────────────────────────────────

    /// Request a TCP connection through the tunnel.
    ///
    /// Returns the allocated stream ID on success.  The caller should then
    /// read the next frame from the server to receive `TcpOpened` or an error.
    pub async fn open_tcp(
        &mut self,
        destination: TunnelDestination,
    ) -> Result<u64, TunnelClientError> {
        let stream_id = self.alloc_stream_id();
        let (host, port) = match &destination {
            TunnelDestination::Ip(addr) => (addr.ip().to_string(), addr.port()),
            TunnelDestination::Domain(name, port) => (name.clone(), *port),
        };
        self.write_frame(&TunnelFrame::OpenTcp {
            stream_id,
            host,
            port,
        })
        .await?;
        Ok(stream_id)
    }

    /// Open a UDP association through the tunnel.
    ///
    /// Returns the allocated association ID.
    pub async fn open_udp(&mut self) -> Result<u64, TunnelClientError> {
        let assoc_id = self.alloc_assoc_id();
        self.write_frame(&TunnelFrame::OpenUdp {
            association_id: assoc_id,
        })
        .await?;
        Ok(assoc_id)
    }

    /// Send TCP stream data through the tunnel.
    pub async fn send_tcp_data(
        &mut self,
        stream_id: u64,
        data: impl Into<Bytes>,
    ) -> Result<(), TunnelClientError> {
        self.write_frame(&TunnelFrame::TcpData {
            stream_id,
            bytes: data.into(),
        })
        .await
    }

    /// Send a UDP datagram through the tunnel.
    pub async fn send_udp_datagram(
        &mut self,
        association_id: u64,
        destination: TunnelDestination,
        data: impl Into<Bytes>,
    ) -> Result<(), TunnelClientError> {
        self.write_frame(&TunnelFrame::UdpDatagram {
            association_id,
            destination,
            bytes: data.into(),
        })
        .await
    }

    /// Gracefully close a TCP stream (half-close).
    pub async fn close_tcp(&mut self, stream_id: u64) -> Result<(), TunnelClientError> {
        self.write_frame(&TunnelFrame::TcpFin { stream_id }).await
    }

    /// Close a UDP association.
    pub async fn close_udp(&mut self, association_id: u64) -> Result<(), TunnelClientError> {
        self.write_frame(&TunnelFrame::CloseUdp { association_id })
            .await
    }

    /// Send a credit grant for flow control.
    pub async fn send_credit(
        &mut self,
        stream_id: u64,
        bytes: u32,
    ) -> Result<(), TunnelClientError> {
        self.write_frame(&TunnelFrame::Credit { stream_id, bytes })
            .await
    }

    /// Send a ping (keep-alive).
    pub async fn send_ping(&mut self, nonce: u64) -> Result<(), TunnelClientError> {
        self.write_frame(&TunnelFrame::Ping { nonce }).await
    }

    // ── Frame I/O over the carrier ───────────────────────────────────────

    /// Read the next decrypted `TunnelFrame` from the server, serving piece
    /// cover (Request→Piece) inline along the way. Reassembles chunked Noise
    /// ciphertext from `rq_tunnel` messages via the persistent defragmenter.
    pub async fn read_frame(&mut self) -> Result<TunnelFrame, TunnelClientError> {
        use crate::tunnel::carrier_peer::CarrierAction;
        use peer_binary_protocol::{Message, extended::ExtendedMessage};
        loop {
            if let Some(blob) = self.pending.pop_front() {
                return self
                    .transport
                    .decrypt(&blob)
                    .map_err(TunnelClientError::NoiseHandshake);
            }
            let msg = match self.read_half.recv_message().await {
                Ok(Some(m)) => m,
                Ok(None) | Err(_) => return Err(TunnelClientError::ConnectionLost),
            };
            match msg {
                Message::Extended(ExtendedMessage::RqTunnel(rq)) => {
                    match self.defrag.push(rq.as_bytes()) {
                        Ok(blobs) => {
                            for blob in blobs {
                                self.pending.push_back(blob);
                            }
                        }
                        Err(_) => return Err(TunnelClientError::ConnectionLost),
                    }
                }
                Message::KeepAlive => {}
                other => match self.carrier_peer.on_message(other).await {
                    Ok(actions) => {
                        for a in actions {
                            match a {
                                CarrierAction::OutgoingMessage(m) => {
                                    let _ = self.write_half.send_message(&m.to_message()).await;
                                }
                                CarrierAction::Disconnect(_) => {
                                    return Err(TunnelClientError::ConnectionLost);
                                }
                            }
                        }
                    }
                    Err(_) => return Err(TunnelClientError::ConnectionLost),
                },
            }
        }
    }

    /// Write a frame to the server: encrypt, chunk across `rq_tunnel` messages.
    pub async fn write_frame(&mut self, frame: &TunnelFrame) -> Result<(), TunnelClientError> {
        let blob = self
            .transport
            .encrypt(frame)
            .map_err(TunnelClientError::NoiseHandshake)?;
        for chunk in super::carrier_chunk::chunk_ciphertext(&blob) {
            self.write_half
                .send_tunnel(&chunk)
                .await
                .map_err(|e| TunnelClientError::CarrierHandshake(e.to_string()))?;
        }
        Ok(())
    }

    // ── Construction from handshake parts ─────────────────────────────────

    /// Create a [`TunnelClient`] from already-completed carrier + Noise parts.
    ///
    /// For tests that run the MSE + BT + Noise handshake outside of
    /// [`TunnelClient::connect`].
    pub(crate) fn from_carrier_parts(
        transport: NoiseTransport,
        read_half: CarrierReadHalf,
        write_half: CarrierWriteHalf,
        carrier_peer: TunnelCarrierPeer,
    ) -> Self {
        Self {
            transport,
            read_half,
            write_half,
            carrier_peer,
            defrag: super::carrier_chunk::CarrierDefragmenter::new(
                super::carrier_chunk::MAX_CARRIER_CIPHERTEXT,
            ),
            pending: std::collections::VecDeque::new(),
            next_stream_id: std::sync::atomic::AtomicU64::new(1),
            next_assoc_id: std::sync::atomic::AtomicU64::new(1),
            local_resolver_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    // ── Test hooks ───────────────────────────────────────────────────────

    /// Returns the number of local DNS resolver calls.
    /// Always 0 in production (the client never resolves).
    pub fn local_resolver_calls(&self) -> usize {
        self.local_resolver_calls.load(Ordering::Relaxed)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::crypto::generate_keypair;
    use librqbit_core::Id20;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};

    /// Build a test client and server already connected via an in-process
    /// duplex, running the full BitTorrent-masquerade carrier + Noise handshake.
    /// The server-side carrier halves are returned (unused by callers) so their
    /// transport stays alive for the duration of the test.
    async fn test_tunnel_pair() -> (
        TunnelClient,
        NoiseTransport,
        CarrierReadHalf,
        CarrierWriteHalf,
    ) {
        use crate::tunnel::carrier_chunk::{
            CarrierDefragmenter, MAX_CARRIER_CIPHERTEXT, chunk_ciphertext, recv_one_ciphertext,
        };
        use crate::tunnel::carrier_identity::build_carrier_store;

        let (client_key, client_pub) = generate_keypair();
        let (server_key, server_pub) = generate_keypair();
        let carrier_hash = Id20::new([0xAB; 20]);

        // Deterministic carrier store shared by both ends (same `info_hash`).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep();
        let carrier_store = build_carrier_store(&path, &server_pub).await.unwrap();
        let info_hash = carrier_store.descriptor().handshake_info_hash;

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let server_store = carrier_store.clone();
        let client_pub_clone = client_pub.clone();

        let server_handle = tokio::spawn(async move {
            let enc = PeerWireCrypto::responder(server_stream, carrier_hash)
                .await
                .unwrap();
            let wire = CarrierWire::establish(enc.reader, enc.writer, server_store, info_hash)
                .await
                .unwrap();
            let (mut read_half, mut write_half, carrier_peer) = wire.into_halves();

            let mut defrag = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
            let noise_msg = recv_one_ciphertext(&mut read_half, &mut defrag)
                .await
                .unwrap();
            let mut allowed = HashSet::new();
            allowed.insert(client_pub_clone);
            let (transport, _ck, reply) =
                crypto::responder_accept(&server_key, &noise_msg, &allowed).unwrap();
            for chunk in chunk_ciphertext(&reply) {
                write_half.send_tunnel(&chunk).await.unwrap();
            }
            (transport, read_half, write_half, carrier_peer)
        });

        // Client side: MSE + BT + Noise over the carrier.
        let enc = PeerWireCrypto::initiator(client_stream, carrier_hash)
            .await
            .unwrap();
        let wire = CarrierWire::establish(enc.reader, enc.writer, carrier_store, info_hash)
            .await
            .unwrap();
        let (mut read_half, mut write_half, carrier_peer) = wire.into_halves();

        let (handshake, noise_msg) = crypto::initiator_start(&client_key, &server_pub).unwrap();
        for chunk in chunk_ciphertext(&noise_msg) {
            write_half.send_tunnel(&chunk).await.unwrap();
        }
        let mut defrag = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
        let reply = recv_one_ciphertext(&mut read_half, &mut defrag)
            .await
            .unwrap();
        let transport = crypto::initiator_complete(handshake, &reply).unwrap();

        let (server_transport, server_read, server_write, _server_peer) =
            server_handle.await.unwrap();

        let client =
            TunnelClient::from_carrier_parts(transport, read_half, write_half, carrier_peer);
        (client, server_transport, server_read, server_write)
    }

    #[tokio::test]
    async fn client_connect_and_exchange_frames() {
        let (mut client, _server_transport, _server_reader, _server_writer) =
            test_tunnel_pair().await;

        // Send an OpenTcp request
        let stream_id = client
            .open_tcp(TunnelDestination::Domain("example.com".into(), 443))
            .await
            .unwrap();
        assert_eq!(stream_id, 1);

        // Send a close
        client.close_tcp(stream_id).await.unwrap();
    }

    #[tokio::test]
    async fn client_never_resolves_a_domain_before_tunnel_open() {
        let (mut client, _server_transport, _server_reader, _server_writer) =
            test_tunnel_pair().await;

        // Open TCP with a domain destination
        let stream_id = client
            .open_tcp(TunnelDestination::Domain("example.test".into(), 443))
            .await
            .unwrap();

        assert_eq!(stream_id, 1);
        assert_eq!(client.local_resolver_calls(), 0);
    }

    #[tokio::test]
    async fn client_opens_udp_association() {
        let (mut client, _server_transport, _server_reader, _server_writer) =
            test_tunnel_pair().await;

        let assoc_id = client.open_udp().await.unwrap();
        assert_eq!(assoc_id, 1);

        // Send a datagram
        client
            .send_udp_datagram(
                assoc_id,
                TunnelDestination::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)),
                Bytes::from(&b"test"[..]),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn client_allocates_monotonic_stream_ids() {
        let (client, _server_transport, _server_reader, _server_writer) = test_tunnel_pair().await;

        let id1 = client.alloc_stream_id();
        let id2 = client.alloc_stream_id();
        assert!(id2 > id1);
    }
}
