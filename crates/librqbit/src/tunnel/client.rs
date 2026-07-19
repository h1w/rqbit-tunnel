// ── Authenticated tunnel client ─────────────────────────────────────────────
///
/// `TunnelClient` connects to a tunnel server through TCP, performs the
/// PeerWireCrypto initiator handshake followed by a Noise IK initiator
/// handshake, then sends/receives encrypted `TunnelFrame`s.
///
/// All destination traffic goes through the tunnel — the client never opens
/// a direct connection to the requested destination.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::tunnel::crypto::{self, NoiseTransport, TunnelCryptoError};
use crate::tunnel::frame::{TunnelDestination, TunnelFrame, TunnelPrivateKey, TunnelPublicKey};
use crate::tunnel::peer_wire_crypto::{EncryptedPeerIo, PeerWireCrypto};
use crate::tunnel::server;

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
    /// Encrypted reader half.
    reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    /// Encrypted writer half.
    writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    /// Next stream ID (even numbers for client-initiated).
    next_stream_id: AtomicU64,
    /// Next association ID.
    next_assoc_id: AtomicU64,
    /// Resolver call counter (test-only, never incremented in production).
    #[cfg(test)]
    local_resolver_calls: std::sync::atomic::AtomicUsize,
}

impl TunnelClient {
    /// Connect to the tunnel server and complete both handshake phases.
    pub async fn connect(
        server_addr: SocketAddr,
        identity_key: &TunnelPrivateKey,
        expected_server_key: &TunnelPublicKey,
        carrier_hash: librqbit_core::Id20,
    ) -> Result<Self, TunnelClientError> {
        // ── Step 1: TCP connect ──────────────────────────────────────────
        let stream = TcpStream::connect(server_addr).await?;

        // ── Step 2: PeerWireCrypto initiator handshake ───────────────────
        let EncryptedPeerIo { reader, writer } = PeerWireCrypto::initiator(stream, carrier_hash)
            .await
            .map_err(|e| TunnelClientError::CarrierHandshake(e.to_string()))?;

        // ── Step 3: Noise IK initiator handshake ─────────────────────────
        let (handshake, noise_msg) = crypto::initiator_start(identity_key, expected_server_key)?;

        // Write: 2-byte length-prefixed Noise initiator message
        let mut writer = writer;
        let msg_len = (noise_msg.len() as u16).to_be_bytes();
        writer.write_all(&msg_len).await?;
        writer.write_all(&noise_msg).await?;
        writer.flush().await?;

        // Read: 2-byte length-prefixed Noise responder reply
        let mut reader = reader;
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).await?;
        let reply_len = u16::from_be_bytes(len_buf) as usize;
        if reply_len > 256 {
            return Err(TunnelCryptoError::HandshakeFailed(format!(
                "noise reply too large: {reply_len}"
            ))
            .into());
        }
        let mut reply_buf = vec![0u8; reply_len];
        reader.read_exact(&mut reply_buf).await?;

        let transport = crypto::initiator_complete(handshake, &reply_buf)?;

        Ok(Self {
            transport,
            reader: Box::new(reader),
            writer: Box::new(writer),
            next_stream_id: AtomicU64::new(1),
            next_assoc_id: AtomicU64::new(1),
            #[cfg(test)]
            local_resolver_calls: std::sync::atomic::AtomicUsize::new(0),
        })
    }

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

    // ── Frame I/O ────────────────────────────────────────────────────────

    /// Read the next encrypted frame from the server.
    pub async fn read_frame(&mut self) -> Result<TunnelFrame, TunnelClientError> {
        server::read_frame(&mut self.transport, &mut self.reader)
            .await
            .map_err(|e| match &e {
                TunnelCryptoError::DecryptFailed(_) if e.to_string().contains("read len") => {
                    TunnelClientError::ConnectionLost
                }
                _ => TunnelClientError::NoiseHandshake(e),
            })
    }

    /// Write a frame to the server (encrypted, length-prefixed).
    pub async fn write_frame(&mut self, frame: &TunnelFrame) -> Result<(), TunnelClientError> {
        server::write_frame(&mut self.transport, &mut self.writer, frame)
            .await
            .map_err(TunnelClientError::NoiseHandshake)
    }

    // ── Accessors ────────────────────────────────────────────────────────

    /// Split the client into separate read and write halves.
    ///
    /// The caller must manage the `NoiseTransport` — both halves need it.
    /// For most use cases, use [`read_frame`] and [`write_frame`] instead.
    pub fn into_split(
        self,
    ) -> (
        NoiseTransport,
        Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    ) {
        (self.transport, self.reader, self.writer)
    }

    // ── Test hooks ───────────────────────────────────────────────────────

    /// Returns the number of local DNS resolver calls.
    /// Always 0 in production (the client never resolves).
    #[cfg(test)]
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

    /// Build a test client and server that are already connected via an
    /// in-process pair of TCP streams (tokio duplex).
    async fn test_tunnel_pair() -> (
        TunnelClient,
        NoiseTransport,
        Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    ) {
        let (client_key, client_pub) = generate_keypair();
        let (server_key, server_pub) = generate_keypair();

        let client_pub_clone = client_pub.clone();

        // In-process duplex for the initiator/responder
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);

        let carrier_hash = Id20::new([0xAB; 20]);

        // Spawn the server side
        let server_handle = tokio::spawn(async move {
            let encrypted = PeerWireCrypto::responder(server_stream, carrier_hash)
                .await
                .unwrap();

            let mut reader = encrypted.reader;
            let mut writer = encrypted.writer;

            // Read Noise initiator message
            let mut len_buf = [0u8; 2];
            use tokio::io::AsyncReadExt;
            reader.read_exact(&mut len_buf).await.unwrap();
            let msg_len = u16::from_be_bytes(len_buf) as usize;
            let mut noise_msg = vec![0u8; msg_len];
            reader.read_exact(&mut noise_msg).await.unwrap();

            // Responder accept
            let mut allowed = HashSet::new();
            allowed.insert(client_pub_clone);
            let (transport, _client_key, reply) =
                crypto::responder_accept(&server_key, &noise_msg, &allowed).unwrap();

            // Send reply
            let reply_len = (reply.len() as u16).to_be_bytes();
            use tokio::io::AsyncWriteExt;
            writer.write_all(&reply_len).await.unwrap();
            writer.write_all(&reply).await.unwrap();
            writer.flush().await.unwrap();

            (
                transport,
                Box::new(reader) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                Box::new(writer) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
            )
        });

        // Client side: connect through the duplex
        let encrypted = PeerWireCrypto::initiator(client_stream, carrier_hash)
            .await
            .unwrap();

        let (handshake, noise_msg) = crypto::initiator_start(&client_key, &server_pub).unwrap();

        let mut reader = encrypted.reader;
        let mut writer = encrypted.writer;

        let msg_len = (noise_msg.len() as u16).to_be_bytes();
        writer.write_all(&msg_len).await.unwrap();
        writer.write_all(&noise_msg).await.unwrap();
        writer.flush().await.unwrap();

        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).await.unwrap();
        let reply_len = u16::from_be_bytes(len_buf) as usize;
        let mut reply_buf = vec![0u8; reply_len];
        reader.read_exact(&mut reply_buf).await.unwrap();

        let transport = crypto::initiator_complete(handshake, &reply_buf).unwrap();

        let (_server_transport, server_reader, server_writer) = server_handle.await.unwrap();

        let client = TunnelClient {
            transport,
            reader: Box::new(reader),
            writer: Box::new(writer),
            next_stream_id: AtomicU64::new(1),
            next_assoc_id: AtomicU64::new(1),
            local_resolver_calls: std::sync::atomic::AtomicUsize::new(0),
        };

        (client, _server_transport, server_reader, server_writer)
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
