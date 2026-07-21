// ── BitTorrent peer-wire carrier for the tunnel ─────────────────────────────
//
// Makes the tunnel carrier speak a real BitTorrent peer-wire protocol on top of
// the MSE/PE-encrypted stream, so on the wire it is (structurally) an ordinary
// encrypted BitTorrent peer connection:
//
//   MSE handshake (keyed by a v2 torrent info-hash)
//     → BitTorrent handshake  (pstr "BitTorrent protocol", info_hash, peer_id)
//     → BEP10 extended handshake (advertises the `rq_tunnel` extension)
//     → Bitfield + Unchoke + Interested (cover)
//     → steady state: `rq_tunnel` extended messages carry the (Noise-encrypted)
//       tunnel frames; ordinary peer messages (Request/Piece/…) are handled by
//       `TunnelCarrierPeer` as plausible cover traffic.
//
// NOTE: this masquerades the PROTOCOL, not the BEHAVIOUR. A single long-lived,
// high-throughput connection to one peer, with no swarm/DHT/tracker activity,
// is still distinguishable by traffic analysis. Full behavioural cover is out
// of scope here.

use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
use bytes::Bytes;
use librqbit_core::Id20;
use peer_binary_protocol::extended::ExtendedMessage;
use peer_binary_protocol::extended::PeerExtendedMessageIds;
use peer_binary_protocol::extended::handshake::ExtendedHandshake;
use peer_binary_protocol::extended::rq_tunnel::RqTunnelMessage;
use peer_binary_protocol::{Handshake, MAX_MSG_LEN, Message};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::read_buf::ReadBuf;
use crate::type_aliases::{BoxAsyncReadVectored, BoxAsyncWrite};

use super::carrier::TunnelCarrierStore;
use super::carrier_peer::{CarrierAction, TunnelCarrierPeer};

/// Reserved-bits value advertised in the BitTorrent handshake. Matches a common
/// qBittorrent fingerprint: DHT (bit 0), Fast extension (bit 2), and LTEP /
/// extended messaging (bit 20) — the last is required for `rq_tunnel`.
const HANDSHAKE_RESERVED: u64 = 0x0000_0000_0018_0005;

/// Client version string advertised in the extended handshake (`v`), for blending.
const CLIENT_VERSION: &[u8] = b"qBittorrent/4.6.5";

/// Timeout for a single handshake/message read.
const WIRE_TIMEOUT: Duration = Duration::from_secs(30);

/// Overall wall-clock deadline for the ENTIRE pre-auth handshake in
/// [`CarrierWire::establish`]. `WIRE_TIMEOUT` resets on every message, so a
/// slowloris peer that dribbles a valid message just under that per-read timeout
/// could keep the connection in handshake — driving a disk read per `Request` —
/// indefinitely before Noise auth. This bounds the whole handshake.
const ESTABLISH_DEADLINE: Duration = Duration::from_secs(30);

/// Cap on the number of non-extended-handshake messages tolerated before the
/// peer's BEP-10 extended handshake arrives. A peer streaming unbounded early
/// cover (each message triggering a piece read) that never sends its extended
/// handshake is rejected once this is exceeded.
const MAX_PRE_HANDSHAKE_MSGS: usize = 16;

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub(crate) enum CarrierWireError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("peer wire error: {0}")]
    Wire(String),

    #[error("info_hash mismatch: peer is on a different torrent")]
    InfoHashMismatch,

    #[error("peer does not support extended messaging (BEP10)")]
    NoExtended,

    #[error("peer did not advertise the rq_tunnel extension")]
    NoRqTunnel,

    #[error("carrier handshake exceeded the overall deadline")]
    HandshakeTimeout,

    #[error("peer sent too many messages before its extended handshake")]
    TooManyPreHandshakeMessages,

    #[error("serialize error: {0}")]
    Serialize(String),

    #[error("carrier error: {0}")]
    Carrier(#[from] super::carrier_peer::TunnelCarrierError),
}

// ── Peer id / handshake helpers ─────────────────────────────────────────────

/// Generate a plausible qBittorrent-style peer id: `-qB4650-` + 12 random bytes.
fn make_peer_id() -> Id20 {
    let mut id = [0u8; 20];
    id[..8].copy_from_slice(b"-qB4650-");
    for b in id[8..].iter_mut() {
        *b = rand::random();
    }
    Id20::new(id)
}

// ── Test-only message-level trace tap ───────────────────────────────────────
//
// `write_message` (below) is the single outgoing serialization choke point —
// used by `establish`, `send_tunnel`, and `send_message` alike — so tapping it
// here captures every BT message either carrier endpoint puts on the wire.
// Tunnel tests run on the current-thread runtime (`#[tokio::test]`, not
// `flavor = "multi_thread"`), so all spawned relay tasks for a given test
// share one OS thread and a `thread_local!` sink is visible to both the
// client and server tasks within that same test.

#[cfg(test)]
thread_local! {
    static CARRIER_TRACE: std::cell::RefCell<Option<std::sync::Arc<parking_lot::Mutex<super::test_capture::CarrierTrace>>>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only: install a trace sink for this thread. Returns the handle to read
/// later.
#[cfg(test)]
pub(crate) fn install_carrier_trace()
-> std::sync::Arc<parking_lot::Mutex<super::test_capture::CarrierTrace>> {
    let sink = std::sync::Arc::new(parking_lot::Mutex::new(
        super::test_capture::CarrierTrace::new(),
    ));
    CARRIER_TRACE.with(|c| *c.borrow_mut() = Some(sink.clone()));
    sink
}

/// Test-only: remove this thread's trace sink (if any).
#[cfg(test)]
pub(crate) fn clear_carrier_trace() {
    CARRIER_TRACE.with(|c| *c.borrow_mut() = None);
}

#[cfg(test)]
fn record_carrier_event(msg: &Message<'_>) {
    CARRIER_TRACE.with(|c| {
        if let Some(sink) = c.borrow().as_ref() {
            sink.lock()
                .push(super::test_capture::CarrierEvent::from_message(msg));
        }
    });
}

/// Serialize `msg` and write it to `writer`.
async fn write_message<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    scratch: &mut [u8],
    msg: &Message<'_>,
    peer_ids: PeerExtendedMessageIds,
) -> Result<(), CarrierWireError> {
    #[cfg(test)]
    record_carrier_event(msg);
    let len = msg
        .serialize(scratch, &|| peer_ids)
        .map_err(|e| CarrierWireError::Serialize(format!("{e:?}")))?;
    writer.write_all(&scratch[..len]).await?;
    writer.flush().await?;
    Ok(())
}

// ── Handshake result ────────────────────────────────────────────────────────

/// Everything needed to run the steady-state carrier after a completed
/// BitTorrent + extended handshake over the MSE stream.
pub(crate) struct CarrierWire {
    pub read_buf: ReadBuf,
    pub reader: BoxAsyncReadVectored,
    pub writer: BoxAsyncWrite,
    /// The remote peer's advertised extension ids (its `rq_tunnel` id is what we
    /// must use for OUTGOING rq_tunnel messages).
    pub peer_ids: PeerExtendedMessageIds,
    pub carrier_peer: TunnelCarrierPeer,
}

impl CarrierWire {
    /// Perform the BitTorrent handshake, BEP10 extended handshake, and send the
    /// initial Bitfield/Unchoke/Interested cover messages.
    pub(crate) async fn establish(
        mut reader: BoxAsyncReadVectored,
        mut writer: BoxAsyncWrite,
        carrier: Arc<TunnelCarrierStore>,
        info_hash: Id20,
    ) -> Result<Self, CarrierWireError> {
        let mut scratch = vec![0u8; MAX_MSG_LEN];
        let mut read_buf = ReadBuf::new();

        // The per-read `WIRE_TIMEOUT` resets on every message, so it alone can't
        // bound the whole handshake against a slowloris peer. Wrap the ENTIRE
        // pre-auth handshake in one overall deadline; a peer that keeps us in
        // handshake past it — or floods early cover past `MAX_PRE_HANDSHAKE_MSGS`
        // — is dropped before Noise auth.
        let handshake = async {
            // ── BitTorrent handshake (send ours, read theirs) ───────────────
            let ours = Handshake {
                reserved: HANDSHAKE_RESERVED,
                info_hash,
                peer_id: make_peer_id(),
            };
            let n = ours.serialize_unchecked_len(&mut scratch);
            writer.write_all(&scratch[..n]).await?;
            writer.flush().await?;

            let theirs = read_buf
                .read_handshake(&mut reader, WIRE_TIMEOUT)
                .await
                .map_err(|e| CarrierWireError::Wire(format!("read handshake: {e}")))?;
            if theirs.info_hash != info_hash {
                return Err(CarrierWireError::InfoHashMismatch);
            }
            if !theirs.supports_extended() {
                return Err(CarrierWireError::NoExtended);
            }

            // ── BEP10 extended handshake ────────────────────────────────────
            let mut ext = ExtendedHandshake::new();
            ext.v = Some(buffers::ByteBuf(CLIENT_VERSION));
            write_message(
                &mut writer,
                &mut scratch,
                &Message::Extended(ExtendedMessage::Handshake(ext)),
                PeerExtendedMessageIds::default(),
            )
            .await?;

            // Read messages until we get the peer's extended handshake, bounded
            // by `MAX_PRE_HANDSHAKE_MSGS` so an endless early-cover stream (each
            // message driving a piece read) can't stall us pre-auth.
            let mut carrier_peer = TunnelCarrierPeer::new(carrier)?;
            let mut pre_handshake_msgs = 0usize;
            let peer_ids = loop {
                let msg = read_buf
                    .read_message(&mut reader, WIRE_TIMEOUT)
                    .await
                    .map_err(|e| CarrierWireError::Wire(format!("read ext handshake: {e}")))?;
                match msg {
                    Message::Extended(ExtendedMessage::Handshake(h)) => {
                        break h.peer_extended_messages();
                    }
                    other => {
                        pre_handshake_msgs += 1;
                        if pre_handshake_msgs > MAX_PRE_HANDSHAKE_MSGS {
                            return Err(CarrierWireError::TooManyPreHandshakeMessages);
                        }
                        // Handle any early cover messages (bitfield, etc.).
                        let actions = carrier_peer.on_message(other).await?;
                        dispatch_actions(
                            &mut writer,
                            &mut scratch,
                            actions,
                            PeerExtendedMessageIds::default(),
                        )
                        .await?;
                    }
                }
            };
            if peer_ids.rq_tunnel.is_none() {
                return Err(CarrierWireError::NoRqTunnel);
            }

            // ── Initial cover: Bitfield + Unchoke, plus Interested ──────────
            for msg in carrier_peer.initial_messages() {
                write_message(&mut writer, &mut scratch, &msg.to_message(), peer_ids).await?;
            }
            write_message(&mut writer, &mut scratch, &Message::Interested, peer_ids).await?;

            Ok::<_, CarrierWireError>((carrier_peer, peer_ids))
        };

        let (carrier_peer, peer_ids) =
            match tokio::time::timeout(ESTABLISH_DEADLINE, handshake).await {
                Ok(res) => res?,
                Err(_elapsed) => return Err(CarrierWireError::HandshakeTimeout),
            };

        Ok(Self {
            read_buf,
            reader,
            writer,
            peer_ids,
            carrier_peer,
        })
    }

    /// Send an opaque tunnel payload as an `rq_tunnel` extended message.
    ///
    /// Test-only: production always immediately splits a freshly-established
    /// `CarrierWire` via [`into_halves`](Self::into_halves) and drives
    /// [`CarrierWriteHalf::send_tunnel`] from there instead, so this
    /// whole-`CarrierWire` convenience method is only exercised directly by
    /// this module's own tests below.
    #[cfg(test)]
    pub(crate) async fn send_tunnel(&mut self, payload: &[u8]) -> Result<(), CarrierWireError> {
        let mut scratch = vec![0u8; MAX_MSG_LEN];
        let msg = Message::Extended(ExtendedMessage::RqTunnel(RqTunnelMessage::from_bytes(
            payload,
        )));
        write_message(&mut self.writer, &mut scratch, &msg, self.peer_ids).await
    }

    /// Read peer messages, handling cover traffic inline, until the next
    /// `rq_tunnel` payload arrives. Returns `None` on disconnect.
    ///
    /// Test-only: see [`send_tunnel`](Self::send_tunnel) — production drives
    /// [`CarrierReadHalf::recv_message`] instead.
    #[cfg(test)]
    pub(crate) async fn recv_tunnel(&mut self) -> Result<Option<Bytes>, CarrierWireError> {
        let mut scratch = vec![0u8; MAX_MSG_LEN];
        loop {
            let msg = match self
                .read_buf
                .read_message(&mut self.reader, WIRE_TIMEOUT)
                .await
            {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!(error = %e, "carrier wire read ended");
                    return Ok(None);
                }
            };
            match msg {
                Message::Extended(ExtendedMessage::RqTunnel(rq)) => {
                    return Ok(Some(Bytes::copy_from_slice(rq.as_bytes())));
                }
                Message::KeepAlive => {}
                other => {
                    let actions = self.carrier_peer.on_message(other).await?;
                    match dispatch_actions(&mut self.writer, &mut scratch, actions, self.peer_ids)
                        .await?
                    {
                        Control::Continue => {}
                        Control::Disconnect => return Ok(None),
                    }
                }
            }
        }
    }
}

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
        let msg = Message::Extended(ExtendedMessage::RqTunnel(RqTunnelMessage::from_bytes(
            payload,
        )));
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
    pub(crate) async fn recv_message(&mut self) -> Result<Option<Message<'_>>, CarrierWireError> {
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

enum Control {
    Continue,
    Disconnect,
}

async fn dispatch_actions<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    scratch: &mut [u8],
    actions: Vec<CarrierAction>,
    peer_ids: PeerExtendedMessageIds,
) -> Result<Control, CarrierWireError> {
    for action in actions {
        match action {
            CarrierAction::OutgoingMessage(msg) => {
                write_message(writer, scratch, &msg.to_message(), peer_ids).await?;
            }
            CarrierAction::Disconnect(reason) => {
                tracing::debug!(%reason, "carrier peer requested disconnect");
                return Ok(Control::Disconnect);
            }
        }
    }
    Ok(Control::Continue)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::carrier::TunnelCarrierConfig;
    use crate::tunnel::peer_wire_crypto::PeerWireCrypto;

    async fn test_carrier() -> Arc<TunnelCarrierStore> {
        let dir = tempfile::TempDir::new().unwrap();
        // Leak the tempdir so the store's files outlive this fn for the test.
        let path = dir.keep();
        let config = TunnelCarrierConfig {
            corpus_bytes: 512 * 1024,
            piece_length: 128 * 1024,
            display_name: "debian-12.iso".to_string(),
            seed: [0u8; 32],
        };
        Arc::new(
            TunnelCarrierStore::open_or_initialize(&path, &config)
                .await
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn bt_masquerade_handshake_and_tunnel_roundtrip() {
        let carrier = test_carrier().await;
        let info_hash = carrier.descriptor().handshake_info_hash;

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);

        // Server side.
        let server_carrier = carrier.clone();
        let server = tokio::spawn(async move {
            let enc = PeerWireCrypto::responder(server_io, info_hash)
                .await
                .unwrap();
            let mut wire =
                CarrierWire::establish(enc.reader, enc.writer, server_carrier, info_hash)
                    .await
                    .unwrap();
            // Echo one tunnel payload back.
            let got = wire.recv_tunnel().await.unwrap().unwrap();
            wire.send_tunnel(&got).await.unwrap();
            got
        });

        // Client side.
        let enc = PeerWireCrypto::initiator(client_io, info_hash)
            .await
            .unwrap();
        let mut wire = CarrierWire::establish(enc.reader, enc.writer, carrier, info_hash)
            .await
            .unwrap();

        let payload = b"noise-encrypted-tunnel-frame-would-go-here";
        wire.send_tunnel(payload).await.unwrap();
        let echoed = wire.recv_tunnel().await.unwrap().unwrap();

        assert_eq!(&echoed[..], payload);
        let server_got = server.await.unwrap();
        assert_eq!(&server_got[..], payload);
    }

    #[tokio::test]
    async fn split_halves_carry_tunnel_and_cover() {
        let carrier = test_carrier().await;
        let info_hash = carrier.descriptor().handshake_info_hash;
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);

        let server_carrier = carrier.clone();
        let server = tokio::spawn(async move {
            let enc = PeerWireCrypto::responder(server_io, info_hash)
                .await
                .unwrap();
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

        let enc = PeerWireCrypto::initiator(client_io, info_hash)
            .await
            .unwrap();
        let wire = CarrierWire::establish(enc.reader, enc.writer, carrier, info_hash)
            .await
            .unwrap();
        let (mut r, mut w, _peer) = wire.into_halves();

        let payload = b"noise-blob".to_vec();
        w.send_tunnel(&payload).await.unwrap();
        let echoed = loop {
            match r.recv_message().await.unwrap() {
                Some(Message::Extended(ExtendedMessage::RqTunnel(rq))) => {
                    break rq.as_bytes().to_vec();
                }
                Some(_) => continue,
                None => panic!("client disconnected early"),
            }
        };
        assert_eq!(echoed, payload);
        assert_eq!(server.await.unwrap(), payload);
    }
}
