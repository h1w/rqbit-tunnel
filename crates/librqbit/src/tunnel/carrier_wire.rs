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

/// Serialize `msg` and write it to `writer`.
async fn write_message<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    scratch: &mut [u8],
    msg: &Message<'_>,
    peer_ids: PeerExtendedMessageIds,
) -> Result<(), CarrierWireError> {
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

        // ── BitTorrent handshake (send ours, read theirs) ───────────────────
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

        // ── BEP10 extended handshake ────────────────────────────────────────
        let mut ext = ExtendedHandshake::new();
        ext.v = Some(buffers::ByteBuf(CLIENT_VERSION));
        write_message(
            &mut writer,
            &mut scratch,
            &Message::Extended(ExtendedMessage::Handshake(ext)),
            PeerExtendedMessageIds::default(),
        )
        .await?;

        // Read messages until we get the peer's extended handshake.
        let mut carrier_peer = TunnelCarrierPeer::new(carrier)?;
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

        // ── Initial cover: Bitfield + Unchoke, plus Interested ──────────────
        for msg in carrier_peer.initial_messages() {
            write_message(&mut writer, &mut scratch, &msg, peer_ids).await?;
        }
        write_message(&mut writer, &mut scratch, &Message::Interested, peer_ids).await?;

        Ok(Self {
            read_buf,
            reader,
            writer,
            peer_ids,
            carrier_peer,
        })
    }

    /// Send an opaque tunnel payload as an `rq_tunnel` extended message.
    pub(crate) async fn send_tunnel(&mut self, payload: &[u8]) -> Result<(), CarrierWireError> {
        let mut scratch = vec![0u8; MAX_MSG_LEN];
        let msg = Message::Extended(ExtendedMessage::RqTunnel(RqTunnelMessage::from_bytes(
            payload,
        )));
        write_message(&mut self.writer, &mut scratch, &msg, self.peer_ids).await
    }

    /// Read peer messages, handling cover traffic inline, until the next
    /// `rq_tunnel` payload arrives. Returns `None` on disconnect.
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
                write_message(writer, scratch, &msg, peer_ids).await?;
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
}
