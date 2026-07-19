use std::io::Cursor;

use bencode::BencodeValue;
use bencode::bencode_serialize_to_writer;
use buffers::ByteBuf;
use buffers::ByteBufT;
use byteorder::WriteBytesExt;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use ut_pex::UtPex;

use crate::DoubleBufHelper;
use crate::MSGID_EXTENDED;
use crate::MY_EXTENDED_RQ_TUNNEL;
use crate::MY_EXTENDED_UT_PEX;
use crate::SerializeError;

use self::{handshake::ExtendedHandshake, rq_tunnel::RqTunnelMessage, ut_metadata::UtMetadata};

use super::MessageDeserializeError;

pub mod handshake;
pub mod rq_tunnel;
pub mod ut_metadata;
pub mod ut_pex;

use super::MY_EXTENDED_UT_METADATA;

#[derive(Debug, Default, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct PeerExtendedMessageIds {
    pub ut_metadata: Option<u8>,
    pub ut_pex: Option<u8>,
    pub rq_tunnel: Option<u8>,
}

impl PeerExtendedMessageIds {
    pub fn my() -> Self {
        Self {
            ut_metadata: Some(MY_EXTENDED_UT_METADATA),
            ut_pex: Some(MY_EXTENDED_UT_PEX),
            rq_tunnel: Some(MY_EXTENDED_RQ_TUNNEL),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ExtendedMessage<ByteBuf: ByteBufT> {
    Handshake(ExtendedHandshake<ByteBuf>),
    UtMetadata(UtMetadata<ByteBuf>),
    UtPex(UtPex<ByteBuf>),
    RqTunnel(RqTunnelMessage<ByteBuf>),
    Dyn(u8, BencodeValue<ByteBuf>),
}

impl<'a> ExtendedMessage<ByteBuf<'a>> {
    pub fn serialize(
        &self,
        out: &mut [u8],
        peer_extended_msg_ids: &dyn Fn() -> PeerExtendedMessageIds,
    ) -> Result<usize, SerializeError> {
        let mut out = Cursor::new(out);
        match self {
            ExtendedMessage::Dyn(msg_id, v) => {
                out.write_u8(*msg_id)?;
                bencode_serialize_to_writer(v, &mut out)?;
            }
            ExtendedMessage::Handshake(h) => {
                out.write_u8(0)?;
                bencode_serialize_to_writer(h, &mut out)?;
            }
            ExtendedMessage::UtMetadata(u) => {
                let emsg_id = peer_extended_msg_ids()
                    .ut_metadata
                    .ok_or(SerializeError::NeedUtMetadata)?;
                out.write_u8(emsg_id)?;
                u.serialize(&mut out)?;
            }
            ExtendedMessage::UtPex(m) => {
                let emsg_id = peer_extended_msg_ids()
                    .ut_pex
                    .ok_or(SerializeError::NeedPex)?;
                out.write_u8(emsg_id)?;
                bencode_serialize_to_writer(m, &mut out)?;
            }
            ExtendedMessage::RqTunnel(msg) => {
                let emsg_id = peer_extended_msg_ids()
                    .rq_tunnel
                    .ok_or(SerializeError::NeedRqTunnel)?;
                out.write_u8(emsg_id)?;
                msg.serialize(&mut out)?;
            }
        }
        Ok(out.position() as usize)
    }

    pub fn deserialize(mut buf: DoubleBufHelper<'a>) -> Result<Self, MessageDeserializeError> {
        let msg_id = crate::MsgIdDebug(MSGID_EXTENDED);
        let emsg_id = buf
            .read_u8()
            .ok_or(MessageDeserializeError::NotEnoughData(1, Some(msg_id)))?;

        fn from_bytes_contig<'a, T>(buf: &DoubleBufHelper<'a>) -> Result<T, MessageDeserializeError>
        where
            T: serde::de::Deserialize<'a>,
        {
            let buf = buf
                .get_contiguous(buf.len())
                .ok_or(MessageDeserializeError::NeedContiguous)?;
            bencode::from_bytes(buf).map_err(|e| {
                tracing::trace!("error deserializing extended: {e:#}");
                MessageDeserializeError::Bencode(e.into_kind())
            })
        }

        match emsg_id {
            0 => Ok(ExtendedMessage::Handshake(from_bytes_contig(&buf)?)),
            MY_EXTENDED_UT_METADATA => {
                Ok(ExtendedMessage::UtMetadata(UtMetadata::deserialize(buf)?))
            }
            MY_EXTENDED_RQ_TUNNEL => {
                let payload_len = buf.len();
                let contiguous = buf
                    .get_contiguous(payload_len)
                    .ok_or(MessageDeserializeError::NeedContiguous)?;
                Ok(ExtendedMessage::RqTunnel(RqTunnelMessage::deserialize(
                    contiguous,
                    payload_len,
                )?))
            }
            MY_EXTENDED_UT_PEX => Ok(ExtendedMessage::UtPex(from_bytes_contig(&buf)?)),
            _ => Ok(ExtendedMessage::Dyn(emsg_id, from_bytes_contig(&buf)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use buffers::ByteBuf;

    use crate::{
        DoubleBufHelper, Message, MessageDeserializeError,
        extended::{
            ExtendedMessage, PeerExtendedMessageIds,
            rq_tunnel::RqTunnelMessage,
            ut_metadata::{UtMetadata, UtMetadataData},
        },
    };

    #[track_caller]
    fn ut_metadata_trailing_bytes_is_error(msg: ExtendedMessage<ByteBuf>) {
        let mut buf = [0u8; 100];
        let sz = msg
            .serialize(&mut buf, &|| PeerExtendedMessageIds::my())
            .unwrap();

        let deserialized =
            ExtendedMessage::deserialize(DoubleBufHelper::new(&buf[..sz], &[])).unwrap();
        assert_eq!(msg, deserialized);

        let res = ExtendedMessage::deserialize(DoubleBufHelper::new(&buf[..sz + 1], &[]));
        assert!(
            matches!(
                res,
                Err(MessageDeserializeError::UtMetadataTrailingBytes
                    | MessageDeserializeError::UtMetadataSizeMismatch {
                        expected_size: 5,
                        received_size: 6
                    })
            ),
            "expected trailing bytes error, got {res:?}"
        )
    }

    #[test]
    fn test_ut_metadata_trailing_bytes_is_error() {
        ut_metadata_trailing_bytes_is_error(ExtendedMessage::UtMetadata(UtMetadata::Request(42)));
        ut_metadata_trailing_bytes_is_error(ExtendedMessage::UtMetadata(UtMetadata::Reject(43)));
        ut_metadata_trailing_bytes_is_error(ExtendedMessage::UtMetadata(UtMetadata::Data(
            UtMetadataData::from_bytes(0, 5, b"\x42\x42\x42\x42\x42"[..].into()),
        )));
    }

    #[test]
    fn test_ut_metadata_non_contiguous() {
        let mut buf = [0u8; 100];
        let msg = ExtendedMessage::UtMetadata(UtMetadata::Data(UtMetadataData::from_bytes(
            0,
            5,
            b"\x42\x42\x42\x42\x42"[..].into(),
        )));
        let sz = msg
            .serialize(&mut buf, &|| PeerExtendedMessageIds::my())
            .unwrap();
        let bencode_sz = buf[..sz].iter().position(|byte| *byte == 0x42).unwrap();

        for split_point in 0..sz {
            let (d0, d1) = buf[..sz].split_at(split_point);
            let buf = DoubleBufHelper::new(d0, d1);
            let res = ExtendedMessage::deserialize(buf);
            if (2..bencode_sz).contains(&split_point) {
                assert!(
                    matches!(res, Err(MessageDeserializeError::NeedContiguous)),
                    "expected NeedContiguous, got {res:?}, split_point={split_point}, bencode_sz={bencode_sz}"
                );
                continue;
            }
            let de = res.unwrap();
            match de {
                ExtendedMessage::UtMetadata(UtMetadata::Data(d)) => {
                    assert_eq!(d.piece(), 0);
                    assert_eq!(d.len(), 5);
                    let mut debuf = [0u8; 5];
                    d.copy_to_slice(&mut debuf);
                    assert_eq!(debuf, b"\x42\x42\x42\x42\x42"[..]);
                }
                _ => panic!("bad msg"),
            }
        }
    }

    #[test]
    fn uses_the_remote_rq_tunnel_id_for_outgoing_payload() {
        let ids = PeerExtendedMessageIds {
            rq_tunnel: Some(9),
            ..Default::default()
        };
        let message = Message::Extended(ExtendedMessage::RqTunnel(RqTunnelMessage::from_bytes(
            b"abc",
        )));
        let mut out = [0; 64];
        let written = message.serialize(&mut out, &|| ids).unwrap();
        assert_eq!(out[5], 9);
        assert_eq!(&out[6..written], b"abc");
    }

    #[test]
    fn unknown_extension_ids_decode_as_dyn() {
        let buf = [
            99u8, b'd', b'3', b':', b'k', b'e', b'y', b'5', b':', b'v', b'a', b'l', b'u', b'e',
            b'e',
        ];
        let result = ExtendedMessage::deserialize(DoubleBufHelper::new(&buf, &[]));
        assert!(
            matches!(result, Ok(ExtendedMessage::Dyn(99, _))),
            "expected Dyn(99, ...), got {result:?}"
        );
    }

    #[test]
    fn oversized_rq_tunnel_payload_is_rejected() {
        let oversize = crate::MAX_RQ_TUNNEL_MESSAGE_LEN + 1;
        let mut buf = vec![0u8; 1 + oversize];
        buf[0] = crate::MY_EXTENDED_RQ_TUNNEL;
        buf[1..].fill(0x42u8);
        let result = ExtendedMessage::deserialize(DoubleBufHelper::new(&buf, &[]));
        assert!(
            matches!(
                result,
                Err(MessageDeserializeError::RqTunnelMessageTooLarge { .. })
            ),
            "expected RqTunnelMessageTooLarge, got {result:?}"
        );
    }

    #[test]
    fn rq_tunnel_split_buffer_roundtrip() {
        let ids = PeerExtendedMessageIds::my();
        let payload = b"hello tunnel data";
        let msg = Message::Extended(ExtendedMessage::RqTunnel(RqTunnelMessage::from_bytes(
            payload,
        )));
        let mut out = [0u8; 256];
        let written = msg.serialize(&mut out, &|| ids).unwrap();
        let wire = &out[..written];

        for split_point in 0..wire.len() {
            let (d0, d1) = wire.split_at(split_point);
            let res = Message::deserialize(d0, d1);
            match res {
                Ok((Message::Extended(ExtendedMessage::RqTunnel(m)), _)) => {
                    assert_eq!(m.as_bytes(), payload);
                }
                Err(MessageDeserializeError::NeedContiguous) => {
                    // Splitting in the middle of the raw payload requires contiguous bytes
                }
                other => panic!("unexpected result at split_point={split_point}: {other:?}"),
            }
        }
    }
}
