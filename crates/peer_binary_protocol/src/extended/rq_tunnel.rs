use std::io::Cursor;
use std::io::Write;

use buffers::ByteBuf;

use crate::MessageDeserializeError;
use crate::SerializeError;

/// Raw rq_tunnel extension message payload.
/// Wraps arbitrary bytes sent via the "rq_tunnel" peer extension.
#[derive(Debug, Eq, PartialEq)]
pub struct RqTunnelMessage<B>(pub B);

impl<'a> RqTunnelMessage<ByteBuf<'a>> {
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        Self(ByteBuf::from(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> RqTunnelMessage<ByteBuf<'a>> {
    pub(crate) fn serialize(
        &self,
        out: &mut Cursor<&mut [u8]>,
    ) -> Result<(), SerializeError> {
        out.write_all(self.as_bytes())
            .map_err(|_| SerializeError::NoSpaceInBuffer)?;
        Ok(())
    }

    pub(crate) fn deserialize(
        buf: &'a [u8],
        len: usize,
    ) -> Result<Self, MessageDeserializeError> {
        use crate::MAX_RQ_TUNNEL_MESSAGE_LEN;
        if len > MAX_RQ_TUNNEL_MESSAGE_LEN {
            return Err(MessageDeserializeError::RqTunnelMessageTooLarge {
                size: len,
                max: MAX_RQ_TUNNEL_MESSAGE_LEN,
            });
        }
        Ok(Self(ByteBuf::from(&buf[..len])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_RQ_TUNNEL_MESSAGE_LEN;

    #[test]
    fn test_rq_tunnel_message_roundtrip() {
        let payload = b"hello tunnel";
        let msg = RqTunnelMessage::from_bytes(payload);
        assert_eq!(msg.as_bytes(), payload);
    }

    #[test]
    fn test_rq_tunnel_message_empty() {
        let msg = RqTunnelMessage::from_bytes(b"");
        assert!(msg.as_bytes().is_empty());
    }

    #[test]
    fn test_rq_tunnel_rejects_oversized_payload() {
        let oversized = vec![0u8; MAX_RQ_TUNNEL_MESSAGE_LEN + 1];
        let result = RqTunnelMessage::deserialize(&oversized, oversized.len());
        assert!(
            matches!(
                result,
                Err(MessageDeserializeError::RqTunnelMessageTooLarge { .. })
            ),
            "expected RqTunnelMessageTooLarge, got {result:?}"
        );
    }

    #[test]
    fn test_rq_tunnel_accepts_max_sized_payload() {
        let max = vec![0x42u8; MAX_RQ_TUNNEL_MESSAGE_LEN];
        let result = RqTunnelMessage::deserialize(&max, max.len());
        assert!(result.is_ok(), "expected ok, got {result:?}");
        assert_eq!(result.unwrap().as_bytes(), max.as_slice());
    }
}