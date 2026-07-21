// ── Chunk a Noise ciphertext blob across rq_tunnel messages ──────────────────
//
// Wire form is a length-prefixed byte stream: for each blob we emit
// `u32-BE length || blob`, then slice that stream into <= CHUNK_MAX pieces.
// Delivery under rq_tunnel is reliable + ordered, so the receiver just
// accumulates bytes and drains complete `length || payload` messages.

use peer_binary_protocol::MAX_RQ_TUNNEL_MESSAGE_LEN;

use super::frame::MAX_FRAME_PAYLOAD;

pub(crate) const CHUNK_MAX: usize = MAX_RQ_TUNNEL_MESSAGE_LEN;

/// Upper bound on a single reassembled ciphertext message. A declared length
/// above this is rejected before buffering — a legitimate Noise ciphertext of a
/// max-size frame is `MAX_FRAME_PAYLOAD + 32`; the extra slack is defensive.
pub(crate) const MAX_CARRIER_CIPHERTEXT: usize = MAX_FRAME_PAYLOAD + 64;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CarrierChunkError {
    #[error("declared message length {declared} exceeds max {max}")]
    MessageTooLarge { declared: usize, max: usize },
}

/// Split one ciphertext blob into ordered <= CHUNK_MAX chunks (with a 4-byte
/// length prefix on the logical message).
pub(crate) fn chunk_ciphertext(blob: &[u8]) -> Vec<Vec<u8>> {
    let mut framed = Vec::with_capacity(4 + blob.len());
    framed.extend_from_slice(&(blob.len() as u32).to_be_bytes());
    framed.extend_from_slice(blob);

    framed.chunks(CHUNK_MAX).map(|c| c.to_vec()).collect()
}

/// Reassembles the length-prefixed ciphertext stream produced by
/// `chunk_ciphertext`.
pub(crate) struct CarrierDefragmenter {
    buf: Vec<u8>,
    max: usize,
}

impl CarrierDefragmenter {
    pub(crate) fn new(max_msg_len: usize) -> Self {
        Self {
            buf: Vec::new(),
            max: max_msg_len,
        }
    }

    /// Push one received rq_tunnel payload; return zero or more complete
    /// ciphertext messages now available. Returns `MessageTooLarge` (before
    /// buffering the rest) if a declared length exceeds `max`.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, CarrierChunkError> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 4 {
                break;
            }
            let len =
                u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
            if len > self.max {
                return Err(CarrierChunkError::MessageTooLarge {
                    declared: len,
                    max: self.max,
                });
            }
            if self.buf.len() < 4 + len {
                break;
            }
            let msg = self.buf[4..4 + len].to_vec();
            self.buf.drain(..4 + len);
            out.push(msg);
        }
        Ok(out)
    }
}

/// Pump carrier messages until one full defragmented ciphertext is available.
///
/// Shared by both the client and server during the Noise-over-carrier
/// handshake. Non-`rq_tunnel` messages (early piece cover such as
/// Bitfield/Unchoke/Interested) are ignored — the handshake only expects the
/// peer's Noise chunks. Returns `None` on disconnect or a defrag error (an
/// oversized declared length is treated as a disconnect, closing a pre-auth
/// memory-DoS).
pub(crate) async fn recv_one_ciphertext(
    read_half: &mut super::carrier_wire::CarrierReadHalf,
    defrag: &mut CarrierDefragmenter,
) -> Option<Vec<u8>> {
    use peer_binary_protocol::{Message, extended::ExtendedMessage};
    loop {
        match read_half.recv_message().await.ok()?? {
            Message::Extended(ExtendedMessage::RqTunnel(rq)) => match defrag.push(rq.as_bytes()) {
                Ok(mut done) => {
                    if !done.is_empty() {
                        return Some(done.remove(0));
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "carrier defrag error during handshake");
                    return None;
                }
            },
            _ => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(blob: Vec<u8>) {
        let chunks = chunk_ciphertext(&blob);
        for c in &chunks {
            assert!(c.len() <= CHUNK_MAX, "chunk {} > CHUNK_MAX", c.len());
        }
        let mut d = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
        let mut out = Vec::new();
        for c in chunks {
            out.extend(d.push(&c).unwrap());
        }
        assert_eq!(out.len(), 1, "exactly one message reassembled");
        assert_eq!(out[0], blob);
    }

    #[test]
    fn roundtrips_small() {
        roundtrip(vec![0xAB; 10]);
    }

    #[test]
    fn roundtrips_empty() {
        roundtrip(Vec::new());
    }

    #[test]
    fn roundtrips_larger_than_chunk() {
        roundtrip((0..40_000u32).map(|i| i as u8).collect());
    }

    #[test]
    fn reassembles_multiple_messages_from_one_stream() {
        let a = vec![1u8; 100];
        let b = vec![2u8; 20_000];
        let mut stream = chunk_ciphertext(&a);
        stream.extend(chunk_ciphertext(&b));

        let mut d = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
        let mut out = Vec::new();
        for c in stream {
            out.extend(d.push(&c).unwrap());
        }
        assert_eq!(out, vec![a, b]);
    }

    #[test]
    fn handles_chunk_split_across_length_prefix() {
        // Feed one byte at a time; a message must only appear once complete.
        let blob = vec![9u8; 5000];
        let chunks = chunk_ciphertext(&blob);
        let joined: Vec<u8> = chunks.into_iter().flatten().collect();
        let mut d = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
        let mut out = Vec::new();
        for byte in joined {
            out.extend(d.push(&[byte]).unwrap());
        }
        assert_eq!(out, vec![blob]);
    }

    #[test]
    fn rejects_oversized_declared_length() {
        // A 4-byte prefix declaring a length just over the cap, with no payload,
        // must return MessageTooLarge without buffering.
        let mut d = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
        let declared = (MAX_CARRIER_CIPHERTEXT + 1) as u32;
        let err = d.push(&declared.to_be_bytes()).unwrap_err();
        assert_eq!(
            err,
            CarrierChunkError::MessageTooLarge {
                declared: MAX_CARRIER_CIPHERTEXT + 1,
                max: MAX_CARRIER_CIPHERTEXT
            }
        );
    }
}
