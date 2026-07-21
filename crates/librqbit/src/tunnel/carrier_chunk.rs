// ── Chunk a Noise ciphertext blob across rq_tunnel messages ──────────────────
//
// Wire form is a length-prefixed byte stream: for each blob we emit
// `u32-BE length || blob`, then slice that stream into <= CHUNK_MAX pieces.
// Delivery under rq_tunnel is reliable + ordered, so the receiver just
// accumulates bytes and drains complete `length || payload` messages.

use peer_binary_protocol::MAX_RQ_TUNNEL_MESSAGE_LEN;

pub(crate) const CHUNK_MAX: usize = MAX_RQ_TUNNEL_MESSAGE_LEN;

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
}

impl CarrierDefragmenter {
    pub(crate) fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Push one received rq_tunnel payload; return zero or more complete
    /// ciphertext messages now available.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 4 {
                break;
            }
            let len =
                u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
            if self.buf.len() < 4 + len {
                break;
            }
            let msg = self.buf[4..4 + len].to_vec();
            self.buf.drain(..4 + len);
            out.push(msg);
        }
        out
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
        let mut d = CarrierDefragmenter::new();
        let mut out = Vec::new();
        for c in chunks {
            out.extend(d.push(&c));
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

        let mut d = CarrierDefragmenter::new();
        let mut out = Vec::new();
        for c in stream {
            out.extend(d.push(&c));
        }
        assert_eq!(out, vec![a, b]);
    }

    #[test]
    fn handles_chunk_split_across_length_prefix() {
        // Feed one byte at a time; a message must only appear once complete.
        let blob = vec![9u8; 5000];
        let chunks = chunk_ciphertext(&blob);
        let joined: Vec<u8> = chunks.into_iter().flatten().collect();
        let mut d = CarrierDefragmenter::new();
        let mut out = Vec::new();
        for byte in joined {
            out.extend(d.push(&[byte]));
        }
        assert_eq!(out, vec![blob]);
    }
}
