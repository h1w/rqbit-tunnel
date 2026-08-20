// ── Chunk a Noise ciphertext blob across rq_tunnel messages ──────────────────
//
// Wire form is a length-prefixed byte stream: for each blob we emit
// `u32-BE length || blob`, then slice that stream into <= CHUNK_MAX pieces.
// Delivery under rq_tunnel is reliable + ordered, so the receiver just
// accumulates bytes and drains complete `length || payload` messages.

use bytes::{BufMut, Bytes, BytesMut};

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
///
/// The payload is copied once into one contiguous allocation. Each returned
/// [`Bytes`] is then a zero-copy view into that shared allocation, avoiding one
/// allocation and payload copy per carrier chunk.
pub(crate) fn chunk_ciphertext(blob: &[u8]) -> Vec<Bytes> {
    let framed_len = 4 + blob.len();
    let chunk_count = framed_len.div_ceil(CHUNK_MAX);
    let mut framed = BytesMut::with_capacity(framed_len);
    framed.put_u32(blob.len() as u32);
    framed.extend_from_slice(blob);

    let mut framed = framed.freeze();
    let mut chunks = Vec::with_capacity(chunk_count);
    while !framed.is_empty() {
        let chunk_len = framed.len().min(CHUNK_MAX);
        chunks.push(framed.split_to(chunk_len));
    }
    chunks
}

/// Reassembles the length-prefixed ciphertext stream produced by
/// `chunk_ciphertext`.
pub(crate) struct CarrierDefragmenter {
    buf: BytesMut,
    max: usize,
}

impl CarrierDefragmenter {
    pub(crate) fn new(max_msg_len: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(CHUNK_MAX.min(max_msg_len.saturating_add(4))),
            max: max_msg_len,
        }
    }

    /// Push one received rq_tunnel payload; return zero or more complete
    /// ciphertext messages now available. Returns `MessageTooLarge` (before
    /// buffering the rest) if a declared length exceeds `max`.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, CarrierChunkError> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        let mut consumed = 0;
        loop {
            let remaining = &self.buf[consumed..];
            if remaining.len() < 4 {
                break;
            }
            let len =
                u32::from_be_bytes(remaining[..4].try_into().expect("length checked")) as usize;
            if len > self.max {
                return Err(CarrierChunkError::MessageTooLarge {
                    declared: len,
                    max: self.max,
                });
            }
            if remaining.len() < 4 + len {
                break;
            }
            out.push(remaining[4..4 + len].to_vec());
            consumed += 4 + len;
        }

        if consumed != 0 {
            let remaining = self.buf.len() - consumed;
            if remaining != 0 {
                self.buf.copy_within(consumed.., 0);
            }
            self.buf.truncate(remaining);
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

    #[test]
    fn chunks_share_one_contiguous_allocation() {
        let blob = vec![0x5A; CHUNK_MAX * 2];
        let chunks = chunk_ciphertext(&blob);
        assert!(chunks.len() >= 2);

        assert_eq!(
            chunks[0].as_ptr().wrapping_add(chunks[0].len()),
            chunks[1].as_ptr()
        );
        let cloned = chunks[0].clone();
        assert_eq!(cloned.as_ptr(), chunks[0].as_ptr());
    }

    #[test]
    fn high_throughput_defragmentation_preserves_all_messages() {
        const MESSAGES: usize = 4_096;
        let blob = vec![0xC3; CHUNK_MAX - 4];
        let chunks = chunk_ciphertext(&blob);
        let mut d = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
        let mut decoded = 0;

        for _ in 0..MESSAGES {
            for chunk in &chunks {
                let messages = d.push(chunk).unwrap();
                decoded += messages.len();
                assert!(messages.iter().all(|message| message == &blob));
            }
        }

        assert_eq!(decoded, MESSAGES);
    }

    #[test]
    fn defragmenter_reuses_accumulation_buffer() {
        let blob = vec![0xA5; CHUNK_MAX - 4];
        let chunks = chunk_ciphertext(&blob);
        assert_eq!(chunks.len(), 1);

        let mut d = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
        let initial_capacity = d.buf.capacity();
        for _ in 0..1_024 {
            let messages = d.push(&chunks[0]).unwrap();
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0], blob);
            assert_eq!(d.buf.capacity(), initial_capacity);
        }
    }

    #[test]
    fn defragmenter_retains_capacity_with_partial_trailing_message() {
        let first = [1u8, 2, 3, 4];
        let second = [5u8; 32];
        let mut stream = chunk_ciphertext(&first)[0].to_vec();
        stream.extend_from_slice(&chunk_ciphertext(&second)[0][..1]);

        let mut d = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
        let initial_capacity = d.buf.capacity();
        assert_eq!(d.push(&stream).unwrap(), vec![first.to_vec()]);
        assert_eq!(d.buf.as_ref(), &chunk_ciphertext(&second)[0][..1]);
        assert_eq!(d.buf.capacity(), initial_capacity);
    }

    #[test]
    #[ignore = "throughput microbenchmark; run explicitly with --ignored --nocapture"]
    fn benchmark_high_throughput_defragmentation() {
        use std::hint::black_box;
        use std::time::Instant;

        struct LegacyDefragmenter {
            buf: Vec<u8>,
        }

        impl LegacyDefragmenter {
            fn push(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
                self.buf.extend_from_slice(chunk);
                let mut out = Vec::new();
                while self.buf.len() >= 4 {
                    let len = u32::from_be_bytes(self.buf[..4].try_into().unwrap()) as usize;
                    if self.buf.len() < 4 + len {
                        break;
                    }
                    out.push(self.buf[4..4 + len].to_vec());
                    self.buf.drain(..4 + len);
                }
                out
            }
        }

        const MESSAGES: usize = 8_192;
        let blob = vec![0x7D; CHUNK_MAX - 4];
        let chunks = chunk_ciphertext(&blob);

        let legacy_started = Instant::now();
        let mut legacy = LegacyDefragmenter { buf: Vec::new() };
        let mut legacy_decoded = 0;
        for _ in 0..MESSAGES {
            for chunk in &chunks {
                legacy_decoded += black_box(legacy.push(black_box(chunk))).len();
            }
        }
        let legacy_elapsed = legacy_started.elapsed();

        let optimized_started = Instant::now();
        let mut optimized = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
        let mut optimized_decoded = 0;
        for _ in 0..MESSAGES {
            for chunk in &chunks {
                optimized_decoded += black_box(optimized.push(black_box(chunk)).unwrap()).len();
            }
        }
        let optimized_elapsed = optimized_started.elapsed();

        let mib = (blob.len() * MESSAGES) as f64 / (1024.0 * 1024.0);
        eprintln!(
            "carrier defrag legacy: {mib:.1} MiB in {legacy_elapsed:?} ({:.1} MiB/s)",
            mib / legacy_elapsed.as_secs_f64()
        );
        eprintln!(
            "carrier defrag optimized: {mib:.1} MiB in {optimized_elapsed:?} ({:.1} MiB/s), {:.2}x speedup",
            mib / optimized_elapsed.as_secs_f64(),
            legacy_elapsed.as_secs_f64() / optimized_elapsed.as_secs_f64()
        );
        assert_eq!(legacy_decoded, MESSAGES);
        assert_eq!(optimized_decoded, MESSAGES);
    }
}
