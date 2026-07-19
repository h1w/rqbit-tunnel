//! Test-only capture wrappers for verifying encrypted-wire traffic contracts.
//!
//! # RawCapture
//! Bounded in-memory capture of raw (encrypted) bytes.  Wraps a transport
//! stream to record every byte that passes through, up to a configured
//! maximum.  Test captures are never printed to logs and are only placed in
//! test temp directories.
//!
//! # CarrierTrace
//! Normalised message-event trace.  Records carrier protocol events with
//! their kinds (and optionally payload lengths), never decrypted tunnel
//! content.  Trace assertions require actual carrier piece events, not
//! merely custom extension handshakes.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum raw bytes to capture (1 MiB).
pub(crate) const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

// ── CarrierEvent ─────────────────────────────────────────────────────────────

/// Normalised carrier-protocol message event.
///
/// Records the protocol event kind.  Payload content is never retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CarrierEvent {
    ExtendedHandshake,
    Bitfield,
    Interested,
    NotInterested,
    Request,
    Piece,
    Choke,
    Unchoke,
    Have,
    Cancel,
    KeepAlive,
    Extended,
}

impl CarrierEvent {
    /// Determine the event kind from a borrowed message.
    pub(crate) fn from_message(msg: &peer_binary_protocol::Message<'_>) -> Self {
        use peer_binary_protocol::Message;
        match msg {
            Message::Request(_) => CarrierEvent::Request,
            Message::Cancel(_) => CarrierEvent::Cancel,
            Message::Bitfield(_) => CarrierEvent::Bitfield,
            Message::KeepAlive => CarrierEvent::KeepAlive,
            Message::Have(_) => CarrierEvent::Have,
            Message::Choke => CarrierEvent::Choke,
            Message::Unchoke => CarrierEvent::Unchoke,
            Message::Interested => CarrierEvent::Interested,
            Message::NotInterested => CarrierEvent::NotInterested,
            Message::Piece(_) => CarrierEvent::Piece,
            Message::Extended(ext_msg) => {
                use peer_binary_protocol::extended::ExtendedMessage;
                match ext_msg {
                    ExtendedMessage::Handshake(_) => CarrierEvent::ExtendedHandshake,
                    _ => CarrierEvent::Extended,
                }
            }
        }
    }
}

// ── RawCapture ───────────────────────────────────────────────────────────────

/// Bounded in-memory capture of raw bytes.
#[derive(Debug)]
pub(crate) struct RawCapture {
    buf: Vec<u8>,
    max: usize,
    overflow: bool,
}

impl RawCapture {
    pub(crate) fn new(max_bytes: usize) -> Self {
        Self {
            buf: Vec::with_capacity(max_bytes.min(65536)),
            max: max_bytes,
            overflow: false,
        }
    }

    pub(crate) fn push(&mut self, data: &[u8]) {
        if self.overflow {
            return;
        }
        let remaining = self.max.saturating_sub(self.buf.len());
        if data.len() > remaining {
            self.buf.extend_from_slice(&data[..remaining]);
            self.overflow = true;
        } else {
            self.buf.extend_from_slice(data);
        }
    }

    pub(crate) fn contains(&self, needle: &[u8]) -> bool {
        self.buf.windows(needle.len()).any(|w| w == needle)
    }

    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }
}

// ── CarrierTrace ─────────────────────────────────────────────────────────────

/// Normalised carrier-protocol message trace.
#[derive(Debug)]
pub(crate) struct CarrierTrace {
    events: Vec<CarrierEvent>,
}

impl CarrierTrace {
    pub(crate) fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub(crate) fn push(&mut self, event: CarrierEvent) {
        self.events.push(event);
    }

    /// Assert that `wanted` events appear in order (not necessarily
    /// consecutive).
    ///
    /// # Panics
    /// Panics if any wanted event cannot be matched in sequence.
    pub(crate) fn assert_contains_in_order(&self, wanted: &[CarrierEvent]) {
        let mut idx = 0;
        for event in &self.events {
            if idx >= wanted.len() {
                break;
            }
            if *event == wanted[idx] {
                idx += 1;
            }
        }
        assert!(
            idx == wanted.len(),
            "carrier trace missing events: expected {:?}, got through index {} of {} \
             (full trace: {:?})",
            &wanted[idx..],
            idx,
            wanted.len(),
            &self.events,
        );
    }

    #[allow(dead_code)]
    pub(crate) fn events(&self) -> &[CarrierEvent] {
        &self.events
    }
}

// ── CaptureStream ────────────────────────────────────────────────────────────

pub(crate) struct CaptureStream<S> {
    inner: S,
    capture: Arc<Mutex<RawCapture>>,
}

impl<S> CaptureStream<S> {
    pub(crate) fn new(inner: S, capture: Arc<Mutex<RawCapture>>) -> Self {
        Self { inner, capture }
    }

    #[allow(dead_code)]
    pub(crate) fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CaptureStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled_before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let filled = buf.filled();
            let new_data = &filled[filled_before..];
            if !new_data.is_empty() {
                let mut cap = self.capture.lock();
                cap.push(new_data);
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CaptureStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            if *n > 0 {
                let mut cap = self.capture.lock();
                cap.push(&buf[..*n]);
            }
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ── Conversion helpers ──────────────────────────────────────────────────────

impl From<peer_binary_protocol::Message<'_>> for CarrierEvent {
    fn from(msg: peer_binary_protocol::Message<'_>) -> Self {
        CarrierEvent::from_message(&msg)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_capture_stores_bytes_up_to_limit() {
        let mut cap = RawCapture::new(10);
        cap.push(b"hello");
        assert!(cap.contains(b"hello"));
        assert!(!cap.contains(b"world"));
        assert_eq!(cap.len(), 5);
    }

    #[test]
    fn raw_capture_truncates_at_limit() {
        let mut cap = RawCapture::new(5);
        cap.push(b"hello");
        cap.push(b"world");
        assert_eq!(cap.len(), 5);
        assert!(cap.contains(b"hello"));
    }

    #[test]
    fn raw_capture_contains_finds_substring() {
        let mut cap = RawCapture::new(100);
        cap.push(b"secret-for-capture-and-more");
        assert!(cap.contains(b"secret-for-capture"));
        assert!(!cap.contains(b"plaintext-not-present"));
    }

    #[test]
    fn carrier_trace_assert_contains_in_order_passes() {
        let mut trace = CarrierTrace::new();
        trace.push(CarrierEvent::ExtendedHandshake);
        trace.push(CarrierEvent::Bitfield);
        trace.push(CarrierEvent::Unchoke);
        trace.push(CarrierEvent::Interested);
        trace.push(CarrierEvent::Request);
        trace.push(CarrierEvent::Piece);

        trace.assert_contains_in_order(&[
            CarrierEvent::ExtendedHandshake,
            CarrierEvent::Bitfield,
            CarrierEvent::Interested,
            CarrierEvent::Request,
            CarrierEvent::Piece,
        ]);
    }

    #[test]
    #[should_panic(expected = "carrier trace missing events")]
    fn carrier_trace_assert_contains_in_order_fails_on_missing() {
        let mut trace = CarrierTrace::new();
        trace.push(CarrierEvent::Bitfield);
        trace.push(CarrierEvent::Piece);

        trace.assert_contains_in_order(&[
            CarrierEvent::ExtendedHandshake,
            CarrierEvent::Bitfield,
            CarrierEvent::Piece,
        ]);
    }

    #[test]
    fn message_to_carrier_event_conversion() {
        let msg =
            peer_binary_protocol::Message::Request(peer_binary_protocol::Request::new(0, 0, 16384));
        let event: CarrierEvent = msg.into();
        assert_eq!(event, CarrierEvent::Request);
    }
}
