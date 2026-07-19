// ── Binary tunnel frame encoding ────────────────────────────────────────────
//
// Wire format:
//   - 1 byte:  version (0x01)
//   - 1 byte:  frame type
//   - varint:  stream_id / association_id
//   - 2 bytes: payload length (big-endian)
//   - N bytes: payload
//
// Unknown versions and malformed lengths are rejected before allocation.

use std::net::SocketAddr;

use bytes::Bytes;

// ── Fixed parameters ────────────────────────────────────────────────────────

/// Current frame protocol version.
pub(crate) const FRAME_VERSION: u8 = 0x01;

/// Maximum payload length per frame (64 KiB).
pub(crate) const MAX_FRAME_PAYLOAD: usize = u16::MAX as usize;

// ── Key types ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelPrivateKey(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TunnelPublicKey(pub [u8; 32]);

#[derive(Clone, Debug)]
pub struct TunnelPairingBundle {
    pub carrier: super::carrier::TunnelCarrierDescriptor,
    pub server_addr: SocketAddr,
    pub server_public_key: TunnelPublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelDestination {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelErrorCode {
    DestinationDenied,
    HostUnreachable,
    ConnectionRefused,
    TimedOut,
    PeerDisconnected,
    ProtocolViolation,
}

// ── Frame type identifiers ──────────────────────────────────────────────────

mod frame_type {
    pub(crate) const CLIENT_HELLO: u8 = 0x01;
    pub(crate) const SERVER_HELLO: u8 = 0x02;
    pub(crate) const OPEN_TCP: u8 = 0x03;
    pub(crate) const TCP_OPENED: u8 = 0x04;
    pub(crate) const TCP_DATA: u8 = 0x05;
    pub(crate) const TCP_FIN: u8 = 0x06;
    pub(crate) const TCP_RESET: u8 = 0x07;
    pub(crate) const OPEN_UDP: u8 = 0x08;
    pub(crate) const UDP_DATAGRAM: u8 = 0x09;
    pub(crate) const CLOSE_UDP: u8 = 0x0A;
    pub(crate) const CREDIT: u8 = 0x0B;
    pub(crate) const PING: u8 = 0x0C;
    pub(crate) const PONG: u8 = 0x0D;
}

// ── Frame enum ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelFrame {
    /// Opaque client identity token (first message after Noise handshake).
    ClientHello(Vec<u8>),
    /// Opaque server identity token (response to ClientHello).
    ServerHello(Vec<u8>),
    /// Request to open a TCP connection to `host:port`.
    OpenTcp {
        stream_id: u64,
        host: String,
        port: u16,
    },
    /// TCP connection established; `bind_addr` is the local bound address.
    TcpOpened {
        stream_id: u64,
        bind_addr: SocketAddr,
    },
    /// TCP stream data chunk.
    TcpData { stream_id: u64, bytes: Bytes },
    /// Graceful TCP half-close.
    TcpFin { stream_id: u64 },
    /// Hard TCP reset with error code.
    TcpReset {
        stream_id: u64,
        code: TunnelErrorCode,
    },
    /// Open a UDP association.
    OpenUdp { association_id: u64 },
    /// UDP datagram.
    UdpDatagram {
        association_id: u64,
        destination: TunnelDestination,
        bytes: Bytes,
    },
    /// Close a UDP association.
    CloseUdp { association_id: u64 },
    /// Flow-control credit grant.
    Credit { stream_id: u64, bytes: u32 },
    /// Keep-alive / latency probe.
    Ping { nonce: u64 },
    /// Keep-alive / latency response.
    Pong { nonce: u64 },
}

// ── Encode / decode ─────────────────────────────────────────────────────────

/// Error while encoding or decoding a frame.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// Unknown or unsupported frame version byte.
    #[error("unknown frame version: {0:#04x}")]
    UnknownVersion(u8),
    /// Unknown frame type byte.
    #[error("unknown frame type: {0:#04x}")]
    UnknownFrameType(u8),
    /// Payload length overflows the remaining buffer.
    #[error("payload too large: declared {declared} bytes, only {remaining} remaining")]
    PayloadTooLarge { declared: usize, remaining: usize },
    /// Buffer too short to contain the frame header.
    #[error("buffer too short for frame header")]
    BufferTooShort,
    /// The encoded frame would exceed the maximum allowed size.
    #[error("frame too large: {size} bytes > {max} max")]
    FrameTooLarge { size: usize, max: usize },
    /// Invalid data in payload (e.g. bad UTF-8 for a hostname).
    #[error("invalid frame payload: {0}")]
    InvalidPayload(&'static str),
    /// Invalid SocketAddr encoding.
    #[error("invalid socket address encoding")]
    InvalidSocketAddr,
}

// ── Varint helpers ──────────────────────────────────────────────────────────

fn put_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn read_varint(buf: &[u8]) -> Result<(u64, usize), FrameError> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in buf.iter().enumerate() {
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return Err(FrameError::InvalidPayload("varint overflow"));
        }
    }
    Err(FrameError::BufferTooShort)
}

// ── Encoder ─────────────────────────────────────────────────────────────────

impl TunnelFrame {
    /// Encode this frame into its wire representation.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut buf = Vec::with_capacity(256);

        // Version byte.
        buf.push(FRAME_VERSION);

        match self {
            TunnelFrame::ClientHello(token) => {
                buf.push(frame_type::CLIENT_HELLO);
                put_varint(&mut buf, 0);
                let payload = &token[..];
                put_u16_be(&mut buf, payload.len() as u16);
                buf.extend_from_slice(payload);
            }
            TunnelFrame::ServerHello(token) => {
                buf.push(frame_type::SERVER_HELLO);
                put_varint(&mut buf, 0);
                let payload = &token[..];
                put_u16_be(&mut buf, payload.len() as u16);
                buf.extend_from_slice(payload);
            }
            TunnelFrame::OpenTcp {
                stream_id,
                host,
                port,
            } => {
                buf.push(frame_type::OPEN_TCP);
                put_varint(&mut buf, *stream_id);
                let mut payload = Vec::with_capacity(host.len() + 4);
                put_u16_be(&mut payload, host.len() as u16);
                payload.extend_from_slice(host.as_bytes());
                payload.push((*port >> 8) as u8);
                payload.push((*port & 0xFF) as u8);
                put_u16_be(&mut buf, payload.len() as u16);
                buf.extend_from_slice(&payload);
            }
            TunnelFrame::TcpOpened {
                stream_id,
                bind_addr,
            } => {
                buf.push(frame_type::TCP_OPENED);
                put_varint(&mut buf, *stream_id);
                let payload = sockaddr_to_bytes(*bind_addr);
                put_u16_be(&mut buf, payload.len() as u16);
                buf.extend_from_slice(&payload);
            }
            TunnelFrame::TcpData { stream_id, bytes } => {
                buf.push(frame_type::TCP_DATA);
                put_varint(&mut buf, *stream_id);
                let payload = &bytes[..];
                put_u16_be(&mut buf, payload.len() as u16);
                buf.extend_from_slice(payload);
            }
            TunnelFrame::TcpFin { stream_id } => {
                buf.push(frame_type::TCP_FIN);
                put_varint(&mut buf, *stream_id);
                put_u16_be(&mut buf, 0);
            }
            TunnelFrame::TcpReset { stream_id, code } => {
                buf.push(frame_type::TCP_RESET);
                put_varint(&mut buf, *stream_id);
                let c: u8 = error_code_to_byte(*code);
                put_u16_be(&mut buf, 1);
                buf.push(c);
            }
            TunnelFrame::OpenUdp { association_id } => {
                buf.push(frame_type::OPEN_UDP);
                put_varint(&mut buf, *association_id);
                put_u16_be(&mut buf, 0);
            }
            TunnelFrame::UdpDatagram {
                association_id,
                destination,
                bytes,
            } => {
                buf.push(frame_type::UDP_DATAGRAM);
                put_varint(&mut buf, *association_id);
                let dest_bytes = destination_to_bytes(destination);
                let payload_len = dest_bytes.len() + bytes.len();
                if payload_len > MAX_FRAME_PAYLOAD {
                    return Err(FrameError::FrameTooLarge {
                        size: payload_len,
                        max: MAX_FRAME_PAYLOAD,
                    });
                }
                put_u16_be(&mut buf, payload_len as u16);
                buf.extend_from_slice(&dest_bytes);
                buf.extend_from_slice(bytes);
            }
            TunnelFrame::CloseUdp { association_id } => {
                buf.push(frame_type::CLOSE_UDP);
                put_varint(&mut buf, *association_id);
                put_u16_be(&mut buf, 0);
            }
            TunnelFrame::Credit {
                stream_id,
                bytes: credit,
            } => {
                buf.push(frame_type::CREDIT);
                put_varint(&mut buf, *stream_id);
                let mut payload = [0u8; 4];
                payload[0] = (*credit >> 24) as u8;
                payload[1] = (*credit >> 16) as u8;
                payload[2] = (*credit >> 8) as u8;
                payload[3] = (*credit & 0xFF) as u8;
                put_u16_be(&mut buf, 4);
                buf.extend_from_slice(&payload);
            }
            TunnelFrame::Ping { nonce } => {
                buf.push(frame_type::PING);
                put_varint(&mut buf, 0);
                let mut payload = [0u8; 8];
                payload[0] = (*nonce >> 56) as u8;
                payload[1] = (*nonce >> 48) as u8;
                payload[2] = (*nonce >> 40) as u8;
                payload[3] = (*nonce >> 32) as u8;
                payload[4] = (*nonce >> 24) as u8;
                payload[5] = (*nonce >> 16) as u8;
                payload[6] = (*nonce >> 8) as u8;
                payload[7] = (*nonce & 0xFF) as u8;
                put_u16_be(&mut buf, 8);
                buf.extend_from_slice(&payload);
            }
            TunnelFrame::Pong { nonce } => {
                buf.push(frame_type::PONG);
                put_varint(&mut buf, 0);
                let mut payload = [0u8; 8];
                payload[0] = (*nonce >> 56) as u8;
                payload[1] = (*nonce >> 48) as u8;
                payload[2] = (*nonce >> 40) as u8;
                payload[3] = (*nonce >> 32) as u8;
                payload[4] = (*nonce >> 24) as u8;
                payload[5] = (*nonce >> 16) as u8;
                payload[6] = (*nonce >> 8) as u8;
                payload[7] = (*nonce & 0xFF) as u8;
                put_u16_be(&mut buf, 8);
                buf.extend_from_slice(&payload);
            }
        }

        // Just check overall size sanity
        if buf.len() > MAX_FRAME_PAYLOAD + 16 {
            return Err(FrameError::FrameTooLarge {
                size: buf.len(),
                max: MAX_FRAME_PAYLOAD + 16,
            });
        }

        Ok(buf)
    }

    /// Decode a frame from wire bytes.
    pub fn decode(mut buf: &[u8]) -> Result<Self, FrameError> {
        if buf.len() < 4 {
            return Err(FrameError::BufferTooShort);
        }

        // Version byte.
        let version = buf[0];
        if version != FRAME_VERSION {
            return Err(FrameError::UnknownVersion(version));
        }
        buf = &buf[1..];

        // Frame type.
        let frame_type = buf[0];
        buf = &buf[1..];

        // Stream / association id (varint).
        let (stream_id, vi_len) = read_varint(buf)?;
        buf = &buf[vi_len..];

        // Payload length.
        if buf.len() < 2 {
            return Err(FrameError::BufferTooShort);
        }
        let payload_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        buf = &buf[2..];

        if payload_len > buf.len() {
            return Err(FrameError::PayloadTooLarge {
                declared: payload_len,
                remaining: buf.len(),
            });
        }

        let payload = &buf[..payload_len];

        match frame_type {
            frame_type::CLIENT_HELLO => Ok(TunnelFrame::ClientHello(payload.to_vec())),
            frame_type::SERVER_HELLO => Ok(TunnelFrame::ServerHello(payload.to_vec())),
            frame_type::OPEN_TCP => {
                if payload.len() < 4 {
                    return Err(FrameError::InvalidPayload("OpenTcp too short"));
                }
                let host_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                if payload.len() < 4 + host_len {
                    return Err(FrameError::InvalidPayload("OpenTcp host truncated"));
                }
                let host = std::str::from_utf8(&payload[2..2 + host_len])
                    .map_err(|_| FrameError::InvalidPayload("OpenTcp host not UTF-8"))?;
                let port = u16::from_be_bytes([payload[2 + host_len], payload[3 + host_len]]);
                Ok(TunnelFrame::OpenTcp {
                    stream_id,
                    host: host.to_string(),
                    port,
                })
            }
            frame_type::TCP_OPENED => {
                let bind_addr = bytes_to_sockaddr(payload)?;
                Ok(TunnelFrame::TcpOpened {
                    stream_id,
                    bind_addr,
                })
            }
            frame_type::TCP_DATA => Ok(TunnelFrame::TcpData {
                stream_id,
                bytes: Bytes::copy_from_slice(payload),
            }),
            frame_type::TCP_FIN => Ok(TunnelFrame::TcpFin { stream_id }),
            frame_type::TCP_RESET => {
                if payload.is_empty() {
                    return Err(FrameError::InvalidPayload("TcpReset missing error code"));
                }
                let code = byte_to_error_code(payload[0])?;
                Ok(TunnelFrame::TcpReset { stream_id, code })
            }
            frame_type::OPEN_UDP => Ok(TunnelFrame::OpenUdp {
                association_id: stream_id,
            }),
            frame_type::UDP_DATAGRAM => {
                if payload.len() < 2 {
                    return Err(FrameError::InvalidPayload("UdpDatagram too short"));
                }
                let dest = bytes_to_destination(payload)?;
                let dest_len = destination_encoded_len(&dest);
                let data = Bytes::copy_from_slice(&payload[dest_len..]);
                Ok(TunnelFrame::UdpDatagram {
                    association_id: stream_id,
                    destination: dest,
                    bytes: data,
                })
            }
            frame_type::CLOSE_UDP => Ok(TunnelFrame::CloseUdp {
                association_id: stream_id,
            }),
            frame_type::CREDIT => {
                if payload.len() < 4 {
                    return Err(FrameError::InvalidPayload("Credit too short"));
                }
                let credit = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                Ok(TunnelFrame::Credit {
                    stream_id,
                    bytes: credit,
                })
            }
            frame_type::PING => {
                if payload.len() < 8 {
                    return Err(FrameError::InvalidPayload("Ping too short"));
                }
                let nonce = u64::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                    payload[6], payload[7],
                ]);
                Ok(TunnelFrame::Ping { nonce })
            }
            frame_type::PONG => {
                if payload.len() < 8 {
                    return Err(FrameError::InvalidPayload("Pong too short"));
                }
                let nonce = u64::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                    payload[6], payload[7],
                ]);
                Ok(TunnelFrame::Pong { nonce })
            }
            _ => Err(FrameError::UnknownFrameType(frame_type)),
        }
    }
}

// ── Helper functions ────────────────────────────────────────────────────────

fn put_u16_be(buf: &mut Vec<u8>, val: u16) {
    buf.push((val >> 8) as u8);
    buf.push((val & 0xFF) as u8);
}

fn error_code_to_byte(code: TunnelErrorCode) -> u8 {
    match code {
        TunnelErrorCode::DestinationDenied => 0x01,
        TunnelErrorCode::HostUnreachable => 0x02,
        TunnelErrorCode::ConnectionRefused => 0x03,
        TunnelErrorCode::TimedOut => 0x04,
        TunnelErrorCode::PeerDisconnected => 0x05,
        TunnelErrorCode::ProtocolViolation => 0x06,
    }
}

fn byte_to_error_code(b: u8) -> Result<TunnelErrorCode, FrameError> {
    match b {
        0x01 => Ok(TunnelErrorCode::DestinationDenied),
        0x02 => Ok(TunnelErrorCode::HostUnreachable),
        0x03 => Ok(TunnelErrorCode::ConnectionRefused),
        0x04 => Ok(TunnelErrorCode::TimedOut),
        0x05 => Ok(TunnelErrorCode::PeerDisconnected),
        0x06 => Ok(TunnelErrorCode::ProtocolViolation),
        _ => Err(FrameError::InvalidPayload("unknown error code")),
    }
}

fn sockaddr_to_bytes(addr: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(18);
    match addr {
        SocketAddr::V4(v4) => {
            buf.push(0x04); // IPv4 tag
            buf.extend_from_slice(&v4.ip().octets());
            buf.push((addr.port() >> 8) as u8);
            buf.push((addr.port() & 0xFF) as u8);
        }
        SocketAddr::V6(v6) => {
            buf.push(0x06); // IPv6 tag
            buf.extend_from_slice(&v6.ip().octets());
            buf.push((addr.port() >> 8) as u8);
            buf.push((addr.port() & 0xFF) as u8);
        }
    }
    buf
}

fn bytes_to_sockaddr(buf: &[u8]) -> Result<SocketAddr, FrameError> {
    if buf.is_empty() {
        return Err(FrameError::InvalidSocketAddr);
    }
    match buf[0] {
        0x04 => {
            if buf.len() < 1 + 4 + 2 {
                return Err(FrameError::InvalidSocketAddr);
            }
            let ip = std::net::Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
        }
        0x06 => {
            if buf.len() < 1 + 16 + 2 {
                return Err(FrameError::InvalidSocketAddr);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0)))
        }
        _ => Err(FrameError::InvalidSocketAddr),
    }
}

fn destination_to_bytes(dest: &TunnelDestination) -> Vec<u8> {
    match dest {
        TunnelDestination::Ip(addr) => sockaddr_to_bytes(*addr),
        TunnelDestination::Domain(host, port) => {
            let mut buf = Vec::with_capacity(1 + 2 + host.len() + 2);
            buf.push(0x00); // domain tag
            buf.push((host.len() >> 8) as u8);
            buf.push((host.len() & 0xFF) as u8);
            buf.extend_from_slice(host.as_bytes());
            buf.push((*port >> 8) as u8);
            buf.push((*port & 0xFF) as u8);
            buf
        }
    }
}

fn bytes_to_destination(buf: &[u8]) -> Result<TunnelDestination, FrameError> {
    if buf.is_empty() {
        return Err(FrameError::InvalidPayload("empty destination"));
    }
    match buf[0] {
        0x00 => {
            // Domain
            if buf.len() < 5 {
                return Err(FrameError::InvalidPayload("domain destination too short"));
            }
            let host_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
            if buf.len() < 5 + host_len {
                return Err(FrameError::InvalidPayload("domain host truncated"));
            }
            let host = std::str::from_utf8(&buf[3..3 + host_len])
                .map_err(|_| FrameError::InvalidPayload("domain not UTF-8"))?;
            let port = u16::from_be_bytes([buf[3 + host_len], buf[4 + host_len]]);
            Ok(TunnelDestination::Domain(host.to_string(), port))
        }
        0x04 | 0x06 => {
            let addr = bytes_to_sockaddr(buf)?;
            Ok(TunnelDestination::Ip(addr))
        }
        _ => Err(FrameError::InvalidPayload("unknown destination type")),
    }
}

fn destination_encoded_len(dest: &TunnelDestination) -> usize {
    match dest {
        TunnelDestination::Ip(SocketAddr::V4(_)) => 1 + 4 + 2,
        TunnelDestination::Ip(SocketAddr::V6(_)) => 1 + 16 + 2,
        TunnelDestination::Domain(host, _) => 1 + 2 + host.len() + 2,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn round_trip(frame: &TunnelFrame) {
        let encoded = frame.encode().expect("encode should succeed");
        let decoded = TunnelFrame::decode(&encoded).expect("decode should succeed");
        assert_eq!(&decoded, frame, "round-trip mismatch: {frame:?}");
    }

    #[test]
    fn rejects_unknown_frame_version() {
        let buf = [0xFF, 0x01, 0x00, 0x00, 0x00];
        let result = TunnelFrame::decode(&buf);
        assert!(matches!(result, Err(FrameError::UnknownVersion(0xFF))));
    }

    #[test]
    fn rejects_truncated_header() {
        let result = TunnelFrame::decode(&[0x01, 0x02]);
        assert!(matches!(result, Err(FrameError::BufferTooShort)));
    }

    #[test]
    fn rejects_unknown_frame_type() {
        let buf = [0x01, 0xFF, 0x00, 0x00, 0x00];
        let result = TunnelFrame::decode(&buf);
        assert!(matches!(result, Err(FrameError::UnknownFrameType(0xFF))));
    }

    #[test]
    fn rejects_payload_too_large() {
        // Declare 100 bytes but only provide 5.
        let buf = [0x01, 0x05, 0x01, 0x00, 100, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = TunnelFrame::decode(&buf);
        assert!(matches!(result, Err(FrameError::PayloadTooLarge { .. })));
    }

    #[test]
    fn open_tcp_round_trip() {
        round_trip(&TunnelFrame::OpenTcp {
            stream_id: 42,
            host: "example.test".into(),
            port: 443,
        });
    }

    #[test]
    fn tcp_data_round_trip() {
        round_trip(&TunnelFrame::TcpData {
            stream_id: 7,
            bytes: Bytes::from_static(b"hello world"),
        });
    }

    #[test]
    fn tcp_fin_round_trip() {
        round_trip(&TunnelFrame::TcpFin { stream_id: 99 });
    }

    #[test]
    fn tcp_reset_round_trip() {
        round_trip(&TunnelFrame::TcpReset {
            stream_id: 3,
            code: TunnelErrorCode::ConnectionRefused,
        });
    }

    #[test]
    fn client_hello_round_trip() {
        round_trip(&TunnelFrame::ClientHello(b"my-identity-token".to_vec()));
    }

    #[test]
    fn server_hello_round_trip() {
        round_trip(&TunnelFrame::ServerHello(b"server-identity".to_vec()));
    }

    #[test]
    fn tcp_opened_round_trip() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
        round_trip(&TunnelFrame::TcpOpened {
            stream_id: 1,
            bind_addr: addr,
        });
    }

    #[test]
    fn open_udp_round_trip() {
        round_trip(&TunnelFrame::OpenUdp { association_id: 55 });
    }

    #[test]
    fn udp_datagram_round_trip() {
        round_trip(&TunnelFrame::UdpDatagram {
            association_id: 10,
            destination: TunnelDestination::Domain("example.test".into(), 53),
            bytes: Bytes::from_static(b"dns-query"),
        });
    }

    #[test]
    fn udp_datagram_ip_round_trip() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53));
        round_trip(&TunnelFrame::UdpDatagram {
            association_id: 10,
            destination: TunnelDestination::Ip(addr),
            bytes: Bytes::from_static(b"dns-query"),
        });
    }

    #[test]
    fn close_udp_round_trip() {
        round_trip(&TunnelFrame::CloseUdp { association_id: 99 });
    }

    #[test]
    fn credit_round_trip() {
        round_trip(&TunnelFrame::Credit {
            stream_id: 5,
            bytes: 4096,
        });
    }

    #[test]
    fn ping_round_trip() {
        round_trip(&TunnelFrame::Ping {
            nonce: 0xDEADBEEF_CAFEBABE,
        });
    }

    #[test]
    fn pong_round_trip() {
        round_trip(&TunnelFrame::Pong {
            nonce: 0x12345678_90ABCDEF,
        });
    }

    #[test]
    fn varint_boundaries() {
        round_trip(&TunnelFrame::TcpFin { stream_id: 0 });
        round_trip(&TunnelFrame::TcpFin { stream_id: 127 });
        round_trip(&TunnelFrame::TcpFin { stream_id: 16383 });
        round_trip(&TunnelFrame::TcpFin {
            stream_id: u64::MAX,
        });
    }
}
