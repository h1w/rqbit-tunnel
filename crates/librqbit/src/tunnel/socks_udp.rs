// ── RFC 1928 SOCKS5 UDP encapsulation ──────────────────────────────────────
///
/// Parse and encode SOCKS5 UDP datagrams per RFC 1928:
///
/// ```text
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
/// ```
///
/// RSV MUST be 0x0000.  FRAG != 0 is rejected (fragmentation unsupported).
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::frame::TunnelDestination;

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SocksUdpError {
    #[error("datagram too short for SOCKS5 UDP header")]
    TooShort,

    #[error("reserved field is non-zero")]
    InvalidReserved,

    #[error("SOCKS5 UDP fragmentation is not supported (FRAG={0})")]
    FragmentationUnsupported(u8),

    #[error("unknown address type: 0x{0:02x}")]
    UnknownAddressType(u8),

    #[error("truncated address: expected {expected} bytes, got {got}")]
    TruncatedAddress { expected: usize, got: usize },

    #[error("domain name exceeds 255 bytes: {0}")]
    DomainTooLong(usize),

    #[error("payload exceeds {0} bytes")]
    PayloadTooLarge(usize),
}

/// Maximum datagram payload (aligned with frame MAX_FRAME_PAYLOAD, minus
/// generous SOCKS5 UDP header overhead).
pub(crate) const MAX_UDP_PAYLOAD: usize = super::frame::MAX_FRAME_PAYLOAD - 300;

// ── Parse ───────────────────────────────────────────────────────────────────

/// Parse a SOCKS5 UDP datagram, returning the destination and payload slice.
///
/// Returns `Err(SocksUdpError::FragmentationUnsupported)` when FRAG != 0.
pub(crate) fn parse_socks_udp_datagram(
    input: &[u8],
) -> Result<(TunnelDestination, &[u8]), SocksUdpError> {
    if input.len() < 4 {
        return Err(SocksUdpError::TooShort);
    }

    let rsv = u16::from_be_bytes([input[0], input[1]]);
    if rsv != 0 {
        return Err(SocksUdpError::InvalidReserved);
    }

    let frag = input[2];
    if frag != 0 {
        return Err(SocksUdpError::FragmentationUnsupported(frag));
    }

    let atyp = input[3];
    match atyp {
        0x01 => {
            // IPv4: 4 bytes address + 2 bytes port
            if input.len() < 4 + 6 {
                return Err(SocksUdpError::TruncatedAddress {
                    expected: 6,
                    got: input.len().saturating_sub(4),
                });
            }
            let addr = Ipv4Addr::new(input[4], input[5], input[6], input[7]);
            let port = u16::from_be_bytes([input[8], input[9]]);
            let dest = TunnelDestination::Ip(SocketAddr::new(IpAddr::V4(addr), port));
            Ok((dest, &input[10..]))
        }
        0x04 => {
            // IPv6: 16 bytes address + 2 bytes port
            if input.len() < 4 + 18 {
                return Err(SocksUdpError::TruncatedAddress {
                    expected: 18,
                    got: input.len().saturating_sub(4),
                });
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&input[4..20]);
            let addr = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([input[20], input[21]]);
            let dest = TunnelDestination::Ip(SocketAddr::new(IpAddr::V6(addr), port));
            Ok((dest, &input[22..]))
        }
        0x03 => {
            // Domain: 1 byte length, N bytes name, 2 bytes port
            if input.len() < 5 {
                return Err(SocksUdpError::TruncatedAddress {
                    expected: 1,
                    got: input.len().saturating_sub(4),
                });
            }
            let domain_len = input[4] as usize;
            if domain_len > 255 {
                return Err(SocksUdpError::DomainTooLong(domain_len));
            }
            let header_end = 5 + domain_len + 2; // 4 base + 1 len + N name + 2 port
            if input.len() < header_end {
                return Err(SocksUdpError::TruncatedAddress {
                    expected: domain_len + 3,
                    got: input.len().saturating_sub(5),
                });
            }
            let domain = String::from_utf8_lossy(&input[5..5 + domain_len]).into_owned();
            let port = u16::from_be_bytes([input[5 + domain_len], input[6 + domain_len]]);
            let dest = TunnelDestination::Domain(domain, port);
            Ok((dest, &input[header_end..]))
        }
        other => Err(SocksUdpError::UnknownAddressType(other)),
    }
}

// ── Encode ──────────────────────────────────────────────────────────────────

/// Encode a SOCKS5 UDP datagram header + payload into `out`.
///
/// Writes `RSV(0) | FRAG(0) | ATYP | DST.ADDR | DST.PORT | PAYLOAD`.
pub(crate) fn encode_socks_udp_datagram(
    source: &TunnelDestination,
    payload: &[u8],
    out: &mut Vec<u8>,
) {
    // RSV (2 bytes) + FRAG (1 byte)
    out.extend_from_slice(&[0, 0, 0]);

    match source {
        TunnelDestination::Ip(addr) => match addr {
            SocketAddr::V4(v4) => {
                out.push(0x01); // ATYP = IPv4
                out.extend_from_slice(&v4.ip().octets());
                out.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                out.push(0x04); // ATYP = IPv6
                out.extend_from_slice(&v6.ip().octets());
                out.extend_from_slice(&v6.port().to_be_bytes());
            }
        },
        TunnelDestination::Domain(name, port) => {
            out.push(0x03); // ATYP = Domain
            let name_bytes = name.as_bytes();
            assert!(name_bytes.len() <= 255, "domain name too long");
            out.push(name_bytes.len() as u8);
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&port.to_be_bytes());
        }
    }

    out.extend_from_slice(payload);
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── Parse tests ──────────────────────────────────────────────────────

    #[test]
    fn parse_ipv4_datagram() {
        let input = [
            0, 0,    // RSV
            0,    // FRAG
            0x01, // ATYP = IPv4
            192, 168, 1, 100, // addr
            0, 80, // port = 80
            b'H', b'e', b'l', b'l', b'o', // payload
        ];
        let (dest, payload) = parse_socks_udp_datagram(&input).unwrap();
        assert_eq!(
            dest,
            TunnelDestination::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                80
            ))
        );
        assert_eq!(payload, b"Hello");
    }

    #[test]
    fn parse_ipv6_datagram() {
        let mut input = vec![0u8; 4 + 18];
        input[3] = 0x04; // ATYP = IPv6
        input[4..20].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        input[20] = 0x01; // port = 443 hi
        input[21] = 0xBB; // port = 443 lo
        // payload
        input.extend_from_slice(b"data");

        let (dest, payload) = parse_socks_udp_datagram(&input).unwrap();
        assert_eq!(
            dest,
            TunnelDestination::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
                443
            ))
        );
        assert_eq!(payload, b"data");
    }

    #[test]
    fn parse_domain_datagram() {
        let mut input = vec![
            0, 0,    // RSV
            0,    // FRAG
            0x03, // ATYP = Domain
            11,   // len
        ];
        input.extend_from_slice(b"example.com");
        input.extend_from_slice(&[0x01, 0xBB]); // port 443
        input.extend_from_slice(b"payload");

        let (dest, payload) = parse_socks_udp_datagram(&input).unwrap();
        assert_eq!(dest, TunnelDestination::Domain("example.com".into(), 443));
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn rejects_fragmented_socks_udp_datagrams() {
        let result = parse_socks_udp_datagram(&[0, 0, 1, 1]);
        assert!(matches!(
            result,
            Err(SocksUdpError::FragmentationUnsupported(1))
        ));
    }

    #[test]
    fn rejects_nonzero_rsv() {
        let result = parse_socks_udp_datagram(&[0, 1, 0, 1]);
        assert!(matches!(result, Err(SocksUdpError::InvalidReserved)));
    }

    #[test]
    fn rejects_too_short() {
        assert!(matches!(
            parse_socks_udp_datagram(&[0, 0, 0]),
            Err(SocksUdpError::TooShort)
        ));
    }

    #[test]
    fn rejects_unknown_atyp() {
        let result = parse_socks_udp_datagram(&[0, 0, 0, 0x05, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(
            result,
            Err(SocksUdpError::UnknownAddressType(0x05))
        ));
    }

    #[test]
    fn rejects_truncated_ipv4() {
        let result = parse_socks_udp_datagram(&[0, 0, 0, 0x01, 192, 168]);
        assert!(matches!(
            result,
            Err(SocksUdpError::TruncatedAddress { .. })
        ));
    }

    #[test]
    fn rejects_truncated_domain() {
        let input = [0, 0, 0, 0x03, 20, b'e']; // claims 20 bytes but only 1
        let result = parse_socks_udp_datagram(&input);
        assert!(matches!(
            result,
            Err(SocksUdpError::TruncatedAddress { .. })
        ));
    }

    #[test]
    fn rejects_domain_too_long_marker() {
        // domain length byte is 255, but data doesn't follow — truncated
        let mut input = vec![0, 0, 0, 0x03, 255];
        input.extend(vec![b'x'; 255]);
        // needs port too
        let result = parse_socks_udp_datagram(&input);
        assert!(matches!(
            result,
            Err(SocksUdpError::TruncatedAddress { .. })
        ));
    }

    // ── Encode tests ─────────────────────────────────────────────────────

    #[test]
    fn encode_ipv4_datagram() {
        let dest = TunnelDestination::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8080,
        ));
        let mut out = Vec::new();
        encode_socks_udp_datagram(&dest, b"hello", &mut out);

        // Parse it back to verify round-trip
        let (parsed, payload) = parse_socks_udp_datagram(&out).unwrap();
        assert_eq!(parsed, dest);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn encode_ipv6_datagram() {
        let dest = TunnelDestination::Ip(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            53,
        ));
        let mut out = Vec::new();
        encode_socks_udp_datagram(&dest, b"dns", &mut out);

        let (parsed, payload) = parse_socks_udp_datagram(&out).unwrap();
        assert_eq!(parsed, dest);
        assert_eq!(payload, b"dns");
    }

    #[test]
    fn encode_domain_datagram() {
        let dest = TunnelDestination::Domain("test.example.org".into(), 9999);
        let mut out = Vec::new();
        encode_socks_udp_datagram(&dest, b"body", &mut out);

        let (parsed, payload) = parse_socks_udp_datagram(&out).unwrap();
        assert_eq!(parsed, dest);
        assert_eq!(payload, b"body");
    }

    #[test]
    fn encode_empty_payload() {
        let dest =
            TunnelDestination::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0));
        let mut out = Vec::new();
        encode_socks_udp_datagram(&dest, b"", &mut out);

        let (parsed, payload) = parse_socks_udp_datagram(&out).unwrap();
        assert_eq!(parsed, dest);
        assert_eq!(payload, b"");
    }
}
