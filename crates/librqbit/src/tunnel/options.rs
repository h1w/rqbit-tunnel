// ── Tunnel role configuration types ──────────────────────────────────────────
//
// Typed configuration for client (SOCKS proxy) and server (peer gateway)
// tunnel roles.  Validation ensures a deployable config before the service
// starts.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use super::frame::{TunnelPairingBundle, TunnelPrivateKey, TunnelPublicKey};

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum TunnelConfigError {
    #[error("client mode requires a pinned server public key")]
    MissingServerKey,

    #[error("server mode requires at least one allowed client key")]
    EmptyClientAllowlist,

    #[error("carriers must be between 1 and 16")]
    InvalidCarrierCount,
}

// ── Role enum ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum TunnelOptions {
    Client(TunnelClientOptions),
    Server(TunnelServerOptions),
}

// ── Client configuration ────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct TunnelClientOptions {
    /// SOCKS5 listen address.  Defaults to loopback `127.0.0.1:0` (OS-assigned port).
    pub socks_listen: SocketAddr,

    /// Address of the tunnel server to connect to. Optional: when `None`, or as
    /// a fallback, the client discovers the server via the DHT (looking up the
    /// carrier hash derived from `expected_server_key`). When `Some`, it is
    /// tried first as a fast path / static override.
    pub server_addr: Option<SocketAddr>,

    /// Client identity key (Noise static key).
    pub identity_key: TunnelPrivateKey,

    /// Pinned server public key.  REQUIRED — validated by `validate()`.
    pub expected_server_key: TunnelPublicKey,

    /// Pairing bundle containing carrier descriptor and server metadata.
    pub pairing: Option<TunnelPairingBundle>,

    /// Number of parallel carrier connections to open (per-stream striping).
    pub carriers: usize,

    /// Root dir for this client's copy of the carrier torrent store.
    pub carrier_root: PathBuf,
}

impl Default for TunnelClientOptions {
    fn default() -> Self {
        Self {
            socks_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr: None,
            identity_key: TunnelPrivateKey([0u8; 32]),
            expected_server_key: TunnelPublicKey([0u8; 32]),
            pairing: None,
            carriers: super::config::DEFAULT_CARRIERS,
            carrier_root: std::env::temp_dir().join("rqbit-tunnel-carrier-client"),
        }
    }
}

// ── Server configuration ────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct TunnelServerOptions {
    /// Address to listen for incoming tunnel peer connections.
    pub peer_listen: SocketAddr,

    /// Server identity key (Noise static key).
    pub identity_key: TunnelPrivateKey,

    /// Set of client public keys allowed to connect.  REQUIRED — validated by `validate()`.
    pub allowed_client_keys: HashSet<TunnelPublicKey>,

    /// Network egress policy for tunneled traffic.
    pub egress_policy: EgressPolicy,

    /// Path to the carrier-torrent store root.
    pub carrier_root: PathBuf,
}

// ── Egress policy ────────────────────────────────────────────────────────────

/// Controls what destinations tunnelled traffic may reach.
///
/// Default policy: allow public-internet destinations; block private / loopback
/// / link-local / multicast.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct EgressPolicy {
    /// Allow connections to private / RFC 1918 ranges.
    pub allow_private: bool,

    /// Allow connections to loopback addresses.
    pub allow_loopback: bool,

    /// Allow connections to link-local addresses.
    pub allow_link_local: bool,

    /// Allow connections to multicast addresses.
    pub allow_multicast: bool,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            allow_private: false,
            allow_loopback: false,
            allow_link_local: false,
            allow_multicast: false,
        }
    }
}

// ── Validation ──────────────────────────────────────────────────────────────

impl TunnelOptions {
    /// Validate that the configuration is deployable.
    pub fn validate(&self) -> Result<(), TunnelConfigError> {
        match self {
            TunnelOptions::Client(opts) => {
                // `server_addr` is optional (the server can be discovered via
                // the DHT), but the pinned server key is always required — it is
                // what authenticates the server and derives the carrier hash.
                if opts.expected_server_key == TunnelPublicKey([0u8; 32]) {
                    return Err(TunnelConfigError::MissingServerKey);
                }
                if opts.carriers == 0 || opts.carriers > super::config::MAX_CARRIERS {
                    return Err(TunnelConfigError::InvalidCarrierCount);
                }
                Ok(())
            }
            TunnelOptions::Server(opts) => {
                if opts.allowed_client_keys.is_empty() {
                    return Err(TunnelConfigError::EmptyClientAllowlist);
                }
                Ok(())
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;

    fn dummy_client_key() -> TunnelPublicKey {
        let mut key = [0u8; 32];
        key[0] = 1;
        TunnelPublicKey(key)
    }

    fn dummy_private_key() -> TunnelPrivateKey {
        let mut key = [0u8; 32];
        key[0] = 1;
        TunnelPrivateKey(key)
    }

    #[test]
    fn client_mode_requires_pinned_key() {
        // No server_addr and no key -> only the missing key is an error now
        // (the address is optional; the server can be found via DHT).
        let options = TunnelOptions::Client(TunnelClientOptions::default());
        assert!(matches!(
            options.validate(),
            Err(TunnelConfigError::MissingServerKey)
        ));
    }

    #[test]
    fn client_mode_rejects_missing_server_key() {
        let mut opts = TunnelClientOptions::default();
        opts.server_addr = Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, 1),
            9090,
        )));
        // expected_server_key is still the zero sentinel
        let options = TunnelOptions::Client(opts);
        assert!(matches!(
            options.validate(),
            Err(TunnelConfigError::MissingServerKey)
        ));
    }

    #[test]
    fn client_mode_passes_with_key_and_no_address() {
        // A pinned key with no static address is valid — DHT discovery.
        let opts = TunnelClientOptions {
            server_addr: None,
            expected_server_key: dummy_client_key(),
            ..Default::default()
        };
        let options = TunnelOptions::Client(opts);
        assert!(options.validate().is_ok());
    }

    #[test]
    fn client_mode_passes_with_key_and_address() {
        let opts = TunnelClientOptions {
            server_addr: Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 1),
                9090,
            ))),
            expected_server_key: dummy_client_key(),
            ..Default::default()
        };
        let options = TunnelOptions::Client(opts);
        assert!(options.validate().is_ok());
    }

    #[test]
    fn server_mode_rejects_empty_allowlist() {
        let opts = TunnelServerOptions {
            peer_listen: SocketAddr::from(([0, 0, 0, 0], 9091)),
            identity_key: dummy_private_key(),
            allowed_client_keys: HashSet::new(),
            egress_policy: EgressPolicy::default(),
            carrier_root: PathBuf::from("/tmp"),
        };
        let options = TunnelOptions::Server(opts);
        assert!(matches!(
            options.validate(),
            Err(TunnelConfigError::EmptyClientAllowlist)
        ));
    }

    #[test]
    fn server_mode_passes_with_nonempty_allowlist() {
        let mut allowed = HashSet::new();
        allowed.insert(dummy_client_key());
        let opts = TunnelServerOptions {
            peer_listen: SocketAddr::from(([0, 0, 0, 0], 9091)),
            identity_key: dummy_private_key(),
            allowed_client_keys: allowed,
            egress_policy: EgressPolicy::default(),
            carrier_root: PathBuf::from("/tmp"),
        };
        let options = TunnelOptions::Server(opts);
        assert!(options.validate().is_ok());
    }

    #[test]
    fn egress_policy_default_blocks_all_restricted() {
        let policy = EgressPolicy::default();
        assert!(!policy.allow_private);
        assert!(!policy.allow_loopback);
        assert!(!policy.allow_link_local);
        assert!(!policy.allow_multicast);
    }

    #[test]
    fn client_has_carrier_root_default() {
        let o = super::TunnelClientOptions::default();
        assert!(!o.carrier_root.as_os_str().is_empty());
    }
}

#[cfg(test)]
mod carrier_tests {
    use super::*;

    #[test]
    fn client_options_default_carriers_is_four() {
        assert_eq!(TunnelClientOptions::default().carriers, 4);
    }

    #[test]
    fn validate_rejects_zero_carriers() {
        let mut opts = TunnelClientOptions {
            expected_server_key: TunnelPublicKey([1u8; 32]),
            ..Default::default()
        };
        opts.carriers = 0;
        assert!(matches!(
            TunnelOptions::Client(opts).validate(),
            Err(TunnelConfigError::InvalidCarrierCount)
        ));
    }

    #[test]
    fn validate_rejects_too_many_carriers() {
        let opts = TunnelClientOptions {
            expected_server_key: TunnelPublicKey([1u8; 32]),
            carriers: super::super::config::MAX_CARRIERS + 1,
            ..Default::default()
        };
        assert!(matches!(
            TunnelOptions::Client(opts).validate(),
            Err(TunnelConfigError::InvalidCarrierCount)
        ));
    }
}
