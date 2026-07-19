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
    #[error("client mode requires a server address")]
    MissingServerAddress,

    #[error("client mode requires a pinned server public key")]
    MissingServerKey,

    #[error("server mode requires at least one allowed client key")]
    EmptyClientAllowlist,
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

    /// Address of the tunnel server to connect to.  REQUIRED — validated by `validate()`.
    pub server_addr: SocketAddr,

    /// Client identity key (Noise static key).
    pub identity_key: TunnelPrivateKey,

    /// Pinned server public key.  REQUIRED — validated by `validate()`.
    pub expected_server_key: TunnelPublicKey,

    /// Pairing bundle containing carrier descriptor and server metadata.
    pub pairing: Option<TunnelPairingBundle>,
}

impl Default for TunnelClientOptions {
    fn default() -> Self {
        Self {
            socks_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            identity_key: TunnelPrivateKey([0u8; 32]),
            expected_server_key: TunnelPublicKey([0u8; 32]),
            pairing: None,
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
                if opts.server_addr.ip().is_unspecified() && opts.server_addr.port() == 0 {
                    return Err(TunnelConfigError::MissingServerAddress);
                }
                if opts.expected_server_key == TunnelPublicKey([0u8; 32]) {
                    return Err(TunnelConfigError::MissingServerKey);
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
    fn client_mode_requires_server_address_and_pinned_key() {
        let options = TunnelOptions::Client(TunnelClientOptions::default());
        assert!(matches!(
            options.validate(),
            Err(TunnelConfigError::MissingServerAddress)
        ));
    }

    #[test]
    fn client_mode_rejects_missing_server_key() {
        let mut opts = TunnelClientOptions::default();
        opts.server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9090));
        // expected_server_key is still the zero sentinel
        let options = TunnelOptions::Client(opts);
        assert!(matches!(
            options.validate(),
            Err(TunnelConfigError::MissingServerKey)
        ));
    }

    #[test]
    fn client_mode_passes_with_valid_config() {
        let opts = TunnelClientOptions {
            server_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9090)),
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
}
