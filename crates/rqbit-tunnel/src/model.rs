use std::{net::SocketAddr, path::PathBuf};

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::Uuid;

use crate::paths::ClientPaths;

pub const BUNDLE_SCHEMA_VERSION: u32 = 1;
pub const SERVER_CONFIG_SCHEMA_VERSION: u32 = 1;
pub const CLIENT_CONFIG_SCHEMA_VERSION: u32 = 1;
/// Maximum UTF-8 byte length accepted for an administrative user name.
///
/// Keeping names small bounds every control-plane snapshot without requiring a
/// serializer to materialize an unbounded response.
pub const MAX_USER_NAME_BYTES: usize = 64;
/// Maximum users that can appear in one control-plane page.
pub const MAX_USER_PAGE_SIZE: usize = 32;
/// Default page size for a user list request.
pub const DEFAULT_USER_PAGE_SIZE: usize = MAX_USER_PAGE_SIZE;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    pub schema_version: u32,
    pub peer_listen: SocketAddr,
    /// Public tunnel endpoint written into new enrollment bundles. When absent,
    /// pre-existing configurations keep advertising their bind address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertised_peer: Option<SocketAddr>,
    pub egress: ServerEgressConfig,
    pub default_client_socks_listen: SocketAddr,
    pub default_client_carriers: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerEgressConfig {
    pub allow_private: bool,
    pub allow_loopback: bool,
    pub allow_link_local: bool,
    pub allow_multicast: bool,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ServerConfigError {
    #[error("server configuration schema version {actual} is unsupported (expected {expected})")]
    UnsupportedSchemaVersion { actual: u32, expected: u32 },
    #[error("the tunnel peer listener port must not be zero")]
    ZeroPeerListenPort,
    #[error("the advertised tunnel peer port must not be zero")]
    ZeroAdvertisedPeerPort,
    #[error("default client carrier count {actual} must be in 1..=16")]
    InvalidDefaultClientCarriers { actual: usize },
}

impl ServerConfig {
    pub fn validate(&self) -> Result<(), ServerConfigError> {
        if self.schema_version != SERVER_CONFIG_SCHEMA_VERSION {
            return Err(ServerConfigError::UnsupportedSchemaVersion {
                actual: self.schema_version,
                expected: SERVER_CONFIG_SCHEMA_VERSION,
            });
        }
        if self.peer_listen.port() == 0 {
            return Err(ServerConfigError::ZeroPeerListenPort);
        }
        if self
            .advertised_peer
            .is_some_and(|address| address.port() == 0)
        {
            return Err(ServerConfigError::ZeroAdvertisedPeerPort);
        }
        if !(1..=16).contains(&self.default_client_carriers) {
            return Err(ServerConfigError::InvalidDefaultClientCarriers {
                actual: self.default_client_carriers,
            });
        }

        Ok(())
    }

    pub fn advertised_peer(&self) -> SocketAddr {
        self.advertised_peer.unwrap_or(self.peer_listen)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentBundle {
    pub schema_version: u32,
    pub user_name: String,
    #[serde(
        serialize_with = "serialize_hex_key",
        deserialize_with = "deserialize_hex_key"
    )]
    pub client_private_key: [u8; 32],
    #[serde(
        serialize_with = "serialize_hex_key",
        deserialize_with = "deserialize_hex_key"
    )]
    pub server_public_key: [u8; 32],
    pub server_addr: SocketAddr,
    pub socks_listen: SocketAddr,
    pub carriers: usize,
}

/// The desktop identity allowed to read the managed client's local status IPC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case")]
pub enum ClientStatusOwner {
    Unix { uid: u32 },
    Windows { sid: String },
}

/// Non-secret client tunnel configuration persisted outside the service process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_owner: Option<ClientStatusOwner>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_addr: Option<SocketAddr>,
    #[serde(
        serialize_with = "serialize_hex_key",
        deserialize_with = "deserialize_hex_key"
    )]
    pub server_public_key: [u8; 32],
    pub client_key_path: PathBuf,
    pub socks_listen: SocketAddr,
    pub carriers: usize,
    pub carrier_root: PathBuf,
    pub allow_unauthenticated_lan_socks: bool,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ClientConfigError {
    #[error("client configuration schema version {actual} is unsupported (expected {expected})")]
    UnsupportedSchemaVersion { actual: u32, expected: u32 },
    #[error("enrollment bundle schema version {actual} is unsupported (expected {expected})")]
    UnsupportedBundleSchemaVersion { actual: u32, expected: u32 },
    #[error("the configured tunnel server port must not be zero")]
    ZeroServerPort,
    #[error("client carrier count {actual} must be in 1..=16")]
    InvalidCarrierCount { actual: usize },
    #[error("a non-loopback SOCKS listener requires explicit insecure LAN acknowledgement")]
    InsecureLanSocksNotAcknowledged,
    #[error("Windows client status owner SID must not be empty")]
    EmptyWindowsStatusOwnerSid,
}

impl ClientConfig {
    pub fn from_bundle(
        paths: &ClientPaths,
        bundle: &EnrollmentBundle,
    ) -> Result<Self, ClientConfigError> {
        if bundle.schema_version != BUNDLE_SCHEMA_VERSION {
            return Err(ClientConfigError::UnsupportedBundleSchemaVersion {
                actual: bundle.schema_version,
                expected: BUNDLE_SCHEMA_VERSION,
            });
        }

        let config = Self {
            schema_version: CLIENT_CONFIG_SCHEMA_VERSION,
            status_owner: None,
            server_addr: Some(bundle.server_addr),
            server_public_key: bundle.server_public_key,
            client_key_path: paths.client_key_path(),
            socks_listen: bundle.socks_listen,
            carriers: bundle.carriers,
            carrier_root: paths.carrier_root(),
            allow_unauthenticated_lan_socks: false,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ClientConfigError> {
        if self.schema_version != CLIENT_CONFIG_SCHEMA_VERSION {
            return Err(ClientConfigError::UnsupportedSchemaVersion {
                actual: self.schema_version,
                expected: CLIENT_CONFIG_SCHEMA_VERSION,
            });
        }
        if self.server_addr.is_some_and(|address| address.port() == 0) {
            return Err(ClientConfigError::ZeroServerPort);
        }
        if !(1..=16).contains(&self.carriers) {
            return Err(ClientConfigError::InvalidCarrierCount {
                actual: self.carriers,
            });
        }
        if !self.socks_listen.ip().is_loopback() && !self.allow_unauthenticated_lan_socks {
            return Err(ClientConfigError::InsecureLanSocksNotAcknowledged);
        }
        if matches!(
            self.status_owner.as_ref(),
            Some(ClientStatusOwner::Windows { sid }) if sid.trim().is_empty()
        ) {
            return Err(ClientConfigError::EmptyWindowsStatusOwnerSid);
        }

        Ok(())
    }

    #[cfg(test)]
    fn for_test(socks_listen: SocketAddr) -> Self {
        Self {
            schema_version: CLIENT_CONFIG_SCHEMA_VERSION,
            status_owner: None,
            server_addr: Some("203.0.113.8:4242".parse().unwrap()),
            server_public_key: [8; 32],
            client_key_path: PathBuf::from("/tmp/rqbit-tunnel-client.key"),
            socks_listen,
            carriers: 4,
            carrier_root: PathBuf::from("/tmp/rqbit-tunnel-client-carrier"),
            allow_unauthenticated_lan_socks: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalServiceState {
    #[serde(rename = "running", alias = "Running")]
    Running,
    #[serde(rename = "stopped", alias = "Stopped")]
    Stopped,
    #[serde(rename = "failed", alias = "Failed")]
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalTunnelState {
    #[serde(rename = "connected", alias = "Connected")]
    Connected,
    #[serde(rename = "reconnecting", alias = "Reconnecting")]
    Reconnecting,
    #[serde(rename = "error", alias = "Error")]
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSnapshot {
    pub service: LocalServiceState,
    pub tunnel: LocalTunnelState,
    pub socks_listen: Option<SocketAddr>,
    pub configured_carriers: usize,
    pub live_carriers: usize,
    pub version: String,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRecord {
    pub id: Uuid,
    pub name: String,
    #[serde(
        serialize_with = "serialize_hex_key",
        deserialize_with = "deserialize_hex_key"
    )]
    pub public_key: [u8; 32],
    pub enabled: bool,
    pub created_at: i64,
    pub reset_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserSnapshot {
    pub id: Uuid,
    pub name: String,
    /// `Some(original_byte_length)` means `name` is a bounded display prefix rather
    /// than the complete stored name; use `id` as the management identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_truncated_bytes: Option<usize>,
    pub enabled: bool,
    pub connected: usize,
    pub traffic: TrafficTotals,
    pub last_seen: Option<i64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficTotals {
    pub upload: u64,
    pub download: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPage {
    pub users: Vec<UserSnapshot>,
    /// The last user identifier in this page, if another page is available.
    pub next_page: Option<Uuid>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSnapshot {
    pub users: Vec<UserSnapshot>,
}

#[cfg(test)]
impl EnrollmentBundle {
    fn for_test(
        user_name: impl Into<String>,
        client_private_key: [u8; 32],
        server_public_key: [u8; 32],
        server_addr: &str,
    ) -> Self {
        Self {
            schema_version: BUNDLE_SCHEMA_VERSION,
            user_name: user_name.into(),
            client_private_key,
            server_public_key,
            server_addr: server_addr.parse().expect("valid test server address"),
            socks_listen: "127.0.0.1:1080".parse().expect("valid test SOCKS address"),
            carriers: 4,
        }
    }
}

fn serialize_hex_key<S>(key: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(key))
}

fn deserialize_hex_key<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    if encoded.len() != 64 {
        return Err(D::Error::custom("expected a 64-character hexadecimal key"));
    }

    let mut key = [0; 32];
    hex::decode_to_slice(encoded, &mut key).map_err(D::Error::custom)?;
    Ok(key)
}
#[cfg(test)]
mod tests {
    use super::{
        ClientConfig, ClientConfigError, ClientStatusOwner, EnrollmentBundle, LocalServiceState,
        LocalTunnelState, SERVER_CONFIG_SCHEMA_VERSION, ServerConfig, ServerConfigError,
        ServerEgressConfig,
    };

    #[test]
    fn local_status_states_serialize_as_lowercase_snake_case() {
        for (state, expected) in [
            (LocalServiceState::Running, "running"),
            (LocalServiceState::Stopped, "stopped"),
            (LocalServiceState::Failed, "failed"),
        ] {
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!(r#""{expected}""#)
            );
        }
        for (state, expected) in [
            (LocalTunnelState::Connected, "connected"),
            (LocalTunnelState::Reconnecting, "reconnecting"),
            (LocalTunnelState::Error, "error"),
        ] {
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!(r#""{expected}""#)
            );
        }
    }

    #[test]
    fn non_loopback_listener_requires_explicit_insecure_acknowledgement() {
        let config = ClientConfig::for_test("0.0.0.0:1080".parse().unwrap());

        assert_eq!(
            config.validate().unwrap_err(),
            ClientConfigError::InsecureLanSocksNotAcknowledged
        );
    }

    #[test]
    fn empty_windows_status_owner_is_rejected_for_loopback_listener() {
        let mut config = ClientConfig::for_test("127.0.0.1:1080".parse().unwrap());
        config.status_owner = Some(ClientStatusOwner::Windows {
            sid: "   ".to_owned(),
        });

        assert_eq!(
            config.validate().unwrap_err(),
            ClientConfigError::EmptyWindowsStatusOwnerSid
        );
    }

    #[test]
    fn loopback_client_config_accepts_valid_carrier_counts_only() {
        let valid = ClientConfig::for_test("127.0.0.1:1080".parse().unwrap());
        assert!(valid.validate().is_ok());

        let mut invalid = valid.clone();
        invalid.carriers = 0;
        assert_eq!(
            invalid.validate().unwrap_err(),
            ClientConfigError::InvalidCarrierCount { actual: 0 }
        );

        let mut invalid = valid;
        invalid.carriers = 17;
        assert_eq!(
            invalid.validate().unwrap_err(),
            ClientConfigError::InvalidCarrierCount { actual: 17 }
        );
    }

    #[test]
    fn enrollment_bundle_round_trips_hex_keys_without_leaking_extra_fields() {
        let bundle = EnrollmentBundle::for_test("alice", [7; 32], [8; 32], "203.0.113.8:4242");
        let encoded = serde_json::to_string(&bundle).unwrap();
        assert!(
            encoded.contains("0707070707070707070707070707070707070707070707070707070707070707")
        );
        assert!(!encoded.contains("carrier_root"));
        assert_eq!(
            serde_json::from_str::<EnrollmentBundle>(&encoded).unwrap(),
            bundle
        );
    }

    #[test]
    fn server_config_rejects_unsupported_schema_zero_peer_port_and_invalid_carriers() {
        let valid = ServerConfig {
            schema_version: SERVER_CONFIG_SCHEMA_VERSION,
            peer_listen: "127.0.0.1:4242".parse().unwrap(),
            advertised_peer: None,
            egress: ServerEgressConfig {
                allow_private: false,
                allow_loopback: false,
                allow_link_local: false,
                allow_multicast: false,
            },
            default_client_socks_listen: "127.0.0.1:1080".parse().unwrap(),
            default_client_carriers: 4,
        };
        assert!(valid.validate().is_ok());

        let mut invalid = valid.clone();
        invalid.schema_version = SERVER_CONFIG_SCHEMA_VERSION + 1;
        assert!(matches!(
            invalid.validate(),
            Err(ServerConfigError::UnsupportedSchemaVersion { .. })
        ));

        let mut invalid = valid.clone();
        invalid.peer_listen = "127.0.0.1:0".parse().unwrap();
        assert!(matches!(
            invalid.validate(),
            Err(ServerConfigError::ZeroPeerListenPort)
        ));

        let mut invalid = valid.clone();
        invalid.advertised_peer = Some("8.8.8.8:0".parse().unwrap());
        assert!(matches!(
            invalid.validate(),
            Err(ServerConfigError::ZeroAdvertisedPeerPort)
        ));

        let mut invalid = valid.clone();
        invalid.default_client_carriers = 17;
        assert!(matches!(
            invalid.validate(),
            Err(ServerConfigError::InvalidDefaultClientCarriers { .. })
        ));
    }

    #[test]
    fn legacy_server_config_without_an_advertised_peer_uses_its_bind_address() {
        let config: ServerConfig = serde_json::from_str(
            r#"{
                "schema_version": 1,
                "peer_listen": "127.0.0.1:4242",
                "egress": {
                    "allow_private": false,
                    "allow_loopback": false,
                    "allow_link_local": false,
                    "allow_multicast": false
                },
                "default_client_socks_listen": "127.0.0.1:1080",
                "default_client_carriers": 4
            }"#,
        )
        .unwrap();

        assert_eq!(config.advertised_peer(), "127.0.0.1:4242".parse().unwrap());
    }
}
