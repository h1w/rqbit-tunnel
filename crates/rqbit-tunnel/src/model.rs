use std::net::SocketAddr;

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::Uuid;

pub const BUNDLE_SCHEMA_VERSION: u32 = 1;
pub const SERVER_CONFIG_SCHEMA_VERSION: u32 = 1;
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
        if !(1..=16).contains(&self.default_client_carriers) {
            return Err(ServerConfigError::InvalidDefaultClientCarriers {
                actual: self.default_client_carriers,
            });
        }

        Ok(())
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
        EnrollmentBundle, SERVER_CONFIG_SCHEMA_VERSION, ServerConfig, ServerConfigError,
        ServerEgressConfig,
    };

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
        invalid.default_client_carriers = 17;
        assert!(matches!(
            invalid.validate(),
            Err(ServerConfigError::InvalidDefaultClientCarriers { .. })
        ));
    }
}
