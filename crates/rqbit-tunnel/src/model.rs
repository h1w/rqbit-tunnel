use std::net::SocketAddr;

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

pub const BUNDLE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    pub schema_version: u32,
    pub server_addr: SocketAddr,
    pub carriers: usize,
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
            socks_listen: "127.0.0.1:1080"
                .parse()
                .expect("valid test SOCKS address"),
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
    use super::EnrollmentBundle;

    #[test]
    fn enrollment_bundle_round_trips_hex_keys_without_leaking_extra_fields() {
        let bundle = EnrollmentBundle::for_test("alice", [7; 32], [8; 32], "203.0.113.8:4242");
        let encoded = serde_json::to_string(&bundle).unwrap();
        assert!(encoded.contains("0707070707070707070707070707070707070707070707070707070707070707"));
        assert!(!encoded.contains("carrier_root"));
        assert_eq!(serde_json::from_str::<EnrollmentBundle>(&encoded).unwrap(), bundle);
    }
}
