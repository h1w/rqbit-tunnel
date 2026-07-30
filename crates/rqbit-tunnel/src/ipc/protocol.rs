use std::io;

#[cfg(unix)]
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(unix)]
use uuid::Uuid;

use crate::model::ClientSnapshot;
#[cfg(unix)]
use crate::model::{ServerConfig, ServerSnapshot, UserPage, UserSnapshot};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerRequest {
    Snapshot,
    SnapshotPage,
    ListUsers,
    ListUserPage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after: Option<Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<usize>,
    },
    AddUser {
        name: String,
        export_path: PathBuf,
    },
    SetEnabled {
        id: Uuid,
        enabled: bool,
    },
    DeleteUser {
        id: Uuid,
    },
    ResetTraffic {
        id: Uuid,
    },
    GetConfig,
    SetConfig {
        config: ServerConfig,
    },
    Shutdown,
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ServerResponse {
    Snapshot(ServerSnapshot),
    SnapshotPage(UserPage),
    Users(Vec<UserSnapshot>),
    UserPage(UserPage),
    User(UserSnapshot),
    Deleted { id: Uuid },
    Config(ServerConfigResponse),
    Shutdown,
    Error(ServerError),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientRequest {
    Snapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ClientResponse {
    Snapshot(ClientSnapshot),
    Error(ClientError),
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfigResponse {
    pub config: ServerConfig,
    pub restart_required: bool,
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerError {
    pub code: String,
    pub message: String,
    pub recovery: String,
}

#[cfg(unix)]
impl ServerError {
    pub(crate) fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        recovery: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            recovery: recovery.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientError {
    pub code: String,
    pub message: String,
    pub recovery: String,
}

impl ClientError {
    pub(crate) fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        recovery: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            recovery: recovery.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("control frame length {length} is outside 1..={MAX_FRAME_BYTES}")]
    InvalidFrameLength { length: u32 },
    #[error("control protocol version {received} is unsupported")]
    UnsupportedProtocolVersion { received: u32 },
    #[error("control frame is not valid UTF-8")]
    InvalidUtf8,
    #[error("control frame JSON is invalid: {0}")]
    InvalidJson(#[source] serde_json::Error),
    #[error("failed to serialize control frame: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("encoded control frame is too large: {length} bytes")]
    EncodedFrameTooLarge { length: usize },
}

impl ProtocolError {
    #[cfg(unix)]
    pub(crate) fn response(&self) -> ServerError {
        match self {
            Self::InvalidFrameLength { .. } => ServerError::new(
                "invalid_frame_length",
                "The control frame length must be between 1 and 65536 bytes.",
                "Send a single bounded protocol version 1 frame.",
            ),
            Self::UnsupportedProtocolVersion { .. } => ServerError::new(
                "unsupported_protocol_version",
                "The control protocol version is not supported.",
                "Upgrade or downgrade the control client to protocol version 1.",
            ),
            Self::InvalidUtf8 | Self::InvalidJson(_) => ServerError::new(
                "invalid_frame",
                "The control frame must contain valid UTF-8 JSON.",
                "Send a protocol version 1 JSON envelope.",
            ),
            Self::Serialize(_) | Self::EncodedFrameTooLarge { .. } => ServerError::new(
                "response_encoding_failed",
                "The control response could not be encoded safely.",
                "Reduce the request payload and try again.",
            ),
        }
    }

    pub(crate) fn client_response(&self) -> ClientError {
        match self {
            Self::InvalidFrameLength { .. } => ClientError::new(
                "invalid_frame_length",
                "The client control frame length must be between 1 and 65536 bytes.",
                "Send a single bounded protocol version 1 frame.",
            ),
            Self::UnsupportedProtocolVersion { .. } => ClientError::new(
                "unsupported_protocol_version",
                "The client control protocol version is not supported.",
                "Use a client control consumer compatible with protocol version 1.",
            ),
            Self::InvalidUtf8 | Self::InvalidJson(_) => ClientError::new(
                "invalid_frame",
                "The client control frame must contain valid UTF-8 JSON.",
                "Send a protocol version 1 JSON envelope.",
            ),
            Self::Serialize(_) | Self::EncodedFrameTooLarge { .. } => ClientError::new(
                "response_encoding_failed",
                "The client control response could not be encoded safely.",
                "Retry the read-only snapshot request.",
            ),
        }
    }
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    protocol_version: u32,
    request: ServerRequest,
}

#[cfg(unix)]
#[derive(Serialize)]
struct ResponseEnvelope<'a> {
    protocol_version: u32,
    response: &'a ServerResponse,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IncomingResponseEnvelope {
    protocol_version: u32,
    response: ServerResponse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientRequestEnvelope {
    protocol_version: u32,
    client_request: ClientRequest,
}

#[derive(Serialize)]
struct ClientResponseEnvelope<'a> {
    protocol_version: u32,
    client_response: &'a ClientResponse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IncomingClientResponseEnvelope {
    protocol_version: u32,
    client_response: ClientResponse,
}

#[cfg(unix)]
pub(crate) fn encode_request(request: &ServerRequest) -> Result<Vec<u8>, ProtocolError> {
    encode_bounded(&RequestEnvelopeRef {
        protocol_version: PROTOCOL_VERSION,
        request,
    })
}

#[cfg(unix)]
pub(crate) fn decode_request(body: &[u8]) -> Result<ServerRequest, ProtocolError> {
    let text = std::str::from_utf8(body).map_err(|_| ProtocolError::InvalidUtf8)?;
    let envelope =
        serde_json::from_str::<RequestEnvelope>(text).map_err(ProtocolError::InvalidJson)?;
    check_protocol_version(envelope.protocol_version)?;
    Ok(envelope.request)
}

#[cfg(unix)]
pub(crate) fn encode_response(response: &ServerResponse) -> Result<Vec<u8>, ProtocolError> {
    encode_bounded(&ResponseEnvelope {
        protocol_version: PROTOCOL_VERSION,
        response,
    })
}

#[cfg(unix)]
pub(crate) fn decode_response(body: &[u8]) -> Result<ServerResponse, ProtocolError> {
    let text = std::str::from_utf8(body).map_err(|_| ProtocolError::InvalidUtf8)?;
    let envelope = serde_json::from_str::<IncomingResponseEnvelope>(text)
        .map_err(ProtocolError::InvalidJson)?;
    check_protocol_version(envelope.protocol_version)?;
    Ok(envelope.response)
}

pub(crate) fn encode_client_request(request: &ClientRequest) -> Result<Vec<u8>, ProtocolError> {
    encode_bounded(&ClientRequestEnvelopeRef {
        protocol_version: PROTOCOL_VERSION,
        client_request: request,
    })
}

pub(crate) fn decode_client_request(body: &[u8]) -> Result<ClientRequest, ProtocolError> {
    let text = std::str::from_utf8(body).map_err(|_| ProtocolError::InvalidUtf8)?;
    let envelope =
        serde_json::from_str::<ClientRequestEnvelope>(text).map_err(ProtocolError::InvalidJson)?;
    check_protocol_version(envelope.protocol_version)?;
    Ok(envelope.client_request)
}

pub(crate) fn encode_client_response(response: &ClientResponse) -> Result<Vec<u8>, ProtocolError> {
    encode_bounded(&ClientResponseEnvelope {
        protocol_version: PROTOCOL_VERSION,
        client_response: response,
    })
}

pub(crate) fn decode_client_response(body: &[u8]) -> Result<ClientResponse, ProtocolError> {
    let text = std::str::from_utf8(body).map_err(|_| ProtocolError::InvalidUtf8)?;
    let envelope = serde_json::from_str::<IncomingClientResponseEnvelope>(text)
        .map_err(ProtocolError::InvalidJson)?;
    check_protocol_version(envelope.protocol_version)?;
    Ok(envelope.client_response)
}

#[cfg(unix)]
#[derive(Serialize)]
struct RequestEnvelopeRef<'a> {
    protocol_version: u32,
    request: &'a ServerRequest,
}

#[derive(Serialize)]
struct ClientRequestEnvelopeRef<'a> {
    protocol_version: u32,
    client_request: &'a ClientRequest,
}

fn check_protocol_version(version: u32) -> Result<(), ProtocolError> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedProtocolVersion { received: version })
    }
}

fn encode_bounded<T>(value: &T) -> Result<Vec<u8>, ProtocolError>
where
    T: Serialize + ?Sized,
{
    let mut writer = BoundedWriter::default();
    let result = serde_json::to_writer(&mut writer, value);
    if writer.overflowed {
        return Err(ProtocolError::EncodedFrameTooLarge {
            length: MAX_FRAME_BYTES + 1,
        });
    }
    result.map_err(ProtocolError::Serialize)?;

    if writer.bytes.is_empty() {
        return Err(ProtocolError::EncodedFrameTooLarge { length: 0 });
    }

    Ok(writer.bytes)
}

#[derive(Default)]
struct BoundedWriter {
    bytes: Vec<u8>,
    overflowed: bool,
}

impl io::Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = MAX_FRAME_BYTES.saturating_sub(self.bytes.len());
        if bytes.len() > remaining {
            self.overflowed = true;
            return Err(io::Error::other("control frame exceeds its bounded writer"));
        }

        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::model::{ClientSnapshot, LocalServiceState, LocalTunnelState};

    #[cfg(unix)]
    use super::{
        MAX_FRAME_BYTES, ProtocolError, ServerRequest, ServerResponse, decode_request,
        decode_response, encode_response,
    };
    #[cfg(unix)]
    use crate::model::{TrafficTotals, UserSnapshot};

    #[test]
    fn client_snapshot_round_trips_without_secret_material() {
        let snapshot = ClientSnapshot {
            service: LocalServiceState::Running,
            tunnel: LocalTunnelState::Reconnecting,
            socks_listen: Some("127.0.0.1:1080".parse().unwrap()),
            configured_carriers: 4,
            live_carriers: 0,
            version: "rqbit-tunnel test".to_owned(),
            error: None,
        };
        let request = super::ClientRequest::Snapshot;
        let encoded_request = super::encode_client_request(&request).unwrap();
        let request_envelope: serde_json::Value = serde_json::from_slice(&encoded_request).unwrap();
        assert!(request_envelope.get("client_request").is_some());
        assert!(request_envelope.get("request").is_none());
        assert_eq!(
            super::decode_client_request(&encoded_request).unwrap(),
            request
        );

        let response = super::ClientResponse::Snapshot(snapshot);
        let encoded_response = super::encode_client_response(&response).unwrap();
        let body = std::str::from_utf8(&encoded_response).unwrap();
        let response_envelope: serde_json::Value = serde_json::from_str(body).unwrap();
        assert!(response_envelope.get("client_response").is_some());
        assert!(response_envelope.get("response").is_none());
        assert!(!body.contains("private_key"));
        assert!(!body.contains("server_public_key"));
        assert!(!body.contains("destination"));
        assert!(!body.contains("payload_data"));
        assert_eq!(
            super::decode_client_response(&encoded_response).unwrap(),
            response
        );
    }

    #[cfg(unix)]
    #[test]
    fn client_and_server_envelopes_reject_each_other() {
        let client_request = super::encode_client_request(&super::ClientRequest::Snapshot).unwrap();
        assert!(decode_request(&client_request).is_err());
        let server_request = super::encode_request(&ServerRequest::Snapshot).unwrap();
        assert!(super::decode_client_request(&server_request).is_err());

        let client_response = super::encode_client_response(&super::ClientResponse::Error(
            super::ClientError::new("client_error", "client only", "retry snapshot"),
        ))
        .unwrap();
        assert!(decode_response(&client_response).is_err());
        let server_response = encode_response(&ServerResponse::Error(super::ServerError::new(
            "server_error",
            "server only",
            "retry server command",
        )))
        .unwrap();
        assert!(super::decode_client_response(&server_response).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn response_encoding_stops_at_the_frame_limit_without_materializing_the_payload() {
        let response = ServerResponse::User(UserSnapshot {
            id: uuid::Uuid::nil(),
            name: "x".repeat(MAX_FRAME_BYTES * 16),
            name_truncated_bytes: None,
            enabled: true,
            connected: 0,
            traffic: TrafficTotals::default(),
            last_seen: None,
        });

        let error = encode_response(&response).unwrap_err();

        assert!(matches!(
            error,
            ProtocolError::EncodedFrameTooLarge { length }
                if length == MAX_FRAME_BYTES + 1
        ));
    }

    #[cfg(unix)]
    #[test]
    fn legacy_v1_snapshot_and_user_list_payloads_remain_decodable() {
        assert!(matches!(
            decode_request(br#"{"protocol_version":1,"request":{"type":"list_users"}}"#).unwrap(),
            ServerRequest::ListUsers
        ));
        assert!(matches!(
            decode_response(br#"{"protocol_version":1,"response":{"type":"snapshot","payload":{"users":[]}}}"#)
                .unwrap(),
            ServerResponse::Snapshot(snapshot) if snapshot.users.is_empty()
        ));
        assert!(matches!(
            decode_response(br#"{"protocol_version":1,"response":{"type":"users","payload":[]}}"#)
                .unwrap(),
            ServerResponse::Users(users) if users.is_empty()
        ));
    }
}
