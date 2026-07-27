use std::{
    io,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::model::{ServerConfig, ServerSnapshot, UserPage, UserSnapshot};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

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
    AddUser { name: String, export_path: PathBuf },
    SetEnabled { id: Uuid, enabled: bool },
    DeleteUser { id: Uuid },
    ResetTraffic { id: Uuid },
    GetConfig,
    SetConfig { config: ServerConfig },
    Shutdown,
}

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
pub struct ServerConfigResponse {
    pub config: ServerConfig,
    pub restart_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerError {
    pub code: String,
    pub message: String,
    pub recovery: String,
}

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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    protocol_version: u32,
    request: ServerRequest,
}

#[derive(Serialize)]
struct ResponseEnvelope<'a> {
    protocol_version: u32,
    response: &'a ServerResponse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IncomingResponseEnvelope {
    protocol_version: u32,
    response: ServerResponse,
}

pub(crate) fn encode_request(request: &ServerRequest) -> Result<Vec<u8>, ProtocolError> {
    encode_bounded(&RequestEnvelopeRef {
        protocol_version: PROTOCOL_VERSION,
        request,
    })
}

pub(crate) fn decode_request(body: &[u8]) -> Result<ServerRequest, ProtocolError> {
    let text = std::str::from_utf8(body).map_err(|_| ProtocolError::InvalidUtf8)?;
    let envelope = serde_json::from_str::<RequestEnvelope>(text).map_err(ProtocolError::InvalidJson)?;
    check_protocol_version(envelope.protocol_version)?;
    Ok(envelope.request)
}

pub(crate) fn encode_response(response: &ServerResponse) -> Result<Vec<u8>, ProtocolError> {
    encode_bounded(&ResponseEnvelope {
        protocol_version: PROTOCOL_VERSION,
        response,
    })
}

pub(crate) fn decode_response(body: &[u8]) -> Result<ServerResponse, ProtocolError> {
    let text = std::str::from_utf8(body).map_err(|_| ProtocolError::InvalidUtf8)?;
    let envelope = serde_json::from_str::<IncomingResponseEnvelope>(text)
        .map_err(ProtocolError::InvalidJson)?;
    check_protocol_version(envelope.protocol_version)?;
    Ok(envelope.response)
}

#[derive(Serialize)]
struct RequestEnvelopeRef<'a> {
    protocol_version: u32,
    request: &'a ServerRequest,
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
    use super::{
        MAX_FRAME_BYTES, ProtocolError, ServerRequest, ServerResponse, decode_request,
        decode_response, encode_response,
    };
    use crate::model::{TrafficTotals, UserSnapshot};

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
