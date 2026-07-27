use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::model::{ServerConfig, ServerSnapshot, UserSnapshot};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerRequest {
    Snapshot,
    ListUsers,
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
    Users(Vec<UserSnapshot>),
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
    let encoded = serde_json::to_vec(&RequestEnvelopeRef {
        protocol_version: PROTOCOL_VERSION,
        request,
    })
    .map_err(ProtocolError::Serialize)?;
    ensure_encoded_length(encoded)
}

pub(crate) fn decode_request(body: &[u8]) -> Result<ServerRequest, ProtocolError> {
    let text = std::str::from_utf8(body).map_err(|_| ProtocolError::InvalidUtf8)?;
    let envelope = serde_json::from_str::<RequestEnvelope>(text).map_err(ProtocolError::InvalidJson)?;
    check_protocol_version(envelope.protocol_version)?;
    Ok(envelope.request)
}

pub(crate) fn encode_response(response: &ServerResponse) -> Result<Vec<u8>, ProtocolError> {
    let encoded = serde_json::to_vec(&ResponseEnvelope {
        protocol_version: PROTOCOL_VERSION,
        response,
    })
    .map_err(ProtocolError::Serialize)?;
    ensure_encoded_length(encoded)
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

fn ensure_encoded_length(encoded: Vec<u8>) -> Result<Vec<u8>, ProtocolError> {
    if encoded.is_empty() || encoded.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::EncodedFrameTooLarge {
            length: encoded.len(),
        });
    }

    Ok(encoded)
}
