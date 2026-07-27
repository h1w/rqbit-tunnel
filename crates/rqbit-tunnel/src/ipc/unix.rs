use std::{
    io,
    path::{Path, PathBuf},
};

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
};

use super::protocol::{
    MAX_FRAME_BYTES, ProtocolError, ServerRequest, ServerResponse, decode_request,
    decode_response, encode_request, encode_response,
};

#[derive(Debug, Error)]
pub enum UnixControlError {
    #[error("failed to connect to control socket {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read control socket frame: {0}")]
    Read(#[source] io::Error),
    #[error("failed to write control socket frame: {0}")]
    Write(#[source] io::Error),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

pub struct UnixControlClient {
    stream: UnixStream,
}

impl UnixControlClient {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, UnixControlError> {
        let path = path.as_ref().to_path_buf();
        let stream = UnixStream::connect(&path)
            .await
            .map_err(|source| UnixControlError::Connect {
                path: path.clone(),
                source,
            })?;
        Ok(Self { stream })
    }

    pub async fn request(
        &mut self,
        request: ServerRequest,
    ) -> Result<ServerResponse, UnixControlError> {
        write_request(&mut self.stream, &request).await?;
        read_response(&mut self.stream).await
    }
}

pub(crate) async fn read_request<R>(reader: &mut R) -> Result<ServerRequest, UnixControlError>
where
    R: AsyncRead + Unpin,
{
    let body = read_frame(reader).await?;
    Ok(decode_request(&body)?)
}

pub(crate) async fn write_request<W>(
    writer: &mut W,
    request: &ServerRequest,
) -> Result<(), UnixControlError>
where
    W: AsyncWrite + Unpin,
{
    let body = encode_request(request)?;
    write_frame(writer, &body).await
}

pub(crate) async fn read_response<R>(reader: &mut R) -> Result<ServerResponse, UnixControlError>
where
    R: AsyncRead + Unpin,
{
    let body = read_frame(reader).await?;
    Ok(decode_response(&body)?)
}

pub(crate) async fn write_response<W>(
    writer: &mut W,
    response: &ServerResponse,
) -> Result<(), UnixControlError>
where
    W: AsyncWrite + Unpin,
{
    let body = encode_response(response)?;
    write_frame(writer, &body).await
}

async fn read_frame<R>(reader: &mut R) -> Result<Vec<u8>, UnixControlError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    reader
        .read_exact(&mut header)
        .await
        .map_err(UnixControlError::Read)?;
    let length = u32::from_be_bytes(header);
    if length == 0 || length as usize > MAX_FRAME_BYTES {
        return Err(ProtocolError::InvalidFrameLength { length }.into());
    }

    let mut body = vec![0_u8; length as usize];
    reader
        .read_exact(&mut body)
        .await
        .map_err(UnixControlError::Read)?;
    Ok(body)
}

async fn write_frame<W>(writer: &mut W, body: &[u8]) -> Result<(), UnixControlError>
where
    W: AsyncWrite + Unpin,
{
    let length = u32::try_from(body.len()).map_err(|_| {
        UnixControlError::Protocol(ProtocolError::EncodedFrameTooLarge { length: body.len() })
    })?;
    writer
        .write_all(&length.to_be_bytes())
        .await
        .map_err(UnixControlError::Write)?;
    writer
        .write_all(body)
        .await
        .map_err(UnixControlError::Write)
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    use super::{UnixControlError, read_request};
    use crate::ipc::protocol::{ProtocolError, MAX_FRAME_BYTES};

    #[tokio::test]
    async fn request_reader_rejects_a_zero_length_frame_before_reading_a_body() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&0_u32.to_be_bytes()).await.unwrap();
        drop(writer);

        let error = read_request(&mut reader).await.unwrap_err();

        assert!(matches!(
            error,
            UnixControlError::Protocol(ProtocolError::InvalidFrameLength { length: 0 })
        ));
    }

    #[tokio::test]
    async fn request_reader_rejects_an_oversized_frame_before_reading_a_body() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let length = (MAX_FRAME_BYTES + 1) as u32;
        writer.write_all(&length.to_be_bytes()).await.unwrap();
        drop(writer);

        let error = read_request(&mut reader).await.unwrap_err();

        assert!(matches!(
            error,
            UnixControlError::Protocol(ProtocolError::InvalidFrameLength { length: actual })
                if actual == length
        ));
    }

    #[tokio::test]
    async fn request_reader_rejects_an_unsupported_protocol_version() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let body = br#"{"protocol_version":2,"request":{"type":"snapshot"}}"#;
        writer
            .write_all(&(body.len() as u32).to_be_bytes())
            .await
            .unwrap();
        writer.write_all(body).await.unwrap();
        drop(writer);

        let error = read_request(&mut reader).await.unwrap_err();

        assert!(matches!(
            error,
            UnixControlError::Protocol(ProtocolError::UnsupportedProtocolVersion { received: 2 })
        ));
    }
}
