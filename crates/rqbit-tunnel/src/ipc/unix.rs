use std::{
    io,
    path::{Path, PathBuf},
};

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
    time::{Duration, timeout},
};
use tokio_util::sync::CancellationToken;

use super::protocol::{
    ClientError, ClientRequest, ClientResponse, MAX_FRAME_BYTES, ProtocolError, ServerRequest,
    ServerResponse, decode_client_request, decode_client_response, decode_request, decode_response,
    encode_client_request, encode_client_response, encode_request, encode_response,
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
        let stream =
            UnixStream::connect(&path)
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

/// A bounded, read-only control client for a managed tunnel client.
pub struct UnixClientControlClient {
    stream: UnixStream,
}

impl UnixClientControlClient {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, UnixControlError> {
        let path = path.as_ref().to_path_buf();
        let stream =
            UnixStream::connect(&path)
                .await
                .map_err(|source| UnixControlError::Connect {
                    path: path.clone(),
                    source,
                })?;
        Ok(Self { stream })
    }

    pub async fn request(
        &mut self,
        request: ClientRequest,
    ) -> Result<ClientResponse, UnixControlError> {
        write_client_request(&mut self.stream, &request).await?;
        read_client_response(&mut self.stream).await
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

pub(crate) async fn read_client_request<R>(
    reader: &mut R,
) -> Result<ClientRequest, UnixControlError>
where
    R: AsyncRead + Unpin,
{
    let body = read_frame(reader).await?;
    Ok(decode_client_request(&body)?)
}

pub(crate) async fn write_client_request<W>(
    writer: &mut W,
    request: &ClientRequest,
) -> Result<(), UnixControlError>
where
    W: AsyncWrite + Unpin,
{
    let body = encode_client_request(request)?;
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

pub(crate) async fn read_client_response<R>(
    reader: &mut R,
) -> Result<ClientResponse, UnixControlError>
where
    R: AsyncRead + Unpin,
{
    let body = read_frame(reader).await?;
    Ok(decode_client_response(&body)?)
}

pub(crate) async fn write_client_response<W>(
    writer: &mut W,
    response: &ClientResponse,
) -> Result<(), UnixControlError>
where
    W: AsyncWrite + Unpin,
{
    let body = encode_client_response(response)?;
    write_frame(writer, &body).await
}

/// Writes a response, replacing an oversized normal payload with a small typed error.
pub(crate) async fn write_bounded_response<W>(
    writer: &mut W,
    response: &ServerResponse,
) -> Result<(), UnixControlError>
where
    W: AsyncWrite + Unpin,
{
    match write_response(writer, response).await {
        Err(UnixControlError::Protocol(ProtocolError::EncodedFrameTooLarge { .. })) => {
            write_response(writer, &response_too_large()).await
        }
        result => result,
    }
}

/// Writes a client response, replacing an oversized snapshot with a small typed error.
pub(crate) async fn write_bounded_client_response<W>(
    writer: &mut W,
    response: &ClientResponse,
) -> Result<(), UnixControlError>
where
    W: AsyncWrite + Unpin,
{
    match write_client_response(writer, response).await {
        Err(UnixControlError::Protocol(ProtocolError::EncodedFrameTooLarge { .. })) => {
            write_client_response(writer, &client_response_too_large()).await
        }
        result => result,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlResponseWrite {
    Written,
    Cancelled,
    TimedOut,
}

/// Writes a bounded response unless managed-server shutdown wins the race.
pub(crate) async fn write_response_until_shutdown<W>(
    writer: &mut W,
    response: &ServerResponse,
    shutdown: &CancellationToken,
) -> Result<ControlResponseWrite, UnixControlError>
where
    W: AsyncWrite + Unpin,
{
    tokio::select! {
        _ = shutdown.cancelled() => Ok(ControlResponseWrite::Cancelled),
        result = write_bounded_response(writer, response) => result.map(|()| ControlResponseWrite::Written),
    }
}

/// Writes a bounded client response unless managed-client shutdown wins the race.
pub(crate) async fn write_client_response_until_shutdown<W>(
    writer: &mut W,
    response: &ClientResponse,
    shutdown: &CancellationToken,
) -> Result<ControlResponseWrite, UnixControlError>
where
    W: AsyncWrite + Unpin,
{
    tokio::select! {
        _ = shutdown.cancelled() => Ok(ControlResponseWrite::Cancelled),
        result = write_bounded_client_response(writer, response) => result.map(|()| ControlResponseWrite::Written),
    }
}

/// Writes a bounded response with a finite deadline for the shutdown acknowledgement path.
pub(crate) async fn write_response_with_deadline<W>(
    writer: &mut W,
    response: &ServerResponse,
    deadline: Duration,
) -> Result<ControlResponseWrite, UnixControlError>
where
    W: AsyncWrite + Unpin,
{
    match timeout(deadline, write_bounded_response(writer, response)).await {
        Ok(result) => result.map(|()| ControlResponseWrite::Written),
        Err(_) => Ok(ControlResponseWrite::TimedOut),
    }
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
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(UnixControlError::Protocol(
            ProtocolError::EncodedFrameTooLarge { length: body.len() },
        ));
    }
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

fn response_too_large() -> ServerResponse {
    ServerResponse::Error(super::protocol::ServerError::new(
        "response_too_large",
        "The requested response exceeds the 64 KiB control-plane frame limit.",
        "Narrow or page the query before retrying. If this command may have changed server state, inspect state before retrying.",
    ))
}

fn client_response_too_large() -> ClientResponse {
    ClientResponse::Error(ClientError::new(
        "response_too_large",
        "The requested client snapshot exceeds the 64 KiB control-plane frame limit.",
        "Restart the local client service and retry the read-only snapshot request.",
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
        time::Duration,
    };

    use tokio::{
        io::{AsyncWrite, AsyncWriteExt},
        net::UnixStream,
        sync::Notify,
    };
    use tokio_util::sync::CancellationToken;

    use super::{
        ControlResponseWrite, UnixControlError, read_request, write_response_until_shutdown,
    };
    use crate::ipc::protocol::{MAX_FRAME_BYTES, ProtocolError, ServerResponse};

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

    #[tokio::test]
    async fn a_stalled_response_write_is_cancelled_when_the_server_shuts_down() {
        let started = Arc::new(Notify::new());
        let cancellation = CancellationToken::new();
        let mut writer = StalledWriter {
            started: Arc::clone(&started),
        };
        let response = ServerResponse::Shutdown;
        let writer_cancellation = cancellation.clone();
        let response_write = tokio::spawn(async move {
            write_response_until_shutdown(&mut writer, &response, &writer_cancellation).await
        });

        started.notified().await;
        cancellation.cancel();
        let result = tokio::time::timeout(Duration::from_secs(1), response_write)
            .await
            .expect("a cancelled response write must not block shutdown")
            .unwrap()
            .unwrap();
        assert_eq!(result, ControlResponseWrite::Cancelled);
    }

    struct StalledWriter {
        started: Arc<Notify>,
    }

    impl AsyncWrite for StalledWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.started.notify_one();
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
}
