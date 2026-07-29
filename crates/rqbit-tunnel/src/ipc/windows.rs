#![cfg(windows)]

use std::{ffi::c_void, io, iter};

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions},
};
use tokio_util::sync::CancellationToken;
use windows::{
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                ConvertStringSidToSidW, SDDL_REVISION_1,
            },
            LookupAccountSidW, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SID_NAME_USE,
            SidTypeUser,
        },
    },
    core::{PCWSTR, PWSTR},
};

use super::protocol::{
    ClientError, ClientRequest, ClientResponse, MAX_FRAME_BYTES, ProtocolError,
    decode_client_request, decode_client_response, encode_client_request, encode_client_response,
};

const PIPE_PREFIX: &str = r"\\.\pipe\rqbit-tunnel-client-";

#[derive(Debug, Error)]
pub enum WindowsClientControlError {
    #[error("protected client configuration does not identify a usable desktop owner")]
    DesktopOwnerUnavailable,
    #[error("failed to build the client control pipe security descriptor: {source}")]
    SecurityDescriptor {
        #[source]
        source: io::Error,
    },
    #[error("failed to create or connect client control pipe {pipe}: {source}")]
    Pipe {
        pipe: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to read client control pipe frame: {0}")]
    Read(#[source] io::Error),
    #[error("failed to write client control pipe frame: {0}")]
    Write(#[source] io::Error),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

/// Formats the pipe name for a syntactically valid SID.
///
/// Pipe creation separately requires `LookupAccountSidW` to identify that SID
/// as a desktop user before granting it access.
pub fn client_pipe_name(owner_sid: &str) -> Result<String, WindowsClientControlError> {
    validate_sid_text(owner_sid)?;
    Ok(format!("{PIPE_PREFIX}{owner_sid}"))
}

/// Accepts one client connection at a time using a fresh, ACL-protected pipe
/// instance. A fresh instance keeps its security descriptor lifetime bounded to
/// the CreateNamedPipe call.
pub struct WindowsClientControlListener {
    pipe_name: String,
    owner_sid: String,
    initial_pipe: Option<NamedPipeServer>,
}

impl WindowsClientControlListener {
    pub fn bind(owner_sid: &str) -> Result<Self, WindowsClientControlError> {
        validate_desktop_owner_sid(owner_sid)?;
        let pipe_name = client_pipe_name(owner_sid)?;
        let initial_pipe = create_pipe(&pipe_name, owner_sid, true)?;
        Ok(Self {
            pipe_name,
            owner_sid: owner_sid.to_owned(),
            initial_pipe: Some(initial_pipe),
        })
    }

    pub async fn accept(&mut self) -> Result<NamedPipeServer, WindowsClientControlError> {
        let pipe = match self.initial_pipe.take() {
            Some(pipe) => pipe,
            None => create_pipe(&self.pipe_name, &self.owner_sid, false)?,
        };
        pipe.connect()
            .await
            .map_err(|source| WindowsClientControlError::Pipe {
                pipe: self.pipe_name.clone(),
                source,
            })?;
        Ok(pipe)
    }
}

fn create_pipe(
    pipe_name: &str,
    owner_sid: &str,
    first_instance: bool,
) -> Result<NamedPipeServer, WindowsClientControlError> {
    let pipe = {
        let mut descriptor = PipeSecurityDescriptor::new(owner_sid)?;
        let mut attributes = descriptor.attributes();
        let mut options = ServerOptions::new();
        options
            .access_inbound(true)
            .access_outbound(true)
            .first_pipe_instance(first_instance)
            .reject_remote_clients(true);
        unsafe {
            options.create_with_security_attributes_raw(
                pipe_name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
        }
        .map_err(|source| WindowsClientControlError::Pipe {
            pipe: pipe_name.to_owned(),
            source,
        })?
    };
    Ok(pipe)
}

/// A bounded read-only client for the local managed-client named pipe.
pub struct WindowsClientControlClient {
    stream: NamedPipeClient,
}

impl WindowsClientControlClient {
    pub fn connect(owner_sid: &str) -> Result<Self, WindowsClientControlError> {
        let pipe = client_pipe_name(owner_sid)?;
        let stream =
            ClientOptions::new()
                .open(&pipe)
                .map_err(|source| WindowsClientControlError::Pipe {
                    pipe: pipe.clone(),
                    source,
                })?;
        Ok(Self { stream })
    }

    pub async fn request(
        &mut self,
        request: ClientRequest,
    ) -> Result<ClientResponse, WindowsClientControlError> {
        write_client_request(&mut self.stream, &request).await?;
        read_client_response(&mut self.stream).await
    }
}

pub(crate) async fn read_client_request<R>(
    reader: &mut R,
) -> Result<ClientRequest, WindowsClientControlError>
where
    R: AsyncRead + Unpin,
{
    let body = read_frame(reader).await?;
    Ok(decode_client_request(&body)?)
}

pub(crate) async fn write_client_request<W>(
    writer: &mut W,
    request: &ClientRequest,
) -> Result<(), WindowsClientControlError>
where
    W: AsyncWrite + Unpin,
{
    let body = encode_client_request(request)?;
    write_frame(writer, &body).await
}

pub(crate) async fn read_client_response<R>(
    reader: &mut R,
) -> Result<ClientResponse, WindowsClientControlError>
where
    R: AsyncRead + Unpin,
{
    let body = read_frame(reader).await?;
    Ok(decode_client_response(&body)?)
}

pub(crate) async fn write_client_response<W>(
    writer: &mut W,
    response: &ClientResponse,
) -> Result<(), WindowsClientControlError>
where
    W: AsyncWrite + Unpin,
{
    let body = encode_client_response(response)?;
    write_frame(writer, &body).await
}

pub(crate) async fn write_bounded_client_response<W>(
    writer: &mut W,
    response: &ClientResponse,
) -> Result<(), WindowsClientControlError>
where
    W: AsyncWrite + Unpin,
{
    match write_client_response(writer, response).await {
        Err(WindowsClientControlError::Protocol(ProtocolError::EncodedFrameTooLarge {
            ..
        })) => write_client_response(writer, &client_response_too_large()).await,
        result => result,
    }
}

pub(crate) async fn write_client_response_until_shutdown<W>(
    writer: &mut W,
    response: &ClientResponse,
    shutdown: &CancellationToken,
) -> Result<(), WindowsClientControlError>
where
    W: AsyncWrite + Unpin,
{
    tokio::select! {
        _ = shutdown.cancelled() => Ok(()),
        result = write_bounded_client_response(writer, response) => result,
    }
}

fn client_pipe_sddl(owner_sid: &str) -> Result<String, WindowsClientControlError> {
    validate_sid_text(owner_sid)?;
    Ok(format!(
        "O:{owner_sid}D:P(A;;GRGW;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;{owner_sid})"
    ))
}

pub(crate) fn validate_desktop_owner_sid(owner_sid: &str) -> Result<(), WindowsClientControlError> {
    desktop_owner_sid_from_string(owner_sid).map(|_| ())
}

fn desktop_owner_sid_from_string(owner_sid: &str) -> Result<String, WindowsClientControlError> {
    validate_sid_text(owner_sid)?;
    let wide: Vec<u16> = owner_sid.encode_utf16().chain(iter::once(0)).collect();
    unsafe {
        let mut sid = PSID::default();
        ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut sid)
            .map_err(|_| WindowsClientControlError::DesktopOwnerUnavailable)?;
        let result = desktop_owner_sid_from_raw(sid);
        let _ = LocalFree(Some(HLOCAL(sid.0)));
        result
    }
}

fn desktop_owner_sid_from_raw(sid: PSID) -> Result<String, WindowsClientControlError> {
    if sid.is_invalid() {
        return Err(WindowsClientControlError::DesktopOwnerUnavailable);
    }
    require_desktop_user_sid(sid)?;
    let owner_sid = sid_to_string(sid)?;
    validate_sid_text(&owner_sid)?;
    Ok(owner_sid)
}

fn require_desktop_user_sid(sid: PSID) -> Result<(), WindowsClientControlError> {
    const ACCOUNT_NAME_CAPACITY: usize = 256;
    const DOMAIN_NAME_CAPACITY: usize = 256;

    let mut account_name = [0_u16; ACCOUNT_NAME_CAPACITY];
    let mut account_name_length = ACCOUNT_NAME_CAPACITY as u32;
    let mut domain_name = [0_u16; DOMAIN_NAME_CAPACITY];
    let mut domain_name_length = DOMAIN_NAME_CAPACITY as u32;
    let mut sid_type = SID_NAME_USE::default();
    unsafe {
        LookupAccountSidW(
            PCWSTR(std::ptr::null()),
            sid,
            Some(PWSTR(account_name.as_mut_ptr())),
            &mut account_name_length,
            Some(PWSTR(domain_name.as_mut_ptr())),
            &mut domain_name_length,
            &mut sid_type,
        )
        .map_err(|_| WindowsClientControlError::DesktopOwnerUnavailable)?;
    }
    if sid_type != SidTypeUser || domain_name_length as usize > DOMAIN_NAME_CAPACITY {
        return Err(WindowsClientControlError::DesktopOwnerUnavailable);
    }
    let domain_name = String::from_utf16_lossy(&domain_name[..domain_name_length as usize]);
    let service_or_builtin_domain = ["NT AUTHORITY", "NT SERVICE", "BUILTIN"]
        .iter()
        .any(|rejected| domain_name.eq_ignore_ascii_case(rejected));
    if service_or_builtin_domain {
        return Err(WindowsClientControlError::DesktopOwnerUnavailable);
    }
    Ok(())
}

fn validate_sid_text(owner_sid: &str) -> Result<(), WindowsClientControlError> {
    let syntactically_valid = owner_sid.starts_with("S-1-")
        && owner_sid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    if syntactically_valid {
        Ok(())
    } else {
        Err(WindowsClientControlError::DesktopOwnerUnavailable)
    }
}

fn sid_to_string(sid: PSID) -> Result<String, WindowsClientControlError> {
    unsafe {
        let mut text = PWSTR::default();
        ConvertSidToStringSidW(sid, &mut text).map_err(|source| {
            WindowsClientControlError::SecurityDescriptor {
                source: io::Error::other(source),
            }
        })?;
        let result = (|| {
            let mut length = 0;
            while *text.0.add(length) != 0 {
                length += 1;
            }
            Ok(String::from_utf16_lossy(std::slice::from_raw_parts(
                text.0, length,
            )))
        })();
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        result
    }
}

struct PipeSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl PipeSecurityDescriptor {
    fn new(owner_sid: &str) -> Result<Self, WindowsClientControlError> {
        let text = client_pipe_sddl(owner_sid)?;
        let wide: Vec<u16> = text.encode_utf16().chain(iter::once(0)).collect();
        unsafe {
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
            .map_err(|source| WindowsClientControlError::SecurityDescriptor {
                source: io::Error::other(source),
            })?;
            Ok(Self(descriptor))
        }
    }

    fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: false.into(),
        }
    }
}

impl Drop for PipeSecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

async fn read_frame<R>(reader: &mut R) -> Result<Vec<u8>, WindowsClientControlError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    reader
        .read_exact(&mut header)
        .await
        .map_err(WindowsClientControlError::Read)?;
    let length = u32::from_be_bytes(header);
    if length == 0 || length as usize > MAX_FRAME_BYTES {
        return Err(ProtocolError::InvalidFrameLength { length }.into());
    }

    let mut body = vec![0_u8; length as usize];
    reader
        .read_exact(&mut body)
        .await
        .map_err(WindowsClientControlError::Read)?;
    Ok(body)
}

async fn write_frame<W>(writer: &mut W, body: &[u8]) -> Result<(), WindowsClientControlError>
where
    W: AsyncWrite + Unpin,
{
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(WindowsClientControlError::Protocol(
            ProtocolError::EncodedFrameTooLarge { length: body.len() },
        ));
    }
    let length = u32::try_from(body.len()).map_err(|_| {
        WindowsClientControlError::Protocol(ProtocolError::EncodedFrameTooLarge {
            length: body.len(),
        })
    })?;
    writer
        .write_all(&length.to_be_bytes())
        .await
        .map_err(WindowsClientControlError::Write)?;
    writer
        .write_all(body)
        .await
        .map_err(WindowsClientControlError::Write)
}

fn client_response_too_large() -> ClientResponse {
    ClientResponse::Error(ClientError::new(
        "response_too_large",
        "The requested client snapshot exceeds the 64 KiB control-plane frame limit.",
        "Restart the local client service and retry the read-only snapshot request.",
    ))
}

#[cfg(all(test, windows))]
mod tests {
    use super::{client_pipe_name, client_pipe_sddl, desktop_owner_sid_from_string};

    const OWNER_SID: &str = "S-1-5-21-123456789-234567890-345678901-1001";

    #[test]
    fn client_pipe_name_is_scoped_to_the_desktop_owner_sid() {
        assert_eq!(
            client_pipe_name(OWNER_SID).unwrap(),
            r"\\.\pipe\rqbit-tunnel-client-S-1-5-21-123456789-234567890-345678901-1001"
        );
    }

    #[test]
    fn client_pipe_security_grants_read_write_only_to_system_administrators_and_owner() {
        let descriptor = client_pipe_sddl(OWNER_SID).unwrap();

        assert!(descriptor.starts_with(&format!("O:{OWNER_SID}D:P")));
        assert!(descriptor.contains("(A;;GRGW;;;SY)"));
        assert!(descriptor.contains("(A;;GRGW;;;BA)"));
        assert!(descriptor.contains(&format!("(A;;GRGW;;;{OWNER_SID})")));
        assert!(!descriptor.contains(";;;WD"));
    }

    #[test]
    fn client_pipe_rejects_system_group_and_service_sids_as_desktop_owners() {
        for sid in ["S-1-5-18", "S-1-5-32-545", "S-1-5-80-0"] {
            assert!(
                desktop_owner_sid_from_string(sid).is_err(),
                "{sid} must be rejected"
            );
        }
    }
}
