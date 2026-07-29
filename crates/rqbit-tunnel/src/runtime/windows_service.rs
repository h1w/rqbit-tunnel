#![cfg(windows)]

use std::{ffi::OsStr, iter, os::windows::ffi::OsStrExt, path::PathBuf};

use thiserror::Error;
use uuid::Uuid;
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{
            EVENT_MODIFY_STATE, INFINITE, OpenEventW, SYNCHRONIZATION_ACCESS_RIGHTS,
            SYNCHRONIZATION_SYNCHRONIZE, SetEvent, WaitForSingleObject,
        },
    },
    core::PCWSTR,
};

use crate::{
    paths::ClientPaths,
    runtime::client::{ClientRuntimeError, ManagedClient},
};

const EVENT_NAME_PREFIX: &str = "Local\\rqbit-tunnel-launcher-";

/// Errors raised by the versioned, non-SCM payload worker.
#[derive(Debug, Error)]
pub enum WindowsClientPayloadError {
    #[error("payload host must use system client configuration {expected}, not {actual}")]
    UnexpectedConfigPath { expected: PathBuf, actual: PathBuf },
    #[error("payload host received an invalid launcher event contract")]
    InvalidLauncherEvents,
    #[error("failed to open launcher {kind} event {name}: {source}")]
    OpenEvent {
        kind: &'static str,
        name: String,
        #[source]
        source: windows::core::Error,
    },
    #[error("failed to signal launcher worker readiness: {source}")]
    SignalReady {
        #[source]
        source: windows::core::Error,
    },
    #[error("failed while waiting for launcher stop event: {source}")]
    WaitStop {
        #[source]
        source: windows::core::Error,
    },
    #[error("Windows returned unexpected stop-event wait result {result}")]
    UnexpectedWait { result: u32 },
    #[error("launcher stop-event wait task failed: {source}")]
    WaitTask {
        #[source]
        source: tokio::task::JoinError,
    },
    #[error(transparent)]
    Client(#[from] ClientRuntimeError),
}

/// Starts the managed-client runtime in the payload process. It intentionally
/// never enters `service_dispatcher`: that belongs exclusively to the stable
/// launcher process registered with SCM.
pub async fn run_client_payload_host(
    config_path: PathBuf,
    ready_event_name: String,
    stop_event_name: String,
) -> Result<(), WindowsClientPayloadError> {
    validate_launcher_events(&ready_event_name, &stop_event_name)?;

    let paths = ClientPaths::system();
    let expected_config_path = paths.config_path();
    if config_path != expected_config_path {
        return Err(WindowsClientPayloadError::UnexpectedConfigPath {
            expected: expected_config_path,
            actual: config_path,
        });
    }

    let ready = OwnedEvent::open(&ready_event_name, EVENT_MODIFY_STATE, "readiness")?;
    let stop = OwnedEvent::open(&stop_event_name, SYNCHRONIZATION_SYNCHRONIZE, "stop")?;
    let client = ManagedClient::start(paths).await?;

    let wait_result = wait_for_launcher_stop(&ready, &stop).await;
    let shutdown_result = client.shutdown().await;
    match wait_result {
        Err(error) => Err(error),
        Ok(()) => shutdown_result.map_err(WindowsClientPayloadError::from),
    }
}

async fn wait_for_launcher_stop(
    ready: &OwnedEvent,
    stop: &OwnedEvent,
) -> Result<(), WindowsClientPayloadError> {
    if event_is_signaled(stop.raw())? {
        return Ok(());
    }
    ready.signal()?;

    // A Win32 event has no async handle wrapper. Wait in Tokio's blocking pool
    // after startup so the worker can still await ManagedClient::shutdown.
    let stop_handle = stop.raw().0 as usize;
    tokio::task::spawn_blocking(move || wait_for_stop(HANDLE(stop_handle as *mut _)))
        .await
        .map_err(|source| WindowsClientPayloadError::WaitTask { source })?
}

fn validate_launcher_events(
    ready_event_name: &str,
    stop_event_name: &str,
) -> Result<(), WindowsClientPayloadError> {
    let Some(ready_id) = event_identifier(ready_event_name, "-ready") else {
        return Err(WindowsClientPayloadError::InvalidLauncherEvents);
    };
    let Some(stop_id) = event_identifier(stop_event_name, "-stop") else {
        return Err(WindowsClientPayloadError::InvalidLauncherEvents);
    };
    if ready_id != stop_id {
        return Err(WindowsClientPayloadError::InvalidLauncherEvents);
    }
    Ok(())
}

fn event_identifier<'a>(name: &'a str, suffix: &str) -> Option<&'a str> {
    let id = name.strip_prefix(EVENT_NAME_PREFIX)?.strip_suffix(suffix)?;
    Uuid::parse_str(id).ok()?;
    Some(id)
}

struct OwnedEvent(HANDLE);

impl OwnedEvent {
    fn open(
        name: &str,
        access: SYNCHRONIZATION_ACCESS_RIGHTS,
        kind: &'static str,
    ) -> Result<Self, WindowsClientPayloadError> {
        let wide_name = wide_terminated(name);
        let handle = unsafe {
            OpenEventW(access, false, PCWSTR(wide_name.as_ptr())).map_err(|source| {
                WindowsClientPayloadError::OpenEvent {
                    kind,
                    name: name.to_owned(),
                    source,
                }
            })?
        };
        Ok(Self(handle))
    }

    fn raw(&self) -> HANDLE {
        self.0
    }

    fn signal(&self) -> Result<(), WindowsClientPayloadError> {
        unsafe { SetEvent(self.0) }
            .map_err(|source| WindowsClientPayloadError::SignalReady { source })
    }
}

impl Drop for OwnedEvent {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn event_is_signaled(handle: HANDLE) -> Result<bool, WindowsClientPayloadError> {
    match unsafe { WaitForSingleObject(handle, 0) }.0 {
        result if result == WAIT_OBJECT_0.0 => Ok(true),
        result if result == WAIT_TIMEOUT.0 => Ok(false),
        result if result == WAIT_FAILED.0 => Err(WindowsClientPayloadError::WaitStop {
            source: windows::core::Error::from_thread(),
        }),
        result => Err(WindowsClientPayloadError::UnexpectedWait { result }),
    }
}

fn wait_for_stop(handle: HANDLE) -> Result<(), WindowsClientPayloadError> {
    match unsafe { WaitForSingleObject(handle, INFINITE) }.0 {
        result if result == WAIT_OBJECT_0.0 => Ok(()),
        result if result == WAIT_FAILED.0 => Err(WindowsClientPayloadError::WaitStop {
            source: windows::core::Error::from_thread(),
        }),
        result => Err(WindowsClientPayloadError::UnexpectedWait { result }),
    }
}

fn wide_terminated(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(iter::once(0))
        .collect()
}
