use std::{
    ffi::{OsStr, OsString},
    io,
    path::PathBuf,
};

use thiserror::Error;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(windows)]
pub mod windows;

pub const CLIENT_SERVICE: &str = "rqbit-tunnel-client";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    Running,
    Stopped,
    Starting,
    Stopping,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceInstallSpec {
    /// Absolute path to the executable or launcher registered with the service manager.
    pub executable: PathBuf,
    /// Individual service arguments. These are never interpreted as a shell command.
    pub arguments: Vec<OsString>,
    /// Absolute directory the launcher expects as its working directory.
    pub working_directory: PathBuf,
    pub display_name: String,
}

impl ServiceInstallSpec {
    pub fn validate(&self) -> Result<(), ServiceError> {
        validate_absolute_path("executable", &self.executable)?;
        validate_absolute_path("working_directory", &self.working_directory)?;

        if contains_nul(self.executable.as_os_str()) {
            return Err(ServiceError::EmbeddedNul {
                field: "executable",
            });
        }
        if contains_nul(self.working_directory.as_os_str()) {
            return Err(ServiceError::EmbeddedNul {
                field: "working_directory",
            });
        }
        for argument in &self.arguments {
            if contains_nul(argument) {
                return Err(ServiceError::EmbeddedNul { field: "argument" });
            }
        }
        if self.display_name.is_empty() {
            return Err(ServiceError::EmptyDisplayName);
        }
        if self.display_name.contains('\0') {
            return Err(ServiceError::EmbeddedNul {
                field: "display_name",
            });
        }

        Ok(())
    }
}

pub trait ServiceManager: Send + Sync {
    fn install(&self, spec: &ServiceInstallSpec) -> Result<(), ServiceError>;
    fn start(&self, name: &str) -> Result<ServiceState, ServiceError>;
    fn stop(&self, name: &str) -> Result<ServiceState, ServiceError>;
    fn restart(&self, name: &str) -> Result<ServiceState, ServiceError>;
    fn status(&self, name: &str) -> Result<ServiceState, ServiceError>;
    fn set_autostart(&self, name: &str, enabled: bool) -> Result<(), ServiceError>;
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("service {field} path must be absolute: {path}")]
    RelativePath { field: &'static str, path: PathBuf },
    #[error("service installation {field} contains an embedded NUL")]
    EmbeddedNul { field: &'static str },
    #[error("service display name cannot be empty")]
    EmptyDisplayName,
    #[error("service name cannot be empty")]
    EmptyServiceName,
    #[error("service name contains an embedded NUL")]
    ServiceNameContainsNul,
    #[error("service manager command {operation} could not be run: {source}")]
    CommandIo {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("service manager command {operation} failed: {message}")]
    CommandFailed {
        operation: &'static str,
        message: String,
    },
    #[error("service manager reported a failed state")]
    FailedState,
    #[error("service {name} did not reach {expected:?} before the deadline")]
    TimedOut {
        name: String,
        expected: ServiceState,
    },
    #[error("service manager operation {operation} failed: {source}")]
    Platform {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}

pub(crate) fn validate_service_name(name: &str) -> Result<(), ServiceError> {
    if name.is_empty() {
        return Err(ServiceError::EmptyServiceName);
    }
    if name.contains('\0') {
        return Err(ServiceError::ServiceNameContainsNul);
    }
    Ok(())
}

fn validate_absolute_path(field: &'static str, path: &PathBuf) -> Result<(), ServiceError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(ServiceError::RelativePath {
            field,
            path: path.clone(),
        })
    }
}

fn contains_nul(value: &OsStr) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        return value.as_bytes().contains(&0);
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        return value.encode_wide().any(|code_unit| code_unit == 0);
    }

    #[cfg(not(any(unix, windows)))]
    {
        value.to_string_lossy().contains('\0')
    }
}
