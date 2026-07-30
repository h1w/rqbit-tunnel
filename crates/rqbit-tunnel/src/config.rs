use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::{
    ffi::{CString, OsStr, OsString},
    fs::File,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
};

#[cfg(windows)]
use crate::ipc::windows::validate_desktop_owner_sid;

use thiserror::Error;
use uuid::Uuid;

use crate::{
    model::{ClientConfig, ClientConfigError, ClientStatusOwner, EnrollmentBundle},
    paths::ClientPaths,
};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(transparent)]
    Validation(#[from] ClientConfigError),
    #[error("client {kind} file {path} is missing")]
    MissingFile { kind: &'static str, path: PathBuf },
    #[error("failed to inspect client {kind} file {path}: {source}")]
    InspectFile {
        kind: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("client {kind} path {path} is not a regular file")]
    NotRegularFile { kind: &'static str, path: PathBuf },
    #[error("failed to create client directory {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to inspect client directory {path}: {source}")]
    InspectDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("client directory {path} is not a real directory")]
    UnsafeDirectory { path: PathBuf },

    #[cfg(any(unix, windows))]
    #[error("failed to protect client directory {path}: {source}")]
    ProtectDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[cfg(windows)]
    #[error("client directory {path} is not owned and ACL-protected by this installation")]
    UntrustedWindowsDirectory { path: PathBuf },

    #[cfg(unix)]
    #[error(
        "client configuration directory {path} must be root-owned and not writable by group or other users (owner {owner}, mode {mode:o})"
    )]
    InsecureConfigDirectory {
        path: PathBuf,
        owner: u32,
        mode: u32,
    },

    #[error("failed to read client {kind} file {path}: {source}")]
    ReadFile {
        kind: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("client configuration file {path} is invalid JSON: {source}")]
    DeserializeConfig {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize client configuration: {0}")]
    SerializeConfig(#[source] serde_json::Error),
    #[error(
        "client private key file {path} must contain exactly 64 hexadecimal characters, got {actual}"
    )]
    InvalidKeyLength { path: PathBuf, actual: usize },
    #[error("client private key file {path} is not valid hexadecimal")]
    InvalidKeyHex { path: PathBuf },
    #[cfg(unix)]
    #[error("client private key file {path} has insecure permissions {mode:o}")]
    InsecureKeyPermissions { path: PathBuf, mode: u32 },
    #[cfg(unix)]
    #[error("client status owner UID {value:?} is invalid")]
    InvalidStatusOwnerUid { value: OsString },
    #[cfg(unix)]
    #[error(
        "client {kind} file {path} must be root-owned with permissions {expected_mode:o} (owner {owner}, mode {mode:o})"
    )]
    InsecureClientFile {
        kind: &'static str,
        path: PathBuf,
        owner: u32,
        mode: u32,
        expected_mode: u32,
    },
    #[cfg(windows)]
    #[error("failed to determine a valid Windows desktop status owner: {source}")]
    WindowsStatusOwner {
        #[source]
        source: io::Error,
    },
    #[error("failed to atomically write client {kind} file {path}: {source}")]
    AtomicWrite {
        kind: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("client private key rollback at {path} completed but directory sync failed: {source}")]
    RollbackPrivateKeyNotDurable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error(
        "client import failed to publish configuration and could not safely complete private-key rollback: {publish}; rollback: {rollback}"
    )]
    ImportRollback {
        publish: Box<ConfigError>,
        rollback: Box<ConfigError>,
    },
    #[error(
        "client import committed but one or more directory sync operations failed; inspect {config_path} and {key_path} before retrying (private key: {key_sync_error:?}; configuration: {config_sync_error:?})"
    )]
    ImportCommittedButUnsynced {
        config_path: PathBuf,
        key_path: PathBuf,
        key_sync_error: Option<io::Error>,
        config_sync_error: Option<io::Error>,
    },
    #[error(
        "client configuration was committed but its directory sync failed; inspect {config_path} before retrying: {source}"
    )]
    ConfigCommittedButUnsynced {
        config_path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Imports a bundle with the desktop identity currently allowed to read status IPC.
pub fn import_bundle_for_current_status_owner(
    paths: &ClientPaths,
    bundle: EnrollmentBundle,
) -> Result<ClientConfig, ConfigError> {
    import_bundle_with_status_owner(paths, bundle, current_client_status_owner()?)
}

pub fn import_bundle(
    paths: &ClientPaths,
    bundle: EnrollmentBundle,
) -> Result<ClientConfig, ConfigError> {
    import_bundle_for_current_status_owner(paths, bundle)
}

fn import_bundle_with_status_owner(
    paths: &ClientPaths,
    bundle: EnrollmentBundle,
    status_owner: ClientStatusOwner,
) -> Result<ClientConfig, ConfigError> {
    let mut config = ClientConfig::from_bundle(paths, &bundle)?;
    config.status_owner = Some(status_owner);
    config.validate()?;

    create_client_directories(paths)?;
    let key_path = paths.client_key_path();
    let previous_private_key = existing_private_key(&key_path)?;
    let key_sync_error = match write_private_key(&key_path, bundle.client_private_key)? {
        AtomicWriteOutcome::Durable => None,
        AtomicWriteOutcome::CommittedButUnsynced(source) => Some(source),
    };
    let config_path = paths.config_path();
    let config_sync_error = match atomic_write_json(&config_path, &config) {
        Ok(AtomicWriteOutcome::Durable) => None,
        Ok(AtomicWriteOutcome::CommittedButUnsynced(source)) => Some(source),
        Err(publish) => {
            return Err(resolve_failed_config_publication(
                &key_path,
                publish,
                restore_private_key(&key_path, previous_private_key),
            ));
        }
    };
    if key_sync_error.is_some() || config_sync_error.is_some() {
        return Err(ConfigError::ImportCommittedButUnsynced {
            config_path,
            key_path,
            key_sync_error,
            config_sync_error,
        });
    }
    Ok(config)
}

#[cfg(unix)]
fn current_client_status_owner() -> Result<ClientStatusOwner, ConfigError> {
    let effective_uid = unsafe { libc::geteuid() as u32 };
    let sudo_uid = if effective_uid == 0 {
        std::env::var_os("SUDO_UID")
    } else {
        None
    };
    unix_status_owner_from_sudo(effective_uid, sudo_uid.as_deref())
}

#[cfg(unix)]
fn unix_status_owner_from_sudo(
    effective_uid: u32,
    sudo_uid: Option<&OsStr>,
) -> Result<ClientStatusOwner, ConfigError> {
    let uid = if effective_uid == 0 {
        match sudo_uid {
            Some(value) => value
                .to_str()
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or_else(|| ConfigError::InvalidStatusOwnerUid {
                    value: value.to_os_string(),
                })?,
            None => effective_uid,
        }
    } else {
        effective_uid
    };
    Ok(ClientStatusOwner::Unix { uid })
}

#[cfg(windows)]
pub(crate) fn current_windows_status_owner_sid() -> Result<String, ConfigError> {
    let sid = match std::env::var_os("RQBIT_TUNNEL_STATUS_OWNER_SID") {
        Some(sid) => sid
            .into_string()
            .map_err(|_| ConfigError::WindowsStatusOwner {
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "desktop status owner SID is not valid Unicode",
                ),
            })?,
        None => current_windows_user_sid().map_err(|source| ConfigError::WindowsStatusOwner {
            source: io::Error::other(source),
        })?,
    };
    validate_desktop_owner_sid(&sid).map_err(|source| ConfigError::WindowsStatusOwner {
        source: io::Error::other(source),
    })?;
    Ok(sid)
}

#[cfg(windows)]
fn current_client_status_owner() -> Result<ClientStatusOwner, ConfigError> {
    Ok(ClientStatusOwner::Windows {
        sid: current_windows_status_owner_sid()?,
    })
}

/// Validates and atomically replaces the protected client configuration.
pub fn write_client_config(paths: &ClientPaths, config: &ClientConfig) -> Result<(), ConfigError> {
    config.validate()?;
    create_client_directories(paths)?;
    match atomic_write_json(&paths.config_path(), config)? {
        AtomicWriteOutcome::Durable => Ok(()),
        AtomicWriteOutcome::CommittedButUnsynced(source) => {
            Err(ConfigError::ConfigCommittedButUnsynced {
                config_path: paths.config_path(),
                source,
            })
        }
    }
}

#[cfg(unix)]
fn verify_unix_config_directory_policy(path: &Path) -> Result<(), ConfigError> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| ConfigError::InspectDirectory {
        path: path.to_path_buf(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.file_type().is_dir()
        || !unix_config_directory_policy_is_secure(metadata.uid(), mode)
    {
        return Err(ConfigError::InsecureConfigDirectory {
            path: path.to_path_buf(),
            owner: metadata.uid(),
            mode,
        });
    }
    Ok(())
}

#[cfg(unix)]
fn verify_unix_root_owned_file(
    path: &Path,
    kind: &'static str,
    metadata: &fs::Metadata,
    expected_mode: u32,
) -> Result<(), ConfigError> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let mode = metadata.permissions().mode() & 0o777;
    if !unix_file_policy_is_secure(metadata.uid(), mode, expected_mode) {
        return Err(ConfigError::InsecureClientFile {
            kind,
            path: path.to_path_buf(),
            owner: metadata.uid(),
            mode,
            expected_mode,
        });
    }
    Ok(())
}

/// Loads and validates the non-secret client configuration.
pub fn load_client_config(paths: &ClientPaths) -> Result<ClientConfig, ConfigError> {
    #[cfg(unix)]
    verify_unix_config_directory_policy(&paths.config_dir)?;
    let path = paths.config_path();
    #[cfg(unix)]
    let metadata = inspect_regular_file(&path, "configuration")?;
    #[cfg(not(unix))]
    inspect_regular_file(&path, "configuration")?;
    #[cfg(unix)]
    verify_unix_root_owned_file(&path, "configuration", &metadata, 0o644)?;
    let bytes = fs::read(&path).map_err(|source| ConfigError::ReadFile {
        kind: "configuration",
        path: path.clone(),
        source,
    })?;
    let config: ClientConfig = serde_json::from_slice(&bytes)
        .map_err(|source| ConfigError::DeserializeConfig { path, source })?;
    config.validate()?;
    Ok(config)
}

/// Reads the separately stored client private key without exposing it in a DTO.
pub fn read_private_key(path: impl AsRef<Path>) -> Result<[u8; 32], ConfigError> {
    let path = path.as_ref();
    let metadata = inspect_regular_file(path, "private key")?;
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(ConfigError::InsecureKeyPermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
        verify_unix_root_owned_file(path, "private key", &metadata, 0o600)?;
    }
    #[cfg(not(unix))]
    let _ = metadata;
    let bytes = fs::read(path).map_err(|source| ConfigError::ReadFile {
        kind: "private key",
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.len() != 64 {
        return Err(ConfigError::InvalidKeyLength {
            path: path.to_path_buf(),
            actual: bytes.len(),
        });
    }
    let encoded = std::str::from_utf8(&bytes).map_err(|_| ConfigError::InvalidKeyHex {
        path: path.to_path_buf(),
    })?;
    let mut key = [0_u8; 32];
    hex::decode_to_slice(encoded, &mut key).map_err(|_| ConfigError::InvalidKeyHex {
        path: path.to_path_buf(),
    })?;
    Ok(key)
}

fn existing_private_key(path: &Path) -> Result<Option<[u8; 32]>, ConfigError> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_private_key(path).map(Some),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ConfigError::InspectFile {
            kind: "private key",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn write_private_key(path: &Path, key: [u8; 32]) -> Result<AtomicWriteOutcome, ConfigError> {
    atomic_write(path, hex::encode(key).as_bytes(), "private key", 0o600)
}

fn restore_private_key(
    path: &Path,
    previous: Option<[u8; 32]>,
) -> Result<AtomicWriteOutcome, ConfigError> {
    match previous {
        Some(key) => write_private_key(path, key),
        None => {
            let removed = match fs::remove_file(path) {
                Ok(()) => true,
                Err(source) if source.kind() == io::ErrorKind::NotFound => false,
                Err(source) => {
                    return Err(ConfigError::AtomicWrite {
                        kind: "private key rollback",
                        path: path.to_path_buf(),
                        source,
                    });
                }
            };
            if !removed {
                return Ok(AtomicWriteOutcome::Durable);
            }
            let parent = path.parent().ok_or_else(|| ConfigError::AtomicWrite {
                kind: "private key rollback",
                path: path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "client private key has no parent directory",
                ),
            })?;
            Ok(match sync_directory(parent) {
                Ok(()) => AtomicWriteOutcome::Durable,
                Err(source) => AtomicWriteOutcome::CommittedButUnsynced(source),
            })
        }
    }
}

fn resolve_failed_config_publication(
    key_path: &Path,
    publish: ConfigError,
    rollback: Result<AtomicWriteOutcome, ConfigError>,
) -> ConfigError {
    match rollback {
        Ok(AtomicWriteOutcome::Durable) => publish,
        Ok(AtomicWriteOutcome::CommittedButUnsynced(source)) => ConfigError::ImportRollback {
            publish: Box::new(publish),
            rollback: Box::new(ConfigError::RollbackPrivateKeyNotDurable {
                path: key_path.to_path_buf(),
                source,
            }),
        },
        Err(rollback) => ConfigError::ImportRollback {
            publish: Box::new(publish),
            rollback: Box::new(rollback),
        },
    }
}

fn atomic_write_json(
    path: &Path,
    config: &ClientConfig,
) -> Result<AtomicWriteOutcome, ConfigError> {
    let encoded = serde_json::to_vec(config).map_err(ConfigError::SerializeConfig)?;
    atomic_write(path, &encoded, "configuration", 0o644)
}

#[cfg(not(windows))]
fn create_directory(path: &Path) -> Result<(), ConfigError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|source| ConfigError::CreateDirectory {
                path: path.to_path_buf(),
                source,
            })?;
            fs::symlink_metadata(path).map_err(|source| ConfigError::InspectDirectory {
                path: path.to_path_buf(),
                source,
            })?
        }
        Err(source) => {
            return Err(ConfigError::InspectDirectory {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    validate_client_directory(path, &metadata)
}

#[cfg(not(windows))]
fn validate_client_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), ConfigError> {
    if !metadata.file_type().is_dir() {
        return Err(ConfigError::UnsafeDirectory {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn unix_config_directory_policy_is_secure(owner: u32, mode: u32) -> bool {
    owner == 0 && mode & 0o022 == 0
}

#[cfg(unix)]
fn unix_file_policy_is_secure(owner: u32, mode: u32, expected_mode: u32) -> bool {
    owner == 0 && mode == expected_mode
}

#[cfg(unix)]
fn protect_unix_config_directory(path: &Path) -> Result<(), ConfigError> {
    create_directory(path)?;
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let path_bytes =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| ConfigError::ProtectDirectory {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "client configuration directory path contains a NUL byte",
            ),
        })?;
    if unsafe { libc::lchown(path_bytes.as_ptr(), 0, u32::MAX) } != 0 {
        return Err(ConfigError::ProtectDirectory {
            path: path.to_path_buf(),
            source: io::Error::last_os_error(),
        });
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|source| {
        ConfigError::ProtectDirectory {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|source| ConfigError::InspectDirectory {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir()
        || !unix_config_directory_policy_is_secure(
            metadata.uid(),
            metadata.permissions().mode() & 0o777,
        )
    {
        return Err(ConfigError::ProtectDirectory {
            path: path.to_path_buf(),
            source: io::Error::other("client configuration directory policy was not applied"),
        });
    }
    Ok(())
}

fn create_client_directories(paths: &ClientPaths) -> Result<(), ConfigError> {
    #[cfg(unix)]
    protect_unix_config_directory(&paths.config_dir)?;
    #[cfg(windows)]
    create_or_verify_windows_directory(&paths.config_dir)?;
    #[cfg(not(any(unix, windows)))]
    create_directory(&paths.config_dir)?;

    for directory in [&paths.data_dir, &paths.run_dir] {
        #[cfg(windows)]
        create_or_verify_windows_directory(directory)?;
        #[cfg(not(windows))]
        create_directory(directory)?;
    }
    Ok(())
}

#[cfg(windows)]
fn current_windows_user_sid() -> Result<String, windows::core::Error> {
    use windows::{
        Win32::{
            Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
            Security::{
                Authorization::ConvertSidToStringSidW, GetTokenInformation, PSID, TOKEN_QUERY,
                TOKEN_USER, TokenUser,
            },
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        },
        core::PWSTR,
    };

    fn sid_to_string(sid: PSID) -> Result<String, windows::core::Error> {
        unsafe {
            let mut text = PWSTR::default();
            ConvertSidToStringSidW(sid, &mut text)?;
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

    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let result = (|| {
            let mut length = 0;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut length);
            if length == 0 {
                return Err(windows::core::Error::from_thread());
            }
            let mut information =
                vec![0_usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
            GetTokenInformation(
                token,
                TokenUser,
                Some(information.as_mut_ptr().cast()),
                length,
                &mut length,
            )?;
            sid_to_string((&*information.as_ptr().cast::<TOKEN_USER>()).User.Sid)
        })();
        let _ = CloseHandle(token);
        result
    }
}

#[cfg(windows)]
fn create_or_verify_windows_directory(path: &Path) -> Result<(), ConfigError> {
    use std::{iter, os::windows::ffi::OsStrExt};

    use windows::{
        Win32::{
            Foundation::{CloseHandle, HLOCAL, LocalFree},
            Security::{
                ACL,
                Authorization::{
                    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                    GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
                },
                DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
                GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
                SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
            },
            Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW,
                FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                FILE_SHARE_WRITE, GetFileInformationByHandle, OPEN_EXISTING, READ_CONTROL,
            },
        },
        core::{PCWSTR, PWSTR},
    };

    fn windows_error(path: &Path, source: windows::core::Error) -> ConfigError {
        ConfigError::ProtectDirectory {
            path: path.to_path_buf(),
            source: io::Error::other(source),
        }
    }

    fn sid_to_string(sid: PSID) -> Result<String, windows::core::Error> {
        unsafe {
            let mut text = PWSTR::default();
            ConvertSidToStringSidW(sid, &mut text)?;
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

    fn security_descriptor(path: &Path) -> Result<PSECURITY_DESCRIPTOR, ConfigError> {
        let text = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        let wide: Vec<u16> = text.encode_utf16().chain(iter::once(0)).collect();
        unsafe {
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
            .map_err(|source| windows_error(path, source))?;
            Ok(descriptor)
        }
    }

    fn same_acl(left: *mut ACL, right: *mut ACL) -> bool {
        if left.is_null() || right.is_null() {
            return false;
        }
        unsafe {
            let left_size = (*left).AclSize as usize;
            let right_size = (*right).AclSize as usize;
            left_size == right_size
                && std::slice::from_raw_parts(left.cast::<u8>(), left_size)
                    == std::slice::from_raw_parts(right.cast::<u8>(), right_size)
        }
    }

    fn descriptor_matches(
        path: &Path,
        actual: PSECURITY_DESCRIPTOR,
        expected: PSECURITY_DESCRIPTOR,
    ) -> Result<bool, ConfigError> {
        unsafe {
            let mut actual_owner = PSID::default();
            let mut actual_owner_defaulted = Default::default();
            GetSecurityDescriptorOwner(actual, &mut actual_owner, &mut actual_owner_defaulted)
                .map_err(|source| windows_error(path, source))?;
            let mut expected_owner = PSID::default();
            let mut expected_owner_defaulted = Default::default();
            GetSecurityDescriptorOwner(
                expected,
                &mut expected_owner,
                &mut expected_owner_defaulted,
            )
            .map_err(|source| windows_error(path, source))?;
            let mut actual_dacl_present = Default::default();
            let mut actual_dacl = std::ptr::null_mut();
            let mut actual_dacl_defaulted = Default::default();
            GetSecurityDescriptorDacl(
                actual,
                &mut actual_dacl_present,
                &mut actual_dacl,
                &mut actual_dacl_defaulted,
            )
            .map_err(|source| windows_error(path, source))?;
            let mut expected_dacl_present = Default::default();
            let mut expected_dacl = std::ptr::null_mut();
            let mut expected_dacl_defaulted = Default::default();
            GetSecurityDescriptorDacl(
                expected,
                &mut expected_dacl_present,
                &mut expected_dacl,
                &mut expected_dacl_defaulted,
            )
            .map_err(|source| windows_error(path, source))?;
            let mut control = 0;
            let mut revision = 0;
            GetSecurityDescriptorControl(actual, &mut control, &mut revision)
                .map_err(|source| windows_error(path, source))?;
            if actual_owner.is_invalid() || expected_owner.is_invalid() {
                return Ok(false);
            }
            Ok(control & SE_DACL_PROTECTED.0 != 0
                && sid_to_string(actual_owner).map_err(|source| windows_error(path, source))?
                    == sid_to_string(expected_owner)
                        .map_err(|source| windows_error(path, source))?
                && same_acl(actual_dacl, expected_dacl))
        }
    }

    fn verify(path: &Path, expected: PSECURITY_DESCRIPTOR) -> Result<(), ConfigError> {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect();
        unsafe {
            let handle = CreateFileW(
                PCWSTR(wide.as_ptr()),
                (FILE_READ_ATTRIBUTES | READ_CONTROL).0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
            .map_err(|source| windows_error(path, source))?;
            let result = (|| {
                let mut information = BY_HANDLE_FILE_INFORMATION::default();
                GetFileInformationByHandle(handle, &mut information)
                    .map_err(|source| windows_error(path, source))?;
                if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
                    || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
                {
                    return Err(ConfigError::UnsafeDirectory {
                        path: path.to_path_buf(),
                    });
                }
                let mut actual = PSECURITY_DESCRIPTOR::default();
                GetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    None,
                    None,
                    Some(&mut actual),
                )
                .ok()
                .map_err(|source| windows_error(path, source))?;
                let result = descriptor_matches(path, actual, expected).and_then(|matches| {
                    if matches {
                        Ok(())
                    } else {
                        Err(ConfigError::UntrustedWindowsDirectory {
                            path: path.to_path_buf(),
                        })
                    }
                });
                let _ = LocalFree(Some(HLOCAL(actual.0)));
                result
            })();
            let _ = CloseHandle(handle);
            result
        }
    }

    let expected = security_descriptor(path)?;
    let result = (|| match fs::symlink_metadata(path) {
        Ok(_) => verify(path, expected),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| ConfigError::CreateDirectory {
                path: path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "client directory has no parent",
                ),
            })?;
            match fs::symlink_metadata(parent) {
                Ok(_) => {}
                Err(source) if source.kind() == io::ErrorKind::NotFound => {
                    create_or_verify_windows_directory(parent)?;
                }
                Err(source) => {
                    return Err(ConfigError::InspectDirectory {
                        path: parent.to_path_buf(),
                        source,
                    });
                }
            }
            let wide: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(iter::once(0))
                .collect();
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: expected.0,
                bInheritHandle: false.into(),
            };
            match unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&attributes)) } {
                Ok(()) => verify(path, expected),
                Err(create_source) => match fs::symlink_metadata(path) {
                    Ok(_) => verify(path, expected),
                    Err(_) => Err(ConfigError::CreateDirectory {
                        path: path.to_path_buf(),
                        source: io::Error::other(create_source),
                    }),
                },
            }
        }
        Err(source) => Err(ConfigError::InspectDirectory {
            path: path.to_path_buf(),
            source,
        }),
    })();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(expected.0)));
    }
    result
}

fn inspect_regular_file(path: &Path, kind: &'static str) -> Result<fs::Metadata, ConfigError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            ConfigError::MissingFile {
                kind,
                path: path.to_path_buf(),
            }
        } else {
            ConfigError::InspectFile {
                kind,
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(ConfigError::NotRegularFile {
            kind,
            path: path.to_path_buf(),
        });
    }
    Ok(metadata)
}

fn inspect_replacement_target(path: &Path, kind: &'static str) -> Result<(), ConfigError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(ConfigError::NotRegularFile {
            kind,
            path: path.to_path_buf(),
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ConfigError::InspectFile {
            kind,
            path: path.to_path_buf(),
            source,
        }),
    }
}

enum AtomicWriteOutcome {
    Durable,
    CommittedButUnsynced(io::Error),
}

fn atomic_write(
    path: &Path,
    bytes: &[u8],
    kind: &'static str,
    mode: u32,
) -> Result<AtomicWriteOutcome, ConfigError> {
    inspect_replacement_target(path, kind)?;
    let parent = path.parent().ok_or_else(|| ConfigError::AtomicWrite {
        kind,
        path: path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "client artifact has no parent directory",
        ),
    })?;
    let filename = path.file_name().ok_or_else(|| ConfigError::AtomicWrite {
        kind,
        path: path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "client artifact has no file name",
        ),
    })?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        filename.to_string_lossy(),
        Uuid::new_v4()
    ));

    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(mode);
        #[cfg(not(unix))]
        let _ = mode;
        let mut file = options
            .open(&temporary)
            .map_err(|source| ConfigError::AtomicWrite {
                kind,
                path: path.to_path_buf(),
                source,
            })?;
        #[cfg(unix)]
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|source| ConfigError::AtomicWrite {
                kind,
                path: path.to_path_buf(),
                source,
            })?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| ConfigError::AtomicWrite {
                kind,
                path: path.to_path_buf(),
                source,
            })?;
        replace_file(&temporary, path).map_err(|source| ConfigError::AtomicWrite {
            kind,
            path: path.to_path_buf(),
            source,
        })?;
        Ok(match sync_directory(parent) {
            Ok(()) => AtomicWriteOutcome::Durable,
            Err(source) => AtomicWriteOutcome::CommittedButUnsynced(source),
        })
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(not(windows))]
fn replace_file(temporary: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temporary, path)
}

#[cfg(windows)]
fn replace_file(temporary: &Path, path: &Path) -> io::Result<()> {
    use std::{iter, os::windows::ffi::OsStrExt};

    use windows::{
        Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        },
        core::PCWSTR,
    };

    let temporary_wide: Vec<u16> = temporary
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    unsafe {
        MoveFileExW(
            PCWSTR(temporary_wide.as_ptr()),
            PCWSTR(path_wide.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
        .map_err(io::Error::other)
    }
}

#[cfg(unix)]
fn sync_directory(parent: &Path) -> io::Result<()> {
    File::open(parent).and_then(|directory| directory.sync_all())
}

#[cfg(not(unix))]
fn sync_directory(_parent: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::{
        ffi::OsStr,
        os::unix::fs::{PermissionsExt, symlink},
    };
    use std::{fs, io, path::Path};

    use crate::{
        config::{
            AtomicWriteOutcome, ConfigError, import_bundle, load_client_config, read_private_key,
            resolve_failed_config_publication,
        },
        model::{BUNDLE_SCHEMA_VERSION, EnrollmentBundle},
        paths::ClientPaths,
    };
    #[cfg(unix)]
    use crate::{
        config::{
            import_bundle_with_status_owner, unix_config_directory_policy_is_secure,
            unix_file_policy_is_secure, unix_status_owner_from_sudo, write_client_config,
        },
        model::ClientStatusOwner,
    };

    #[test]
    fn imported_bundle_writes_private_key_outside_json_config() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        import_bundle(&paths, sample_bundle()).unwrap();

        let config = load_client_config(&paths).unwrap();
        assert_eq!(config.client_key_path, paths.client_key_path());
        assert_eq!(read_private_key(&config.client_key_path).unwrap(), [7; 32]);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&config.client_key_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(
            !fs::read_to_string(paths.config_path())
                .unwrap()
                .contains("070707")
        );
    }

    #[cfg(unix)]
    #[test]
    fn import_persists_sudo_selected_status_owner_without_exposing_key_material() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());

        let config = import_bundle_with_status_owner(
            &paths,
            sample_bundle(),
            ClientStatusOwner::Unix { uid: 42_424 },
        )
        .unwrap();
        let config_metadata = fs::metadata(paths.config_path()).unwrap();

        assert_eq!(
            config.status_owner,
            Some(ClientStatusOwner::Unix { uid: 42_424 })
        );
        assert_eq!(
            load_client_config(&paths).unwrap().status_owner,
            Some(ClientStatusOwner::Unix { uid: 42_424 })
        );
        assert_eq!(config_metadata.permissions().mode() & 0o777, 0o644);
        assert!(
            !fs::read_to_string(paths.config_path())
                .unwrap()
                .contains("070707")
        );
    }

    #[cfg(unix)]
    #[test]
    fn status_owner_uid_uses_sudo_uid_only_for_elevated_imports() {
        assert_eq!(
            unix_status_owner_from_sudo(0, Some(OsStr::new("42424"))).unwrap(),
            ClientStatusOwner::Unix { uid: 42_424 }
        );
        assert_eq!(
            unix_status_owner_from_sudo(0, None).unwrap(),
            ClientStatusOwner::Unix { uid: 0 }
        );
        assert_eq!(
            unix_status_owner_from_sudo(1_000, Some(OsStr::new("42424"))).unwrap(),
            ClientStatusOwner::Unix { uid: 1_000 }
        );
        assert!(unix_status_owner_from_sudo(0, Some(OsStr::new("not-a-uid"))).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn protected_unix_artifacts_require_root_ownership_and_no_user_write_access() {
        assert!(unix_config_directory_policy_is_secure(0, 0o755));
        assert!(!unix_config_directory_policy_is_secure(1_000, 0o755));
        assert!(!unix_config_directory_policy_is_secure(0, 0o775));
        assert!(unix_file_policy_is_secure(0, 0o644, 0o644));
        assert!(unix_file_policy_is_secure(0, 0o600, 0o600));
        assert!(!unix_file_policy_is_secure(1_000, 0o644, 0o644));
        assert!(!unix_file_policy_is_secure(0, 0o666, 0o644));
    }

    #[cfg(unix)]
    #[test]
    fn config_replacement_preserves_imported_status_owner() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        let mut config = import_bundle_with_status_owner(
            &paths,
            sample_bundle(),
            ClientStatusOwner::Unix { uid: 42_424 },
        )
        .unwrap();

        config.carriers = 5;
        write_client_config(&paths, &config).unwrap();

        assert_eq!(
            load_client_config(&paths).unwrap().status_owner,
            Some(ClientStatusOwner::Unix { uid: 42_424 })
        );
    }

    #[test]
    fn rejected_bundle_does_not_create_client_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        let mut bundle = sample_bundle();
        bundle.schema_version = BUNDLE_SCHEMA_VERSION + 1;

        assert!(import_bundle(&paths, bundle).is_err());
        assert!(!paths.config_path().exists());
        assert!(!paths.client_key_path().exists());
    }

    #[test]
    fn reimport_replaces_both_client_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        import_bundle(&paths, sample_bundle()).unwrap();
        let mut replacement = sample_bundle();
        replacement.client_private_key = [9; 32];
        replacement.server_public_key = [10; 32];

        import_bundle(&paths, replacement).unwrap();

        let config = load_client_config(&paths).unwrap();
        assert_eq!(config.server_public_key, [10; 32]);
        assert_eq!(read_private_key(config.client_key_path).unwrap(), [9; 32]);
    }

    #[cfg(unix)]
    #[test]
    fn private_key_reader_rejects_group_or_world_access() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        import_bundle(&paths, sample_bundle()).unwrap();
        fs::set_permissions(paths.client_key_path(), fs::Permissions::from_mode(0o640)).unwrap();

        assert!(matches!(
            read_private_key(paths.client_key_path()),
            Err(ConfigError::InsecureKeyPermissions { .. })
        ));
    }

    #[test]
    fn failed_config_publication_restores_the_previous_private_key() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        import_bundle(&paths, sample_bundle()).unwrap();
        fs::remove_file(paths.config_path()).unwrap();
        fs::create_dir(paths.config_path()).unwrap();
        let mut replacement = sample_bundle();
        replacement.client_private_key = [9; 32];

        assert!(import_bundle(&paths, replacement).is_err());
        assert_eq!(read_private_key(paths.client_key_path()).unwrap(), [7; 32]);
    }

    #[cfg(unix)]
    #[test]
    fn import_rejects_a_symlinked_client_configuration_directory() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        let target = directory.path().join("untrusted");
        fs::create_dir(&target).unwrap();
        fs::create_dir_all(paths.config_dir.parent().unwrap()).unwrap();
        symlink(&target, &paths.config_dir).unwrap();

        assert!(matches!(
            import_bundle(&paths, sample_bundle()),
            Err(ConfigError::UnsafeDirectory { path }) if path == paths.config_dir
        ));
        assert!(!target.join("client.key").exists());
    }

    #[cfg(unix)]
    #[test]
    fn import_rejects_a_symlinked_client_configuration_file() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        let target = directory.path().join("untrusted-config");
        fs::create_dir_all(&paths.config_dir).unwrap();
        fs::write(&target, "untrusted").unwrap();
        symlink(&target, paths.config_path()).unwrap();

        assert!(matches!(
            import_bundle(&paths, sample_bundle()),
            Err(ConfigError::NotRegularFile {
                kind: "configuration",
                ..
            })
        ));
        assert_eq!(fs::read_to_string(target).unwrap(), "untrusted");
        assert!(!paths.client_key_path().exists());
    }

    #[test]
    fn unsynced_private_key_rollback_is_not_reported_as_an_ordinary_publish_failure() {
        let publish = ConfigError::AtomicWrite {
            kind: "configuration",
            path: "client.json".into(),
            source: io::Error::other("write failed"),
        };

        let error = resolve_failed_config_publication(
            Path::new("client.key"),
            publish,
            Ok(AtomicWriteOutcome::CommittedButUnsynced(io::Error::other(
                "directory sync failed",
            ))),
        );

        assert!(matches!(error, ConfigError::ImportRollback { .. }));
    }

    fn sample_bundle() -> EnrollmentBundle {
        EnrollmentBundle {
            schema_version: BUNDLE_SCHEMA_VERSION,
            user_name: "alice".to_owned(),
            client_private_key: [7; 32],
            server_public_key: [8; 32],
            server_addr: "203.0.113.8:4242".parse().unwrap(),
            socks_listen: "127.0.0.1:1080".parse().unwrap(),
            carriers: 4,
        }
    }
}
