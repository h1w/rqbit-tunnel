use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

use semver::Version;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// ABI implemented by this stable launcher.
pub const LAUNCHER_ABI: u32 = 1;
/// The durable pointer selecting the active immutable release.
pub const ACTIVE_RELEASE_FILE_NAME: &str = "active.json";

const PAYLOAD_EXECUTABLE_NAME: &str = "rqbit-tunnel";
const POINTER_TEMP_ATTEMPTS: usize = 16;

/// Returns the platform-specific suffix of an installed executable.
pub fn current_exe_suffix() -> &'static str {
    if cfg!(windows) { ".exe" } else { "" }
}

/// A validated immutable release selected by the active installation pointer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActiveRelease {
    pub version: Version,
    pub payload_dir: PathBuf,
    pub launcher_abi: u32,
}

impl ActiveRelease {
    /// Creates an active-release record after validating its untrusted path.
    pub fn new(
        version: Version,
        payload_dir: PathBuf,
        launcher_abi: u32,
    ) -> Result<Self, ActiveReleaseError> {
        validate_payload_dir(&payload_dir)?;
        Ok(Self {
            version,
            payload_dir,
            launcher_abi,
        })
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub fn payload_dir(&self) -> &Path {
        &self.payload_dir
    }

    pub fn launcher_abi(&self) -> u32 {
        self.launcher_abi
    }

    /// Resolves this release's main payload without permitting an escape from
    /// the installation root.
    pub fn payload_executable(&self, install_root: &Path) -> Result<PathBuf, ActiveReleaseError> {
        resolve_payload_executable(install_root, &self.payload_dir)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveReleaseDocument {
    version: Version,
    payload_dir: PathBuf,
    launcher_abi: u32,
}

/// Errors raised while validating or durably updating the active-release
/// pointer.
#[derive(Debug, Error)]
pub enum ActiveReleaseError {
    #[error(
        "active release payload directory is not a safe relative path {payload_dir:?}: {reason}"
    )]
    InvalidPayloadDirectory {
        payload_dir: PathBuf,
        reason: &'static str,
    },
    #[error("failed to read active release pointer {path}: {source}")]
    ReadPointer {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("active release pointer {path} is not valid JSON: {source}")]
    DecodePointer {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize active release pointer {path}: {source}")]
    EncodePointer {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to create active release temporary pointer {path}: {source}")]
    CreateTemporaryPointer {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write active release temporary pointer {path}: {source}")]
    WriteTemporaryPointer {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[cfg(unix)]
    #[error("failed to set active release temporary pointer permissions {path}: {source}")]
    SetTemporaryPointerPermissions {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to sync active release temporary pointer {path}: {source}")]
    SyncTemporaryPointer {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not allocate a unique active release temporary pointer in {directory}")]
    TemporaryPointerNameExhausted { directory: PathBuf },
    #[error("failed to atomically replace active release pointer {path}: {source}")]
    ReplacePointer {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to canonicalize installation root {path}: {source}")]
    CanonicalizeInstallRoot {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to canonicalize selected payload executable {path}: {source}")]
    CanonicalizePayloadExecutable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "selected payload executable {payload} resolves outside installation root {install_root}"
    )]
    PayloadEscapesInstallRoot {
        install_root: PathBuf,
        payload: PathBuf,
    },
    #[error("failed to inspect selected payload executable {path}: {source}")]
    InspectPayloadExecutable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("selected payload executable is not a regular file {path}")]
    PayloadNotRegularFile { path: PathBuf },
    #[cfg(unix)]
    #[error("selected payload executable is not executable {path}")]
    PayloadNotExecutable { path: PathBuf },
    #[cfg(unix)]
    #[error(
        "active release pointer {path} was replaced but syncing its directory failed: {source}"
    )]
    SyncPointerDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Reads and validates the durable active-release pointer from an installation
/// root.
pub fn read_active_release(install_root: &Path) -> Result<ActiveRelease, ActiveReleaseError> {
    let pointer_path = active_release_path(install_root);
    let bytes = fs::read(&pointer_path).map_err(|source| ActiveReleaseError::ReadPointer {
        path: pointer_path.clone(),
        source,
    })?;
    let document = serde_json::from_slice::<ActiveReleaseDocument>(&bytes).map_err(|source| {
        ActiveReleaseError::DecodePointer {
            path: pointer_path,
            source,
        }
    })?;

    ActiveRelease::new(
        document.version,
        document.payload_dir,
        document.launcher_abi,
    )
}

/// Atomically replaces the durable active-release pointer. The temporary file
/// is created beside the destination, synced, renamed, and then the directory
/// is synced on Unix so a completed return reflects a durable replacement.
pub fn write_active_release(
    install_root: &Path,
    active_release: &ActiveRelease,
) -> Result<(), ActiveReleaseError> {
    validate_payload_dir(active_release.payload_dir())?;

    let pointer_path = active_release_path(install_root);
    let encoded =
        serde_json::to_vec(active_release).map_err(|source| ActiveReleaseError::EncodePointer {
            path: pointer_path.clone(),
            source,
        })?;
    let (temporary_path, mut temporary_file) = create_temporary_pointer(install_root)?;
    #[cfg(unix)]
    if let Err(source) = temporary_file.set_permissions(fs::Permissions::from_mode(0o644)) {
        drop(temporary_file);
        let _ = fs::remove_file(&temporary_path);
        return Err(ActiveReleaseError::SetTemporaryPointerPermissions {
            path: temporary_path,
            source,
        });
    }

    if let Err(source) = temporary_file.write_all(&encoded) {
        drop(temporary_file);
        let _ = fs::remove_file(&temporary_path);
        return Err(ActiveReleaseError::WriteTemporaryPointer {
            path: temporary_path,
            source,
        });
    }
    if let Err(source) = temporary_file.sync_all() {
        drop(temporary_file);
        let _ = fs::remove_file(&temporary_path);
        return Err(ActiveReleaseError::SyncTemporaryPointer {
            path: temporary_path,
            source,
        });
    }
    drop(temporary_file);

    if let Err(source) = replace_pointer_file(&temporary_path, &pointer_path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(ActiveReleaseError::ReplacePointer {
            path: pointer_path,
            source,
        });
    }

    #[cfg(unix)]
    {
        File::open(install_root)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| ActiveReleaseError::SyncPointerDirectory {
                path: pointer_path,
                source,
            })?;
    }

    Ok(())
}

/// Resolves this release's main payload after requiring an ordinary executable
/// file rooted under the installation directory.
pub fn resolve_payload_executable(
    install_root: &Path,
    payload_dir: &Path,
) -> Result<PathBuf, ActiveReleaseError> {
    validate_payload_dir(payload_dir)?;

    let candidate = install_root
        .join(payload_dir)
        .join(format!("{PAYLOAD_EXECUTABLE_NAME}{}", current_exe_suffix()));
    let metadata = fs::symlink_metadata(&candidate).map_err(|source| {
        ActiveReleaseError::InspectPayloadExecutable {
            path: candidate.clone(),
            source,
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(ActiveReleaseError::PayloadNotRegularFile { path: candidate });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(ActiveReleaseError::PayloadNotExecutable { path: candidate });
        }
    }

    let canonical_install_root = fs::canonicalize(install_root).map_err(|source| {
        ActiveReleaseError::CanonicalizeInstallRoot {
            path: install_root.to_path_buf(),
            source,
        }
    })?;
    let canonical_payload = fs::canonicalize(&candidate).map_err(|source| {
        ActiveReleaseError::CanonicalizePayloadExecutable {
            path: candidate.clone(),
            source,
        }
    })?;
    if !canonical_payload.starts_with(&canonical_install_root) {
        return Err(ActiveReleaseError::PayloadEscapesInstallRoot {
            install_root: canonical_install_root,
            payload: canonical_payload,
        });
    }

    Ok(canonical_payload)
}

fn active_release_path(install_root: &Path) -> PathBuf {
    install_root.join(ACTIVE_RELEASE_FILE_NAME)
}

#[cfg(not(windows))]
fn replace_pointer_file(temporary_path: &Path, pointer_path: &Path) -> io::Result<()> {
    fs::rename(temporary_path, pointer_path)
}

#[cfg(windows)]
fn replace_pointer_file(temporary_path: &Path, pointer_path: &Path) -> io::Result<()> {
    use windows::{
        Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        },
        core::PCWSTR,
    };

    let temporary_path = wide_terminated(temporary_path);
    let pointer_path = wide_terminated(pointer_path);
    unsafe {
        MoveFileExW(
            PCWSTR(temporary_path.as_ptr()),
            PCWSTR(pointer_path.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
        .map_err(io::Error::other)
    }
}

#[cfg(windows)]
fn wide_terminated(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn create_temporary_pointer(install_root: &Path) -> Result<(PathBuf, File), ActiveReleaseError> {
    for _ in 0..POINTER_TEMP_ATTEMPTS {
        let path = install_root.join(format!(
            ".{ACTIVE_RELEASE_FILE_NAME}.{}.tmp",
            Uuid::new_v4()
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(ActiveReleaseError::CreateTemporaryPointer { path, source });
            }
        }
    }

    Err(ActiveReleaseError::TemporaryPointerNameExhausted {
        directory: install_root.to_path_buf(),
    })
}

fn validate_payload_dir(payload_dir: &Path) -> Result<(), ActiveReleaseError> {
    if payload_dir.as_os_str().is_empty() {
        return Err(invalid_payload_dir(payload_dir, "it is empty"));
    }

    let rendered = payload_dir.to_string_lossy();
    let bytes = rendered.as_bytes();
    if payload_dir.is_absolute()
        || rendered.starts_with('\\')
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
    {
        return Err(invalid_payload_dir(
            payload_dir,
            "it is absolute or has a platform path prefix",
        ));
    }
    if rendered
        .split(['/', '\\'])
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(invalid_payload_dir(
            payload_dir,
            "it contains an empty or non-normal component",
        ));
    }

    let mut has_component = false;
    for component in payload_dir.components() {
        match component {
            Component::Normal(_) => has_component = true,
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(invalid_payload_dir(
                    payload_dir,
                    "it contains a non-normal path component",
                ));
            }
        }
    }
    if !has_component {
        return Err(invalid_payload_dir(
            payload_dir,
            "it has no normal components",
        ));
    }

    Ok(())
}

fn invalid_payload_dir(payload_dir: &Path, reason: &'static str) -> ActiveReleaseError {
    ActiveReleaseError::InvalidPayloadDirectory {
        payload_dir: payload_dir.to_path_buf(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    #[cfg(unix)]
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        process::Command,
    };

    use semver::Version;

    use super::{
        ActiveRelease, read_active_release, resolve_payload_executable, write_active_release,
    };

    #[test]
    fn active_release_rejects_parent_components_and_absolute_payload_paths() {
        let version = Version::new(1, 2, 3);

        for payload_dir in [
            PathBuf::from("../releases/1.2.3"),
            PathBuf::from("/releases/1.2.3"),
        ] {
            assert!(ActiveRelease::new(version.clone(), payload_dir, 1).is_err());
        }
    }

    #[test]
    fn active_release_rejects_empty_current_prefix_and_non_normal_payload_paths() {
        let version = Version::new(1, 2, 3);

        for payload_dir in [
            PathBuf::new(),
            PathBuf::from("."),
            PathBuf::from("./releases/1.2.3"),
            PathBuf::from("releases/../1.2.3"),
            PathBuf::from("releases//1.2.3"),
            PathBuf::from(r"releases\..\1.2.3"),
            PathBuf::from(r"\releases\1.2.3"),
            PathBuf::from(r"C:\releases\1.2.3"),
            PathBuf::from(r"C:releases\1.2.3"),
        ] {
            assert!(ActiveRelease::new(version.clone(), payload_dir, 1).is_err());
        }
    }

    #[test]
    fn active_release_round_trips_through_the_install_pointer() {
        let install_root = tempfile::tempdir().unwrap();
        let active_release =
            ActiveRelease::new(Version::new(1, 2, 3), PathBuf::from("releases/1.2.3"), 1).unwrap();

        write_active_release(install_root.path(), &active_release).unwrap();

        assert_eq!(
            read_active_release(install_root.path()).unwrap(),
            active_release
        );
    }

    #[cfg(unix)]
    #[test]
    fn active_release_pointer_is_readable_with_a_restrictive_umask() {
        const CHILD_ENVIRONMENT: &str = "RQBIT_TUNNEL_RESTRICTIVE_UMASK_TEST";

        if std::env::var_os(CHILD_ENVIRONMENT).is_none() {
            let status = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("version::tests::active_release_pointer_is_readable_with_a_restrictive_umask")
                .env(CHILD_ENVIRONMENT, "1")
                .status()
                .expect("restricted-umask child should start");
            assert!(status.success(), "restricted-umask child must pass");
            return;
        }

        let previous_umask = unsafe { libc::umask(0o077) };
        let install_root = tempfile::tempdir().unwrap();
        let active_release =
            ActiveRelease::new(Version::new(1, 2, 3), PathBuf::from("releases/1.2.3"), 1).unwrap();
        write_active_release(install_root.path(), &active_release).unwrap();
        unsafe {
            libc::umask(previous_umask);
        }

        assert_eq!(
            fs::metadata(install_root.path().join("active.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[test]
    fn payload_executable_resolution_cannot_escape_install_root() {
        let install_root = tempfile::tempdir().unwrap();

        assert!(
            resolve_payload_executable(
                install_root.path(),
                Path::new("releases/1.2.3/../../outside"),
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn payload_executable_resolution_rejects_a_symlink_escape() {
        let install_root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(install_root.path().join("releases")).unwrap();
        fs::write(outside.path().join("rqbit-tunnel"), b"outside payload").unwrap();
        symlink(outside.path(), install_root.path().join("releases/1.2.3")).unwrap();

        assert!(
            resolve_payload_executable(install_root.path(), Path::new("releases/1.2.3"),).is_err()
        );
    }
}
