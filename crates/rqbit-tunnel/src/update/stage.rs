use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

use flate2::read::MultiGzDecoder;
#[cfg(not(any(unix, windows)))]
use std::fs::OpenOptions;
#[cfg(windows)]
use std::{
    cell::RefCell,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
};
#[cfg(unix)]
use std::{
    ffi::{CStr, CString},
    os::unix::{
        ffi::OsStrExt,
        fs::PermissionsExt,
        io::{AsRawFd, FromRawFd, RawFd},
    },
};
use zip::ZipArchive;

use crate::update::component::validate_portable_component;

use crate::update::manifest::UpdateError;

/// Archive formats accepted at the verified staging boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveKind {
    TarGz,
    Zip,
}

#[derive(Debug)]
struct ValidatedArchive {
    bundle_directory: String,
    entries: Vec<ValidatedEntry>,
}

#[derive(Debug)]
struct RawZipArchive {
    central_directory_offset: u64,
    minimum_local_header_offset: Option<u64>,
    entries: Vec<RawZipEntry>,
}

#[derive(Debug)]
struct RawZipEntry {
    raw_path: String,
    central_header_offset: u64,
    local_header_offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedEntry {
    normalized_path: String,
    filesystem_key: String,
    output_path: PathBuf,
    kind: ArchiveEntryKind,
    output_mode: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArchiveEntryKind {
    Regular,
    Directory,
}
#[cfg(windows)]
#[derive(Debug)]
struct RetainedDirectory {
    path: PathBuf,
    _handle: File,
}

#[derive(Debug)]
struct StagingDirectory {
    path: PathBuf,
    #[cfg(unix)]
    root: File,
    #[cfg(windows)]
    retained_directories: RefCell<Vec<RetainedDirectory>>,
}

#[derive(Debug)]
pub struct StagedBundle {
    staging_directory: StagingDirectory,
    relative_directory: PathBuf,
}

impl StagedBundle {
    pub fn relative_directory(&self) -> &Path {
        &self.relative_directory
    }

    pub fn read_file(&self, relative_path: &Path) -> Result<Vec<u8>, UpdateError> {
        if !strictly_normal_relative_path(relative_path) {
            return Err(UpdateError::UnsafeExtractionFile {
                path: self.staging_directory.output_path(&self.relative_directory),
            });
        }

        self.staging_directory
            .read_file(&self.relative_directory.join(relative_path))
    }

    /// Verifies the managed client, tray companion, and temporary updater
    /// are present as regular executable files before release promotion.
    pub fn validate_client_payload_layout(&self) -> Result<(), UpdateError> {
        for component in [
            format!("rqbit-tunnel{}", crate::version::current_exe_suffix()),
            format!("rqbit-tunnel-tray{}", crate::version::current_exe_suffix()),
            format!(
                "rqbit-tunnel-updater{}",
                crate::version::current_exe_suffix()
            ),
        ] {
            self.require_client_payload_component(&component)?;
        }
        Ok(())
    }

    fn require_client_payload_component(&self, component: &str) -> Result<(), UpdateError> {
        let relative_path = self.relative_directory.join(component);
        let metadata = self
            .staging_directory
            .inspect_file(&relative_path)
            .map_err(|error| match error {
                UpdateError::InspectExtractionPath { source, .. }
                    if source.kind() == io::ErrorKind::NotFound =>
                {
                    UpdateError::MissingClientPayloadComponent {
                        component: component.to_owned(),
                    }
                }
                error => error,
            })?;
        if !metadata.is_file() {
            return Err(UpdateError::MissingClientPayloadComponent {
                component: component.to_owned(),
            });
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(UpdateError::NonExecutableClientPayloadComponent {
                component: component.to_owned(),
            });
        }
        Ok(())
    }

    /// Promotes this verified bundle to its immutable release destination.
    ///
    /// The destination is always `releases/<version>/payload` below an
    /// absolute installation root. Unix promotion uses descriptor-relative
    /// no-replace renames, so neither the staged source nor destination can
    /// escape through a raced path component.
    pub fn promote_to_release(
        self,
        install_root: &Path,
        version: &semver::Version,
    ) -> Result<PathBuf, UpdateError> {
        if !install_root.is_absolute() {
            return Err(UpdateError::InvalidInstallRoot {
                path: install_root.to_path_buf(),
            });
        }

        let mut source_components = self.relative_directory.components();
        let Some(Component::Normal(source_name)) = source_components.next() else {
            return Err(UpdateError::UnsafeStagingDirectory {
                path: self.staging_directory.path.clone(),
            });
        };
        if source_components.next().is_some() {
            return Err(UpdateError::UnsafeStagingDirectory {
                path: self.staging_directory.path.clone(),
            });
        }
        let source_name = source_name.to_owned();

        let version_component = version.to_string();
        validate_portable_component(&version_component).map_err(|_| {
            UpdateError::InvalidInstallRoot {
                path: install_root.to_path_buf(),
            }
        })?;
        let destination = install_root
            .join("releases")
            .join(&version_component)
            .join("payload");

        #[cfg(unix)]
        {
            return promote_staged_bundle_unix(
                self,
                install_root,
                source_name.as_os_str(),
                &version_component,
                destination,
            );
        }

        #[cfg(windows)]
        {
            return promote_staged_bundle_windows(
                self,
                install_root,
                source_name.as_os_str(),
                &version_component,
                destination,
            );
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = source_name;
            let _ = version_component;
            let _ = destination;
            Err(UpdateError::UnsupportedBundlePromotion)
        }
    }
}

/// Removes an inactive promoted candidate after activation has rolled back.
///
/// The caller must invoke this only after the previous active release has been
/// restored. Unix removal walks descriptor-relative paths without following
/// symlinks; Windows validates the root and candidate directories before
/// removal.
pub fn discard_promoted_release(
    install_root: &Path,
    version: &semver::Version,
) -> Result<(), UpdateError> {
    if !install_root.is_absolute() {
        return Err(UpdateError::InvalidInstallRoot {
            path: install_root.to_path_buf(),
        });
    }

    let version_component = version.to_string();
    validate_portable_component(&version_component).map_err(|_| {
        UpdateError::InvalidInstallRoot {
            path: install_root.to_path_buf(),
        }
    })?;
    let candidate_path = install_root.join("releases").join(&version_component);

    #[cfg(unix)]
    {
        return discard_promoted_release_unix(install_root, &version_component, &candidate_path);
    }

    #[cfg(windows)]
    {
        return discard_promoted_release_windows(install_root, &candidate_path);
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = candidate_path;
        Err(UpdateError::UnsupportedBundlePromotion)
    }
}

#[cfg(unix)]
fn promote_staged_bundle_unix(
    staged: StagedBundle,
    install_root: &Path,
    source_name: &OsStr,
    version_component: &str,
    destination: PathBuf,
) -> Result<PathBuf, UpdateError> {
    let root = open_staging_directory(install_root)?;
    let releases_path = install_root.join("releases");
    let releases_name = CString::new("releases").expect("literal does not contain NUL");
    let releases_directory =
        open_or_create_output_directory_at(root.as_raw_fd(), &releases_name, &releases_path)?;
    let version_path = releases_path.join(version_component);
    let version_name = CString::new(version_component).expect("validated version has no NUL");
    let version_directory = create_new_release_directory_at(
        releases_directory.as_raw_fd(),
        &version_name,
        &version_path,
    )?;
    let source_name =
        CString::new(source_name.as_bytes()).map_err(|_| UpdateError::UnsafeStagingDirectory {
            path: staged.staging_directory.path.clone(),
        })?;
    let payload_name = CString::new("payload").expect("literal does not contain NUL");

    atomic_rename_directory_no_replace_at(
        staged.staging_directory.root.as_raw_fd(),
        &source_name,
        version_directory.as_raw_fd(),
        &payload_name,
    )
    .map_err(|source| map_bundle_promotion_error(&destination, source))?;

    version_directory
        .sync_all()
        .map_err(|source| UpdateError::PromoteStagedBundle {
            destination: destination.clone(),
            source,
        })?;
    releases_directory
        .sync_all()
        .map_err(|source| UpdateError::PromoteStagedBundle {
            destination: destination.clone(),
            source,
        })?;
    root.sync_all()
        .map_err(|source| UpdateError::PromoteStagedBundle {
            destination: destination.clone(),
            source,
        })?;
    Ok(destination)
}

#[cfg(unix)]
fn discard_promoted_release_unix(
    install_root: &Path,
    version_component: &str,
    candidate_path: &Path,
) -> Result<(), UpdateError> {
    let root = open_staging_directory(install_root)?;
    let releases_path = install_root.join("releases");
    let releases_name = CString::new("releases").expect("literal does not contain NUL");
    let releases_directory =
        open_existing_output_directory_at(root.as_raw_fd(), &releases_name, &releases_path)?;
    let version_name =
        CString::new(version_component).expect("validated version component does not contain NUL");
    let candidate_directory = open_existing_output_directory_at(
        releases_directory.as_raw_fd(),
        &version_name,
        candidate_path,
    )?;

    discard_directory_contents_at(candidate_directory.as_raw_fd(), candidate_path)?;
    drop(candidate_directory);
    // SAFETY: `releases_directory` owns the parent descriptor and `version_name` is NUL-terminated.
    if unsafe {
        libc::unlinkat(
            releases_directory.as_raw_fd(),
            version_name.as_ptr(),
            libc::AT_REMOVEDIR,
        )
    } != 0
    {
        return Err(discard_rolled_back_release_error(
            candidate_path,
            io::Error::last_os_error(),
        ));
    }
    releases_directory
        .sync_all()
        .map_err(|source| discard_rolled_back_release_error(&releases_path, source))?;
    root.sync_all()
        .map_err(|source| discard_rolled_back_release_error(install_root, source))?;
    Ok(())
}

#[cfg(unix)]
fn discard_directory_contents_at(
    directory_fd: RawFd,
    directory_path: &Path,
) -> Result<(), UpdateError> {
    // SAFETY: `directory_fd` owns a valid directory descriptor; `fcntl` duplicates it.
    let duplicate_fd = unsafe { libc::fcntl(directory_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate_fd == -1 {
        return Err(discard_rolled_back_release_error(
            directory_path,
            io::Error::last_os_error(),
        ));
    }

    // SAFETY: `duplicate_fd` is valid and remains owned here if `fdopendir` fails.
    let stream = unsafe { libc::fdopendir(duplicate_fd) };
    if stream.is_null() {
        let source = io::Error::last_os_error();
        // SAFETY: `fdopendir` did not take ownership of this duplicated descriptor.
        unsafe {
            libc::close(duplicate_fd);
        }
        return Err(discard_rolled_back_release_error(directory_path, source));
    }
    let stream = DirectoryStream(stream);

    loop {
        clear_readdir_errno();
        // SAFETY: `stream` owns a valid `DIR*` for the lifetime of this loop.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let errno = readdir_errno();
            if errno == 0 {
                return Ok(());
            }
            return Err(discard_rolled_back_release_error(
                directory_path,
                io::Error::from_raw_os_error(errno),
            ));
        }
        // SAFETY: `readdir` returned a valid entry whose name is NUL-terminated.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        discard_directory_entry_at(directory_fd, name, directory_path)?;
    }
}

#[cfg(unix)]
fn discard_directory_entry_at(
    parent_fd: RawFd,
    name: &CStr,
    parent_path: &Path,
) -> Result<(), UpdateError> {
    let entry_path = parent_path.join(OsStr::from_bytes(name.to_bytes()));
    // SAFETY: `parent_fd` owns a directory descriptor and `name` is NUL-terminated.
    let child_fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if child_fd != -1 {
        // SAFETY: `openat` returned a new owned descriptor.
        let child_directory = unsafe { File::from_raw_fd(child_fd) };
        discard_directory_contents_at(child_directory.as_raw_fd(), &entry_path)?;
        drop(child_directory);
        // SAFETY: `parent_fd` owns the parent descriptor and `name` is NUL-terminated.
        if unsafe { libc::unlinkat(parent_fd, name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            return Err(discard_rolled_back_release_error(
                &entry_path,
                io::Error::last_os_error(),
            ));
        }
        return Ok(());
    }

    let open_error = io::Error::last_os_error();
    if !matches!(
        open_error.raw_os_error(),
        Some(libc::ELOOP) | Some(libc::ENOTDIR)
    ) {
        return Err(discard_rolled_back_release_error(&entry_path, open_error));
    }
    // SAFETY: `unlinkat` with flags zero removes this directory entry itself and never follows it.
    if unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) } != 0 {
        return Err(discard_rolled_back_release_error(
            &entry_path,
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn discard_rolled_back_release_error(path: &Path, source: io::Error) -> UpdateError {
    UpdateError::DiscardRolledBackRelease {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(unix)]
fn create_new_release_directory_at(
    parent_fd: RawFd,
    name: &CStr,
    path: &Path,
) -> Result<File, UpdateError> {
    // SAFETY: `parent_fd` owns an open directory and `name` is NUL-terminated.
    let result = unsafe { libc::mkdirat(parent_fd, name.as_ptr(), 0o755) };
    if result != 0 {
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::AlreadyExists {
            return Err(UpdateError::ReleaseAlreadyExists {
                path: path.to_path_buf(),
            });
        }
        return Err(UpdateError::CreateReleaseDestination {
            path: path.to_path_buf(),
            source,
        });
    }

    // SAFETY: `parent_fd` owns an open directory and `name` is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(UpdateError::OpenReleaseDestination {
            path: path.to_path_buf(),
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: `openat` returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn map_bundle_promotion_error(destination: &Path, source: io::Error) -> UpdateError {
    match source.kind() {
        io::ErrorKind::AlreadyExists => UpdateError::ReleaseAlreadyExists {
            path: destination.to_path_buf(),
        },
        io::ErrorKind::Unsupported => UpdateError::UnsupportedBundlePromotion,
        _ => UpdateError::PromoteStagedBundle {
            destination: destination.to_path_buf(),
            source,
        },
    }
}

#[cfg(target_os = "linux")]
fn atomic_rename_directory_no_replace_at(
    source_directory_fd: RawFd,
    source_name: &CStr,
    destination_directory_fd: RawFd,
    destination_name: &CStr,
) -> io::Result<()> {
    // SAFETY: both descriptors own opened directories and both names are NUL-terminated.
    let result = unsafe {
        libc::renameat2(
            source_directory_fd,
            source_name.as_ptr(),
            destination_directory_fd,
            destination_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn atomic_rename_directory_no_replace_at(
    source_directory_fd: RawFd,
    source_name: &CStr,
    destination_directory_fd: RawFd,
    destination_name: &CStr,
) -> io::Result<()> {
    // SAFETY: both descriptors own opened directories and both names are NUL-terminated.
    let result = unsafe {
        libc::renameatx_np(
            source_directory_fd,
            source_name.as_ptr(),
            destination_directory_fd,
            destination_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn atomic_rename_directory_no_replace_at(
    _source_directory_fd: RawFd,
    _source_name: &CStr,
    _destination_directory_fd: RawFd,
    _destination_name: &CStr,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace directory rename is unavailable on this platform",
    ))
}

#[cfg(windows)]
fn promote_staged_bundle_windows(
    staged: StagedBundle,
    install_root: &Path,
    source_name: &OsStr,
    version_component: &str,
    destination: PathBuf,
) -> Result<PathBuf, UpdateError> {
    use windows::{
        Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW},
        core::PCWSTR,
    };

    let source = staged.staging_directory.path.join(source_name);
    let releases_path = install_root.join("releases");
    let version_path = releases_path.join(version_component);

    let _root = open_windows_staging_directory(install_root)?;
    let _releases = create_or_open_windows_output_directory(&releases_path)?;
    match fs::create_dir(&version_path) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            return Err(UpdateError::ReleaseAlreadyExists { path: version_path });
        }
        Err(source) => {
            return Err(UpdateError::CreateReleaseDestination {
                path: version_path,
                source,
            });
        }
    }
    let _version = open_windows_output_directory(&version_path)?;
    if destination.exists() {
        return Err(UpdateError::ReleaseAlreadyExists { path: destination });
    }

    // The retained staging handles prevent extraction races. Drop them before
    // MoveFileExW because this process's own non-delete-sharing handles would
    // otherwise block the final no-replace move.
    drop(staged);
    let source_wide = wide_windows_path(&source);
    let destination_wide = wide_windows_path(&destination);
    unsafe {
        MoveFileExW(
            PCWSTR(source_wide.as_ptr()),
            PCWSTR(destination_wide.as_ptr()),
            MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|source| {
        let source = io::Error::other(source);
        map_bundle_promotion_error(&destination, source)
    })?;
    Ok(destination)
}

#[cfg(windows)]
fn discard_promoted_release_windows(
    install_root: &Path,
    candidate_path: &Path,
) -> Result<(), UpdateError> {
    let releases_path = install_root.join("releases");
    let root_directories = open_windows_staging_directories(install_root)?;
    let releases_directory = open_windows_output_directory(&releases_path)?;
    let candidate_directory = open_windows_output_directory(candidate_path)?;

    // The validated handles intentionally prevent path replacement while the
    // hierarchy is checked. Drop them immediately before removal because they
    // do not grant delete sharing.
    drop(candidate_directory);
    drop(releases_directory);
    drop(root_directories);
    fs::remove_dir_all(candidate_path).map_err(|source| UpdateError::DiscardRolledBackRelease {
        path: candidate_path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
struct DirectoryStream(*mut libc::DIR);

#[cfg(unix)]
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: `DirectoryStream` owns the non-null stream returned by `fdopendir`.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

#[cfg(all(unix, not(any(target_os = "dragonfly", target_os = "vxworks"))))]
unsafe extern "C" {
    #[cfg_attr(
        any(
            target_os = "linux",
            target_os = "emscripten",
            target_os = "fuchsia",
            target_os = "l4re",
            target_os = "hurd",
            target_os = "redox",
        ),
        link_name = "__errno_location"
    )]
    #[cfg_attr(
        any(
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "cygwin",
            target_os = "android",
            target_os = "nuttx",
            target_env = "newlib",
        ),
        link_name = "__errno"
    )]
    #[cfg_attr(
        any(target_os = "solaris", target_os = "illumos"),
        link_name = "___errno"
    )]
    #[cfg_attr(target_os = "nto", link_name = "__get_errno_ptr")]
    #[cfg_attr(
        any(target_os = "freebsd", target_vendor = "apple"),
        link_name = "__error"
    )]
    #[cfg_attr(target_os = "haiku", link_name = "_errnop")]
    #[cfg_attr(target_os = "aix", link_name = "_Errno")]
    fn readdir_errno_location() -> *mut libc::c_int;
}

#[cfg(all(unix, target_os = "dragonfly"))]
unsafe extern "C" {
    #[link_name = "__errno_location"]
    fn readdir_errno_location() -> *mut libc::c_int;
}

#[cfg(all(unix, not(target_os = "vxworks")))]
fn clear_readdir_errno() {
    // SAFETY: `readdir_errno_location` returns this thread's writable `errno` slot.
    unsafe {
        *readdir_errno_location() = 0;
    }
}

#[cfg(all(unix, target_os = "vxworks"))]
fn clear_readdir_errno() {
    // SAFETY: VxWorks exposes the calling thread's `errno` through `errnoSet`.
    unsafe {
        libc::errnoSet(0);
    }
}

#[cfg(all(unix, not(target_os = "vxworks")))]
fn readdir_errno() -> libc::c_int {
    // SAFETY: `readdir_errno_location` returns this thread's readable `errno` slot.
    unsafe { *readdir_errno_location() }
}

#[cfg(all(unix, target_os = "vxworks"))]
fn readdir_errno() -> libc::c_int {
    // SAFETY: VxWorks exposes the calling thread's `errno` through `errnoGet`.
    unsafe { libc::errnoGet() }
}

struct ArchiveLayout {
    bundle_directory: Option<String>,
    bundle_directory_key: Option<String>,
    filesystem_paths: HashMap<String, String>,
    regular_filesystem_paths: HashMap<String, String>,
    entries: Vec<ValidatedEntry>,
}
impl ArchiveLayout {
    fn new() -> Self {
        Self {
            bundle_directory: None,
            bundle_directory_key: None,
            filesystem_paths: HashMap::new(),
            regular_filesystem_paths: HashMap::new(),
            entries: Vec::new(),
        }
    }

    fn record(&mut self, entry: ValidatedEntry) -> Result<(), UpdateError> {
        if self.filesystem_paths.contains_key(&entry.filesystem_key) {
            return Err(UpdateError::DuplicateArchiveEntryPath {
                path: entry.normalized_path.clone(),
            });
        }
        if entry.kind == ArchiveEntryKind::Regular && !entry.filesystem_key.contains('/') {
            return Err(UpdateError::ArchiveRootFile {
                path: entry.normalized_path.clone(),
            });
        }

        let top_level = entry
            .normalized_path
            .split('/')
            .next()
            .expect("validated archive paths always have a component");
        let top_level_key = entry
            .filesystem_key
            .split('/')
            .next()
            .expect("validated archive paths always have a component");
        match (
            self.bundle_directory.as_ref(),
            self.bundle_directory_key.as_deref(),
        ) {
            (Some(bundle_directory), Some(bundle_directory_key))
                if bundle_directory_key != top_level_key || bundle_directory != top_level =>
            {
                return Err(UpdateError::MultipleArchiveBundleDirectories {
                    first: bundle_directory.clone(),
                    found: top_level.to_owned(),
                });
            }
            (Some(_), Some(_)) => {}
            (None, None) => {
                self.bundle_directory = Some(top_level.to_owned());
                self.bundle_directory_key = Some(top_level_key.to_owned());
            }
            _ => unreachable!("bundle directory spelling and key are recorded together"),
        }

        if entry.kind == ArchiveEntryKind::Regular {
            if let Some(descendant) =
                archive_path_descendant(&entry.filesystem_key, &self.filesystem_paths)
            {
                return Err(UpdateError::ArchiveFileAncestor {
                    path: descendant,
                    ancestor: entry.normalized_path.clone(),
                });
            }
        }

        if let Some(ancestor) =
            regular_file_ancestor(&entry.filesystem_key, &self.regular_filesystem_paths)
        {
            return Err(UpdateError::ArchiveFileAncestor {
                path: entry.normalized_path.clone(),
                ancestor,
            });
        }
        self.filesystem_paths
            .insert(entry.filesystem_key.clone(), entry.normalized_path.clone());
        if entry.kind == ArchiveEntryKind::Regular {
            self.regular_filesystem_paths
                .insert(entry.filesystem_key.clone(), entry.normalized_path.clone());
        }
        self.entries.push(entry);
        Ok(())
    }

    fn finish(self) -> Result<ValidatedArchive, UpdateError> {
        Ok(ValidatedArchive {
            bundle_directory: self.bundle_directory.ok_or(UpdateError::EmptyArchive)?,
            entries: self.entries,
        })
    }
}

/// Preflights an archive completely before writing any staged entry.
pub fn extract_verified_archive(
    archive_path: &Path,
    staging_dir: &Path,
    kind: ArchiveKind,
) -> Result<StagedBundle, UpdateError> {
    let staging_dir = StagingDirectory::open(staging_dir)?;

    let mut archive_file =
        File::open(archive_path).map_err(|source| UpdateError::OpenVerifiedArchive {
            path: archive_path.to_path_buf(),
            source,
        })?;
    // Preflight and extraction must consume this same anonymous snapshot.
    let mut archive_snapshot =
        tempfile::tempfile().map_err(|source| archive_snapshot_error(archive_path, source))?;
    io::copy(&mut archive_file, &mut archive_snapshot)
        .map_err(|source| archive_snapshot_error(archive_path, source))?;
    archive_snapshot
        .seek(SeekFrom::Start(0))
        .map_err(|source| archive_snapshot_error(archive_path, source))?;

    let validated = match kind {
        ArchiveKind::TarGz => preflight_tar_gz(archive_path, &mut archive_snapshot)?,
        ArchiveKind::Zip => preflight_zip(archive_path, &mut archive_snapshot)?,
    };

    archive_snapshot
        .seek(SeekFrom::Start(0))
        .map_err(|source| archive_snapshot_error(archive_path, source))?;
    match kind {
        ArchiveKind::TarGz => extract_preflighted_tar_gz(
            archive_path,
            &mut archive_snapshot,
            &staging_dir,
            &validated,
        )?,
        ArchiveKind::Zip => extract_preflighted_zip(
            archive_path,
            &mut archive_snapshot,
            &staging_dir,
            &validated,
        )?,
    }

    let relative_directory = PathBuf::from(validated.bundle_directory.as_str());
    staging_dir.create_directory(&relative_directory)?;
    staging_dir.sync_extracted_directories(&validated)?;
    Ok(StagedBundle {
        staging_directory: staging_dir,
        relative_directory,
    })
}

fn preflight_tar_gz(
    archive_path: &Path,
    archive_file: &mut File,
) -> Result<ValidatedArchive, UpdateError> {
    let mut archive = tar::Archive::new(MultiGzDecoder::new(&mut *archive_file));
    let mut entries = archive
        .entries()
        .map_err(|source| archive_read_error(archive_path, source))?
        .raw(true);
    let mut layout = ArchiveLayout::new();

    while let Some(entry) = entries.next() {
        let mut entry = entry.map_err(|source| archive_read_error(archive_path, source))?;
        let validated =
            validate_tar_entry(entry.header(), entry.path_bytes().as_ref(), archive_path)?;
        layout.record(validated)?;
        drain_archive_entry(&mut entry, archive_path)?;
    }

    drop(entries);
    let mut decoder = archive.into_inner();
    ensure_tar_padding(&mut decoder, archive_path)?;
    layout.finish()
}

fn preflight_zip(
    archive_path: &Path,
    archive_file: &mut File,
) -> Result<ValidatedArchive, UpdateError> {
    let raw_archive = preflight_raw_zip_headers(archive_path, archive_file)?;
    if raw_archive
        .minimum_local_header_offset
        .is_some_and(|offset| offset != 0)
    {
        return Err(invalid_zip_structure(
            archive_path,
            "ZIP archives with prefixed data are not supported",
        ));
    }
    let mut archive = ZipArchive::new(&mut *archive_file)
        .map_err(|source| zip_archive_read_error(archive_path, source))?;
    if archive.central_directory_start() != raw_archive.central_directory_offset {
        return Err(invalid_zip_structure(
            archive_path,
            "ZIP reader selected a different central directory than the validated end record",
        ));
    }
    if archive.len() != raw_archive.entries.len() {
        return Err(invalid_zip_structure(
            archive_path,
            "ZIP central-directory records do not match the logical archive entries",
        ));
    }
    if archive
        .has_overlapping_files()
        .map_err(|source| zip_archive_read_error(archive_path, source))?
    {
        return Err(UpdateError::OverlappingZipFileData);
    }

    let mut layout = ArchiveLayout::new();
    for (index, raw_entry) in raw_archive.entries.iter().enumerate() {
        let encrypted_entry_path = {
            let entry = archive
                .by_index_raw(index)
                .map_err(|source| zip_archive_read_error(archive_path, source))?;
            let raw_path = std::str::from_utf8(entry.name_raw())
                .map_err(|_| UpdateError::ArchivePathNotUtf8)?;
            if entry.central_header_start() != raw_entry.central_header_offset
                || entry.header_start() != raw_entry.local_header_offset
            {
                return Err(invalid_zip_structure(
                    archive_path,
                    "ZIP reader selected an entry different from the validated raw headers",
                ));
            }
            if raw_path != raw_entry.raw_path {
                return Err(invalid_zip_structure(
                    archive_path,
                    "ZIP logical entry name differs from its raw central-directory name",
                ));
            }
            entry.encrypted().then(|| raw_path.to_owned())
        };
        if let Some(path) = encrypted_entry_path {
            return Err(UpdateError::UnsupportedZipArchiveEntry {
                path,
                reason: "it is encrypted",
            });
        }

        let mut entry = archive
            .by_index(index)
            .map_err(|source| zip_archive_read_error(archive_path, source))?;
        let validated = validate_zip_entry(&entry)?;
        layout.record(validated)?;
        drain_archive_entry(&mut entry, archive_path)?;
    }

    layout.finish()
}

const ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE: [u8; 4] = *b"PK\x05\x06";
const ZIP_CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE: [u8; 4] = *b"PK\x01\x02";
const ZIP_LOCAL_FILE_HEADER_SIGNATURE: [u8; 4] = *b"PK\x03\x04";
const ZIP_END_OF_CENTRAL_DIRECTORY_BYTES: usize = 22;
const ZIP_CENTRAL_DIRECTORY_FILE_HEADER_BYTES: usize = 46;
const ZIP_LOCAL_FILE_HEADER_BYTES: usize = 30;
const ZIP_MAX_COMMENT_BYTES: u64 = u16::MAX as u64;
const ZIP64_EXTENDED_INFORMATION_EXTRA_FIELD: u16 = 0x0001;
const ZIP_UNICODE_PATH_EXTRA_FIELD: u16 = 0x7075;
const ZIP_PKWARE_UNIX_EXTRA_FIELD: u16 = 0x000d;
const ZIP_ASI_UNIX_EXTRA_FIELD: u16 = 0x756e;

fn preflight_raw_zip_headers(
    archive_path: &Path,
    archive_file: &mut File,
) -> Result<RawZipArchive, UpdateError> {
    let archive_len = archive_file
        .seek(SeekFrom::End(0))
        .map_err(|source| archive_read_error(archive_path, source))?;
    if archive_len < ZIP_END_OF_CENTRAL_DIRECTORY_BYTES as u64 {
        return Err(invalid_zip_structure(
            archive_path,
            "ZIP end record is missing",
        ));
    }

    let search_len =
        archive_len.min(ZIP_END_OF_CENTRAL_DIRECTORY_BYTES as u64 + ZIP_MAX_COMMENT_BYTES);
    let search_start = archive_len - search_len;
    archive_file
        .seek(SeekFrom::Start(search_start))
        .map_err(|source| archive_read_error(archive_path, source))?;
    let mut tail = vec![0; search_len as usize];
    archive_file
        .read_exact(&mut tail)
        .map_err(|source| archive_read_error(archive_path, source))?;

    let end_record_index = (0..=tail.len() - 4).rev().find(|&index| {
        if tail[index..index + 4] != ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE
            || index + ZIP_END_OF_CENTRAL_DIRECTORY_BYTES > tail.len()
        {
            return false;
        }
        let comment_len = usize::from(zip_u16(&tail[index + 20..index + 22]));
        index + ZIP_END_OF_CENTRAL_DIRECTORY_BYTES + comment_len == tail.len()
    });
    let Some(end_record_index) = end_record_index else {
        return Err(invalid_zip_structure(
            archive_path,
            "ZIP end record is invalid",
        ));
    };
    let end_record = &tail[end_record_index..end_record_index + ZIP_END_OF_CENTRAL_DIRECTORY_BYTES];
    if zip_u16(&end_record[4..6]) != 0
        || zip_u16(&end_record[6..8]) != 0
        || zip_u16(&end_record[8..10]) != zip_u16(&end_record[10..12])
    {
        return Err(invalid_zip_structure(
            archive_path,
            "multi-disk ZIP archives are not supported",
        ));
    }
    let entry_count = zip_u16(&end_record[10..12]);
    let central_directory_size = zip_u32(&end_record[12..16]);
    let central_directory_offset = zip_u32(&end_record[16..20]);
    if entry_count == u16::MAX
        || central_directory_size == u32::MAX
        || central_directory_offset == u32::MAX
    {
        return Err(invalid_zip_structure(
            archive_path,
            "ZIP64 archives are not supported",
        ));
    }

    let end_record_offset = search_start + end_record_index as u64;
    let central_directory_offset = u64::from(central_directory_offset);
    let central_directory_end = central_directory_offset
        .checked_add(u64::from(central_directory_size))
        .ok_or_else(|| invalid_zip_structure(archive_path, "ZIP central directory overflows"))?;
    if central_directory_end != end_record_offset {
        return Err(invalid_zip_structure(
            archive_path,
            "ZIP central directory does not directly precede its end record",
        ));
    }

    let mut records_offset = central_directory_offset;
    let mut seen_paths = HashSet::new();
    let mut entries = Vec::with_capacity(usize::from(entry_count));
    let mut minimum_local_header_offset: Option<u64> = None;
    for _ in 0..usize::from(entry_count) {
        if records_offset
            .checked_add(ZIP_CENTRAL_DIRECTORY_FILE_HEADER_BYTES as u64)
            .is_none_or(|end| end > central_directory_end)
        {
            return Err(invalid_zip_structure(
                archive_path,
                "ZIP central directory file header is truncated",
            ));
        }
        let central_header = read_zip_bytes(
            archive_path,
            archive_file,
            records_offset,
            ZIP_CENTRAL_DIRECTORY_FILE_HEADER_BYTES,
        )?;
        if central_header[..4] != ZIP_CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE {
            return Err(invalid_zip_structure(
                archive_path,
                "ZIP central directory file header is invalid",
            ));
        }
        let flags = zip_u16(&central_header[8..10]);
        let compression_method = zip_u16(&central_header[10..12]);
        let compressed_size = zip_u32(&central_header[20..24]);
        let uncompressed_size = zip_u32(&central_header[24..28]);
        let path_len = usize::from(zip_u16(&central_header[28..30]));
        let extra_len = usize::from(zip_u16(&central_header[30..32]));
        let comment_len = usize::from(zip_u16(&central_header[32..34]));
        let disk_start = zip_u16(&central_header[34..36]);
        let local_header_offset = zip_u32(&central_header[42..46]);
        if disk_start != 0
            || compressed_size == u32::MAX
            || uncompressed_size == u32::MAX
            || local_header_offset == u32::MAX
        {
            return Err(invalid_zip_structure(
                archive_path,
                "ZIP64 or multi-disk entry metadata is not supported",
            ));
        }
        let local_header_offset = u64::from(local_header_offset);
        minimum_local_header_offset = Some(
            minimum_local_header_offset.map_or(local_header_offset, |minimum| {
                minimum.min(local_header_offset)
            }),
        );
        let record_len = path_len
            .checked_add(extra_len)
            .and_then(|len| len.checked_add(comment_len))
            .and_then(|len| len.checked_add(ZIP_CENTRAL_DIRECTORY_FILE_HEADER_BYTES))
            .ok_or_else(|| {
                invalid_zip_structure(archive_path, "ZIP central directory entry length overflows")
            })?;
        let record_end = records_offset
            .checked_add(record_len as u64)
            .ok_or_else(|| {
                invalid_zip_structure(archive_path, "ZIP central directory entry offset overflows")
            })?;
        if record_end > central_directory_end {
            return Err(invalid_zip_structure(
                archive_path,
                "ZIP central directory entry is truncated",
            ));
        }

        let path_offset = records_offset + ZIP_CENTRAL_DIRECTORY_FILE_HEADER_BYTES as u64;
        let path = read_zip_bytes(archive_path, archive_file, path_offset, path_len)?;
        let raw_path = validate_raw_zip_path(&path)?;
        if !seen_paths.insert(raw_path.clone()) {
            return Err(UpdateError::DuplicateArchiveEntryPath { path: raw_path });
        }
        let extra_offset = path_offset + path_len as u64;
        let extra = read_zip_bytes(archive_path, archive_file, extra_offset, extra_len)?;
        validate_zip_extra_fields(archive_path, &raw_path, &extra)?;
        if flags & 1 != 0 {
            return Err(UpdateError::UnsupportedZipArchiveEntry {
                path: raw_path,
                reason: "it is encrypted",
            });
        }
        validate_raw_zip_local_header(
            archive_path,
            archive_file,
            &raw_path,
            flags,
            compression_method,
            local_header_offset,
            central_directory_offset,
        )?;
        entries.push(RawZipEntry {
            raw_path,
            central_header_offset: records_offset,
            local_header_offset,
        });
        records_offset = record_end;
    }
    if records_offset != central_directory_end {
        return Err(invalid_zip_structure(
            archive_path,
            "ZIP central directory has trailing bytes",
        ));
    }
    archive_file
        .seek(SeekFrom::Start(0))
        .map_err(|source| archive_read_error(archive_path, source))?;
    Ok(RawZipArchive {
        central_directory_offset,
        minimum_local_header_offset,
        entries,
    })
}

fn validate_raw_zip_local_header(
    archive_path: &Path,
    archive_file: &mut File,
    central_path: &str,
    central_flags: u16,
    central_compression_method: u16,
    local_header_offset: u64,
    central_directory_offset: u64,
) -> Result<(), UpdateError> {
    if local_header_offset
        .checked_add(ZIP_LOCAL_FILE_HEADER_BYTES as u64)
        .is_none_or(|end| end > central_directory_offset)
    {
        return Err(invalid_zip_structure(
            archive_path,
            "ZIP local file header is outside file data",
        ));
    }
    let local_header = read_zip_bytes(
        archive_path,
        archive_file,
        local_header_offset,
        ZIP_LOCAL_FILE_HEADER_BYTES,
    )?;
    if local_header[..4] != ZIP_LOCAL_FILE_HEADER_SIGNATURE {
        return Err(invalid_zip_structure(
            archive_path,
            "ZIP local file header is invalid",
        ));
    }
    let local_flags = zip_u16(&local_header[6..8]);
    let local_compression_method = zip_u16(&local_header[8..10]);
    if local_flags != central_flags || local_compression_method != central_compression_method {
        return Err(invalid_zip_structure(
            archive_path,
            "ZIP local file header disagrees with the central directory",
        ));
    }
    let path_len = usize::from(zip_u16(&local_header[26..28]));
    let extra_len = usize::from(zip_u16(&local_header[28..30]));
    let variable_len = path_len.checked_add(extra_len).ok_or_else(|| {
        invalid_zip_structure(archive_path, "ZIP local file header length overflows")
    })?;
    let variable_offset = local_header_offset + ZIP_LOCAL_FILE_HEADER_BYTES as u64;
    let variable_end = variable_offset
        .checked_add(variable_len as u64)
        .ok_or_else(|| {
            invalid_zip_structure(archive_path, "ZIP local file header offset overflows")
        })?;
    if variable_end > central_directory_offset {
        return Err(invalid_zip_structure(
            archive_path,
            "ZIP local file header is truncated",
        ));
    }

    let path = read_zip_bytes(archive_path, archive_file, variable_offset, path_len)?;
    let local_path = validate_raw_zip_path(&path)?;
    if local_path != central_path {
        return Err(invalid_zip_structure(
            archive_path,
            "ZIP local file header path disagrees with the central directory",
        ));
    }
    let extra = read_zip_bytes(
        archive_path,
        archive_file,
        variable_offset + path_len as u64,
        extra_len,
    )?;
    validate_zip_extra_fields(archive_path, central_path, &extra)
}

fn validate_raw_zip_path(raw_path: &[u8]) -> Result<String, UpdateError> {
    let raw_path = std::str::from_utf8(raw_path).map_err(|_| UpdateError::ArchivePathNotUtf8)?;
    let kind = if raw_path.ends_with('/') {
        ArchiveEntryKind::Directory
    } else {
        ArchiveEntryKind::Regular
    };
    normalize_archive_path(raw_path, kind)?;
    Ok(raw_path.to_owned())
}

fn validate_zip_extra_fields(
    archive_path: &Path,
    path: &str,
    extra: &[u8],
) -> Result<(), UpdateError> {
    let mut offset = 0;
    while offset < extra.len() {
        if extra.len() - offset < 4 {
            return Err(invalid_zip_structure(
                archive_path,
                "ZIP extra field header is truncated",
            ));
        }
        let field_id = zip_u16(&extra[offset..offset + 2]);
        let field_len = usize::from(zip_u16(&extra[offset + 2..offset + 4]));
        offset += 4;
        if field_len > extra.len() - offset {
            return Err(invalid_zip_structure(
                archive_path,
                "ZIP extra field is truncated",
            ));
        }
        match field_id {
            ZIP64_EXTENDED_INFORMATION_EXTRA_FIELD => {
                return Err(UpdateError::UnsupportedZipArchiveEntry {
                    path: path.to_owned(),
                    reason: "it has a ZIP64 extended-information extra field",
                });
            }
            ZIP_UNICODE_PATH_EXTRA_FIELD => {
                return Err(UpdateError::UnsupportedZipArchiveEntry {
                    path: path.to_owned(),
                    reason: "it has a Unicode Path extra field",
                });
            }
            ZIP_PKWARE_UNIX_EXTRA_FIELD | ZIP_ASI_UNIX_EXTRA_FIELD => {
                return Err(UpdateError::UnsupportedZipArchiveEntry {
                    path: path.to_owned(),
                    reason: "it has Unix link or device metadata",
                });
            }
            _ => {}
        }
        offset += field_len;
    }
    Ok(())
}

fn read_zip_bytes(
    archive_path: &Path,
    archive_file: &mut File,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, UpdateError> {
    archive_file
        .seek(SeekFrom::Start(offset))
        .map_err(|source| archive_read_error(archive_path, source))?;
    let mut bytes = vec![0; len];
    archive_file
        .read_exact(&mut bytes)
        .map_err(|source| archive_read_error(archive_path, source))?;
    Ok(bytes)
}

fn zip_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn zip_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn invalid_zip_structure(archive_path: &Path, reason: &'static str) -> UpdateError {
    archive_read_error(
        archive_path,
        io::Error::new(io::ErrorKind::InvalidData, reason),
    )
}

fn extract_preflighted_tar_gz(
    archive_path: &Path,
    archive_file: &mut File,
    staging_dir: &StagingDirectory,
    validated: &ValidatedArchive,
) -> Result<(), UpdateError> {
    let mut archive = tar::Archive::new(MultiGzDecoder::new(&mut *archive_file));
    let mut entries = archive
        .entries()
        .map_err(|source| archive_read_error(archive_path, source))?
        .raw(true);

    for expected in &validated.entries {
        let mut entry = match entries.next() {
            Some(entry) => entry.map_err(|source| archive_read_error(archive_path, source))?,
            None => return Err(UpdateError::ArchiveChangedDuringExtraction),
        };
        let actual = validate_tar_entry(entry.header(), entry.path_bytes().as_ref(), archive_path)?;
        if actual != *expected {
            return Err(UpdateError::ArchiveChangedDuringExtraction);
        }

        match expected.kind {
            ArchiveEntryKind::Directory => {
                drain_archive_entry(&mut entry, archive_path)?;
                staging_dir.create_directory(&expected.output_path)?;
            }
            ArchiveEntryKind::Regular => {
                let output_path = staging_dir.output_path(&expected.output_path);
                let mut output = staging_dir.create_file(&expected.output_path)?;
                copy_archive_entry(&mut entry, &mut output, archive_path, &output_path)?;
                #[cfg(unix)]
                set_output_file_mode(
                    &output,
                    &output_path,
                    expected
                        .output_mode
                        .expect("validated regular entries have an output mode"),
                )?;
                sync_extracted_file(&output, &output_path)?;
            }
        }
    }

    match entries.next() {
        Some(Ok(_)) => return Err(UpdateError::ArchiveChangedDuringExtraction),
        Some(Err(source)) => return Err(archive_read_error(archive_path, source)),
        None => {}
    }
    drop(entries);
    let mut decoder = archive.into_inner();
    ensure_tar_padding(&mut decoder, archive_path)
}

fn extract_preflighted_zip(
    archive_path: &Path,
    archive_file: &mut File,
    staging_dir: &StagingDirectory,
    validated: &ValidatedArchive,
) -> Result<(), UpdateError> {
    let mut archive = ZipArchive::new(&mut *archive_file)
        .map_err(|source| zip_archive_read_error(archive_path, source))?;
    if archive.len() != validated.entries.len() {
        return Err(UpdateError::ArchiveChangedDuringExtraction);
    }

    for (index, expected) in validated.entries.iter().enumerate() {
        let mut entry = archive
            .by_index(index)
            .map_err(|source| zip_archive_read_error(archive_path, source))?;
        let actual = validate_zip_entry(&entry)?;
        if actual != *expected {
            return Err(UpdateError::ArchiveChangedDuringExtraction);
        }

        match expected.kind {
            ArchiveEntryKind::Directory => {
                drain_archive_entry(&mut entry, archive_path)?;
                staging_dir.create_directory(&expected.output_path)?;
            }
            ArchiveEntryKind::Regular => {
                let output_path = staging_dir.output_path(&expected.output_path);
                let mut output = staging_dir.create_file(&expected.output_path)?;
                copy_archive_entry(&mut entry, &mut output, archive_path, &output_path)?;
                #[cfg(unix)]
                set_output_file_mode(
                    &output,
                    &output_path,
                    expected
                        .output_mode
                        .expect("validated regular entries have an output mode"),
                )?;
                sync_extracted_file(&output, &output_path)?;
            }
        }
    }

    Ok(())
}

fn validate_tar_entry(
    header: &tar::Header,
    raw_path: &[u8],
    archive_path: &Path,
) -> Result<ValidatedEntry, UpdateError> {
    let kind = match header.entry_type() {
        tar::EntryType::Regular => ArchiveEntryKind::Regular,
        tar::EntryType::Directory => ArchiveEntryKind::Directory,
        _ => {
            return Err(UpdateError::UnsupportedArchiveEntryType {
                entry_type: header.entry_type().as_byte(),
            });
        }
    };
    let output_mode = match kind {
        ArchiveEntryKind::Regular => {
            Some(sanitize_regular_file_mode(header.mode().map_err(
                |source| archive_read_error(archive_path, source),
            )?))
        }
        ArchiveEntryKind::Directory => None,
    };
    let raw_path = std::str::from_utf8(raw_path).map_err(|_| UpdateError::ArchivePathNotUtf8)?;
    let (normalized_path, output_path) = normalize_archive_path(raw_path, kind)?;
    let filesystem_key = normalized_path.to_ascii_lowercase();
    Ok(ValidatedEntry {
        normalized_path,
        filesystem_key,
        output_path,
        kind,
        output_mode,
    })
}

const ZIP_UNIX_FILE_TYPE_MASK: u32 = 0o170000;
const ZIP_UNIX_REGULAR_FILE: u32 = 0o100000;
const ZIP_UNIX_DIRECTORY: u32 = 0o040000;

fn validate_zip_entry<R: Read + ?Sized>(
    entry: &zip::read::ZipFile<'_, R>,
) -> Result<ValidatedEntry, UpdateError> {
    let raw_path =
        std::str::from_utf8(entry.name_raw()).map_err(|_| UpdateError::ArchivePathNotUtf8)?;
    if entry.encrypted() {
        return Err(UpdateError::UnsupportedZipArchiveEntry {
            path: raw_path.to_owned(),
            reason: "it is encrypted",
        });
    }

    let unix_mode = entry.unix_mode();
    if entry.is_symlink() {
        return Err(UpdateError::UnsupportedZipArchiveEntry {
            path: raw_path.to_owned(),
            reason: "it is a symbolic link",
        });
    }
    if let Some(mode) = unix_mode {
        let file_type = mode & ZIP_UNIX_FILE_TYPE_MASK;
        if !matches!(file_type, 0 | ZIP_UNIX_REGULAR_FILE | ZIP_UNIX_DIRECTORY) {
            return Err(UpdateError::UnsupportedZipArchiveEntry {
                path: raw_path.to_owned(),
                reason: "it has a Unix special file type",
            });
        }
    }

    let kind = if raw_path.ends_with('/') {
        ArchiveEntryKind::Directory
    } else {
        ArchiveEntryKind::Regular
    };
    let output_mode = match kind {
        ArchiveEntryKind::Regular => Some(sanitize_regular_file_mode(unix_mode.unwrap_or(0o644))),
        ArchiveEntryKind::Directory => None,
    };
    let (normalized_path, output_path) = normalize_archive_path(raw_path, kind)?;
    let filesystem_key = normalized_path.to_ascii_lowercase();
    Ok(ValidatedEntry {
        normalized_path,
        filesystem_key,
        output_path,
        kind,
        output_mode,
    })
}

fn sanitize_regular_file_mode(source_mode: u32) -> u32 {
    0o644 | (source_mode & 0o111)
}

fn normalize_archive_path(
    raw_path: &str,
    kind: ArchiveEntryKind,
) -> Result<(String, PathBuf), UpdateError> {
    if raw_path.is_empty() {
        return Err(unsafe_archive_path(raw_path, "it is empty"));
    }
    if raw_path.contains('\\') {
        return Err(unsafe_archive_path(
            raw_path,
            "it contains a backslash path separator",
        ));
    }
    if raw_path.starts_with('/') || Path::new(raw_path).is_absolute() {
        return Err(unsafe_archive_path(raw_path, "it is absolute"));
    }
    if has_windows_prefix(raw_path) {
        return Err(unsafe_archive_path(
            raw_path,
            "it has a Windows path prefix",
        ));
    }

    let path = match raw_path.strip_suffix('/') {
        Some(path) if kind == ArchiveEntryKind::Directory => {
            if path.is_empty() || path.ends_with('/') {
                return Err(unsafe_archive_path(
                    raw_path,
                    "it contains an empty path component",
                ));
            }
            path
        }
        Some(_) => {
            return Err(unsafe_archive_path(
                raw_path,
                "a regular file must not end with a path separator",
            ));
        }
        None => raw_path,
    };

    let mut components = path.split('/');
    let first = components
        .next()
        .expect("a non-empty archive path has a first component");
    validate_archive_component(raw_path, first)?;

    let mut normalized_path = String::with_capacity(path.len());
    normalized_path.push_str(first);
    let mut output_path = PathBuf::from(first);
    for component in components {
        validate_archive_component(raw_path, component)?;
        normalized_path.push('/');
        normalized_path.push_str(component);
        output_path.push(component);
    }
    Ok((normalized_path, output_path))
}

fn validate_archive_component(raw_path: &str, component: &str) -> Result<(), UpdateError> {
    validate_portable_component(component).map_err(|reason| unsafe_archive_path(raw_path, reason))
}

fn has_windows_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        || path.starts_with("//?/")
        || path.starts_with("//./")
}

fn unsafe_archive_path(path: &str, reason: &'static str) -> UpdateError {
    UpdateError::UnsafeArchiveEntryPath {
        path: path.to_owned(),
        reason,
    }
}

fn regular_file_ancestor(path: &str, regular_paths: &HashMap<String, String>) -> Option<String> {
    path.match_indices('/')
        .find_map(|(index, _)| regular_paths.get(&path[..index]).cloned())
}

fn archive_path_descendant(path: &str, paths: &HashMap<String, String>) -> Option<String> {
    let mut prefix = String::with_capacity(path.len() + 1);
    prefix.push_str(path);
    prefix.push('/');
    paths.iter().find_map(|(candidate_key, candidate_path)| {
        candidate_key
            .starts_with(&prefix)
            .then(|| candidate_path.clone())
    })
}

impl StagingDirectory {
    fn open(staging_dir: &Path) -> Result<Self, UpdateError> {
        let path = normalize_staging_directory(staging_dir)?;

        #[cfg(unix)]
        {
            let root = open_staging_directory(&path)?;
            let staging_directory = Self { path, root };
            staging_directory.ensure_empty()?;
            Ok(staging_directory)
        }

        #[cfg(windows)]
        {
            let retained_directories = open_windows_staging_directories(&path)?;
            ensure_empty_windows_staging_directory(&path)?;
            Ok(Self {
                path,
                retained_directories: RefCell::new(retained_directories),
            })
        }

        #[cfg(not(any(unix, windows)))]
        {
            ensure_empty_staging_directory(&path)?;
            Ok(Self { path })
        }
    }

    fn output_path(&self, relative_path: &Path) -> PathBuf {
        self.path.join(relative_path)
    }

    fn create_directory(&self, relative_path: &Path) -> Result<(), UpdateError> {
        #[cfg(unix)]
        {
            self.validate_relative_path(relative_path, false)?;
            let output_path = self.output_path(relative_path);
            self.open_or_create_directories(relative_path, &output_path)?;
            Ok(())
        }

        #[cfg(windows)]
        {
            self.validate_relative_path(relative_path, false)?;
            self.open_or_create_windows_directories(relative_path)
        }

        #[cfg(not(any(unix, windows)))]
        {
            self.validate_relative_path(relative_path, false)?;
            let output_path = self.output_path(relative_path);
            create_parent_directories(&self.path, relative_path)?;
            ensure_output_directory(&output_path)
        }
    }

    fn create_file(&self, relative_path: &Path) -> Result<File, UpdateError> {
        #[cfg(unix)]
        {
            self.validate_relative_path(relative_path, true)?;
            let output_path = self.output_path(relative_path);
            let parent = self.open_or_create_directories(
                relative_path.parent().unwrap_or_else(|| Path::new("")),
                &output_path,
            )?;
            let parent_fd = parent
                .as_ref()
                .map_or(self.root.as_raw_fd(), |directory| directory.as_raw_fd());
            let leaf = relative_path
                .file_name()
                .expect("validated relative paths always have a component");
            let leaf = CString::new(leaf.as_bytes())
                .map_err(|_| self.unsafe_relative_path_error(relative_path, true))?;
            create_output_file_at(parent_fd, &leaf, &output_path)
        }

        #[cfg(windows)]
        {
            self.validate_relative_path(relative_path, true)?;
            let output_path = self.output_path(relative_path);
            let parent = relative_path.parent().unwrap_or_else(|| Path::new(""));
            self.open_or_create_windows_directories(parent)?;
            create_new_windows_output_file(&output_path)
        }

        #[cfg(not(any(unix, windows)))]
        {
            self.validate_relative_path(relative_path, true)?;
            let output_path = self.output_path(relative_path);
            create_parent_directories(&self.path, relative_path)?;
            create_new_output_file(&output_path)
        }
    }
    fn inspect_file(&self, relative_path: &Path) -> Result<fs::Metadata, UpdateError> {
        self.validate_relative_path(relative_path, true)?;
        let output_path = self.output_path(relative_path);

        #[cfg(unix)]
        {
            let parent = self.open_existing_directories(
                relative_path.parent().unwrap_or_else(|| Path::new("")),
                &output_path,
            )?;
            let parent_fd = parent
                .as_ref()
                .map_or(self.root.as_raw_fd(), |directory| directory.as_raw_fd());
            let leaf = relative_path
                .file_name()
                .expect("validated relative paths always have a component");
            let leaf = CString::new(leaf.as_bytes())
                .map_err(|_| self.unsafe_relative_path_error(relative_path, true))?;
            let file = open_output_file_for_read_at(parent_fd, &leaf, &output_path)?;
            return file
                .metadata()
                .map_err(|source| UpdateError::InspectExtractionPath {
                    path: output_path,
                    source,
                });
        }

        #[cfg(windows)]
        {
            let parent = relative_path.parent().unwrap_or_else(|| Path::new(""));
            self.open_existing_windows_directories(parent)?;
            let file = open_windows_output_file_for_read(&output_path)?;
            return file
                .metadata()
                .map_err(|source| UpdateError::InspectExtractionPath {
                    path: output_path,
                    source,
                });
        }

        #[cfg(not(any(unix, windows)))]
        {
            return fs::symlink_metadata(&output_path).map_err(|source| {
                UpdateError::InspectExtractionPath {
                    path: output_path,
                    source,
                }
            });
        }
    }

    fn sync_extracted_directories(&self, validated: &ValidatedArchive) -> Result<(), UpdateError> {
        #[cfg(unix)]
        {
            let mut directories = HashSet::new();
            directories.insert(PathBuf::new());
            for entry in &validated.entries {
                let directory = match entry.kind {
                    ArchiveEntryKind::Directory => Some(entry.output_path.as_path()),
                    ArchiveEntryKind::Regular => entry.output_path.parent(),
                };
                if let Some(directory) = directory {
                    directories.insert(directory.to_path_buf());
                }
            }
            let mut directories: Vec<_> = directories.into_iter().collect();
            directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));

            for relative_path in directories {
                let output_path = self.output_path(&relative_path);
                let directory = self.open_existing_directories(&relative_path, &output_path)?;
                let directory = directory.as_ref().unwrap_or(&self.root);
                directory
                    .sync_all()
                    .map_err(|source| UpdateError::SyncExtractionDirectory {
                        path: output_path,
                        source,
                    })?;
            }
            return Ok(());
        }

        #[cfg(not(unix))]
        {
            let _ = validated;
            Ok(())
        }
    }

    fn read_file(&self, relative_path: &Path) -> Result<Vec<u8>, UpdateError> {
        self.validate_relative_path(relative_path, true)?;
        let output_path = self.output_path(relative_path);

        #[cfg(unix)]
        {
            let parent = self.open_existing_directories(
                relative_path.parent().unwrap_or_else(|| Path::new("")),
                &output_path,
            )?;
            let parent_fd = parent
                .as_ref()
                .map_or(self.root.as_raw_fd(), |directory| directory.as_raw_fd());
            let leaf = relative_path
                .file_name()
                .expect("validated relative paths always have a component");
            let leaf = CString::new(leaf.as_bytes())
                .map_err(|_| self.unsafe_relative_path_error(relative_path, true))?;
            let mut file = open_output_file_for_read_at(parent_fd, &leaf, &output_path)?;
            let metadata =
                file.metadata()
                    .map_err(|source| UpdateError::InspectExtractionPath {
                        path: output_path.clone(),
                        source,
                    })?;
            if !metadata.is_file() {
                return Err(UpdateError::UnsafeExtractionFile { path: output_path });
            }

            let mut contents = Vec::new();
            file.read_to_end(&mut contents).map_err(|source| {
                UpdateError::InspectExtractionPath {
                    path: output_path,
                    source,
                }
            })?;
            Ok(contents)
        }

        #[cfg(windows)]
        {
            let parent = relative_path.parent().unwrap_or_else(|| Path::new(""));
            self.open_existing_windows_directories(parent)?;
            let mut file = open_windows_output_file_for_read(&output_path)?;
            let mut contents = Vec::new();
            file.read_to_end(&mut contents).map_err(|source| {
                UpdateError::InspectExtractionPath {
                    path: output_path,
                    source,
                }
            })?;
            Ok(contents)
        }

        #[cfg(not(any(unix, windows)))]
        {
            fs::read(&output_path).map_err(|source| UpdateError::InspectExtractionPath {
                path: output_path,
                source,
            })
        }
    }

    fn validate_relative_path(&self, relative_path: &Path, file: bool) -> Result<(), UpdateError> {
        if strictly_normal_relative_path(relative_path) {
            Ok(())
        } else {
            Err(self.unsafe_relative_path_error(relative_path, file))
        }
    }

    fn unsafe_relative_path_error(&self, relative_path: &Path, file: bool) -> UpdateError {
        let path = self.output_path(relative_path);
        if file {
            UpdateError::UnsafeExtractionFile { path }
        } else {
            UpdateError::UnsafeExtractionPath { path }
        }
    }

    #[cfg(unix)]
    fn open_or_create_directories(
        &self,
        relative_path: &Path,
        output_path: &Path,
    ) -> Result<Option<File>, UpdateError> {
        let mut directory: Option<File> = None;
        for component in relative_path.components() {
            let Component::Normal(component) = component else {
                unreachable!("validated relative paths contain only normal components");
            };
            let component = CString::new(component.as_bytes())
                .map_err(|_| self.unsafe_relative_path_error(relative_path, false))?;
            let parent_fd = directory
                .as_ref()
                .map_or(self.root.as_raw_fd(), |directory| directory.as_raw_fd());
            directory = Some(open_or_create_output_directory_at(
                parent_fd,
                &component,
                output_path,
            )?);
        }
        Ok(directory)
    }

    #[cfg(unix)]
    fn open_existing_directories(
        &self,
        relative_path: &Path,
        output_path: &Path,
    ) -> Result<Option<File>, UpdateError> {
        let mut directory: Option<File> = None;
        for component in relative_path.components() {
            let Component::Normal(component) = component else {
                unreachable!("validated relative paths contain only normal components");
            };
            let component = CString::new(component.as_bytes())
                .map_err(|_| self.unsafe_relative_path_error(relative_path, false))?;
            let parent_fd = directory
                .as_ref()
                .map_or(self.root.as_raw_fd(), |directory| directory.as_raw_fd());
            directory = Some(open_existing_output_directory_at(
                parent_fd,
                &component,
                output_path,
            )?);
        }
        Ok(directory)
    }

    #[cfg(unix)]
    fn ensure_empty(&self) -> Result<(), UpdateError> {
        // SAFETY: the root `File` owns a valid directory descriptor; `fcntl` duplicates it.
        let duplicate_fd = unsafe { libc::fcntl(self.root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate_fd == -1 {
            return Err(UpdateError::InspectStagingDirectory {
                path: self.path.clone(),
                source: io::Error::last_os_error(),
            });
        }

        // SAFETY: `duplicate_fd` is valid and remains owned here if `fdopendir` fails.
        let directory = unsafe { libc::fdopendir(duplicate_fd) };
        if directory.is_null() {
            let source = io::Error::last_os_error();
            // SAFETY: `fdopendir` did not take ownership of this duplicated descriptor.
            unsafe {
                libc::close(duplicate_fd);
            }
            return Err(UpdateError::InspectStagingDirectory {
                path: self.path.clone(),
                source,
            });
        }
        let directory = DirectoryStream(directory);

        loop {
            clear_readdir_errno();
            // SAFETY: `directory` owns a valid `DIR*` for the lifetime of this loop.
            let entry = unsafe { libc::readdir(directory.0) };
            if entry.is_null() {
                let errno = readdir_errno();
                if errno == 0 {
                    return Ok(());
                }
                return Err(UpdateError::InspectStagingDirectory {
                    path: self.path.clone(),
                    source: io::Error::from_raw_os_error(errno),
                });
            }
            // SAFETY: `readdir` returned a valid entry whose name is NUL-terminated.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                return Err(UpdateError::NonEmptyStagingDirectory {
                    path: self.path.clone(),
                });
            }
        }
    }
    #[cfg(windows)]
    fn open_or_create_windows_directories(&self, relative_path: &Path) -> Result<(), UpdateError> {
        self.open_windows_directories(relative_path, true)
    }

    #[cfg(windows)]
    fn open_existing_windows_directories(&self, relative_path: &Path) -> Result<(), UpdateError> {
        self.open_windows_directories(relative_path, false)
    }

    #[cfg(windows)]
    fn open_windows_directories(
        &self,
        relative_path: &Path,
        create_missing: bool,
    ) -> Result<(), UpdateError> {
        let mut current = self.path.clone();
        for component in relative_path.components() {
            let Component::Normal(component) = component else {
                unreachable!("validated relative paths contain only normal components");
            };
            current.push(component);
            if self.windows_directory_is_retained(&current) {
                continue;
            }

            let handle = if create_missing {
                create_or_open_windows_output_directory(&current)?
            } else {
                open_windows_output_directory(&current)?
            };
            self.retained_directories
                .borrow_mut()
                .push(RetainedDirectory {
                    path: current.clone(),
                    _handle: handle,
                });
        }
        Ok(())
    }

    #[cfg(windows)]
    fn windows_directory_is_retained(&self, path: &Path) -> bool {
        self.retained_directories
            .borrow()
            .iter()
            .any(|directory| directory.path.as_path() == path)
    }
}

fn strictly_normal_relative_path(path: &Path) -> bool {
    #[cfg(unix)]
    {
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty()
            || bytes
                .split(|byte| *byte == b'/')
                .any(|component| component.is_empty() || component == b"." || component == b"..")
        {
            return false;
        }
    }

    let mut components = path.components();
    let mut has_component = false;
    while let Some(component) = components.next() {
        let Component::Normal(component) = component else {
            return false;
        };
        let Some(component) = component.to_str() else {
            return false;
        };
        if validate_portable_component(component).is_err() {
            return false;
        }
        has_component = true;
    }
    has_component
}

#[cfg(unix)]
fn open_staging_directory(path: &Path) -> Result<File, UpdateError> {
    let root_name = CStr::from_bytes_with_nul(b"/\0").expect("a slash is NUL-terminated");
    let mut directory = open_staging_directory_at(libc::AT_FDCWD, root_name, path)?;

    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(component) => {
                let component = CString::new(component.as_bytes()).map_err(|_| {
                    UpdateError::UnsafeStagingDirectory {
                        path: path.to_path_buf(),
                    }
                })?;
                directory = open_staging_directory_at(directory.as_raw_fd(), &component, path)?;
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(UpdateError::UnsafeStagingDirectory {
                    path: path.to_path_buf(),
                });
            }
        }
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_staging_directory_at(
    parent_fd: RawFd,
    component: &CStr,
    path: &Path,
) -> Result<File, UpdateError> {
    // SAFETY: `parent_fd` is an open directory descriptor and `component` is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            component.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        let source = io::Error::last_os_error();
        return Err(staging_directory_open_error(path, source));
    }
    // SAFETY: `openat` returned a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn staging_directory_open_error(path: &Path, source: io::Error) -> UpdateError {
    if unsafe_directory_open_error(&source) {
        UpdateError::UnsafeStagingDirectory {
            path: path.to_path_buf(),
        }
    } else {
        UpdateError::InspectStagingDirectory {
            path: path.to_path_buf(),
            source,
        }
    }
}

#[cfg(unix)]
fn open_or_create_output_directory_at(
    parent_fd: RawFd,
    component: &CStr,
    output_path: &Path,
) -> Result<File, UpdateError> {
    // SAFETY: `parent_fd` is an open directory descriptor and `component` is NUL-terminated.
    let result = unsafe { libc::mkdirat(parent_fd, component.as_ptr(), 0o777) };
    if result == -1 {
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(libc::EEXIST) {
            if unsafe_directory_open_error(&source) {
                return Err(UpdateError::UnsafeExtractionPath {
                    path: output_path.to_path_buf(),
                });
            }
            return Err(UpdateError::CreateExtractionDirectory {
                path: output_path.to_path_buf(),
                source,
            });
        }
    }

    // SAFETY: `parent_fd` is an open directory descriptor and `component` is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            component.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        let source = io::Error::last_os_error();
        if unsafe_directory_open_error(&source) {
            return Err(UpdateError::UnsafeExtractionPath {
                path: output_path.to_path_buf(),
            });
        }
        return Err(UpdateError::InspectExtractionPath {
            path: output_path.to_path_buf(),
            source,
        });
    }
    // SAFETY: `openat` returned a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn open_existing_output_directory_at(
    parent_fd: RawFd,
    component: &CStr,
    output_path: &Path,
) -> Result<File, UpdateError> {
    // SAFETY: `parent_fd` is an open directory descriptor and `component` is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            component.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        let source = io::Error::last_os_error();
        if unsafe_directory_open_error(&source) {
            return Err(UpdateError::UnsafeExtractionPath {
                path: output_path.to_path_buf(),
            });
        }
        return Err(UpdateError::InspectExtractionPath {
            path: output_path.to_path_buf(),
            source,
        });
    }
    // SAFETY: `openat` returned a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn open_output_file_for_read_at(
    parent_fd: RawFd,
    component: &CStr,
    output_path: &Path,
) -> Result<File, UpdateError> {
    // SAFETY: `parent_fd` is an open directory descriptor and `component` is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            component.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        let source = io::Error::last_os_error();
        if matches!(
            source.raw_os_error(),
            Some(libc::ELOOP) | Some(libc::EISDIR) | Some(libc::ENOTDIR)
        ) {
            return Err(UpdateError::UnsafeExtractionFile {
                path: output_path.to_path_buf(),
            });
        }
        return Err(UpdateError::InspectExtractionPath {
            path: output_path.to_path_buf(),
            source,
        });
    }
    // SAFETY: `openat` returned a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn create_output_file_at(
    parent_fd: RawFd,
    component: &CStr,
    output_path: &Path,
) -> Result<File, UpdateError> {
    // SAFETY: `parent_fd` is an open directory descriptor and `component` is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            component.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd == -1 {
        let source = io::Error::last_os_error();
        if matches!(
            source.raw_os_error(),
            Some(libc::EEXIST) | Some(libc::EISDIR) | Some(libc::ELOOP) | Some(libc::ENOTDIR)
        ) {
            return Err(UpdateError::UnsafeExtractionFile {
                path: output_path.to_path_buf(),
            });
        }
        return Err(UpdateError::CreateExtractionFile {
            path: output_path.to_path_buf(),
            source,
        });
    }
    // SAFETY: `openat` returned a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn unsafe_directory_open_error(source: &io::Error) -> bool {
    matches!(
        source.raw_os_error(),
        Some(libc::ELOOP) | Some(libc::ENOTDIR)
    )
}

#[cfg(windows)]
enum WindowsDirectoryOpenError {
    Unsafe,
    Inspect(io::Error),
}

#[cfg(windows)]
fn open_windows_staging_directories(path: &Path) -> Result<Vec<RetainedDirectory>, UpdateError> {
    let mut current = PathBuf::new();
    let mut directories = Vec::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            root @ Component::RootDir => {
                current.push(root.as_os_str());
                directories.push(RetainedDirectory {
                    path: current.clone(),
                    _handle: open_windows_staging_directory(&current)?,
                });
            }
            Component::Normal(component) => {
                current.push(component);
                directories.push(RetainedDirectory {
                    path: current.clone(),
                    _handle: open_windows_staging_directory(&current)?,
                });
            }
            Component::CurDir | Component::ParentDir => {
                return Err(UpdateError::UnsafeStagingDirectory {
                    path: path.to_path_buf(),
                });
            }
        }
    }

    if directories.is_empty() {
        return Err(UpdateError::UnsafeStagingDirectory {
            path: path.to_path_buf(),
        });
    }
    Ok(directories)
}

#[cfg(windows)]
fn open_windows_staging_directory(path: &Path) -> Result<File, UpdateError> {
    open_windows_non_reparse_directory(path).map_err(|error| match error {
        WindowsDirectoryOpenError::Unsafe => UpdateError::UnsafeStagingDirectory {
            path: path.to_path_buf(),
        },
        WindowsDirectoryOpenError::Inspect(source) => UpdateError::InspectStagingDirectory {
            path: path.to_path_buf(),
            source,
        },
    })
}

#[cfg(windows)]
fn open_windows_output_directory(path: &Path) -> Result<File, UpdateError> {
    open_windows_non_reparse_directory(path).map_err(|error| match error {
        WindowsDirectoryOpenError::Unsafe => UpdateError::UnsafeExtractionPath {
            path: path.to_path_buf(),
        },
        WindowsDirectoryOpenError::Inspect(source) => UpdateError::InspectExtractionPath {
            path: path.to_path_buf(),
            source,
        },
    })
}

#[cfg(windows)]
fn open_windows_non_reparse_directory(path: &Path) -> Result<File, WindowsDirectoryOpenError> {
    use windows::{
        Win32::{
            Foundation::HANDLE,
            Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
                FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                FILE_SHARE_WRITE, GetFileInformationByHandle, OPEN_EXISTING, READ_CONTROL,
            },
        },
        core::PCWSTR,
    };

    let wide = wide_windows_path(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            (FILE_READ_ATTRIBUTES | READ_CONTROL).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|source| WindowsDirectoryOpenError::Inspect(io::Error::other(source)))?;
    let directory = own_windows_file(handle);
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(directory.as_raw_handle()), &mut information) }
        .map_err(|source| WindowsDirectoryOpenError::Inspect(io::Error::other(source)))?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(WindowsDirectoryOpenError::Unsafe);
    }
    Ok(directory)
}

#[cfg(windows)]
fn own_windows_file(handle: windows::Win32::Foundation::HANDLE) -> File {
    // SAFETY: `CreateFileW` returned this fresh handle, which `File` exclusively owns and closes.
    unsafe { File::from_raw_handle(handle.0) }
}

#[cfg(windows)]
fn wide_windows_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
fn ensure_empty_windows_staging_directory(staging_dir: &Path) -> Result<(), UpdateError> {
    use windows::{
        Win32::{
            Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES, GetLastError},
            Storage::FileSystem::{FindClose, FindFirstFileW, FindNextFileW, WIN32_FIND_DATAW},
        },
        core::PCWSTR,
    };

    let pattern = staging_dir.join("*");
    let wide = wide_windows_path(&pattern);
    let mut entry = WIN32_FIND_DATAW::default();
    let handle = match unsafe { FindFirstFileW(PCWSTR(wide.as_ptr()), &mut entry) } {
        Ok(handle) => handle,
        Err(_) if unsafe { GetLastError() } == ERROR_FILE_NOT_FOUND => return Ok(()),
        Err(source) => {
            return Err(UpdateError::InspectStagingDirectory {
                path: staging_dir.to_path_buf(),
                source: io::Error::other(source),
            });
        }
    };

    let result = (|| loop {
        if !windows_dot_directory_entry(&entry) {
            return Err(UpdateError::NonEmptyStagingDirectory {
                path: staging_dir.to_path_buf(),
            });
        }
        match unsafe { FindNextFileW(handle, &mut entry) } {
            Ok(()) => {}
            Err(_) if unsafe { GetLastError() } == ERROR_NO_MORE_FILES => return Ok(()),
            Err(source) => {
                return Err(UpdateError::InspectStagingDirectory {
                    path: staging_dir.to_path_buf(),
                    source: io::Error::other(source),
                });
            }
        }
    })();
    let _ = unsafe { FindClose(handle) };
    result
}

#[cfg(windows)]
fn windows_dot_directory_entry(
    entry: &windows::Win32::Storage::FileSystem::WIN32_FIND_DATAW,
) -> bool {
    entry.cFileName[0] == b'.' as u16
        && (entry.cFileName[1] == 0
            || (entry.cFileName[1] == b'.' as u16 && entry.cFileName[2] == 0))
}

#[cfg(windows)]
fn create_or_open_windows_output_directory(path: &Path) -> Result<File, UpdateError> {
    use windows::{
        Win32::{
            Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GetLastError},
            Storage::FileSystem::CreateDirectoryW,
        },
        core::PCWSTR,
    };

    let wide = wide_windows_path(path);
    match unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), None) } {
        Ok(()) => {}
        Err(source) => {
            let error = unsafe { GetLastError() };
            if error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS {
                return Err(UpdateError::CreateExtractionDirectory {
                    path: path.to_path_buf(),
                    source: io::Error::other(source),
                });
            }
        }
    }
    open_windows_output_directory(path)
}

#[cfg(windows)]
fn create_new_windows_output_file(path: &Path) -> Result<File, UpdateError> {
    use windows::{
        Win32::{
            Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GENERIC_WRITE, GetLastError},
            Storage::FileSystem::{
                CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
                FILE_SHARE_READ, FILE_SHARE_WRITE,
            },
        },
        core::PCWSTR,
    };

    let wide = wide_windows_path(path);
    match unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    } {
        Ok(handle) => Ok(own_windows_file(handle)),
        Err(source) => {
            let error = unsafe { GetLastError() };
            if error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS {
                Err(UpdateError::UnsafeExtractionFile {
                    path: path.to_path_buf(),
                })
            } else {
                Err(UpdateError::CreateExtractionFile {
                    path: path.to_path_buf(),
                    source: io::Error::other(source),
                })
            }
        }
    }
}

#[cfg(windows)]
fn open_windows_output_file_for_read(path: &Path) -> Result<File, UpdateError> {
    use windows::{
        Win32::{
            Foundation::{GENERIC_READ, HANDLE},
            Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
                FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK,
                GetFileInformationByHandle, GetFileType, OPEN_EXISTING,
            },
        },
        core::PCWSTR,
    };

    let wide = wide_windows_path(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|source| UpdateError::InspectExtractionPath {
        path: path.to_path_buf(),
        source: io::Error::other(source),
    })?;
    let file = own_windows_file(handle);
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information) }.map_err(
        |source| UpdateError::InspectExtractionPath {
            path: path.to_path_buf(),
            source: io::Error::other(source),
        },
    )?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || unsafe { GetFileType(HANDLE(file.as_raw_handle())) } != FILE_TYPE_DISK
    {
        return Err(UpdateError::UnsafeExtractionFile {
            path: path.to_path_buf(),
        });
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn ensure_empty_staging_directory(staging_dir: &Path) -> Result<(), UpdateError> {
    let mut entries =
        fs::read_dir(staging_dir).map_err(|source| UpdateError::InspectStagingDirectory {
            path: staging_dir.to_path_buf(),
            source,
        })?;
    if entries
        .next()
        .transpose()
        .map_err(|source| UpdateError::InspectStagingDirectory {
            path: staging_dir.to_path_buf(),
            source,
        })?
        .is_some()
    {
        return Err(UpdateError::NonEmptyStagingDirectory {
            path: staging_dir.to_path_buf(),
        });
    }
    Ok(())
}

fn normalize_staging_directory(staging_dir: &Path) -> Result<PathBuf, UpdateError> {
    let absolute = if staging_dir.is_absolute() {
        staging_dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| UpdateError::InspectStagingDirectory {
                path: staging_dir.to_path_buf(),
                source,
            })?
            .join(staging_dir)
    };
    #[cfg(unix)]
    let final_component_index = absolute.components().count().saturating_sub(1);
    let mut normalized = PathBuf::new();

    // Rebuild components so a trailing separator cannot make metadata follow a final symlink.
    for (_component_index, component) in absolute.components().enumerate() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(UpdateError::UnsafeStagingDirectory {
                    path: staging_dir.to_path_buf(),
                });
            }
            Component::Normal(component) => {
                normalized.push(component);
                let metadata = fs::symlink_metadata(&normalized).map_err(|source| {
                    UpdateError::InspectStagingDirectory {
                        path: normalized.clone(),
                        source,
                    }
                })?;
                if metadata.file_type().is_symlink() {
                    #[cfg(unix)]
                    if _component_index != final_component_index {
                        // macOS exposes its physical temporary directory through /var. Resolve
                        // only an ancestor, then retain a physical path for the pinned root.
                        normalized = fs::canonicalize(&normalized).map_err(|source| {
                            UpdateError::InspectStagingDirectory {
                                path: normalized.clone(),
                                source,
                            }
                        })?;
                        let target_metadata = fs::metadata(&normalized).map_err(|source| {
                            UpdateError::InspectStagingDirectory {
                                path: normalized.clone(),
                                source,
                            }
                        })?;
                        if target_metadata.is_dir() {
                            continue;
                        }
                    }
                    return Err(UpdateError::UnsafeStagingDirectory { path: normalized });
                }
                if !metadata.is_dir() {
                    return Err(UpdateError::UnsafeStagingDirectory { path: normalized });
                }
            }
        }
    }
    Ok(normalized)
}

#[cfg(not(any(unix, windows)))]
fn create_parent_directories(staging_dir: &Path, relative_path: &Path) -> Result<(), UpdateError> {
    let parent = relative_path.parent().unwrap_or_else(|| Path::new(""));
    let mut current = staging_dir.to_path_buf();
    for component in parent.components() {
        current.push(component.as_os_str());
        ensure_output_directory(&current)?;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_output_directory(path: &Path) -> Result<(), UpdateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_output_directory_metadata(path, metadata),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(UpdateError::CreateExtractionDirectory {
                        path: path.to_path_buf(),
                        source,
                    });
                }
            }
            validate_existing_output_directory(path)
        }
        Err(source) => Err(UpdateError::InspectExtractionPath {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(not(any(unix, windows)))]
fn validate_existing_output_directory(path: &Path) -> Result<(), UpdateError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| UpdateError::InspectExtractionPath {
            path: path.to_path_buf(),
            source,
        })?;
    validate_output_directory_metadata(path, metadata)
}

#[cfg(not(any(unix, windows)))]
fn validate_output_directory_metadata(
    path: &Path,
    metadata: fs::Metadata,
) -> Result<(), UpdateError> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(UpdateError::UnsafeExtractionPath {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn create_new_output_file(path: &Path) -> Result<File, UpdateError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(UpdateError::UnsafeExtractionFile {
                path: path.to_path_buf(),
            });
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(UpdateError::InspectExtractionPath {
                path: path.to_path_buf(),
                source,
            });
        }
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    options
        .open(path)
        .map_err(|source| UpdateError::CreateExtractionFile {
            path: path.to_path_buf(),
            source,
        })
}

fn drain_archive_entry(entry: &mut impl Read, archive_path: &Path) -> Result<(), UpdateError> {
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = entry
            .read(&mut buffer)
            .map_err(|source| archive_read_error(archive_path, source))?;
        if read == 0 {
            return Ok(());
        }
    }
}

fn copy_archive_entry(
    entry: &mut impl Read,
    output: &mut File,
    archive_path: &Path,
    output_path: &Path,
) -> Result<(), UpdateError> {
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = entry
            .read(&mut buffer)
            .map_err(|source| archive_read_error(archive_path, source))?;
        if read == 0 {
            return Ok(());
        }
        output
            .write_all(&buffer[..read])
            .map_err(|source| UpdateError::WriteExtractedFile {
                path: output_path.to_path_buf(),
                source,
            })?;
    }
}

#[cfg(unix)]
fn set_output_file_mode(output: &File, output_path: &Path, mode: u32) -> Result<(), UpdateError> {
    // SAFETY: `output` owns the descriptor for the newly created regular file.
    if unsafe { libc::fchmod(output.as_raw_fd(), mode as libc::mode_t) } == -1 {
        return Err(UpdateError::SetExtractedFilePermissions {
            path: output_path.to_path_buf(),
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

fn sync_extracted_file(output: &File, output_path: &Path) -> Result<(), UpdateError> {
    output
        .sync_all()
        .map_err(|source| UpdateError::SyncExtractedFile {
            path: output_path.to_path_buf(),
            source,
        })
}

fn ensure_tar_padding(reader: &mut impl Read, archive_path: &Path) -> Result<(), UpdateError> {
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| archive_read_error(archive_path, source))?;
        if read == 0 {
            return Ok(());
        }
        if buffer[..read].iter().any(|byte| *byte != 0) {
            return Err(UpdateError::ArchiveTrailingData);
        }
    }
}

fn archive_snapshot_error(archive_path: &Path, source: io::Error) -> UpdateError {
    UpdateError::SnapshotVerifiedArchive {
        path: archive_path.to_path_buf(),
        source,
    }
}

fn archive_read_error(archive_path: &Path, source: io::Error) -> UpdateError {
    UpdateError::ReadVerifiedArchive {
        path: archive_path.to_path_buf(),
        source,
    }
}

fn zip_archive_read_error(archive_path: &Path, source: zip::result::ZipError) -> UpdateError {
    archive_read_error(archive_path, source.into())
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{Cursor, Write},
        path::Path,
    };

    use flate2::{Compression, write::GzEncoder};
    use tempfile::tempdir;

    use super::{ArchiveKind, extract_verified_archive};
    use crate::update::manifest::UpdateError;

    #[test]
    fn archive_extraction_rejects_parent_traversal_before_writing_files() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("malicious.tar.gz");
        write_parent_traversal_archive(&archive_path);

        let staging_dir = sandbox.path().join("staging");
        std::fs::create_dir(&staging_dir).expect("staging directory should be created");
        let escaped_path = sandbox.path().join("outside");

        let error = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz)
            .expect_err("parent traversal archive must be rejected");

        let _: UpdateError = error;
        assert!(
            !escaped_path.exists(),
            "archive extraction must not create files outside staging"
        );
        assert!(
            !staging_dir.join("payload/rqbit-tunnel").exists(),
            "archive extraction must reject the archive before writing payload files"
        );
    }

    fn write_parent_traversal_archive(path: &Path) {
        let archive_file = File::create(path).expect("archive file should be created");
        let encoder = GzEncoder::new(archive_file, Compression::default());
        let mut archive = tar::Builder::new(encoder);

        append_regular_file(
            &mut archive,
            "payload/rqbit-tunnel",
            b"valid-looking payload",
        );
        append_regular_file(&mut archive, "../outside", b"must not escape staging");

        let encoder = archive
            .into_inner()
            .expect("tar archive should be finalized");
        encoder.finish().expect("gzip archive should be finalized");
    }

    fn append_regular_file<W: Write>(archive: &mut tar::Builder<W>, path: &str, contents: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_size(contents.len() as u64);
        assert!(
            path.is_ascii() && path.len() <= 100,
            "fixture path must fit the tar name field"
        );
        let header_bytes = header.as_mut_bytes();
        header_bytes[..100].fill(0);
        header_bytes[..path.len()].copy_from_slice(path.as_bytes());
        header.set_cksum();

        archive
            .append(&header, Cursor::new(contents))
            .expect("archive entry should be written");
    }
}

#[cfg(test)]
mod contract_tests {
    use std::{
        fs::{self, File},
        io::{self, Cursor, Write},
        path::Path,
    };

    use flate2::{Compression, write::GzEncoder};
    use tempfile::tempdir;
    use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

    #[cfg(unix)]
    use super::StagingDirectory;
    use super::{ArchiveKind, StagedBundle, extract_verified_archive};
    use crate::update::manifest::UpdateError;
    #[cfg(unix)]
    use std::ffi::CString;
    #[cfg(unix)]
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt, io::AsRawFd};

    #[test]
    fn archive_extraction_returns_the_common_top_level_bundle_directory() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("bundle.tar.gz");
        write_tar_gz(&archive_path, |archive| {
            append_directory(archive, "bundle");
            append_regular_file(archive, "bundle/rqbit-tunnel", b"payload");
            append_regular_file(archive, "bundle/NOTICE", b"notice");
        });

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        let bundle: StagedBundle =
            extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz)
                .expect("valid bundle should be extracted");

        assert_eq!(bundle.relative_directory(), Path::new("bundle"));
        assert_eq!(
            bundle
                .read_file(Path::new("rqbit-tunnel"))
                .expect("payload should be read through the staged bundle"),
            b"payload"
        );
        assert_eq!(
            bundle
                .read_file(Path::new("NOTICE"))
                .expect("notice should be read through the staged bundle"),
            b"notice"
        );
        assert_eq!(
            fs::read_dir(&staging_dir)
                .expect("staging directory should be readable")
                .count(),
            1,
            "staging must contain only the returned bundle directory"
        );
    }

    #[cfg(unix)]
    #[test]
    fn archive_extraction_allows_a_symlinked_staging_ancestor() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("bundle.tar.gz");
        write_tar_gz(&archive_path, |archive| {
            append_directory(archive, "bundle");
            append_regular_file(archive, "bundle/rqbit-tunnel", b"payload");
        });

        let physical_parent = sandbox.path().join("physical-parent");
        fs::create_dir(&physical_parent).expect("physical parent directory should be created");
        let symlinked_parent = sandbox.path().join("symlinked-parent");
        std::os::unix::fs::symlink(&physical_parent, &symlinked_parent)
            .expect("staging parent symlink should be created");

        let staging_dir = symlinked_parent.join("staging");
        fs::create_dir(physical_parent.join("staging"))
            .expect("staging directory should be created through its physical path");

        let bundle = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz)
            .expect("a staging directory below a symlinked ancestor should be usable");

        assert_eq!(bundle.relative_directory(), Path::new("bundle"));
        assert_eq!(
            fs::read(physical_parent.join("staging/bundle/rqbit-tunnel"))
                .expect("payload should be created below the physical staging directory"),
            b"payload"
        );
    }

    #[test]
    fn staged_client_bundle_requires_the_update_helper() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("bundle.tar.gz");
        write_tar_gz(&archive_path, |archive| {
            append_directory(archive, "bundle");
            append_regular_file_with_mode(archive, "bundle/rqbit-tunnel", b"payload", 0o755);
        });
        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        let bundle = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz)
            .expect("safe incomplete bundle should extract");

        assert!(
            bundle.validate_client_payload_layout().is_err(),
            "a managed bundle without its updater must not activate"
        );
    }

    #[test]
    fn staged_client_bundle_requires_the_tray_companion() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("bundle.tar.gz");
        let executable_suffix = crate::version::current_exe_suffix();
        let payload = format!("bundle/rqbit-tunnel{executable_suffix}");
        let updater = format!("bundle/rqbit-tunnel-updater{executable_suffix}");
        write_tar_gz(&archive_path, |archive| {
            append_directory(archive, "bundle");
            append_regular_file_with_mode(archive, &payload, b"payload", 0o755);
            append_regular_file_with_mode(archive, &updater, b"updater", 0o755);
        });
        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        let bundle = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz)
            .expect("safe incomplete bundle should extract");

        assert!(
            bundle.validate_client_payload_layout().is_err(),
            "a managed bundle without its tray companion must not activate"
        );
    }

    #[test]
    fn zip_archive_extraction_returns_the_common_top_level_bundle_directory() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("bundle.zip");
        write_zip(
            &archive_path,
            &[
                ("bundle/rqbit-tunnel", b"payload"),
                ("bundle/NOTICE", b"notice"),
            ],
        );

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        let bundle: StagedBundle =
            extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::Zip)
                .expect("valid ZIP bundle should be extracted");

        assert_eq!(bundle.relative_directory(), Path::new("bundle"));
        assert_eq!(
            bundle
                .read_file(Path::new("rqbit-tunnel"))
                .expect("payload should be read through the staged bundle"),
            b"payload"
        );
        assert_eq!(
            bundle
                .read_file(Path::new("NOTICE"))
                .expect("notice should be read through the staged bundle"),
            b"notice"
        );
    }

    #[test]
    fn zip_archive_extraction_rejects_parent_traversal_before_writing_files() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("malicious.zip");
        write_zip(
            &archive_path,
            &[
                ("payload/rqbit-tunnel", b"valid-looking payload"),
                ("../outside", b"must not escape staging"),
            ],
        );

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");
        let escaped_path = sandbox.path().join("outside");

        extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::Zip)
            .expect_err("parent traversal ZIP archive must be rejected");

        assert!(
            !escaped_path.exists(),
            "archive extraction must not create files outside staging"
        );
        assert!(
            !staging_dir.join("payload/rqbit-tunnel").exists(),
            "archive extraction must reject the archive before writing payload files"
        );
    }

    #[test]
    fn zip_archive_extraction_rejects_raw_local_header_path_mismatch_before_writing_files() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("local-header-path-mismatch.zip");
        let central_name = b"bundle/rqbit-tunnel";
        let local_name = b"../outsideXXXXXXXXX";
        assert_eq!(
            central_name.len(),
            local_name.len(),
            "fixture names must have equal byte lengths"
        );
        write_raw_stored_zip(
            &archive_path,
            &[raw_stored_regular_file(
                local_name,
                central_name,
                &[],
                &[],
                b"local header path must be verified",
            )],
        );

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::Zip)
            .expect_err("local and central ZIP header paths must agree");

        assert_staging_has_no_payload(&staging_dir);
    }

    #[test]
    fn zip_archive_extraction_rejects_prefixed_archive_with_adjusted_offsets_before_writing_files()
    {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("adjusted-offset-prefix.zip");
        write_adjusted_offset_prefixed_stored_zip(&archive_path);

        let archive = ZipArchive::new(
            File::open(&archive_path).expect("adjusted-offset ZIP archive should be readable"),
        )
        .expect("adjusted-offset ZIP archive should remain parseable");
        assert_eq!(
            archive.offset(),
            0,
            "fixture must bypass zip-rs's leading-data offset detection"
        );

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");
        let result = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::Zip);

        assert!(
            result.is_err(),
            "a ZIP with leading bytes must be rejected even when its offsets are adjusted; got {result:?}"
        );
        assert_staging_has_no_payload(&staging_dir);
    }

    #[test]
    fn zip_archive_extraction_rejects_duplicate_raw_central_directory_names_before_writing_files() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("duplicate-central-directory-names.zip");
        let raw_name = b"bundle/rqbit-tunnel";
        write_raw_stored_zip(
            &archive_path,
            &[
                raw_stored_regular_file(raw_name, raw_name, &[], &[], b"first payload"),
                raw_stored_regular_file(raw_name, raw_name, &[], &[], b"second payload"),
            ],
        );

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::Zip)
            .expect_err("duplicate raw central directory names must be rejected");

        assert_staging_has_no_payload(&staging_dir);
    }

    #[test]
    fn zip_archive_extraction_rejects_unicode_path_extra_field_before_writing_files() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("unicode-path-extra.zip");
        let raw_name = b"bundle/rqbit-tunnel";
        let unicode_name = b"bundle/rewritten-tunnel";
        let unicode_path_extra = zip_unicode_path_extra(raw_name, unicode_name);
        write_raw_stored_zip(
            &archive_path,
            &[raw_stored_regular_file(
                raw_name,
                raw_name,
                &[],
                &unicode_path_extra,
                b"Unicode Path metadata must not rewrite the entry name",
            )],
        );

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::Zip)
            .expect_err("Unicode Path ZIP extra fields must be rejected");

        assert_staging_has_no_payload(&staging_dir);
    }

    #[test]
    fn zip_archive_extraction_rejects_unix_link_extra_field_before_writing_files() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("unix-link-extra.zip");
        let raw_name = b"bundle/rqbit-tunnel";
        let unix_link_extra = zip_unix_link_extra(b"../outside");
        write_raw_stored_zip(
            &archive_path,
            &[raw_stored_regular_file(
                raw_name,
                raw_name,
                &unix_link_extra,
                &[],
                b"Unix link metadata must not be extracted",
            )],
        );

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::Zip)
            .expect_err("Unix link ZIP extra fields must be rejected");

        assert_staging_has_no_payload(&staging_dir);
    }

    #[test]
    fn zip_archive_extraction_rejects_zip64_local_offset_override_before_writing_files() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("zip64-local-offset-override.zip");
        write_zip64_local_offset_override_zip(&archive_path);

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        let result = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::Zip);

        assert!(
            result.is_err(),
            "a ZIP64 central extra field must not redirect an entry away from its validated local header; got {result:?}"
        );
        assert_staging_has_no_payload(&staging_dir);
    }

    #[test]
    fn zip_archive_extraction_rejects_eocd_fallback_before_writing_files() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("eocd-fallback.zip");
        write_eocd_fallback_zip(&archive_path);

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        let result = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::Zip);

        assert!(
            result.is_err(),
            "the ZIP parser must not fall back from the raw-validated EOCD to an earlier directory; got {result:?}"
        );
        assert_staging_has_no_payload(&staging_dir);
    }

    #[cfg(unix)]
    #[test]
    fn zip_archive_extraction_preserves_only_ordinary_executable_mode() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("executable.zip");
        write_zip_with_mode(&archive_path, "bundle/rqbit-tunnel", b"payload", 0o755);

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");
        let bundle = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::Zip)
            .expect("executable ZIP archive entry should be extracted");

        let mode = staged_file_mode(&bundle, Path::new("bundle/rqbit-tunnel"));
        assert_eq!(
            mode & 0o777,
            0o755,
            "staging must preserve ordinary executable permissions from ZipWriter output"
        );
        assert_eq!(
            mode & 0o7000,
            0,
            "staging must not create special permission bits from ZipWriter output"
        );
    }

    #[cfg(unix)]
    #[test]
    fn staged_bundle_read_file_rejects_an_injected_fifo() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("bundle.tar.gz");
        write_tar_gz(&archive_path, |archive| {
            append_regular_file(archive, "bundle/rqbit-tunnel", b"payload");
        });

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");
        let bundle = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz)
            .expect("valid bundle should be extracted");

        let fifo_path = bundle
            .staging_directory
            .output_path(&bundle.relative_directory.join("fifo"));
        let fifo_name = CString::new(fifo_path.as_os_str().as_bytes())
            .expect("temporary FIFO path must not contain a NUL byte");
        assert_eq!(
            unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) },
            0,
            "FIFO should be created inside the staged bundle"
        );

        assert!(matches!(
            bundle.read_file(Path::new("fifo")),
            Err(UpdateError::UnsafeExtractionFile { path }) if path == fifo_path
        ));
    }

    #[test]
    fn archive_extraction_rejects_duplicate_paths_before_writing_files() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("duplicate.tar.gz");
        write_tar_gz(&archive_path, |archive| {
            append_regular_file(archive, "bundle/rqbit-tunnel", b"first payload");
            append_regular_file(archive, "bundle/rqbit-tunnel", b"second payload");
        });

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        assert!(matches!(
            extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz),
            Err(UpdateError::DuplicateArchiveEntryPath { .. })
        ));
        assert!(
            !staging_dir.join("bundle/rqbit-tunnel").exists(),
            "duplicate archives must be rejected before payload extraction"
        );
    }

    #[test]
    fn archive_extraction_rejects_symlinks_before_writing_files() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("symlink.tar.gz");
        write_tar_gz(&archive_path, |archive| {
            append_regular_file(archive, "bundle/rqbit-tunnel", b"valid-looking payload");
            append_symlink(archive, "bundle/escape", "../outside");
        });

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        assert!(matches!(
            extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz),
            Err(UpdateError::UnsupportedArchiveEntryType { .. })
        ));
        assert!(
            !staging_dir.join("bundle/rqbit-tunnel").exists(),
            "unsupported entry types must be rejected before payload extraction"
        );
    }

    #[test]
    fn archive_extraction_rejects_windows_normalized_parent_alias_before_writing_payload() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("windows-parent-alias.tar.gz");
        write_tar_gz(&archive_path, |archive| {
            append_regular_file(archive, "bundle/.. /payload", b"must not be extracted");
        });

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        let error = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz)
            .expect_err("Windows-normalized parent aliases must be rejected");

        assert!(matches!(error, UpdateError::UnsafeArchiveEntryPath { .. }));
        assert!(
            !staging_dir.join("bundle/.. /payload").exists(),
            "unsafe aliases must be rejected before payload extraction"
        );
    }

    #[test]
    fn archive_extraction_rejects_windows_invalid_component_before_writing_payload() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("windows-invalid-component.tar.gz");
        write_tar_gz(&archive_path, |archive| {
            append_regular_file(archive, "bundle/a?b", b"must not be extracted");
        });

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        let error = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz)
            .expect_err("Windows-invalid archive components must be rejected");

        assert!(matches!(error, UpdateError::UnsafeArchiveEntryPath { .. }));
        assert!(
            !staging_dir.join("bundle/a?b").exists(),
            "unsafe components must be rejected before payload extraction"
        );
    }

    #[test]
    fn archive_extraction_rejects_case_insensitive_duplicate_paths_before_writing_payload() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("case-insensitive-duplicate.tar.gz");
        write_tar_gz(&archive_path, |archive| {
            append_regular_file(archive, "bundle/file", b"first payload");
            append_regular_file(archive, "bundle/FILE", b"second payload");
        });

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        let error = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz)
            .expect_err("case-insensitive duplicate archive paths must be rejected");

        assert!(matches!(
            error,
            UpdateError::DuplicateArchiveEntryPath { .. }
        ));
        assert!(
            !staging_dir.join("bundle/file").exists() && !staging_dir.join("bundle/FILE").exists(),
            "duplicate archives must be rejected before payload extraction"
        );
    }
    #[test]
    fn archive_extraction_rejects_case_variant_top_level_roots_before_writing_payload() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("case-variant-roots.tar.gz");
        write_tar_gz(&archive_path, |archive| {
            append_regular_file(archive, "bundle/a", b"first payload");
            append_regular_file(archive, "BUNDLE/b", b"second payload");
        });

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        let error = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz)
            .expect_err("case-variant top-level roots must violate the common-root contract");

        assert!(matches!(
            error,
            UpdateError::MultipleArchiveBundleDirectories { .. }
        ));
        assert!(
            !staging_dir.join("bundle/a").exists() && !staging_dir.join("BUNDLE/b").exists(),
            "common-root violations must be rejected before payload extraction"
        );
    }

    #[test]
    fn archive_extraction_rejects_windows_short_name_aliases_before_writing_payload() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("windows-short-name-alias.tar.gz");
        write_tar_gz(&archive_path, |archive| {
            append_regular_file(archive, "bundle/verylongfilename.txt", b"first payload");
            append_regular_file(archive, "bundle/verylo~1.txt", b"second payload");
        });

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        let error = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz)
            .expect_err("Windows short-name aliases must be rejected");

        assert!(matches!(
            error,
            UpdateError::DuplicateArchiveEntryPath { .. }
                | UpdateError::UnsafeArchiveEntryPath { .. }
        ));
        assert!(
            !staging_dir.join("bundle/verylongfilename.txt").exists()
                && !staging_dir.join("bundle/verylo~1.txt").exists(),
            "short-name aliases must be rejected before payload extraction"
        );
    }

    #[cfg(unix)]
    #[test]
    fn archive_extraction_preserves_executable_regular_file_mode() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("executable.tar.gz");
        write_tar_gz(&archive_path, |archive| {
            append_regular_file_with_mode(archive, "bundle/rqbit-tunnel", b"payload", 0o755);
        });

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        let bundle = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz)
            .expect("executable archive entry should be extracted");

        assert_eq!(
            staged_file_mode(&bundle, Path::new("bundle/rqbit-tunnel")) & 0o777,
            0o755,
            "staging must preserve the archive entry's ordinary executable mode"
        );
    }

    #[cfg(unix)]
    #[test]
    fn archive_extraction_discards_special_bits_from_executable_regular_file_modes() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("special-bit-executables.tar.gz");
        write_tar_gz(&archive_path, |archive| {
            append_regular_file_with_mode(archive, "bundle/setuid", b"payload", 0o4755);
            append_regular_file_with_mode(archive, "bundle/setgid", b"payload", 0o2755);
            append_regular_file_with_mode(archive, "bundle/sticky", b"payload", 0o1755);
        });

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        let bundle = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz)
            .expect("special-mode archive entries should be extracted with sanitized permissions");

        for name in ["setuid", "setgid", "sticky"] {
            let mode = staged_file_mode(&bundle, Path::new("bundle").join(name).as_path());
            assert_eq!(
                mode & 0o777,
                0o755,
                "staging must preserve only ordinary executable permissions for {name}"
            );
            assert_eq!(
                mode & 0o7000,
                0,
                "staging must discard special permission bits for {name}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn archive_extraction_keeps_default_regular_files_non_executable() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("non-executable.tar.gz");
        write_tar_gz(&archive_path, |archive| {
            append_regular_file_with_mode(archive, "bundle/NOTICE", b"notice", 0o644);
        });

        let staging_dir = sandbox.path().join("staging");
        fs::create_dir(&staging_dir).expect("staging directory should be created");

        let bundle = extract_verified_archive(&archive_path, &staging_dir, ArchiveKind::TarGz)
            .expect("non-executable archive entry should be extracted");

        assert_eq!(
            staged_file_mode(&bundle, Path::new("bundle/NOTICE")) & 0o111,
            0,
            "staging must not make non-executable archive entries executable"
        );
    }

    #[cfg(unix)]
    fn staged_file_mode(bundle: &StagedBundle, relative_path: &Path) -> u32 {
        let parent = bundle
            .staging_directory
            .open_existing_directories(
                relative_path.parent().unwrap_or_else(|| Path::new("")),
                relative_path,
            )
            .expect("staged file parent should be opened through the pinned staging root");
        let parent_fd = parent
            .as_ref()
            .map_or(bundle.staging_directory.root.as_raw_fd(), |directory| {
                directory.as_raw_fd()
            });
        let leaf = relative_path
            .file_name()
            .expect("staged file path should have a filename");
        let leaf = std::ffi::CString::new(leaf.as_bytes())
            .expect("staged file name should not contain a NUL byte");
        let file = super::open_output_file_for_read_at(parent_fd, &leaf, relative_path)
            .expect("staged file should be opened through the pinned staging root");

        file.metadata()
            .expect("staged file metadata should be readable")
            .mode()
    }

    #[cfg(unix)]
    #[test]
    fn pinned_staging_root_writes_after_staging_path_is_replaced_with_symlink() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let staging_dir = sandbox.path().join("staging");
        let outside_dir = sandbox.path().join("outside");
        fs::create_dir(&staging_dir).expect("staging directory should be created");
        fs::create_dir(&outside_dir).expect("outside directory should be created");

        let staging_root =
            StagingDirectory::open(&staging_dir).expect("staging directory should be pinned");

        let original_staging_dir = sandbox.path().join("original-staging");
        fs::rename(&staging_dir, &original_staging_dir)
            .expect("staging directory should be renamed");
        std::os::unix::fs::symlink(&outside_dir, &staging_dir)
            .expect("staging pathname should be replaced with an outside symlink");

        staging_root
            .create_directory(Path::new("bundle"))
            .expect("bundle directory should be created through the pinned staging root");
        let mut payload = staging_root
            .create_file(Path::new("bundle/payload"))
            .expect("payload should be created through the pinned staging root");
        payload
            .write_all(b"pinned payload")
            .expect("payload should be written through the pinned staging root");
        drop(payload);

        assert_eq!(
            fs::read(original_staging_dir.join("bundle/payload"))
                .expect("payload should remain under the original staging directory"),
            b"pinned payload"
        );
        assert!(
            !outside_dir.join("bundle/payload").exists(),
            "replacing the staging pathname must not redirect output outside the pinned root"
        );
    }

    #[cfg(unix)]
    #[test]
    fn archive_extraction_rejects_trailing_slash_staging_symlink_before_writing_payload() {
        let sandbox = tempdir().expect("sandbox directory should be created");
        let archive_path = sandbox.path().join("bundle.tar.gz");
        write_tar_gz(&archive_path, |archive| {
            append_regular_file(archive, "bundle/rqbit-tunnel", b"must not be extracted");
        });

        let target_dir = sandbox.path().join("target");
        fs::create_dir(&target_dir).expect("symlink target directory should be created");
        let staging_symlink = sandbox.path().join("staging-link");
        std::os::unix::fs::symlink(&target_dir, &staging_symlink)
            .expect("staging directory symlink should be created");
        let staging_with_trailing_slash = format!("{}/", staging_symlink.display());

        let error = extract_verified_archive(
            &archive_path,
            Path::new(&staging_with_trailing_slash),
            ArchiveKind::TarGz,
        )
        .expect_err("staging directory symlinks must be rejected even with a trailing slash");

        assert!(matches!(error, UpdateError::UnsafeStagingDirectory { .. }));
        assert!(
            !target_dir.join("bundle/rqbit-tunnel").exists(),
            "unsafe staging symlinks must be rejected before payload extraction"
        );
    }

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let archive_file = File::create(path).expect("archive file should be created");
        let mut archive = ZipWriter::new(archive_file);

        for &(entry_path, contents) in entries {
            archive
                .start_file(
                    entry_path,
                    SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
                )
                .expect("ZIP archive entry should be started");
            archive
                .write_all(contents)
                .expect("ZIP archive entry should be written");
        }

        archive.finish().expect("ZIP archive should be finalized");
    }

    #[cfg(unix)]
    fn write_zip_with_mode(path: &Path, entry_path: &str, contents: &[u8], mode: u32) {
        let archive_file = File::create(path).expect("archive file should be created");
        let mut archive = ZipWriter::new(archive_file);
        archive
            .start_file(
                entry_path,
                SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Stored)
                    .unix_permissions(mode),
            )
            .expect("ZIP archive entry should be started");
        archive
            .write_all(contents)
            .expect("ZIP archive entry should be written");
        archive.finish().expect("ZIP archive should be finalized");
    }

    struct RawZipEntry<'a> {
        local_name: &'a [u8],
        central_name: &'a [u8],
        local_extra: &'a [u8],
        central_extra: &'a [u8],
        contents: &'a [u8],
    }

    fn raw_stored_regular_file<'a>(
        local_name: &'a [u8],
        central_name: &'a [u8],
        local_extra: &'a [u8],
        central_extra: &'a [u8],
        contents: &'a [u8],
    ) -> RawZipEntry<'a> {
        RawZipEntry {
            local_name,
            central_name,
            local_extra,
            central_extra,
            contents,
        }
    }

    fn write_raw_stored_zip(path: &Path, entries: &[RawZipEntry<'_>]) {
        let mut archive = Vec::new();
        let mut central_directory = Vec::new();

        for entry in entries {
            let local_header_offset =
                u32::try_from(archive.len()).expect("raw ZIP local header offset must fit in u32");
            let crc32 = raw_zip_crc32(entry.contents);
            append_raw_zip_local_header(&mut archive, entry, crc32);
            archive.extend_from_slice(entry.contents);
            append_raw_zip_central_directory_entry(
                &mut central_directory,
                entry,
                crc32,
                local_header_offset,
            );
        }

        let central_directory_offset =
            u32::try_from(archive.len()).expect("raw ZIP central directory offset must fit in u32");
        let central_directory_size = u32::try_from(central_directory.len())
            .expect("raw ZIP central directory size must fit in u32");
        archive.extend_from_slice(&central_directory);
        append_raw_zip_end_of_central_directory(
            &mut archive,
            u16::try_from(entries.len()).expect("raw ZIP entry count must fit in u16"),
            central_directory_size,
            central_directory_offset,
        );

        write_raw_zip_bytes(path, &archive);
    }

    fn write_adjusted_offset_prefixed_stored_zip(path: &Path) {
        let entry_name = b"bundle/rqbit-tunnel";
        write_raw_stored_zip(
            path,
            &[raw_stored_regular_file(
                entry_name,
                entry_name,
                &[],
                &[],
                b"prefixed archive payload",
            )],
        );

        let archive = fs::read(path).expect("raw ZIP archive should be readable");
        let eocd_offset = archive
            .len()
            .checked_sub(22)
            .expect("raw ZIP archive must contain an EOCD record");
        assert_eq!(
            &archive[eocd_offset..eocd_offset + 4],
            b"PK\x05\x06",
            "raw ZIP archive must end with an EOCD record"
        );
        let central_directory_offset = usize::try_from(u32::from_le_bytes(
            archive[eocd_offset + 16..eocd_offset + 20]
                .try_into()
                .expect("EOCD central-directory offset field must be four bytes"),
        ))
        .expect("central-directory offset must fit in usize");
        assert_eq!(
            &archive[central_directory_offset..central_directory_offset + 4],
            b"PK\x01\x02",
            "EOCD must point to the central-directory header"
        );

        let prefix = b"prefix";
        let prefix_len = raw_zip_u32(prefix.len());
        let mut prefixed_archive = Vec::with_capacity(prefix.len() + archive.len());
        prefixed_archive.extend_from_slice(prefix);
        prefixed_archive.extend_from_slice(&archive);
        add_raw_zip_offset(
            &mut prefixed_archive,
            prefix.len() + central_directory_offset + 42,
            prefix_len,
        );
        add_raw_zip_offset(
            &mut prefixed_archive,
            prefix.len() + eocd_offset + 16,
            prefix_len,
        );

        write_raw_zip_bytes(path, &prefixed_archive);
    }

    fn write_zip64_local_offset_override_zip(path: &Path) {
        let safe_name = b"bundle/rqbit-tunnel";
        let redirected_local_name = b"../outsideXXXXXXXXX";
        assert_eq!(
            safe_name.len(),
            redirected_local_name.len(),
            "the redirected local path must be an equal-length raw mismatch"
        );

        let safe_local_entry =
            raw_stored_regular_file(safe_name, safe_name, &[], &[], b"safe local contents");
        let redirected_local_entry = raw_stored_regular_file(
            redirected_local_name,
            safe_name,
            &[],
            &[],
            b"redirected local contents",
        );
        let mut archive = Vec::new();

        let redirected_local_header_offset = raw_zip_u32(archive.len());
        let redirected_crc32 = raw_zip_crc32(redirected_local_entry.contents);
        append_raw_zip_local_header(&mut archive, &redirected_local_entry, redirected_crc32);
        archive.extend_from_slice(redirected_local_entry.contents);

        let safe_local_header_offset = raw_zip_u32(archive.len());
        let safe_crc32 = raw_zip_crc32(safe_local_entry.contents);
        append_raw_zip_local_header(&mut archive, &safe_local_entry, safe_crc32);
        archive.extend_from_slice(safe_local_entry.contents);

        let zip64_local_offset = zip64_local_offset_extra(
            redirected_local_entry.contents.len(),
            redirected_local_header_offset,
        );
        let central_entry = raw_stored_regular_file(
            safe_name,
            safe_name,
            &[],
            &zip64_local_offset,
            redirected_local_entry.contents,
        );
        let central_directory_offset = raw_zip_u32(archive.len());
        let mut central_directory = Vec::new();
        append_raw_zip_central_directory_entry(
            &mut central_directory,
            &central_entry,
            redirected_crc32,
            safe_local_header_offset,
        );
        let central_directory_size = raw_zip_u32(central_directory.len());
        archive.extend_from_slice(&central_directory);
        append_raw_zip_end_of_central_directory(
            &mut archive,
            1,
            central_directory_size,
            central_directory_offset,
        );

        write_raw_zip_bytes(path, &archive);
    }

    fn write_eocd_fallback_zip(path: &Path) {
        let safe_name = b"bundle/rqbit-tunnel";
        let unsafe_local_name = b"../outsideXXXXXXXXX";
        assert_eq!(
            safe_name.len(),
            unsafe_local_name.len(),
            "the earlier local path must be an equal-length raw mismatch"
        );

        let earlier_entry = raw_stored_regular_file(
            unsafe_local_name,
            safe_name,
            &[],
            &[],
            b"earlier local contents",
        );
        let safe_local_entry =
            raw_stored_regular_file(safe_name, safe_name, &[], &[], b"final local contents");
        let mut archive = Vec::new();

        let earlier_local_header_offset = raw_zip_u32(archive.len());
        let earlier_crc32 = raw_zip_crc32(earlier_entry.contents);
        append_raw_zip_local_header(&mut archive, &earlier_entry, earlier_crc32);
        archive.extend_from_slice(earlier_entry.contents);

        let earlier_central_directory_offset = raw_zip_u32(archive.len());
        let mut earlier_central_directory = Vec::new();
        append_raw_zip_central_directory_entry(
            &mut earlier_central_directory,
            &earlier_entry,
            earlier_crc32,
            earlier_local_header_offset,
        );
        let earlier_central_directory_size = raw_zip_u32(earlier_central_directory.len());
        archive.extend_from_slice(&earlier_central_directory);
        append_raw_zip_end_of_central_directory(
            &mut archive,
            1,
            earlier_central_directory_size,
            earlier_central_directory_offset,
        );

        let final_local_header_offset = raw_zip_u32(archive.len());
        let final_crc32 = raw_zip_crc32(safe_local_entry.contents);
        append_raw_zip_local_header(&mut archive, &safe_local_entry, final_crc32);
        archive.extend_from_slice(safe_local_entry.contents);

        let malformed_extended_timestamp = raw_zip_extra_field(0x5455, &[0x01]);
        let final_entry = raw_stored_regular_file(
            safe_name,
            safe_name,
            &[],
            &malformed_extended_timestamp,
            safe_local_entry.contents,
        );
        assert_eq!(
            earlier_entry.central_name, final_entry.central_name,
            "the earlier and final central directories must expose the same logical entry name"
        );
        let final_central_directory_offset = raw_zip_u32(archive.len());
        let mut final_central_directory = Vec::new();
        append_raw_zip_central_directory_entry(
            &mut final_central_directory,
            &final_entry,
            final_crc32,
            final_local_header_offset,
        );
        let final_central_directory_size = raw_zip_u32(final_central_directory.len());
        archive.extend_from_slice(&final_central_directory);
        append_raw_zip_end_of_central_directory(
            &mut archive,
            1,
            final_central_directory_size,
            final_central_directory_offset,
        );

        write_raw_zip_bytes(path, &archive);
    }

    fn write_raw_zip_bytes(path: &Path, archive: &[u8]) {
        let mut archive_file = File::create(path).expect("raw ZIP archive file should be created");
        archive_file
            .write_all(archive)
            .expect("raw ZIP archive should be written");
    }

    fn zip64_local_offset_extra(contents_len: usize, local_header_offset: u32) -> Vec<u8> {
        let mut data = Vec::with_capacity(24);
        let contents_len =
            u64::try_from(contents_len).expect("raw ZIP contents length must fit in u64");
        append_raw_zip_u64(&mut data, contents_len);
        append_raw_zip_u64(&mut data, contents_len);
        append_raw_zip_u64(&mut data, u64::from(local_header_offset));
        raw_zip_extra_field(0x0001, &data)
    }

    fn append_raw_zip_local_header(bytes: &mut Vec<u8>, entry: &RawZipEntry<'_>, crc32: u32) {
        append_raw_zip_u32(bytes, 0x0403_4b50);
        append_raw_zip_u16(bytes, 20);
        append_raw_zip_u16(bytes, 0);
        append_raw_zip_u16(bytes, 0);
        append_raw_zip_u16(bytes, 0);
        append_raw_zip_u16(bytes, 0);
        append_raw_zip_u32(bytes, crc32);
        append_raw_zip_u32(bytes, raw_zip_u32(entry.contents.len()));
        append_raw_zip_u32(bytes, raw_zip_u32(entry.contents.len()));
        append_raw_zip_u16(bytes, raw_zip_u16(entry.local_name.len()));
        append_raw_zip_u16(bytes, raw_zip_u16(entry.local_extra.len()));
        bytes.extend_from_slice(entry.local_name);
        bytes.extend_from_slice(entry.local_extra);
    }

    fn append_raw_zip_central_directory_entry(
        bytes: &mut Vec<u8>,
        entry: &RawZipEntry<'_>,
        crc32: u32,
        local_header_offset: u32,
    ) {
        append_raw_zip_u32(bytes, 0x0201_4b50);
        append_raw_zip_u16(bytes, 0x0314);
        append_raw_zip_u16(bytes, 20);
        append_raw_zip_u16(bytes, 0);
        append_raw_zip_u16(bytes, 0);
        append_raw_zip_u16(bytes, 0);
        append_raw_zip_u16(bytes, 0);
        append_raw_zip_u32(bytes, crc32);
        append_raw_zip_u32(bytes, raw_zip_u32(entry.contents.len()));
        append_raw_zip_u32(bytes, raw_zip_u32(entry.contents.len()));
        append_raw_zip_u16(bytes, raw_zip_u16(entry.central_name.len()));
        append_raw_zip_u16(bytes, raw_zip_u16(entry.central_extra.len()));
        append_raw_zip_u16(bytes, 0);
        append_raw_zip_u16(bytes, 0);
        append_raw_zip_u16(bytes, 0);
        append_raw_zip_u32(bytes, 0o100644_u32 << 16);
        append_raw_zip_u32(bytes, local_header_offset);
        bytes.extend_from_slice(entry.central_name);
        bytes.extend_from_slice(entry.central_extra);
    }

    fn append_raw_zip_end_of_central_directory(
        bytes: &mut Vec<u8>,
        entry_count: u16,
        central_directory_size: u32,
        central_directory_offset: u32,
    ) {
        append_raw_zip_u32(bytes, 0x0605_4b50);
        append_raw_zip_u16(bytes, 0);
        append_raw_zip_u16(bytes, 0);
        append_raw_zip_u16(bytes, entry_count);
        append_raw_zip_u16(bytes, entry_count);
        append_raw_zip_u32(bytes, central_directory_size);
        append_raw_zip_u32(bytes, central_directory_offset);
        append_raw_zip_u16(bytes, 0);
    }

    fn zip_unicode_path_extra(raw_name: &[u8], unicode_name: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(5 + unicode_name.len());
        data.push(1);
        append_raw_zip_u32(&mut data, raw_zip_crc32(raw_name));
        data.extend_from_slice(unicode_name);
        raw_zip_extra_field(0x7075, &data)
    }

    fn zip_unix_link_extra(link_target: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(12 + link_target.len());
        append_raw_zip_u32(&mut data, 0);
        append_raw_zip_u32(&mut data, 0);
        append_raw_zip_u16(&mut data, 0);
        append_raw_zip_u16(&mut data, 0);
        data.extend_from_slice(link_target);
        raw_zip_extra_field(0x000d, &data)
    }

    fn raw_zip_extra_field(id: u16, data: &[u8]) -> Vec<u8> {
        let mut extra = Vec::with_capacity(4 + data.len());
        append_raw_zip_u16(&mut extra, id);
        append_raw_zip_u16(&mut extra, raw_zip_u16(data.len()));
        extra.extend_from_slice(data);
        extra
    }

    fn raw_zip_crc32(bytes: &[u8]) -> u32 {
        let mut crc = !0_u32;
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 == 0 {
                    crc >> 1
                } else {
                    (crc >> 1) ^ 0xedb8_8320
                };
            }
        }
        !crc
    }

    fn raw_zip_u16(value: usize) -> u16 {
        u16::try_from(value).expect("raw ZIP variable field length must fit in u16")
    }

    fn raw_zip_u32(value: usize) -> u32 {
        u32::try_from(value).expect("raw ZIP size must fit in u32")
    }

    fn append_raw_zip_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn add_raw_zip_offset(bytes: &mut [u8], field_offset: usize, adjustment: u32) {
        let existing = u32::from_le_bytes(
            bytes[field_offset..field_offset + 4]
                .try_into()
                .expect("raw ZIP offset field must be four bytes"),
        );
        let adjusted = existing
            .checked_add(adjustment)
            .expect("adjusted raw ZIP offset must fit in u32");
        bytes[field_offset..field_offset + 4].copy_from_slice(&adjusted.to_le_bytes());
    }

    fn append_raw_zip_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn append_raw_zip_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn assert_staging_has_no_payload(staging_dir: &Path) {
        assert_eq!(
            fs::read_dir(staging_dir)
                .expect("staging directory should be readable")
                .count(),
            0,
            "unsafe ZIP archive must be rejected before staging any payload"
        );
    }

    fn write_tar_gz(path: &Path, build: impl FnOnce(&mut tar::Builder<GzEncoder<File>>)) {
        let archive_file = File::create(path).expect("archive file should be created");
        let encoder = GzEncoder::new(archive_file, Compression::default());
        let mut archive = tar::Builder::new(encoder);
        build(&mut archive);
        let encoder = archive
            .into_inner()
            .expect("tar archive should be finalized");
        encoder.finish().expect("gzip archive should be finalized");
    }

    fn append_regular_file<W: Write>(archive: &mut tar::Builder<W>, path: &str, contents: &[u8]) {
        append_regular_file_with_mode(archive, path, contents, 0o644);
    }

    fn append_regular_file_with_mode<W: Write>(
        archive: &mut tar::Builder<W>,
        path: &str,
        contents: &[u8],
        mode: u32,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(mode);
        header.set_mtime(0);
        header.set_size(contents.len() as u64);
        header.set_path(path).expect("fixture path should be valid");
        header.set_cksum();
        archive
            .append(&header, Cursor::new(contents))
            .expect("fixture entry should be written");
    }

    fn append_directory<W: Write>(archive: &mut tar::Builder<W>, path: &str) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_mode(0o755);
        header.set_mtime(0);
        header.set_size(0);
        header.set_path(path).expect("fixture path should be valid");
        header.set_cksum();
        archive
            .append(&header, io::empty())
            .expect("fixture directory should be written");
    }

    fn append_symlink<W: Write>(archive: &mut tar::Builder<W>, path: &str, target: &str) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_mode(0o777);
        header.set_mtime(0);
        header.set_size(0);
        header.set_path(path).expect("fixture path should be valid");
        header
            .set_link_name(target)
            .expect("fixture target should be valid");
        header.set_cksum();
        archive
            .append(&header, io::empty())
            .expect("fixture symlink should be written");
    }
}
