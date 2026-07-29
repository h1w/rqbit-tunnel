use std::{
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Write},
    path::{Path, PathBuf},
    pin::Pin,
    time::Duration,
};

use ed25519_dalek::VerifyingKey;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::{Instant, sleep, timeout};

#[cfg(unix)]
use crate::ipc::unix::UnixClientControlClient;
#[cfg(windows)]
use crate::ipc::windows::WindowsClientControlClient;
#[cfg(windows)]
use crate::model::ClientStatusOwner;
use crate::{
    config::load_client_config,
    ipc::protocol::{ClientRequest, ClientResponse},
    model::{ClientConfig, ClientSnapshot, LocalServiceState, LocalTunnelState},
    paths::ClientPaths,
    platform::ServiceManager,
    update::{
        activate::{LocalHealth, activate_release},
        github::{GitHubReleaseClient, ReleaseAssetUrls, SelectedGithubRelease},
        manifest::{
            RELEASE_MANIFEST_FILE_NAME, RELEASE_MANIFEST_SIGNATURE_FILE_NAME, ReleaseAsset,
            ReleaseManifest, UpdateError, select_asset, verify_manifest,
        },
        stage::{ArchiveKind, discard_promoted_release, extract_verified_archive},
    },
    version::{ActiveRelease, LAUNCHER_ABI, read_active_release},
};

const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_MANIFEST_SIGNATURE_BYTES: usize = 16 * 1024;
const HEALTH_POLL_INTERVAL: Duration = Duration::from_millis(200);
const INSTALL_HEALTH_DEADLINE: Duration = Duration::from_secs(30);
const UPDATE_LOCK_FILE_NAME: &str = ".rqbit-tunnel-update.lock";

/// The machine-readable output record produced by the updater executable.
///
/// This deliberately carries only a status, a release version, and stable
/// failure code. It never serializes release metadata, URLs, configuration, or
/// key material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum UpdaterResult {
    UpdateAvailable { version: Version },
    Installed { version: Version },
    NoUpdate,
    Failed { code: UpdaterFailureCode },
}

impl UpdaterResult {
    /// Converts an internal update error to the stable public failure DTO.
    pub fn from_error(error: &UpdateError) -> Self {
        match error {
            UpdateError::NoUpdate => Self::NoUpdate,
            _ => Self::Failed {
                code: UpdaterFailureCode::from_error(error),
            },
        }
    }
}

/// Stable, non-sensitive categories for failed updater operations.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdaterFailureCode {
    InvalidSignature,
    InvalidManifest,
    TargetVersionMismatch,
    UnsupportedAbi,
    UnsupportedPlatform,
    Checksum,
    Download,
    Staging,
    UpdateInProgress,
    Service,
    HealthTimeout,
    RolledBack,
    RollbackFailed,
    InvalidRequest,
}

impl UpdaterFailureCode {
    fn from_error(error: &UpdateError) -> Self {
        match error {
            UpdateError::InvalidSignature => Self::InvalidSignature,
            UpdateError::InvalidManifestJson { .. }
            | UpdateError::InvalidGithubReleaseJson { .. }
            | UpdateError::EmptyGithubReleaseAssetName
            | UpdateError::DuplicateGithubReleaseAsset { .. }
            | UpdateError::InvalidGithubReleaseAssetUrl { .. }
            | UpdateError::UnsafeGithubReleaseAssetUrl { .. }
            | UpdateError::UnsafeGithubReleasesUrl { .. }
            | UpdateError::UnsupportedSchemaVersion { .. }
            | UpdateError::InvalidVersion { .. }
            | UpdateError::NonCanonicalVersion { .. }
            | UpdateError::ZeroLauncherAbi
            | UpdateError::EmptyAssets
            | UpdateError::EmptyAssetTarget
            | UpdateError::DuplicateAssetTarget { .. }
            | UpdateError::UnsafeArchiveFilename { .. }
            | UpdateError::InvalidAssetSha256 { .. }
            | UpdateError::InvalidAssetBytes { .. }
            | UpdateError::InvalidPublicKey
            | UpdateError::GithubReleaseManifestVersionMismatch { .. }
            | UpdateError::UnsupportedArchiveFormat { .. } => Self::InvalidManifest,
            UpdateError::RequestedVersionMismatch { .. } => Self::TargetVersionMismatch,
            UpdateError::UnsupportedLauncherAbi { .. } => Self::UnsupportedAbi,
            UpdateError::UnsupportedPlatformTarget | UpdateError::NoMatchingAsset { .. } => {
                Self::UnsupportedPlatform
            }
            UpdateError::DownloadedArchiveLengthMismatch { .. }
            | UpdateError::DownloadedArchiveChecksumMismatch { .. } => Self::Checksum,
            UpdateError::BuildGithubReleaseClient { .. }
            | UpdateError::RequestGithubReleases { .. }
            | UpdateError::UnexpectedGithubReleasesStatus { .. }
            | UpdateError::ReadGithubReleasesResponse { .. }
            | UpdateError::GithubReleasePaginationLimit { .. }
            | UpdateError::NoEligibleGithubRelease
            | UpdateError::RequestGithubReleaseAsset { .. }
            | UpdateError::UnexpectedGithubReleaseAssetStatus { .. }
            | UpdateError::ReadGithubReleaseAsset { .. }
            | UpdateError::MissingGithubReleaseAsset { .. }
            | UpdateError::MissingGithubReleaseSelectionContext
            | UpdateError::WriteDownloadedReleaseAsset { .. }
            | UpdateError::CreateDownloadedReleaseAsset { .. }
            | UpdateError::SyncDownloadedReleaseAsset { .. } => Self::Download,
            UpdateError::UpdateAlreadyRunning { .. } => Self::UpdateInProgress,
            UpdateError::StopClientService { .. }
            | UpdateError::UnexpectedClientStopState { .. }
            | UpdateError::StartClientService { .. }
            | UpdateError::UnexpectedClientStartState { .. } => Self::Service,
            UpdateError::HealthTimeout => Self::HealthTimeout,
            UpdateError::RolledBack { .. } => Self::RolledBack,
            UpdateError::RollbackFailed { .. } => Self::RollbackFailed,
            _ => Self::Staging,
        }
    }
}

/// Exact signed release metadata supplied by a release source.
#[derive(Clone, Debug)]
pub struct ReleaseDiscovery {
    pub raw_manifest: Vec<u8>,
    pub signature: String,
    selected_github_version: Option<Version>,
    selected_github_assets: Option<ReleaseAssetUrls>,
}

impl ReleaseDiscovery {
    pub fn new(raw_manifest: Vec<u8>, signature: String) -> Self {
        Self {
            raw_manifest,
            signature,
            selected_github_version: None,
            selected_github_assets: None,
        }
    }

    pub(crate) fn with_selected_github_release(mut self, selected: SelectedGithubRelease) -> Self {
        self.selected_github_version = Some(selected.version);
        self.selected_github_assets = Some(selected.assets);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_selected_github_version(mut self, version: Version) -> Self {
        self.selected_github_version = Some(version);
        self
    }

    pub(crate) fn selected_github_version(&self) -> Option<&Version> {
        self.selected_github_version.as_ref()
    }

    pub(crate) fn selected_github_assets(&self) -> Option<&ReleaseAssetUrls> {
        self.selected_github_assets.as_ref()
    }
}

/// A release source whose archive writes are consumed by updater-owned bounds
/// and digest verification.
pub trait ReleaseSource: Send + Sync {
    fn discover<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<ReleaseDiscovery, UpdateError>> + Send + 'a>>;

    fn download_asset<'a>(
        &'a self,
        discovery: &'a ReleaseDiscovery,
        asset: &'a ReleaseAsset,
        output: &'a mut (dyn Write + Send),
    ) -> Pin<Box<dyn Future<Output = Result<(), UpdateError>> + Send + 'a>>;
}

/// The strict production release source backed by GitHub's canonical endpoint.
pub struct GitHubReleaseSource {
    client: GitHubReleaseClient,
}

impl GitHubReleaseSource {
    pub fn new() -> Result<Self, UpdateError> {
        Ok(Self {
            client: GitHubReleaseClient::new()?,
        })
    }
}

impl ReleaseSource for GitHubReleaseSource {
    fn discover<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<ReleaseDiscovery, UpdateError>> + Send + 'a>> {
        Box::pin(async move {
            let selected = self.client.fetch_selected_release().await?;
            let mut raw_manifest = BoundedMemoryWriter::new(MAX_MANIFEST_BYTES);
            self.client
                .download_selected_release_asset_to(
                    &selected.assets,
                    RELEASE_MANIFEST_FILE_NAME,
                    &mut raw_manifest,
                )
                .await?;
            let mut signature = BoundedMemoryWriter::new(MAX_MANIFEST_SIGNATURE_BYTES);
            self.client
                .download_selected_release_asset_to(
                    &selected.assets,
                    RELEASE_MANIFEST_SIGNATURE_FILE_NAME,
                    &mut signature,
                )
                .await?;
            let signature = String::from_utf8(signature.into_inner())
                .map_err(|_| UpdateError::InvalidSignature)?;
            Ok(ReleaseDiscovery::new(raw_manifest.into_inner(), signature)
                .with_selected_github_release(selected))
        })
    }

    fn download_asset<'a>(
        &'a self,
        discovery: &'a ReleaseDiscovery,
        asset: &'a ReleaseAsset,
        output: &'a mut (dyn Write + Send),
    ) -> Pin<Box<dyn Future<Output = Result<(), UpdateError>> + Send + 'a>> {
        Box::pin(async move {
            let assets = discovery
                .selected_github_assets()
                .ok_or(UpdateError::MissingGithubReleaseSelectionContext)?;
            self.client
                .download_selected_release_asset_to(assets, &asset.archive, output)
                .await
        })
    }
}

/// Coordinates trusted discovery, verified staging, promotion, and activation.
pub struct Updater<'a> {
    install_root: PathBuf,
    target: String,
    verification_key: VerifyingKey,
    source: &'a dyn ReleaseSource,
    service: &'a dyn ServiceManager,
    health: &'a dyn LocalHealth,
}

/// An exclusive, process-scoped lock retained for the full update transaction.
///
/// OS locks are released automatically when the updater process exits, so a
/// crash never leaves a stale lock that blocks future installations.
#[derive(Debug)]
struct UpdateLock {
    _file: File,
}

impl UpdateLock {
    fn acquire(install_root: &Path) -> Result<Self, UpdateError> {
        let path = install_root.join(UPDATE_LOCK_FILE_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .map_err(|source| UpdateError::OpenUpdateLock {
                path: path.clone(),
                source,
            })?;
        acquire_update_lock(&file, &path)?;
        Ok(Self { _file: file })
    }
}

#[cfg(unix)]
fn acquire_update_lock(file: &File, path: &Path) -> Result<(), UpdateError> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: `file` owns a valid file descriptor and `flock` does not retain
    // any borrowed Rust data.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(());
    }
    let source = io::Error::last_os_error();
    if source.kind() == io::ErrorKind::WouldBlock {
        return Err(UpdateError::UpdateAlreadyRunning {
            path: path.to_path_buf(),
        });
    }
    Err(UpdateError::AcquireUpdateLock {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(windows)]
fn acquire_update_lock(file: &File, path: &Path) -> Result<(), UpdateError> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::{
        Foundation::{ERROR_LOCK_VIOLATION, HANDLE, WIN32_ERROR},
        Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx},
        System::IO::OVERLAPPED,
    };

    let mut overlapped = OVERLAPPED::default();
    // SAFETY: `file` owns the native file handle. The synchronous lock request
    // does not retain the stack-local `OVERLAPPED`; closing `file` releases it.
    match unsafe {
        LockFileEx(
            HANDLE(file.as_raw_handle()),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            None,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    } {
        Ok(()) => Ok(()),
        Err(source) if WIN32_ERROR::from_error(&source) == Some(ERROR_LOCK_VIOLATION) => {
            Err(UpdateError::UpdateAlreadyRunning {
                path: path.to_path_buf(),
            })
        }
        Err(source) => Err(UpdateError::AcquireUpdateLock {
            path: path.to_path_buf(),
            source: io::Error::other(source),
        }),
    }
}

#[cfg(not(any(unix, windows)))]
fn acquire_update_lock(_file: &File, path: &Path) -> Result<(), UpdateError> {
    Err(UpdateError::AcquireUpdateLock {
        path: path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::Unsupported,
            "update locking is unsupported on this platform",
        ),
    })
}

impl<'a> Updater<'a> {
    pub fn new(
        install_root: &Path,
        target: impl Into<String>,
        verification_key: VerifyingKey,
        source: &'a dyn ReleaseSource,
        service: &'a dyn ServiceManager,
        health: &'a dyn LocalHealth,
    ) -> Result<Self, UpdateError> {
        let target = target.into();
        if target.trim().is_empty() {
            return Err(UpdateError::UnsupportedPlatformTarget);
        }
        Ok(Self {
            install_root: validate_install_root(install_root)?,
            target,
            verification_key,
            source,
            service,
            health,
        })
    }

    /// Discovers and verifies the current signed release without touching the
    /// managed client service.
    pub async fn check(&self) -> Result<UpdaterResult, UpdateError> {
        let active = self.read_active_release()?;
        let (_, manifest) = self.discover_verified().await?;
        select_asset(&manifest, &self.target, active.version(), LAUNCHER_ABI)?;
        Ok(UpdaterResult::UpdateAvailable {
            version: manifest.version,
        })
    }

    /// Independently rediscovers and verifies a requested release before
    /// downloading, staging, promoting, and activating it.
    pub async fn install(&self, target_version: &Version) -> Result<UpdaterResult, UpdateError> {
        let _lock = UpdateLock::acquire(&self.install_root)?;
        let (discovery, manifest) = self.discover_verified().await?;
        if &manifest.version != target_version {
            return Err(UpdateError::RequestedVersionMismatch {
                requested: target_version.clone(),
                discovered: manifest.version,
            });
        }

        let active = self.read_active_release()?;
        let asset = select_asset(&manifest, &self.target, active.version(), LAUNCHER_ABI)?.clone();
        let work_directory = tempfile::Builder::new()
            .prefix(".rqbit-tunnel-update-")
            .tempdir_in(&self.install_root)
            .map_err(|source| UpdateError::CreateUpdateWorkDirectory {
                path: self.install_root.clone(),
                source,
            })?;
        let archive_path = work_directory.path().join("archive");
        let archive = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&archive_path)
            .map_err(|source| UpdateError::CreateDownloadedReleaseAsset {
                path: archive_path.clone(),
                source,
            })?;
        let mut writer = VerifiedArchiveWriter::new(archive, asset.bytes);
        let download = self
            .source
            .download_asset(&discovery, &asset, &mut writer)
            .await;
        if writer.exceeded_limit() {
            return Err(UpdateError::DownloadedArchiveLengthMismatch {
                expected: asset.bytes,
                actual: writer.written(),
            });
        }
        download?;
        let (actual_bytes, actual_sha256) = writer.finish(&archive_path)?;
        if actual_bytes != asset.bytes {
            return Err(UpdateError::DownloadedArchiveLengthMismatch {
                expected: asset.bytes,
                actual: actual_bytes,
            });
        }
        if actual_sha256 != asset.sha256 {
            return Err(UpdateError::DownloadedArchiveChecksumMismatch {
                expected_sha256: asset.sha256,
                actual_sha256,
            });
        }

        let staging_directory = work_directory.path().join("stage");
        fs::create_dir(&staging_directory).map_err(|source| {
            UpdateError::CreateUpdateStagingDirectory {
                path: staging_directory.clone(),
                source,
            }
        })?;
        let staged = extract_verified_archive(
            &archive_path,
            &staging_directory,
            archive_kind(&asset.archive)?,
        )?;
        staged.validate_client_payload_layout()?;
        staged.promote_to_release(&self.install_root, &manifest.version)?;

        let candidate = ActiveRelease::new(
            manifest.version.clone(),
            PathBuf::from("releases")
                .join(manifest.version.to_string())
                .join("payload"),
            manifest.launcher_abi,
        )
        .map_err(|source| UpdateError::CreateActiveReleaseCandidate { source })?;
        match activate_release(
            &self.install_root,
            &candidate,
            self.service,
            self.health,
            INSTALL_HEALTH_DEADLINE,
        )
        .await
        {
            Ok(()) => {}
            Err(error @ UpdateError::RolledBack { .. }) => {
                discard_promoted_release(&self.install_root, &manifest.version)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        Ok(UpdaterResult::Installed {
            version: manifest.version,
        })
    }

    fn read_active_release(&self) -> Result<ActiveRelease, UpdateError> {
        read_active_release(&self.install_root)
            .map_err(|source| UpdateError::ReadActiveRelease { source })
    }

    async fn discover_verified(&self) -> Result<(ReleaseDiscovery, ReleaseManifest), UpdateError> {
        let discovery = self.source.discover().await?;
        let manifest = verify_manifest(
            &discovery.raw_manifest,
            &discovery.signature,
            &self.verification_key,
        )?;
        if let Some(selected) = discovery.selected_github_version() {
            if selected != &manifest.version {
                return Err(UpdateError::GithubReleaseManifestVersionMismatch {
                    selected: selected.clone(),
                    manifest: manifest.version.clone(),
                });
            }
        }
        Ok((discovery, manifest))
    }
}

/// Validates an absolute installation root and returns its canonical directory.
pub fn validate_install_root(install_root: &Path) -> Result<PathBuf, UpdateError> {
    if !install_root.is_absolute() {
        return Err(UpdateError::InvalidInstallRoot {
            path: install_root.to_path_buf(),
        });
    }
    let canonical =
        fs::canonicalize(install_root).map_err(|source| UpdateError::InspectInstallRoot {
            path: install_root.to_path_buf(),
            source,
        })?;
    let metadata = fs::metadata(&canonical).map_err(|source| UpdateError::InspectInstallRoot {
        path: canonical.clone(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(UpdateError::InvalidInstallRoot { path: canonical });
    }
    Ok(canonical)
}

/// Derives the installation root from the updater executable's own location.
pub fn current_executable_install_root() -> Result<PathBuf, UpdateError> {
    let executable = std::env::current_exe().map_err(|source| UpdateError::InspectInstallRoot {
        path: PathBuf::from("<current executable>"),
        source,
    })?;
    let Some(root) = executable.parent() else {
        return Err(UpdateError::InvalidInstallRoot { path: executable });
    };
    validate_install_root(root)
}

/// Returns the release asset target supported by this updater build.
pub fn current_platform_target() -> Result<&'static str, UpdateError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return Ok("x86_64-unknown-linux-gnu");
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        return Ok("aarch64-unknown-linux-gnu");
    }
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        return Ok("x86_64-pc-windows-msvc");
    }
    #[cfg(all(windows, target_arch = "aarch64"))]
    {
        return Ok("aarch64-pc-windows-msvc");
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        return Ok("x86_64-apple-darwin");
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return Ok("aarch64-apple-darwin");
    }
    #[allow(unreachable_code)]
    Err(UpdateError::UnsupportedPlatformTarget)
}

/// A sanitized observation used by the readiness adapter. Tunnel reconnecting
/// remains healthy: a running local service and valid configuration are enough
/// to complete activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalHealthObservation {
    pub service: LocalServiceState,
    pub tunnel: LocalTunnelState,
    pub config_valid: bool,
}

impl LocalHealthObservation {
    #[cfg(test)]
    fn running_reconnecting() -> Self {
        Self {
            service: LocalServiceState::Running,
            tunnel: LocalTunnelState::Reconnecting,
            config_valid: true,
        }
    }

    fn is_ready(&self) -> bool {
        self.config_valid && self.service == LocalServiceState::Running
    }
}

/// Read-only source of local client readiness observations.
pub trait LocalHealthProbe: Send + Sync {
    fn observe<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Option<LocalHealthObservation>> + Send + 'a>>;
}

/// Production read-only client IPC and configuration readiness source.
pub struct SystemLocalHealthProbe {
    paths: ClientPaths,
}

impl SystemLocalHealthProbe {
    pub fn new(paths: ClientPaths) -> Self {
        Self { paths }
    }
}

impl LocalHealthProbe for SystemLocalHealthProbe {
    fn observe<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Option<LocalHealthObservation>> + Send + 'a>> {
        Box::pin(async move {
            let config = load_client_config(&self.paths).ok()?;
            let snapshot = read_local_client_snapshot(&self.paths, &config).await?;
            Some(LocalHealthObservation {
                service: snapshot.service,
                tunnel: snapshot.tunnel,
                config_valid: true,
            })
        })
    }
}

async fn read_local_client_snapshot(
    paths: &ClientPaths,
    config: &ClientConfig,
) -> Option<ClientSnapshot> {
    #[cfg(unix)]
    {
        let _ = config;
        let mut client = UnixClientControlClient::connect(paths.control_socket_path())
            .await
            .ok()?;
        return match client.request(ClientRequest::Snapshot).await.ok()? {
            ClientResponse::Snapshot(snapshot) => Some(snapshot),
            ClientResponse::Error(_) => None,
        };
    }

    #[cfg(windows)]
    {
        let _ = paths;
        let ClientStatusOwner::Windows { sid } = config.status_owner.as_ref()? else {
            return None;
        };
        let mut client = WindowsClientControlClient::connect(sid).ok()?;
        return match client.request(ClientRequest::Snapshot).await.ok()? {
            ClientResponse::Snapshot(snapshot) => Some(snapshot),
            ClientResponse::Error(_) => None,
        };
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = paths;
        let _ = config;
        None
    }
}

/// Polls a read-only local probe until the upgraded client is healthy.
pub struct LocalClientHealth<P = SystemLocalHealthProbe> {
    probe: P,
    poll_interval: Duration,
}

impl LocalClientHealth<SystemLocalHealthProbe> {
    pub fn system(paths: ClientPaths) -> Self {
        Self::with_probe(SystemLocalHealthProbe::new(paths), HEALTH_POLL_INTERVAL)
    }
}

impl<P> LocalClientHealth<P> {
    pub fn with_probe(probe: P, poll_interval: Duration) -> Self {
        Self {
            probe,
            poll_interval,
        }
    }
}

impl<P> LocalHealth for LocalClientHealth<P>
where
    P: LocalHealthProbe,
{
    fn wait_for_ready<'a>(
        &'a self,
        deadline: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), UpdateError>> + Send + 'a>> {
        Box::pin(async move {
            let deadline_at = Instant::now() + deadline;
            loop {
                let remaining = deadline_at.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(UpdateError::HealthTimeout);
                }
                let observation = timeout(remaining, self.probe.observe())
                    .await
                    .ok()
                    .flatten();
                if observation.is_some_and(|observation| observation.is_ready()) {
                    return Ok(());
                }

                let remaining = deadline_at.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(UpdateError::HealthTimeout);
                }
                sleep(self.poll_interval.min(remaining)).await;
            }
        })
    }
}

fn archive_kind(archive: &str) -> Result<ArchiveKind, UpdateError> {
    if archive.ends_with(".tar.gz") {
        Ok(ArchiveKind::TarGz)
    } else if archive.ends_with(".zip") {
        Ok(ArchiveKind::Zip)
    } else {
        Err(UpdateError::UnsupportedArchiveFormat {
            archive: archive.to_owned(),
        })
    }
}

struct BoundedMemoryWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedMemoryWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedMemoryWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next_len =
            self.bytes.len().checked_add(bytes.len()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "download is too large")
            })?;
        if next_len > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "download is too large",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct VerifiedArchiveWriter {
    file: File,
    digest: Sha256,
    expected_bytes: u64,
    written: u64,
    exceeded_limit: bool,
}

impl VerifiedArchiveWriter {
    fn new(file: File, expected_bytes: u64) -> Self {
        Self {
            file,
            digest: Sha256::new(),
            expected_bytes,
            written: 0,
            exceeded_limit: false,
        }
    }

    fn exceeded_limit(&self) -> bool {
        self.exceeded_limit
    }

    fn written(&self) -> u64 {
        self.written
    }

    fn finish(mut self, path: &Path) -> Result<(u64, String), UpdateError> {
        self.file
            .flush()
            .map_err(|source| UpdateError::SyncDownloadedReleaseAsset {
                path: path.to_path_buf(),
                source,
            })?;
        self.file
            .sync_all()
            .map_err(|source| UpdateError::SyncDownloadedReleaseAsset {
                path: path.to_path_buf(),
                source,
            })?;
        Ok((self.written, hex::encode(self.digest.finalize())))
    }
}

impl Write for VerifiedArchiveWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.written.checked_add(bytes.len() as u64) else {
            self.exceeded_limit = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "archive exceeds signed byte length",
            ));
        };
        if next > self.expected_bytes {
            self.exceeded_limit = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "archive exceeds signed byte length",
            ));
        }
        let written = self.file.write(bytes)?;
        self.digest.update(&bytes[..written]);
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        io::Write,
        path::{Path, PathBuf},
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use ed25519_dalek::{Signer, SigningKey};
    use flate2::{Compression, write::GzEncoder};
    use parking_lot::Mutex;
    use semver::Version;
    use sha2::Digest as _;
    use tempfile::tempdir;

    use super::{
        LocalClientHealth, LocalHealthObservation, LocalHealthProbe, ReleaseDiscovery,
        ReleaseSource, UpdateLock, Updater, UpdaterFailureCode, UpdaterResult,
        current_platform_target,
    };
    use crate::{
        platform::{ServiceError, ServiceInstallSpec, ServiceManager, ServiceState},
        update::{
            activate::LocalHealth,
            manifest::{ReleaseAsset, UpdateError},
        },
        version::{ActiveRelease, LAUNCHER_ABI, read_active_release, write_active_release},
    };

    fn target() -> &'static str {
        current_platform_target().expect("the test platform must have a release target")
    }
    const INSTALLED_VERSION: &str = "1.0.0";
    const AVAILABLE_VERSION: &str = "2.0.0";

    struct FakeSource {
        discovery: ReleaseDiscovery,
        archive: Vec<u8>,
        discoveries: AtomicUsize,
        downloads: Mutex<Vec<String>>,
    }

    impl FakeSource {
        fn new(discovery: ReleaseDiscovery, archive: Vec<u8>) -> Self {
            Self {
                discovery,
                archive,
                discoveries: AtomicUsize::new(0),
                downloads: Mutex::new(Vec::new()),
            }
        }
    }

    impl ReleaseSource for FakeSource {
        fn discover<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<ReleaseDiscovery, UpdateError>> + Send + 'a>>
        {
            self.discoveries.fetch_add(1, Ordering::SeqCst);
            let discovery = self.discovery.clone();
            Box::pin(async move { Ok(discovery) })
        }

        fn download_asset<'a>(
            &'a self,
            _discovery: &'a ReleaseDiscovery,
            asset: &'a ReleaseAsset,
            output: &'a mut (dyn Write + Send),
        ) -> Pin<Box<dyn Future<Output = Result<(), UpdateError>> + Send + 'a>> {
            self.downloads.lock().push(asset.archive.clone());
            let archive = self.archive.clone();
            let asset = asset.archive.clone();
            Box::pin(async move {
                output
                    .write_all(&archive)
                    .map_err(|source| UpdateError::WriteDownloadedReleaseAsset { asset, source })
            })
        }
    }

    #[derive(Default)]
    struct FakeService {
        calls: Mutex<Vec<&'static str>>,
    }

    impl ServiceManager for FakeService {
        fn install(&self, _spec: &ServiceInstallSpec) -> Result<(), ServiceError> {
            Ok(())
        }

        fn start(&self, _name: &str) -> Result<ServiceState, ServiceError> {
            self.calls.lock().push("start");
            Ok(ServiceState::Running)
        }

        fn stop(&self, _name: &str) -> Result<ServiceState, ServiceError> {
            self.calls.lock().push("stop");
            Ok(ServiceState::Stopped)
        }

        fn restart(&self, _name: &str) -> Result<ServiceState, ServiceError> {
            Ok(ServiceState::Running)
        }

        fn status(&self, _name: &str) -> Result<ServiceState, ServiceError> {
            Ok(ServiceState::Running)
        }

        fn set_autostart(&self, _name: &str, _enabled: bool) -> Result<(), ServiceError> {
            Ok(())
        }
    }

    struct FakeHealth {
        fails: bool,
        calls: AtomicUsize,
    }

    impl FakeHealth {
        fn healthy() -> Self {
            Self {
                fails: false,
                calls: AtomicUsize::new(0),
            }
        }

        fn timing_out() -> Self {
            Self {
                fails: true,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl LocalHealth for FakeHealth {
        fn wait_for_ready<'a>(
            &'a self,
            _deadline: Duration,
        ) -> Pin<Box<dyn Future<Output = Result<(), UpdateError>> + Send + 'a>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if self.fails {
                    Err(UpdateError::HealthTimeout)
                } else {
                    Ok(())
                }
            })
        }
    }

    struct FakeProbe {
        observation: LocalHealthObservation,
    }

    impl LocalHealthProbe for FakeProbe {
        fn observe<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Option<LocalHealthObservation>> + Send + 'a>> {
            let observation = self.observation.clone();
            Box::pin(async move { Some(observation) })
        }
    }

    fn test_archive() -> Vec<u8> {
        test_archive_with_components(true, true)
    }

    fn test_archive_without_updater() -> Vec<u8> {
        test_archive_with_components(false, true)
    }

    fn test_archive_without_tray() -> Vec<u8> {
        test_archive_with_components(true, false)
    }

    fn test_archive_with_components(include_updater: bool, include_tray: bool) -> Vec<u8> {
        let mut archive = Vec::new();
        let encoder = GzEncoder::new(&mut archive, Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let payload = b"#!/bin/sh\nexit 0\n";
        let suffix = crate::version::current_exe_suffix();
        let payload_name = format!("bundle/rqbit-tunnel{suffix}");
        let tray_name = format!("bundle/rqbit-tunnel-tray{suffix}");
        let updater_name = format!("bundle/rqbit-tunnel-updater{suffix}");
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, &payload_name, &payload[..])
            .unwrap();
        if include_tray {
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, &tray_name, &payload[..])
                .unwrap();
        }
        if include_updater {
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, &updater_name, &payload[..])
                .unwrap();
        }
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();
        archive
    }

    fn signed_source(archive: &[u8], valid_signature: bool) -> (SigningKey, FakeSource) {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let manifest = serde_json::json!({
            "schema_version": 1,
            "version": AVAILABLE_VERSION,
            "launcher_abi": LAUNCHER_ABI,
            "assets": [{
                "target": target(),
                "archive": "bundle.tar.gz",
                "bytes": archive.len(),
                "sha256": hex::encode(sha2::Sha256::digest(archive)),
            }],
        });
        let raw_manifest = serde_json::to_vec(&manifest).unwrap();
        let signature = if valid_signature {
            BASE64_STANDARD.encode(signing_key.sign(&raw_manifest).to_bytes())
        } else {
            BASE64_STANDARD.encode([0_u8; 64])
        };
        let source = FakeSource::new(
            ReleaseDiscovery::new(raw_manifest, signature),
            archive.to_vec(),
        );
        (signing_key, source)
    }

    fn install_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let payload_dir = root
            .path()
            .join("releases")
            .join(INSTALLED_VERSION)
            .join("payload");
        std::fs::create_dir_all(&payload_dir).unwrap();
        let executable = payload_dir.join(format!(
            "rqbit-tunnel{}",
            crate::version::current_exe_suffix()
        ));
        std::fs::write(&executable, b"old payload").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&executable, permissions).unwrap();
        }
        write_active_release(
            root.path(),
            &ActiveRelease::new(
                Version::parse(INSTALLED_VERSION).unwrap(),
                PathBuf::from("releases")
                    .join(INSTALLED_VERSION)
                    .join("payload"),
                LAUNCHER_ABI,
            )
            .unwrap(),
        )
        .unwrap();
        root
    }

    #[test]
    fn updater_failure_codes_distinguish_rollbacks_and_concurrent_updates() {
        let restored = UpdateError::RolledBack {
            source: Box::new(UpdateError::HealthTimeout),
        };
        let unrecovered = UpdateError::RollbackFailed {
            source: Box::new(UpdateError::HealthTimeout),
            recovery: Box::new(UpdateError::HealthTimeout),
        };
        let concurrent = UpdateError::UpdateAlreadyRunning {
            path: PathBuf::from("/install"),
        };

        assert_eq!(
            UpdaterFailureCode::from_error(&restored),
            UpdaterFailureCode::RolledBack
        );
        assert_eq!(
            UpdaterFailureCode::from_error(&unrecovered),
            UpdaterFailureCode::RollbackFailed
        );
        assert_eq!(
            UpdaterFailureCode::from_error(&concurrent),
            UpdaterFailureCode::UpdateInProgress
        );
    }

    fn updater<'a>(
        root: &Path,

        signing_key: &SigningKey,
        source: &'a FakeSource,
        service: &'a FakeService,
        health: &'a dyn LocalHealth,
    ) -> Updater<'a> {
        Updater::new(
            root,
            target(),
            signing_key.verifying_key(),
            source,
            service,
            health,
        )
        .unwrap()
    }

    #[test]
    fn update_lock_rejects_another_installer_for_the_same_root() {
        let install_root = tempdir().expect("installation root should be created");
        let first = UpdateLock::acquire(install_root.path())
            .expect("first update operation must acquire the lock");
        let error = UpdateLock::acquire(install_root.path())
            .expect_err("concurrent update operation must not acquire the lock");

        assert!(matches!(error, UpdateError::UpdateAlreadyRunning { .. }));
        drop(first);
        UpdateLock::acquire(install_root.path())
            .expect("lock must become available after the first update completes");
    }

    #[tokio::test]
    async fn install_rejects_a_concurrent_update_before_release_discovery() {
        let root = install_root();
        let archive = test_archive();
        let (signing_key, source) = signed_source(&archive, true);
        let service = FakeService::default();
        let health = FakeHealth::healthy();
        let _lock =
            UpdateLock::acquire(root.path()).expect("first update operation must acquire the lock");

        let error = updater(root.path(), &signing_key, &source, &service, &health)
            .install(&Version::parse(AVAILABLE_VERSION).unwrap())
            .await
            .expect_err("concurrent update must be rejected");

        assert!(matches!(error, UpdateError::UpdateAlreadyRunning { .. }));
        assert_eq!(source.discoveries.load(Ordering::SeqCst), 0);
        assert!(source.downloads.lock().is_empty());
        assert!(service.calls.lock().is_empty());
        assert_eq!(health.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn check_selects_the_verified_platform_asset_without_service_calls() {
        let root = install_root();
        let archive = test_archive();
        let (signing_key, source) = signed_source(&archive, true);
        let service = FakeService::default();
        let health = FakeHealth::healthy();

        let result = updater(root.path(), &signing_key, &source, &service, &health)
            .check()
            .await
            .unwrap();

        assert_eq!(
            result,
            UpdaterResult::UpdateAvailable {
                version: Version::parse(AVAILABLE_VERSION).unwrap(),
            }
        );
        assert_eq!(source.discoveries.load(Ordering::SeqCst), 1);
        assert!(source.downloads.lock().is_empty());
        assert!(service.calls.lock().is_empty());
        assert_eq!(health.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn selected_github_tag_must_match_signed_manifest() {
        let root = install_root();
        let archive = test_archive();
        let (signing_key, mut source) = signed_source(&archive, true);
        let selected = Version::parse("3.0.0").expect("selected fixture version must parse");
        source.discovery = ReleaseDiscovery::new(
            source.discovery.raw_manifest.clone(),
            source.discovery.signature.clone(),
        )
        .with_selected_github_version(selected.clone());
        let service = FakeService::default();
        let health = FakeHealth::healthy();
        let requested = Version::parse(AVAILABLE_VERSION).expect("fixture version must parse");

        let error = updater(root.path(), &signing_key, &source, &service, &health)
            .install(&requested)
            .await
            .expect_err("selected GitHub tag must match the signed manifest version");

        assert!(matches!(
            error,
            UpdateError::GithubReleaseManifestVersionMismatch {
                selected: actual_selected,
                manifest,
            } if actual_selected == selected
                && manifest == Version::parse(AVAILABLE_VERSION).expect("manifest fixture version must parse")
        ));
        assert!(
            source.downloads.lock().is_empty(),
            "version mismatch must be rejected before archive download"
        );
    }

    #[tokio::test]
    async fn install_promotes_a_verified_archive_and_activates_it() {
        let root = install_root();
        let archive = test_archive();
        let (signing_key, source) = signed_source(&archive, true);
        let service = FakeService::default();
        let health = FakeHealth::healthy();

        let result = updater(root.path(), &signing_key, &source, &service, &health)
            .install(&Version::parse(AVAILABLE_VERSION).unwrap())
            .await
            .unwrap();

        assert_eq!(
            result,
            UpdaterResult::Installed {
                version: Version::parse(AVAILABLE_VERSION).unwrap(),
            }
        );
        let active = read_active_release(root.path()).unwrap();
        assert_eq!(
            active.version(),
            &Version::parse(AVAILABLE_VERSION).unwrap()
        );
        assert_eq!(
            active.payload_dir(),
            Path::new("releases")
                .join(AVAILABLE_VERSION)
                .join("payload")
        );
        assert!(
            root.path()
                .join("releases")
                .join(AVAILABLE_VERSION)
                .join("payload")
                .join(format!(
                    "rqbit-tunnel{}",
                    crate::version::current_exe_suffix()
                ))
                .is_file()
        );
        assert_eq!(service.calls.lock().as_slice(), ["stop", "start"]);
    }

    #[tokio::test]
    async fn incomplete_client_bundle_does_not_stop_the_service() {
        let root = install_root();
        let archive = test_archive_without_updater();
        let (signing_key, source) = signed_source(&archive, true);
        let service = FakeService::default();
        let health = FakeHealth::healthy();

        let error = updater(root.path(), &signing_key, &source, &service, &health)
            .install(&Version::parse(AVAILABLE_VERSION).unwrap())
            .await
            .expect_err("archive without the updater must not activate");

        assert!(matches!(
            error,
            UpdateError::MissingClientPayloadComponent { component }
                if component
                    == format!(
                        "rqbit-tunnel-updater{}",
                        crate::version::current_exe_suffix()
                    )
        ));
        assert!(service.calls.lock().is_empty());
        assert_eq!(
            read_active_release(root.path()).unwrap().version(),
            &Version::parse(INSTALLED_VERSION).unwrap()
        );
    }

    #[tokio::test]
    async fn trayless_client_bundle_does_not_stop_the_service() {
        let root = install_root();
        let archive = test_archive_without_tray();
        let (signing_key, source) = signed_source(&archive, true);
        let service = FakeService::default();
        let health = FakeHealth::healthy();

        let error = updater(root.path(), &signing_key, &source, &service, &health)
            .install(&Version::parse(AVAILABLE_VERSION).unwrap())
            .await
            .expect_err("archive without the tray companion must not activate");

        assert!(matches!(
            error,
            UpdateError::MissingClientPayloadComponent { component }
                if component
                    == format!(
                        "rqbit-tunnel-tray{}",
                        crate::version::current_exe_suffix()
                    )
        ));
        assert!(service.calls.lock().is_empty());
        assert_eq!(
            read_active_release(root.path()).unwrap().version(),
            &Version::parse(INSTALLED_VERSION).unwrap()
        );
    }

    #[tokio::test]
    async fn checksum_rejection_leaves_release_and_pointer_untouched() {
        let root = install_root();

        let expected_archive = test_archive();
        let (signing_key, mut source) = signed_source(&expected_archive, true);
        source.archive[0] ^= 0x80;
        let service = FakeService::default();
        let health = FakeHealth::healthy();

        let error = updater(root.path(), &signing_key, &source, &service, &health)
            .install(&Version::parse(AVAILABLE_VERSION).unwrap())
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            UpdateError::DownloadedArchiveChecksumMismatch { .. }
        ));
        assert_eq!(
            read_active_release(root.path()).unwrap().version(),
            &Version::parse(INSTALLED_VERSION).unwrap()
        );
        assert!(
            !root
                .path()
                .join("releases")
                .join(AVAILABLE_VERSION)
                .exists()
        );
        assert!(service.calls.lock().is_empty());
    }

    #[tokio::test]
    async fn signature_rejection_leaves_service_untouched() {
        let root = install_root();
        let archive = test_archive();
        let (signing_key, source) = signed_source(&archive, false);
        let service = FakeService::default();
        let health = FakeHealth::healthy();

        let error = updater(root.path(), &signing_key, &source, &service, &health)
            .install(&Version::parse(AVAILABLE_VERSION).unwrap())
            .await
            .unwrap_err();

        assert!(matches!(error, UpdateError::InvalidSignature));
        assert!(source.downloads.lock().is_empty());
        assert!(service.calls.lock().is_empty());
    }

    #[tokio::test]
    async fn successful_rollback_removes_the_candidate_for_a_retry() {
        let root = install_root();
        let archive = test_archive();
        let (signing_key, source) = signed_source(&archive, true);
        let failed_service = FakeService::default();
        let failed_health = FakeHealth::timing_out();

        let error = updater(
            root.path(),
            &signing_key,
            &source,
            &failed_service,
            &failed_health,
        )
        .install(&Version::parse(AVAILABLE_VERSION).unwrap())
        .await
        .expect_err("unhealthy candidate must roll back");

        assert!(matches!(error, UpdateError::RolledBack { .. }));
        assert!(
            !root
                .path()
                .join("releases")
                .join(AVAILABLE_VERSION)
                .exists(),
            "a rolled-back candidate must not block a retry of the same version"
        );

        let retry_service = FakeService::default();
        let retry_health = FakeHealth::healthy();
        let result = updater(
            root.path(),
            &signing_key,
            &source,
            &retry_service,
            &retry_health,
        )
        .install(&Version::parse(AVAILABLE_VERSION).unwrap())
        .await
        .expect("retry after a successful rollback must install the candidate");

        assert_eq!(
            result,
            UpdaterResult::Installed {
                version: Version::parse(AVAILABLE_VERSION).unwrap()
            }
        );
    }

    #[tokio::test]
    async fn failed_health_restores_the_old_pointer_and_service() {
        let root = install_root();
        let archive = test_archive();
        let (signing_key, source) = signed_source(&archive, true);
        let service = FakeService::default();
        let health = FakeHealth::timing_out();

        let error = updater(root.path(), &signing_key, &source, &service, &health)
            .install(&Version::parse(AVAILABLE_VERSION).unwrap())
            .await
            .unwrap_err();

        assert!(matches!(error, UpdateError::RolledBack { .. }));
        assert_eq!(
            UpdaterResult::from_error(&error),
            UpdaterResult::Failed {
                code: UpdaterFailureCode::RolledBack,
            }
        );
        assert_eq!(
            read_active_release(root.path()).unwrap().version(),
            &Version::parse(INSTALLED_VERSION).unwrap()
        );
        assert_eq!(
            service.calls.lock().as_slice(),
            ["stop", "start", "stop", "start"]
        );
    }

    #[tokio::test]
    async fn reconnecting_but_healthy_local_client_allows_installation() {
        let root = install_root();
        let archive = test_archive();
        let (signing_key, source) = signed_source(&archive, true);
        let service = FakeService::default();
        let health = LocalClientHealth::with_probe(
            FakeProbe {
                observation: LocalHealthObservation::running_reconnecting(),
            },
            Duration::from_millis(1),
        );

        let result = updater(root.path(), &signing_key, &source, &service, &health)
            .install(&Version::parse(AVAILABLE_VERSION).unwrap())
            .await
            .unwrap();

        assert!(matches!(result, UpdaterResult::Installed { .. }));
        assert_eq!(service.calls.lock().as_slice(), ["stop", "start"]);
    }
}
