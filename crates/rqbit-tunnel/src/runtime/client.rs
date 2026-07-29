use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[cfg(all(test, unix))]
use std::sync::LazyLock;

#[cfg(unix)]
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
};

#[cfg(unix)]
use uuid::Uuid;

use librqbit::{
    DhtSessionConfig, Session, SessionOptions, TunnelClientOptions, TunnelOptions,
    TunnelPrivateKey, TunnelPublicKey, TunnelServiceStatus,
};
use thiserror::Error;
use tokio::{
    sync::{Mutex, watch},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

#[cfg(unix)]
use crate::ipc::{
    protocol::{ClientRequest, ClientResponse},
    unix::{UnixControlError, read_client_request, write_client_response_until_shutdown},
};
#[cfg(windows)]
use crate::ipc::{
    protocol::{ClientRequest, ClientResponse},
    windows::{
        WindowsClientControlError, WindowsClientControlListener, read_client_request,
        write_client_response_until_shutdown,
    },
};
use crate::{
    config::{ConfigError, load_client_config, read_private_key},
    model::{ClientConfig, ClientSnapshot, ClientStatusOwner, LocalServiceState, LocalTunnelState},
    paths::ClientPaths,
};

#[derive(Debug, Error)]
pub enum ClientRuntimeError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("librqbit tunnel client session startup failed")]
    SessionStart,
    #[error("client configuration has no usable {platform} status owner")]
    MissingStatusOwner { platform: &'static str },
    #[cfg(unix)]
    #[error("failed to create or bind client control socket {path}: {source}")]
    ControlSocket {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[cfg(unix)]
    #[error("failed to apply client control access policy to {path}: {source}")]
    ControlAccessPolicy {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[cfg(unix)]
    #[error("an active managed client already owns control socket {path}")]
    ActiveControlSocket { path: PathBuf },
    #[cfg(unix)]
    #[error("refusing to remove non-socket client control path {path} ({kind})")]
    UnsafeControlSocketPath { path: PathBuf, kind: &'static str },
    #[cfg(windows)]
    #[error(transparent)]
    WindowsControl(#[from] WindowsClientControlError),
    #[error("client control task failed: {0}")]
    ControlTask(#[from] tokio::task::JoinError),
    #[error("managed client shutdown failed during {code:?}: {message}")]
    SharedShutdownFailure {
        code: ClientShutdownFailureCode,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientShutdownFailureCode {
    Cleanup,
    ControlTask,
}

#[derive(Clone, Debug)]
enum SharedShutdownResult {
    Completed,
    Failed {
        code: ClientShutdownFailureCode,
        message: String,
    },
}

impl SharedShutdownResult {
    fn from_result(result: &Result<(), ClientRuntimeError>) -> Self {
        match result {
            Ok(()) => Self::Completed,
            Err(error) => Self::Failed {
                code: match error {
                    ClientRuntimeError::ControlTask(_) => ClientShutdownFailureCode::ControlTask,
                    _ => ClientShutdownFailureCode::Cleanup,
                },
                message: error.to_string(),
            },
        }
    }

    fn into_result(self) -> Result<(), ClientRuntimeError> {
        match self {
            Self::Completed => Ok(()),
            Self::Failed { code, message } => {
                Err(ClientRuntimeError::SharedShutdownFailure { code, message })
            }
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl SocketIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[cfg(all(test, unix))]
struct CleanupSocketRemovalPause {
    locked: std::sync::Barrier,
    resume: std::sync::Barrier,
}

#[cfg(all(test, unix))]
impl CleanupSocketRemovalPause {
    fn new() -> Self {
        Self {
            locked: std::sync::Barrier::new(2),
            resume: std::sync::Barrier::new(2),
        }
    }

    fn wait_until_locked(&self) {
        self.locked.wait();
    }

    fn resume(&self) {
        self.resume.wait();
    }
}

#[cfg(all(test, unix))]
static CLEANUP_SOCKET_REMOVAL_PAUSE: LazyLock<
    std::sync::Mutex<Option<(PathBuf, Arc<CleanupSocketRemovalPause>)>>,
> = LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(all(test, unix))]
struct CleanupSocketRemovalPauseGuard;

#[cfg(all(test, unix))]
impl Drop for CleanupSocketRemovalPauseGuard {
    fn drop(&mut self) {
        *CLEANUP_SOCKET_REMOVAL_PAUSE
            .lock()
            .expect("cleanup socket removal pause lock must not be poisoned") = None;
    }
}

#[cfg(all(test, unix))]
fn install_cleanup_socket_removal_pause(
    path: &Path,
) -> (
    Arc<CleanupSocketRemovalPause>,
    CleanupSocketRemovalPauseGuard,
) {
    let pause = Arc::new(CleanupSocketRemovalPause::new());
    let previous = CLEANUP_SOCKET_REMOVAL_PAUSE
        .lock()
        .expect("cleanup socket removal pause lock must not be poisoned")
        .replace((path.to_path_buf(), Arc::clone(&pause)));
    assert!(
        previous.is_none(),
        "a cleanup socket removal pause is already installed"
    );
    (pause, CleanupSocketRemovalPauseGuard)
}

#[cfg(all(test, unix))]
fn pause_after_client_socket_lock(path: &Path) {
    let pause = CLEANUP_SOCKET_REMOVAL_PAUSE
        .lock()
        .expect("cleanup socket removal pause lock must not be poisoned")
        .as_ref()
        .filter(|(paused_path, _)| paused_path == path)
        .map(|(_, pause)| Arc::clone(pause));
    if let Some(pause) = pause {
        pause.locked.wait();
        pause.resume.wait();
    }
}

#[cfg(all(test, unix))]
struct ClientSocketPublishPause {
    staged: std::sync::Barrier,
    resume: std::sync::Barrier,
}

#[cfg(all(test, unix))]
impl ClientSocketPublishPause {
    fn new() -> Self {
        Self {
            staged: std::sync::Barrier::new(2),
            resume: std::sync::Barrier::new(2),
        }
    }

    fn wait_until_staged(&self) {
        self.staged.wait();
    }

    fn resume(&self) {
        self.resume.wait();
    }
}

#[cfg(all(test, unix))]
static CLIENT_SOCKET_PUBLISH_PAUSE: LazyLock<
    std::sync::Mutex<Option<(PathBuf, Arc<ClientSocketPublishPause>)>>,
> = LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(all(test, unix))]
struct ClientSocketPublishPauseGuard;

#[cfg(all(test, unix))]
impl Drop for ClientSocketPublishPauseGuard {
    fn drop(&mut self) {
        *CLIENT_SOCKET_PUBLISH_PAUSE
            .lock()
            .expect("client socket publish pause lock must not be poisoned") = None;
    }
}

#[cfg(all(test, unix))]
fn install_client_socket_publish_pause(
    path: &Path,
) -> (Arc<ClientSocketPublishPause>, ClientSocketPublishPauseGuard) {
    let pause = Arc::new(ClientSocketPublishPause::new());
    let previous = CLIENT_SOCKET_PUBLISH_PAUSE
        .lock()
        .expect("client socket publish pause lock must not be poisoned")
        .replace((path.to_path_buf(), Arc::clone(&pause)));
    assert!(
        previous.is_none(),
        "a client socket publish pause is already installed"
    );
    (pause, ClientSocketPublishPauseGuard)
}

#[cfg(all(test, unix))]
fn pause_before_publishing_client_socket(path: &Path) {
    let pause = CLIENT_SOCKET_PUBLISH_PAUSE
        .lock()
        .expect("client socket publish pause lock must not be poisoned")
        .as_ref()
        .filter(|(paused_path, _)| paused_path == path)
        .map(|(_, pause)| Arc::clone(pause));
    if let Some(pause) = pause {
        pause.staged.wait();
        pause.resume.wait();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownPhase {
    Active,
    ShuttingDown,
}

pub struct ManagedClient {
    coordinator: Arc<ClientShutdownCoordinator>,
}

struct ClientShutdownCoordinator {
    inner: Arc<ManagedClientInner>,
    control_task: Mutex<Option<JoinHandle<Result<(), ClientRuntimeError>>>>,
    phase: Mutex<ShutdownPhase>,
    result: watch::Sender<Option<SharedShutdownResult>>,
}

struct ManagedClientInner {
    session: Arc<Session>,
    shutdown: CancellationToken,
    configured_carriers: usize,
    #[cfg(unix)]
    control_socket_path: PathBuf,
    #[cfg(unix)]
    control_socket_identity: SocketIdentity,
    cleanup_gate: Mutex<()>,
    cleanup_complete: AtomicBool,
}

struct ShutdownResultPublication {
    sender: watch::Sender<Option<SharedShutdownResult>>,
    published: bool,
}

impl ShutdownResultPublication {
    fn new(sender: watch::Sender<Option<SharedShutdownResult>>) -> Self {
        Self {
            sender,
            published: false,
        }
    }

    fn publish(&mut self, result: SharedShutdownResult) {
        self.sender.send_replace(Some(result));
        self.published = true;
    }
}

impl Drop for ShutdownResultPublication {
    fn drop(&mut self) {
        if !self.published {
            self.sender.send_replace(Some(SharedShutdownResult::Failed {
                code: ClientShutdownFailureCode::Cleanup,
                message: "the client shutdown coordinator exited before completing cleanup"
                    .to_owned(),
            }));
        }
    }
}

impl ManagedClient {
    #[cfg(unix)]
    pub async fn start(paths: ClientPaths) -> Result<Self, ClientRuntimeError> {
        let (config, private_key) = load_client_material(&paths)?;
        let status_owner_uid = unix_status_owner_uid(&config)?;
        let shutdown = CancellationToken::new();
        let session = start_session(&paths, &config, private_key, shutdown.clone()).await?;
        let control_socket_path = paths.control_socket_path();
        let (listener, control_socket_identity) = match bind_client_socket(&paths, status_owner_uid)
        {
            Ok(listener) => listener,
            Err(error) => {
                session.stop().await;
                return Err(error);
            }
        };
        let inner = Arc::new(ManagedClientInner {
            session,
            shutdown,
            configured_carriers: config.carriers,
            control_socket_path,
            control_socket_identity,
            cleanup_gate: Mutex::new(()),
            cleanup_complete: AtomicBool::new(false),
        });
        let (result, _) = watch::channel(None);
        let control_inner = Arc::clone(&inner);
        let control_task =
            tokio::spawn(async move { serve_client_control_socket(listener, control_inner).await });
        Ok(Self {
            coordinator: Arc::new(ClientShutdownCoordinator {
                inner,
                control_task: Mutex::new(Some(control_task)),
                phase: Mutex::new(ShutdownPhase::Active),
                result,
            }),
        })
    }

    #[cfg(windows)]
    pub async fn start(paths: ClientPaths) -> Result<Self, ClientRuntimeError> {
        let (config, private_key) = load_client_material(&paths)?;
        let owner_sid = windows_status_owner_sid(&config)?;
        let listener = WindowsClientControlListener::bind(owner_sid)?;
        let shutdown = CancellationToken::new();
        let session = start_session(&paths, &config, private_key, shutdown.clone()).await?;
        let inner = Arc::new(ManagedClientInner {
            session,
            shutdown,
            configured_carriers: config.carriers,
            cleanup_gate: Mutex::new(()),
            cleanup_complete: AtomicBool::new(false),
        });
        let (result, _) = watch::channel(None);
        let control_inner = Arc::clone(&inner);
        let control_task =
            tokio::spawn(async move { serve_client_control_pipe(listener, control_inner).await });
        Ok(Self {
            coordinator: Arc::new(ClientShutdownCoordinator {
                inner,
                control_task: Mutex::new(Some(control_task)),
                phase: Mutex::new(ShutdownPhase::Active),
                result,
            }),
        })
    }

    pub async fn snapshot(&self) -> ClientSnapshot {
        self.coordinator.inner.snapshot()
    }

    pub async fn shutdown(&self) -> Result<(), ClientRuntimeError> {
        self.coordinator.request_shutdown().await
    }
}

impl ClientShutdownCoordinator {
    async fn request_shutdown(self: &Arc<Self>) -> Result<(), ClientRuntimeError> {
        let mut result = self.result.subscribe();
        let leader = {
            let mut phase = self.phase.lock().await;
            match *phase {
                ShutdownPhase::Active => {
                    *phase = ShutdownPhase::ShuttingDown;
                    true
                }
                ShutdownPhase::ShuttingDown => false,
            }
        };

        if leader {
            let coordinator = Arc::clone(self);
            tokio::spawn(async move {
                coordinator.run_shutdown().await;
            });
        }

        loop {
            if let Some(shared) = result.borrow().clone() {
                return shared.into_result();
            }
            if result.changed().await.is_err() {
                return Err(ClientRuntimeError::SharedShutdownFailure {
                    code: ClientShutdownFailureCode::Cleanup,
                    message: "the client shutdown coordinator stopped before publishing a result"
                        .to_owned(),
                });
            }
        }
    }

    async fn run_shutdown(self: Arc<Self>) {
        let mut publication = ShutdownResultPublication::new(self.result.clone());
        let outcome = self.shutdown_once().await;
        publication.publish(SharedShutdownResult::from_result(&outcome));
    }

    async fn shutdown_once(&self) -> Result<(), ClientRuntimeError> {
        let cleanup_result = self.inner.cleanup().await;
        let control_task = self.control_task.lock().await.take();
        let task_result = match control_task {
            Some(task) => match task.await {
                Ok(result) => result,
                Err(error) => Err(ClientRuntimeError::ControlTask(error)),
            },
            None => Ok(()),
        };

        cleanup_result?;
        task_result
    }
}

impl ManagedClientInner {
    fn snapshot(&self) -> ClientSnapshot {
        let version = self.session.client_name_and_version().to_owned();
        if self.shutdown.is_cancelled() {
            return ClientSnapshot {
                service: LocalServiceState::Stopped,
                tunnel: LocalTunnelState::Error,
                socks_listen: None,
                configured_carriers: self.configured_carriers,
                live_carriers: 0,
                version,
                error: None,
            };
        }

        match self
            .session
            .tunnel_service()
            .map(|service| service.status())
        {
            Some(TunnelServiceStatus::Client {
                socks_listen,
                configured_carriers,
                live_carriers,
            }) => ClientSnapshot {
                service: LocalServiceState::Running,
                tunnel: local_tunnel_state(live_carriers),
                socks_listen: Some(socks_listen),
                configured_carriers,
                live_carriers,
                version,
                error: None,
            },
            Some(TunnelServiceStatus::Server { .. }) | None => ClientSnapshot {
                service: LocalServiceState::Failed,
                tunnel: LocalTunnelState::Error,
                socks_listen: None,
                configured_carriers: self.configured_carriers,
                live_carriers: 0,
                version,
                error: Some("the local client tunnel service is unavailable".to_owned()),
            },
        }
    }
}

fn local_tunnel_state(live_carriers: usize) -> LocalTunnelState {
    if live_carriers == 0 {
        LocalTunnelState::Reconnecting
    } else {
        LocalTunnelState::Connected
    }
}

fn load_client_material(
    paths: &ClientPaths,
) -> Result<(ClientConfig, [u8; 32]), ClientRuntimeError> {
    let config = load_client_config(paths)?;
    let private_key = read_private_key(&config.client_key_path)?;
    Ok((config, private_key))
}

async fn start_session(
    paths: &ClientPaths,
    config: &ClientConfig,
    private_key: [u8; 32],
    shutdown: CancellationToken,
) -> Result<Arc<Session>, ClientRuntimeError> {
    Session::new_with_opts(
        paths.data_dir.clone(),
        SessionOptions {
            dht: config.server_addr.is_none().then(|| DhtSessionConfig {
                persistence: None,
                ..Default::default()
            }),
            disable_trackers: true,
            persistence: None,
            listen: None,
            connect: None,
            cancellation_token: Some(shutdown),
            disable_local_service_discovery: true,
            tunnel: Some(TunnelOptions::Client(TunnelClientOptions {
                socks_listen: config.socks_listen,
                server_addr: config.server_addr,
                identity_key: TunnelPrivateKey(private_key),
                expected_server_key: TunnelPublicKey(config.server_public_key),
                pairing: None,
                carriers: config.carriers,
                carrier_root: config.carrier_root.clone(),
            })),
            ..Default::default()
        },
    )
    .await
    .map_err(|_| ClientRuntimeError::SessionStart)
}

#[cfg(unix)]
impl ManagedClientInner {
    async fn cleanup(&self) -> Result<(), ClientRuntimeError> {
        let _gate = self.cleanup_gate.lock().await;
        if self.cleanup_complete.load(Ordering::Acquire) {
            return Ok(());
        }

        self.shutdown.cancel();
        self.session.stop().await;
        let socket_result = remove_owned_client_socket_with_lock(
            &self.control_socket_path,
            self.control_socket_identity,
        );
        self.cleanup_complete.store(true, Ordering::Release);
        socket_result
    }
}

#[cfg(windows)]
impl ManagedClientInner {
    async fn cleanup(&self) -> Result<(), ClientRuntimeError> {
        let _gate = self.cleanup_gate.lock().await;
        if self.cleanup_complete.load(Ordering::Acquire) {
            return Ok(());
        }

        self.shutdown.cancel();
        self.session.stop().await;
        self.cleanup_complete.store(true, Ordering::Release);
        Ok(())
    }
}

#[cfg(unix)]
fn client_socket_lock_path(path: &Path) -> PathBuf {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

#[cfg(unix)]
fn lock_client_socket(path: &Path) -> Result<File, ClientRuntimeError> {
    let lock_path = client_socket_lock_path(path);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .map_err(|source| ClientRuntimeError::ControlSocket {
            path: lock_path.clone(),
            source,
        })?;
    lock.lock()
        .map_err(|source| ClientRuntimeError::ControlSocket {
            path: lock_path,
            source,
        })?;
    Ok(lock)
}

#[cfg(unix)]
const CLIENT_SOCKET_STAGING_DIRECTORY_NAME: &str = ".client-socket-staging";

#[cfg(unix)]
fn client_socket_staging_directory(parent: &Path) -> PathBuf {
    parent.join(CLIENT_SOCKET_STAGING_DIRECTORY_NAME)
}

#[cfg(unix)]
fn prepare_root_owned_directory(path: &Path, expected_mode: u32) -> Result<(), ClientRuntimeError> {
    fs::create_dir_all(path).map_err(|source| ClientRuntimeError::ControlAccessPolicy {
        path: path.to_path_buf(),
        source,
    })?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| ClientRuntimeError::ControlAccessPolicy {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata =
        directory
            .metadata()
            .map_err(|source| ClientRuntimeError::ControlAccessPolicy {
                path: path.to_path_buf(),
                source,
            })?;
    if !metadata.file_type().is_dir() {
        return Err(ClientRuntimeError::UnsafeControlSocketPath {
            path: path.to_path_buf(),
            kind: socket_path_kind(&metadata),
        });
    }
    // SAFETY: `directory` is an open descriptor for the inspected directory.
    if unsafe {
        libc::fchown(
            directory.as_raw_fd(),
            0 as libc::uid_t,
            u32::MAX as libc::gid_t,
        )
    } != 0
    {
        return Err(ClientRuntimeError::ControlAccessPolicy {
            path: path.to_path_buf(),
            source: io::Error::last_os_error(),
        });
    }
    directory
        .set_permissions(fs::Permissions::from_mode(expected_mode))
        .map_err(|source| ClientRuntimeError::ControlAccessPolicy {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata =
        directory
            .metadata()
            .map_err(|source| ClientRuntimeError::ControlAccessPolicy {
                path: path.to_path_buf(),
                source,
            })?;
    if metadata.uid() != 0 || metadata.permissions().mode() & 0o777 != expected_mode {
        return Err(ClientRuntimeError::ControlAccessPolicy {
            path: path.to_path_buf(),
            source: io::Error::other("client control directory policy was not applied"),
        });
    }
    Ok(())
}

/// Makes the client runtime directory inaccessible for mutation by the
/// desktop config owner. The installed service creates it as root; staging
/// runs fail closed if that ownership cannot be established.
#[cfg(unix)]
fn prepare_client_run_directory(path: &Path) -> Result<(), ClientRuntimeError> {
    prepare_root_owned_directory(path, 0o711)
}

#[cfg(unix)]
fn prepare_client_socket_staging_directory(parent: &Path) -> Result<PathBuf, ClientRuntimeError> {
    let staging_directory = client_socket_staging_directory(parent);
    prepare_root_owned_directory(&staging_directory, 0o700)?;
    Ok(staging_directory)
}

#[cfg(unix)]
fn purge_stale_staged_client_sockets(staging_directory: &Path) -> Result<(), ClientRuntimeError> {
    let entries =
        fs::read_dir(staging_directory).map_err(|source| ClientRuntimeError::ControlSocket {
            path: staging_directory.to_path_buf(),
            source,
        })?;
    for entry in entries {
        let entry = entry.map_err(|source| ClientRuntimeError::ControlSocket {
            path: staging_directory.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|source| ClientRuntimeError::ControlSocket {
                path: path.clone(),
                source,
            })?;
        if !metadata.file_type().is_socket() {
            return Err(ClientRuntimeError::UnsafeControlSocketPath {
                path,
                kind: socket_path_kind(&metadata),
            });
        }
        let identity = SocketIdentity::from_metadata(&metadata);
        match std::os::unix::net::UnixStream::connect(&path) {
            Ok(_) => return Err(ClientRuntimeError::ActiveControlSocket { path }),
            Err(source) if source.kind() == io::ErrorKind::ConnectionRefused => {
                remove_stale_client_socket(&path, identity)?;
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ClientRuntimeError::ControlSocket { path, source });
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn unix_status_owner_uid(config: &ClientConfig) -> Result<u32, ClientRuntimeError> {
    match config.status_owner.as_ref() {
        Some(ClientStatusOwner::Unix { uid }) => Ok(*uid),
        Some(ClientStatusOwner::Windows { .. }) | None => {
            Err(ClientRuntimeError::MissingStatusOwner { platform: "Unix" })
        }
    }
}

#[cfg(windows)]
fn windows_status_owner_sid(config: &ClientConfig) -> Result<&str, ClientRuntimeError> {
    match config.status_owner.as_ref() {
        Some(ClientStatusOwner::Windows { sid }) => Ok(sid),
        Some(ClientStatusOwner::Unix { .. }) | None => {
            Err(ClientRuntimeError::MissingStatusOwner {
                platform: "Windows",
            })
        }
    }
}

#[cfg(unix)]
fn apply_client_socket_access_policy(
    path: &Path,
    expected_identity: SocketIdentity,
    owner_uid: u32,
) -> Result<(), ClientRuntimeError> {
    let path_bytes = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        ClientRuntimeError::ControlAccessPolicy {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "client control socket path contains a NUL byte",
            ),
        }
    })?;
    // SAFETY: `lchown` receives a NUL-terminated path and never follows a
    // replacement symbolic link.
    if unsafe {
        libc::lchown(
            path_bytes.as_ptr(),
            owner_uid as libc::uid_t,
            u32::MAX as libc::gid_t,
        )
    } != 0
    {
        return Err(ClientRuntimeError::ControlAccessPolicy {
            path: path.to_path_buf(),
            source: io::Error::last_os_error(),
        });
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|source| ClientRuntimeError::ControlAccessPolicy {
            path: path.to_path_buf(),
            source,
        })?;
    if !metadata.file_type().is_socket()
        || SocketIdentity::from_metadata(&metadata) != expected_identity
    {
        return Err(ClientRuntimeError::UnsafeControlSocketPath {
            path: path.to_path_buf(),
            kind: socket_path_kind(&metadata),
        });
    }
    if metadata.uid() != owner_uid {
        return Err(ClientRuntimeError::ControlAccessPolicy {
            path: path.to_path_buf(),
            source: io::Error::other("client control socket owner did not change"),
        });
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        ClientRuntimeError::ControlAccessPolicy {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| ClientRuntimeError::ControlAccessPolicy {
            path: path.to_path_buf(),
            source,
        })?;
    if !metadata.file_type().is_socket()
        || SocketIdentity::from_metadata(&metadata) != expected_identity
    {
        return Err(ClientRuntimeError::UnsafeControlSocketPath {
            path: path.to_path_buf(),
            kind: socket_path_kind(&metadata),
        });
    }
    if metadata.uid() != owner_uid || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(ClientRuntimeError::ControlAccessPolicy {
            path: path.to_path_buf(),
            source: io::Error::other("client control socket policy was not applied"),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn discard_unpublished_client_socket(
    listener: tokio::net::UnixListener,
    path: &Path,
    identity: SocketIdentity,
) {
    drop(listener);
    let _ = remove_owned_client_socket(path, identity);
}

#[cfg(unix)]
fn bind_client_socket(
    paths: &ClientPaths,
    owner_uid: u32,
) -> Result<(tokio::net::UnixListener, SocketIdentity), ClientRuntimeError> {
    let path = paths.control_socket_path();
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| ClientRuntimeError::UnsafeControlSocketPath {
            path: path.clone(),
            kind: "path without a parent directory",
        })?;
    prepare_client_run_directory(parent)?;
    let _lock = lock_client_socket(&path)?;
    let staging_directory = prepare_client_socket_staging_directory(parent)?;
    purge_stale_staged_client_sockets(&staging_directory)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            let stale_identity = SocketIdentity::from_metadata(&metadata);
            match std::os::unix::net::UnixStream::connect(&path) {
                Ok(_) => {
                    return Err(ClientRuntimeError::ActiveControlSocket { path });
                }
                Err(source) if source.kind() == io::ErrorKind::ConnectionRefused => {
                    remove_stale_client_socket(&path, stale_identity)?;
                }
                Err(source) if source.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(ClientRuntimeError::ControlSocket { path, source });
                }
            }
        }
        Ok(metadata) => {
            return Err(ClientRuntimeError::UnsafeControlSocketPath {
                path,
                kind: socket_path_kind(&metadata),
            });
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ClientRuntimeError::ControlSocket { path, source });
        }
    }

    let staging_path = staging_directory.join(format!("{}.sock", Uuid::new_v4()));
    let listener = tokio::net::UnixListener::bind(&staging_path).map_err(|source| {
        ClientRuntimeError::ControlSocket {
            path: staging_path.clone(),
            source,
        }
    })?;
    let metadata = match fs::symlink_metadata(&staging_path) {
        Ok(metadata) => metadata,
        Err(source) => {
            drop(listener);
            return Err(ClientRuntimeError::ControlSocket {
                path: staging_path,
                source,
            });
        }
    };
    if !metadata.file_type().is_socket() {
        drop(listener);
        return Err(ClientRuntimeError::UnsafeControlSocketPath {
            path: staging_path,
            kind: socket_path_kind(&metadata),
        });
    }
    let identity = SocketIdentity::from_metadata(&metadata);
    if let Err(error) = apply_client_socket_access_policy(&staging_path, identity, owner_uid) {
        discard_unpublished_client_socket(listener, &staging_path, identity);
        return Err(error);
    }

    #[cfg(all(test, unix))]
    pause_before_publishing_client_socket(&path);

    match fs::symlink_metadata(&path) {
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Ok(metadata) if metadata.file_type().is_socket() => {
            discard_unpublished_client_socket(listener, &staging_path, identity);
            return Err(ClientRuntimeError::ActiveControlSocket { path });
        }
        Ok(metadata) => {
            discard_unpublished_client_socket(listener, &staging_path, identity);
            return Err(ClientRuntimeError::UnsafeControlSocketPath {
                path,
                kind: socket_path_kind(&metadata),
            });
        }
        Err(source) => {
            discard_unpublished_client_socket(listener, &staging_path, identity);
            return Err(ClientRuntimeError::ControlSocket { path, source });
        }
    }

    // Both paths live beneath the same root-owned runtime directory, so this
    // publishes the fully configured socket atomically without dropping its listener.
    if let Err(source) = fs::rename(&staging_path, &path) {
        discard_unpublished_client_socket(listener, &staging_path, identity);
        return Err(ClientRuntimeError::ControlSocket { path, source });
    }
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(source) => {
            discard_unpublished_client_socket(listener, &path, identity);
            return Err(ClientRuntimeError::ControlSocket { path, source });
        }
    };
    if !metadata.file_type().is_socket() || SocketIdentity::from_metadata(&metadata) != identity {
        discard_unpublished_client_socket(listener, &path, identity);
        return Err(ClientRuntimeError::UnsafeControlSocketPath {
            path,
            kind: socket_path_kind(&metadata),
        });
    }
    if metadata.uid() != owner_uid || metadata.permissions().mode() & 0o777 != 0o600 {
        discard_unpublished_client_socket(listener, &path, identity);
        return Err(ClientRuntimeError::ControlAccessPolicy {
            path,
            source: io::Error::other("published client control socket policy changed"),
        });
    }
    Ok((listener, identity))
}

#[cfg(unix)]
fn remove_stale_client_socket(
    path: &Path,
    expected_identity: SocketIdentity,
) -> Result<(), ClientRuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && SocketIdentity::from_metadata(&metadata) == expected_identity =>
        {
            fs::remove_file(path).map_err(|source| ClientRuntimeError::ControlSocket {
                path: path.to_path_buf(),
                source,
            })
        }
        Ok(metadata) if metadata.file_type().is_socket() => {
            Err(ClientRuntimeError::ActiveControlSocket {
                path: path.to_path_buf(),
            })
        }
        Ok(metadata) => Err(ClientRuntimeError::UnsafeControlSocketPath {
            path: path.to_path_buf(),
            kind: socket_path_kind(&metadata),
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ClientRuntimeError::ControlSocket {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(unix)]
fn remove_owned_client_socket(
    path: &Path,
    expected_identity: SocketIdentity,
) -> Result<(), ClientRuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && SocketIdentity::from_metadata(&metadata) == expected_identity =>
        {
            fs::remove_file(path).map_err(|source| ClientRuntimeError::ControlSocket {
                path: path.to_path_buf(),
                source,
            })
        }
        Ok(_) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ClientRuntimeError::ControlSocket {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(unix)]
fn remove_owned_client_socket_with_lock(
    path: &Path,
    expected_identity: SocketIdentity,
) -> Result<(), ClientRuntimeError> {
    let _lock = lock_client_socket(path)?;
    #[cfg(all(test, unix))]
    pause_after_client_socket_lock(path);
    remove_owned_client_socket(path, expected_identity)
}

#[cfg(unix)]
fn socket_path_kind(metadata: &fs::Metadata) -> &'static str {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        "symbolic link"
    } else if file_type.is_dir() {
        "directory"
    } else if file_type.is_file() {
        "regular file"
    } else {
        "unsupported file type"
    }
}

#[cfg(unix)]
async fn serve_client_control_socket(
    listener: tokio::net::UnixListener,
    inner: Arc<ManagedClientInner>,
) -> Result<(), ClientRuntimeError> {
    let mut connections = JoinSet::new();
    let mut result = loop {
        tokio::select! {
            _ = inner.shutdown.cancelled() => break Ok(()),
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(source) => break Err(ClientRuntimeError::ControlSocket {
                        path: inner.control_socket_path.clone(),
                        source,
                    }),
                };
                let connection_inner = Arc::clone(&inner);
                connections.spawn(async move {
                    let mut stream = stream;
                    serve_client_control_socket_connection(&mut stream, connection_inner.as_ref()).await
                });
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                match joined.expect("non-empty join set returned no task") {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => break Err(error),
                    Err(error) => break Err(ClientRuntimeError::ControlTask(error)),
                }
            }
        }
    };

    inner.shutdown.cancel();
    while let Some(joined) = connections.join_next().await {
        if result.is_ok() {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(error)) => result = Err(error),
                Err(error) => result = Err(ClientRuntimeError::ControlTask(error)),
            }
        }
    }
    if result.is_err() {
        let _ = inner.cleanup().await;
    }
    result
}

#[cfg(unix)]
async fn serve_client_control_socket_connection(
    stream: &mut tokio::net::UnixStream,
    inner: &ManagedClientInner,
) -> Result<(), ClientRuntimeError> {
    let request = tokio::select! {
        _ = inner.shutdown.cancelled() => return Ok(()),
        result = read_client_request(stream) => match result {
            Ok(request) => request,
            Err(UnixControlError::Protocol(error)) => {
                let _ = write_client_response_until_shutdown(
                    stream,
                    &ClientResponse::Error(error.client_response()),
                    &inner.shutdown,
                )
                .await;
                return Ok(());
            }
            Err(_) => return Ok(()),
        },
    };
    let response = match request {
        ClientRequest::Snapshot => ClientResponse::Snapshot(inner.snapshot()),
    };
    let _ = write_client_response_until_shutdown(stream, &response, &inner.shutdown).await;
    Ok(())
}

#[cfg(windows)]
async fn serve_client_control_pipe(
    mut listener: WindowsClientControlListener,
    inner: Arc<ManagedClientInner>,
) -> Result<(), ClientRuntimeError> {
    let mut connections = JoinSet::new();
    let mut result = loop {
        tokio::select! {
            _ = inner.shutdown.cancelled() => break Ok(()),
            accepted = listener.accept() => {
                let stream = match accepted {
                    Ok(stream) => stream,
                    Err(error) => break Err(error.into()),
                };
                let connection_inner = Arc::clone(&inner);
                connections.spawn(async move {
                    let mut stream = stream;
                    serve_client_control_pipe_connection(&mut stream, connection_inner.as_ref()).await
                });
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                match joined.expect("non-empty join set returned no task") {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => break Err(error),
                    Err(error) => break Err(ClientRuntimeError::ControlTask(error)),
                }
            }
        }
    };

    inner.shutdown.cancel();
    while let Some(joined) = connections.join_next().await {
        if result.is_ok() {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(error)) => result = Err(error),
                Err(error) => result = Err(ClientRuntimeError::ControlTask(error)),
            }
        }
    }
    if result.is_err() {
        let _ = inner.cleanup().await;
    }
    result
}

#[cfg(windows)]
async fn serve_client_control_pipe_connection(
    stream: &mut tokio::net::windows::named_pipe::NamedPipeServer,
    inner: &ManagedClientInner,
) -> Result<(), ClientRuntimeError> {
    let request = tokio::select! {
        _ = inner.shutdown.cancelled() => return Ok(()),
        result = read_client_request(stream) => match result {
            Ok(request) => request,
            Err(WindowsClientControlError::Protocol(error)) => {
                let _ = write_client_response_until_shutdown(
                    stream,
                    &ClientResponse::Error(error.client_response()),
                    &inner.shutdown,
                )
                .await;
                return Ok(());
            }
            Err(_) => return Ok(()),
        },
    };
    let response = match request {
        ClientRequest::Snapshot => ClientResponse::Snapshot(inner.snapshot()),
    };
    let _ = write_client_response_until_shutdown(stream, &response, &inner.shutdown).await;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        fs::OpenOptions,
        os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    };

    use tokio::net::UnixListener;
    use tokio_util::sync::CancellationToken;

    use super::{
        ManagedClient, SocketIdentity, bind_client_socket, client_socket_lock_path,
        client_socket_staging_directory, install_cleanup_socket_removal_pause,
        install_client_socket_publish_pause, local_tunnel_state, lock_client_socket,
        prepare_client_run_directory, prepare_client_socket_staging_directory,
        remove_owned_client_socket, remove_owned_client_socket_with_lock, start_session,
        unix_status_owner_uid,
    };
    use crate::{
        config::import_bundle,
        ipc::{
            protocol::{ClientRequest, ClientResponse},
            unix::UnixClientControlClient,
        },
        model::{
            BUNDLE_SCHEMA_VERSION, ClientStatusOwner, EnrollmentBundle, LocalServiceState,
            LocalTunnelState,
        },
        paths::ClientPaths,
    };

    fn fixture_bundle() -> EnrollmentBundle {
        EnrollmentBundle {
            schema_version: BUNDLE_SCHEMA_VERSION,
            user_name: "test-client".to_owned(),
            client_private_key: [7; 32],
            server_public_key: [8; 32],
            server_addr: "192.0.2.1:4242".parse().unwrap(),
            socks_listen: "127.0.0.1:0".parse().unwrap(),
            carriers: 2,
        }
    }

    fn install_client(paths: &ClientPaths) {
        import_bundle(paths, fixture_bundle()).unwrap();
    }

    fn bind_configured_client_socket(
        paths: &ClientPaths,
    ) -> Result<(UnixListener, SocketIdentity), super::ClientRuntimeError> {
        let (config, _) = super::load_client_material(paths)?;
        bind_client_socket(paths, unix_status_owner_uid(&config)?)
    }

    #[test]
    fn carrier_liveness_maps_to_a_connection_state_without_stopping_the_service() {
        assert_eq!(local_tunnel_state(0), LocalTunnelState::Reconnecting);
        assert_eq!(local_tunnel_state(1), LocalTunnelState::Connected);
    }

    #[test]
    fn unix_status_owner_requires_a_stored_unix_identity() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        install_client(&paths);
        let (mut config, _) = super::load_client_material(&paths).unwrap();

        config.status_owner = None;
        assert!(matches!(
            unix_status_owner_uid(&config),
            Err(super::ClientRuntimeError::MissingStatusOwner { .. })
        ));

        config.status_owner = Some(ClientStatusOwner::Windows {
            sid: "S-1-5-21-1".to_owned(),
        });
        assert!(matches!(
            unix_status_owner_uid(&config),
            Err(super::ClientRuntimeError::MissingStatusOwner { .. })
        ));

        config.status_owner = Some(ClientStatusOwner::Unix { uid: 42 });
        assert_eq!(unix_status_owner_uid(&config).unwrap(), 42);
    }

    #[tokio::test]
    async fn unreachable_server_snapshot_remains_running_and_reconnecting() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        install_client(&paths);

        let started = ManagedClient::start(paths).await;
        if unsafe { libc::geteuid() } != 0 {
            assert!(matches!(
                started,
                Err(super::ClientRuntimeError::ControlAccessPolicy { .. })
            ));
            return;
        }
        let client = started.unwrap();
        let snapshot = client.snapshot().await;

        assert_eq!(snapshot.service, LocalServiceState::Running);
        assert_eq!(snapshot.tunnel, LocalTunnelState::Reconnecting);
        assert!(snapshot.socks_listen.is_some());
        assert_eq!(snapshot.configured_carriers, 2);
        assert_eq!(snapshot.live_carriers, 0);
        assert_eq!(snapshot.error, None);
        client.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn read_only_snapshot_round_trips_over_the_client_socket() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        install_client(&paths);

        let started = ManagedClient::start(paths.clone()).await;
        if unsafe { libc::geteuid() } != 0 {
            assert!(matches!(
                started,
                Err(super::ClientRuntimeError::ControlAccessPolicy { .. })
            ));
            return;
        }
        let client = started.unwrap();
        let mut control = UnixClientControlClient::connect(paths.control_socket_path())
            .await
            .unwrap();
        let response = control.request(ClientRequest::Snapshot).await.unwrap();

        match response {
            ClientResponse::Snapshot(snapshot) => {
                assert_eq!(snapshot.service, LocalServiceState::Running);
                assert_eq!(snapshot.tunnel, LocalTunnelState::Reconnecting);
                assert!(snapshot.socks_listen.is_some());
                assert_eq!(snapshot.configured_carriers, 2);
                assert_eq!(snapshot.live_carriers, 0);
            }
            ClientResponse::Error(error) => panic!("unexpected client snapshot error: {error:?}"),
        }
        client.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn client_without_a_static_server_address_uses_an_in_memory_dht() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        install_client(&paths);
        let (mut config, private_key) = super::load_client_material(&paths).unwrap();
        config.server_addr = None;
        let shutdown = CancellationToken::new();

        let session = start_session(&paths, &config, private_key, shutdown)
            .await
            .unwrap();

        assert!(session.get_dht().is_some());
        session.stop().await;
    }

    #[tokio::test]
    async fn client_with_a_static_server_address_keeps_dht_disabled() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        install_client(&paths);
        let (config, private_key) = super::load_client_material(&paths).unwrap();
        let shutdown = CancellationToken::new();

        let session = start_session(&paths, &config, private_key, shutdown)
            .await
            .unwrap();

        assert!(session.get_dht().is_none());
        session.stop().await;
    }

    #[test]
    fn client_socket_policy_uses_the_stored_status_owner() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        install_client(&paths);

        let result = bind_configured_client_socket(&paths);
        if unsafe { libc::geteuid() } != 0 {
            assert!(matches!(
                result,
                Err(super::ClientRuntimeError::ControlAccessPolicy { .. })
            ));
            return;
        }
        let (listener, identity) = result.unwrap();
        let (config, _) = super::load_client_material(&paths).unwrap();
        let owner_uid = unix_status_owner_uid(&config).unwrap();
        let socket_metadata = fs::symlink_metadata(paths.control_socket_path()).unwrap();
        let run_metadata = fs::symlink_metadata(&paths.run_dir).unwrap();

        assert_eq!(socket_metadata.uid(), owner_uid);
        assert_eq!(socket_metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(run_metadata.uid(), 0);
        assert_eq!(run_metadata.permissions().mode() & 0o777, 0o711);

        drop(listener);
        remove_owned_client_socket(&paths.control_socket_path(), identity).unwrap();
    }

    #[test]
    fn client_socket_is_not_published_before_its_owner_policy_is_applied() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        install_client(&paths);

        if unsafe { libc::geteuid() } != 0 {
            assert!(matches!(
                bind_configured_client_socket(&paths),
                Err(super::ClientRuntimeError::ControlAccessPolicy { .. })
            ));
            return;
        }

        let (pause, _guard) = install_client_socket_publish_pause(&paths.control_socket_path());
        let binding_paths = paths.clone();
        let binding = std::thread::spawn(move || bind_configured_client_socket(&binding_paths));
        pause.wait_until_staged();

        assert!(matches!(
            fs::symlink_metadata(paths.control_socket_path()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ));
        let staging_directory = client_socket_staging_directory(&paths.run_dir);
        let staging_metadata = fs::symlink_metadata(&staging_directory).unwrap();
        assert_eq!(staging_metadata.uid(), 0);
        assert_eq!(staging_metadata.permissions().mode() & 0o777, 0o700);
        let mut staged_entries = fs::read_dir(staging_directory).unwrap();
        let staged_path = staged_entries.next().unwrap().unwrap().path();
        assert!(staged_entries.next().is_none());
        let staged_metadata = fs::symlink_metadata(&staged_path).unwrap();
        let (config, _) = super::load_client_material(&paths).unwrap();
        let owner_uid = unix_status_owner_uid(&config).unwrap();
        assert!(staged_metadata.file_type().is_socket());
        assert_eq!(staged_metadata.uid(), owner_uid);
        assert_eq!(staged_metadata.permissions().mode() & 0o777, 0o600);

        pause.resume();
        let (listener, identity) = binding.join().unwrap().unwrap();
        assert!(
            fs::symlink_metadata(paths.control_socket_path())
                .unwrap()
                .file_type()
                .is_socket()
        );
        let connection =
            std::os::unix::net::UnixStream::connect(paths.control_socket_path()).unwrap();
        drop(connection);
        drop(listener);
        remove_owned_client_socket(&paths.control_socket_path(), identity).unwrap();
    }

    #[test]
    fn startup_purges_a_crash_left_staged_socket() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        install_client(&paths);

        if unsafe { libc::geteuid() } != 0 {
            assert!(matches!(
                bind_configured_client_socket(&paths),
                Err(super::ClientRuntimeError::ControlAccessPolicy { .. })
            ));
            return;
        }

        prepare_client_run_directory(&paths.run_dir).unwrap();
        let staging_directory = prepare_client_socket_staging_directory(&paths.run_dir).unwrap();
        let stale_path = staging_directory.join("crash-left.sock");
        let stale_listener = UnixListener::bind(&stale_path).unwrap();
        drop(stale_listener);
        assert!(
            fs::symlink_metadata(&stale_path)
                .unwrap()
                .file_type()
                .is_socket()
        );

        let (listener, identity) = bind_configured_client_socket(&paths).unwrap();

        assert!(matches!(
            fs::symlink_metadata(&stale_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ));
        drop(listener);
        remove_owned_client_socket(&paths.control_socket_path(), identity).unwrap();
    }

    #[test]
    fn startup_rejects_and_preserves_an_unsafe_staging_artifact() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        install_client(&paths);

        if unsafe { libc::geteuid() } != 0 {
            assert!(matches!(
                bind_configured_client_socket(&paths),
                Err(super::ClientRuntimeError::ControlAccessPolicy { .. })
            ));
            return;
        }

        prepare_client_run_directory(&paths.run_dir).unwrap();
        let staging_directory = prepare_client_socket_staging_directory(&paths.run_dir).unwrap();
        let unsafe_path = staging_directory.join("do-not-delete");
        fs::write(&unsafe_path, b"unsafe").unwrap();

        let result = bind_configured_client_socket(&paths);

        assert!(matches!(
            result,
            Err(super::ClientRuntimeError::UnsafeControlSocketPath { .. })
        ));
        assert_eq!(fs::read(unsafe_path).unwrap(), b"unsafe");
    }

    #[test]
    fn client_socket_rejects_a_preexisting_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path());
        install_client(&paths);
        fs::write(paths.control_socket_path(), b"not a socket").unwrap();

        let result = bind_configured_client_socket(&paths);
        if unsafe { libc::geteuid() } != 0 {
            assert!(matches!(
                result,
                Err(super::ClientRuntimeError::ControlAccessPolicy { .. })
            ));
            return;
        }
        let error = result.unwrap_err();

        assert!(matches!(
            error,
            super::ClientRuntimeError::UnsafeControlSocketPath {
                kind: "regular file",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn cleanup_preserves_a_socket_replaced_after_startup() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("client.sock");
        let original = UnixListener::bind(&socket).unwrap();
        let anchor = directory.path().join("original.sock");
        let identity = SocketIdentity::from_metadata(&fs::symlink_metadata(&socket).unwrap());
        fs::hard_link(&socket, &anchor).unwrap();
        drop(original);
        fs::remove_file(&socket).unwrap();
        let replacement = UnixListener::bind(&socket).unwrap();

        remove_owned_client_socket(&socket, identity).unwrap();

        assert!(
            fs::symlink_metadata(&socket)
                .unwrap()
                .file_type()
                .is_socket()
        );
        drop(replacement);
        fs::remove_file(anchor).unwrap();
    }
    #[tokio::test]
    async fn cleanup_holds_the_startup_lock_through_owned_socket_removal() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("client.sock");
        let original = UnixListener::bind(&socket).unwrap();
        let identity = SocketIdentity::from_metadata(&fs::symlink_metadata(&socket).unwrap());
        drop(original);

        let (pause, _guard) = install_cleanup_socket_removal_pause(&socket);
        let cleanup_socket = socket.clone();
        let cleanup = std::thread::spawn(move || {
            remove_owned_client_socket_with_lock(&cleanup_socket, identity)
        });
        pause.wait_until_locked();

        let competing_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(client_socket_lock_path(&socket))
            .unwrap();
        let cleanup_lock_held = competing_lock.try_lock().is_err();
        let rebind_socket = socket.clone();
        let rebind = std::thread::spawn(move || {
            let _lock = lock_client_socket(&rebind_socket).unwrap();
            assert!(matches!(
                fs::symlink_metadata(&rebind_socket),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ));
            let listener = std::os::unix::net::UnixListener::bind(&rebind_socket).unwrap();
            let identity =
                SocketIdentity::from_metadata(&fs::symlink_metadata(&rebind_socket).unwrap());
            (listener, identity)
        });
        pause.resume();
        cleanup.join().unwrap().unwrap();
        assert!(cleanup_lock_held);

        let (replacement, replacement_identity) = rebind.join().unwrap();
        assert!(
            fs::symlink_metadata(&socket)
                .unwrap()
                .file_type()
                .is_socket()
        );
        drop(replacement);
        remove_owned_client_socket(&socket, replacement_identity).unwrap();
    }
}
