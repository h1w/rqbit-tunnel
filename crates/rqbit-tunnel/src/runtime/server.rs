#[cfg(test)]
use std::sync::LazyLock;
use std::{
    collections::HashSet,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use librqbit::{
    EgressPolicy, Session, SessionOptions, TunnelOptions, TunnelPrivateKey, TunnelPublicKey,
    TunnelServerAuthorizer, TunnelServerOptions, tunnel_public_key,
};
use thiserror::Error;
#[cfg(test)]
use tokio::sync::Notify;
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{Mutex, RwLock, watch},
    task::{JoinHandle, JoinSet},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    ipc::{
        protocol::{ServerConfigResponse, ServerError, ServerRequest, ServerResponse},
        unix::{
            UnixControlError, read_request, write_response_until_shutdown,
            write_response_with_deadline,
        },
    },
    model::{
        BUNDLE_SCHEMA_VERSION, DEFAULT_USER_PAGE_SIZE, EnrollmentBundle, ServerConfig,
        ServerConfigError, ServerEgressConfig, ServerSnapshot,
    },
    paths::ServerPaths,
    registry::{RegistryError, UserRegistry},
    store::{ServerStore, StoreError},
};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("server {kind} file {path} is missing")]
    MissingFile { kind: &'static str, path: PathBuf },
    #[error("failed to inspect server {kind} file {path}: {source}")]
    InspectFile {
        kind: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("server {kind} path {path} is not a regular file")]
    NotRegularFile { kind: &'static str, path: PathBuf },
    #[error("failed to read server {kind} file {path}: {source}")]
    ReadFile {
        kind: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("server key file {path} permissions {mode:o} expose it to group or other users")]
    InsecureKeyPermissions { path: PathBuf, mode: u32 },
    #[error("server configuration file {path} is not valid JSON: {source}")]
    DeserializeConfig {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error(transparent)]
    InvalidConfig(#[from] ServerConfigError),
    #[error("server key file {path} must contain exactly 64 hexadecimal characters, got {actual}")]
    InvalidKeyLength { path: PathBuf, actual: usize },
    #[error("server key file {path} is not valid hexadecimal")]
    InvalidKeyHex { path: PathBuf },
    #[error("failed to serialize server configuration: {0}")]
    SerializeConfig(#[source] serde_json::Error),
    #[error("failed to atomically write server configuration: {0}")]
    WriteConfig(#[from] AtomicWriteError),
    #[error("server configuration was committed but its parent directory could not be synced: {0}")]
    ConfigCommittedButUnsynced(#[source] AtomicWriteError),
    #[error("blocking server configuration operation {operation} failed: {source}")]
    Blocking {
        operation: &'static str,
        #[source]
        source: tokio::task::JoinError,
    },
}

#[derive(Debug, Error)]
pub enum AtomicWriteError {
    #[error("output path {path} has no parent directory")]
    MissingParent { path: PathBuf },
    #[error("output path {path} has no normal final component")]
    MissingFinalComponent { path: PathBuf },
    #[error("failed to open output parent directory {path}: {source}")]
    OpenParent {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("output parent path {path} is not a directory")]
    ParentNotDirectory { path: PathBuf },
    #[error("failed to create temporary output file {path}: {source}")]
    CreateTemporary {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write temporary output file {path}: {source}")]
    WriteTemporary {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to sync temporary output file {path}: {source}")]
    SyncTemporary {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to atomically replace output file {path}: {source}")]
    Rename {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to sync output directory {path}: {source}")]
    SyncParent {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to serialize enrollment bundle: {0}")]
    SerializeBundle(#[source] serde_json::Error),
}

#[derive(Debug)]
enum AtomicWriteOutcome {
    Durable,
    CommittedButUnsynced(AtomicWriteError),
}
#[cfg(test)]
static ATOMIC_WRITE_PARENT_OPEN_HOOK: LazyLock<
    std::sync::Mutex<Option<(PathBuf, Box<dyn FnOnce() + Send>)>>,
> = LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
struct AtomicWriteParentOpenHookGuard;

#[cfg(test)]
impl Drop for AtomicWriteParentOpenHookGuard {
    fn drop(&mut self) {
        *ATOMIC_WRITE_PARENT_OPEN_HOOK
            .lock()
            .expect("atomic write parent-open hook lock must not be poisoned") = None;
    }
}

#[cfg(test)]
fn install_atomic_write_parent_open_hook(
    path: &Path,
    hook: impl FnOnce() + Send + 'static,
) -> AtomicWriteParentOpenHookGuard {
    let previous = ATOMIC_WRITE_PARENT_OPEN_HOOK
        .lock()
        .expect("atomic write parent-open hook lock must not be poisoned")
        .replace((path.to_path_buf(), Box::new(hook)));
    assert!(
        previous.is_none(),
        "an atomic write parent-open hook is already installed"
    );
    AtomicWriteParentOpenHookGuard
}

#[cfg(test)]
fn run_atomic_write_parent_open_hook(path: &Path) {
    let hook = {
        let mut slot = ATOMIC_WRITE_PARENT_OPEN_HOOK
            .lock()
            .expect("atomic write parent-open hook lock must not be poisoned");
        match slot.take() {
            Some((expected_path, hook)) if expected_path == path => Some(hook),
            other => {
                *slot = other;
                None
            }
        }
    };
    if let Some(hook) = hook {
        hook();
    }
}

#[derive(Debug, Error)]
pub enum ServerRuntimeError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("failed to open server state: {0}")]
    Store(#[from] StoreError),
    #[error("failed to operate the user registry: {0}")]
    Registry(#[from] RegistryError),
    #[error("librqbit tunnel session startup failed")]
    SessionStart,
    #[error("failed to create or bind control socket {path}: {source}")]
    ControlSocket {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("an active managed server already owns control socket {path}")]
    ActiveControlSocket { path: PathBuf },
    #[error("refusing to remove non-socket control path {path} ({kind})")]
    UnsafeControlSocketPath { path: PathBuf, kind: &'static str },
    #[error("failed to export enrollment bundle to {path}: {source}")]
    EnrollmentExport {
        path: PathBuf,
        #[source]
        source: AtomicWriteError,
    },
    #[error(
        "enrollment bundle at {path} was committed but its parent directory could not be synced: {source}"
    )]
    EnrollmentCommittedButUnsynced {
        path: PathBuf,
        #[source]
        source: AtomicWriteError,
    },
    #[error(
        "failed to export enrollment bundle to {path}: {source}; failed to roll back user {user_id}: {rollback}"
    )]
    EnrollmentRollback {
        path: PathBuf,
        user_id: Uuid,
        #[source]
        source: AtomicWriteError,
        rollback: RegistryError,
    },
    #[error("control server task failed: {0}")]
    ControlTask(#[from] tokio::task::JoinError),
    #[error("managed server shutdown failed during {code:?}: {message}")]
    SharedShutdownFailure {
        code: ShutdownFailureCode,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownFailureCode {
    Cleanup,
    ControlTask,
}

#[derive(Clone, Debug)]
enum SharedShutdownResult {
    Completed,
    Failed {
        code: ShutdownFailureCode,
        message: String,
    },
}

impl SharedShutdownResult {
    fn from_result(result: &Result<(), ServerRuntimeError>) -> Self {
        match result {
            Ok(()) => Self::Completed,
            Err(error) => Self::Failed {
                code: match error {
                    ServerRuntimeError::ControlTask(_) => ShutdownFailureCode::ControlTask,
                    _ => ShutdownFailureCode::Cleanup,
                },
                message: error.to_string(),
            },
        }
    }

    fn into_result(self) -> Result<(), ServerRuntimeError> {
        match self {
            Self::Completed => Ok(()),
            Self::Failed { code, message } => {
                Err(ServerRuntimeError::SharedShutdownFailure { code, message })
            }
        }
    }
}

impl ServerRuntimeError {
    fn response(&self) -> ServerError {
        let (code, recovery) = match self {
            Self::Config(ConfigError::InvalidConfig(_)) => (
                "invalid_config",
                "Correct the configuration values and submit the update again.",
            ),
            Self::Config(ConfigError::ConfigCommittedButUnsynced(_)) => (
                "configuration_durability_uncertain",
                "Restart the managed server before relying on the committed configuration.",
            ),
            Self::Registry(RegistryError::UserNotFound(_)) => (
                "user_not_found",
                "Refresh the user list and choose an existing user identifier.",
            ),
            Self::Registry(RegistryError::UserNameTooLong { .. }) => (
                "invalid_user_name",
                "Choose a user name no longer than 64 UTF-8 bytes.",
            ),
            Self::Registry(RegistryError::InvalidPageSize { .. }) => (
                "invalid_page_size",
                "Request between 1 and 32 users per page.",
            ),
            Self::Registry(RegistryError::PaginationRequired) => (
                "pagination_required",
                "Use the list_user_page or snapshot_page request to fetch bounded user data.",
            ),
            Self::EnrollmentCommittedButUnsynced { .. } => (
                "bundle_durability_uncertain",
                "Keep the exported bundle and retry only after checking its destination filesystem.",
            ),
            Self::EnrollmentExport { .. } | Self::EnrollmentRollback { .. } => (
                "bundle_export_failed",
                "Choose a writable regular-file destination and retry the user creation.",
            ),
            Self::Config(_) => (
                "configuration_error",
                "Repair the root-owned server configuration or key material, then retry.",
            ),
            Self::Store(_) | Self::Registry(_) => (
                "server_state_error",
                "Inspect the managed server state and retry the command.",
            ),
            Self::SessionStart
            | Self::ControlSocket { .. }
            | Self::ActiveControlSocket { .. }
            | Self::UnsafeControlSocketPath { .. } => (
                "server_runtime_error",
                "Repair the local server runtime environment and restart the service.",
            ),
            Self::ControlTask(_) | Self::SharedShutdownFailure { .. } => (
                "server_runtime_error",
                "Restart the managed server after the control task has stopped.",
            ),
        };

        ServerError::new(code, self.to_string(), recovery)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

impl SocketIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownPhase {
    Active,
    ShuttingDown,
}

#[cfg(test)]
struct ConfigAssignmentPause {
    paused: Notify,
    resumed: Notify,
}

#[cfg(test)]
impl ConfigAssignmentPause {
    async fn wait_until_paused(&self) {
        self.paused.notified().await;
    }

    fn resume(&self) {
        self.resumed.notify_one();
    }
}

#[cfg(test)]
struct StaleSocketRemovalPause {
    reached: std::sync::Barrier,
    resumed: std::sync::Barrier,
}

#[cfg(test)]
static STALE_SOCKET_REMOVAL_PAUSE: LazyLock<
    std::sync::Mutex<Option<Arc<StaleSocketRemovalPause>>>,
> = LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
impl StaleSocketRemovalPause {
    fn new() -> Self {
        Self {
            reached: std::sync::Barrier::new(2),
            resumed: std::sync::Barrier::new(2),
        }
    }

    fn wait_until_reached(&self) {
        self.reached.wait();
    }

    fn resume(&self) {
        self.resumed.wait();
    }
}

#[cfg(test)]
struct StaleSocketRemovalPauseGuard;

#[cfg(test)]
impl Drop for StaleSocketRemovalPauseGuard {
    fn drop(&mut self) {
        *STALE_SOCKET_REMOVAL_PAUSE
            .lock()
            .expect("stale socket removal pause lock must not be poisoned") = None;
    }
}

#[cfg(test)]
fn install_stale_socket_removal_pause()
-> (Arc<StaleSocketRemovalPause>, StaleSocketRemovalPauseGuard) {
    let pause = Arc::new(StaleSocketRemovalPause::new());
    let previous = STALE_SOCKET_REMOVAL_PAUSE
        .lock()
        .expect("stale socket removal pause lock must not be poisoned")
        .replace(Arc::clone(&pause));
    assert!(
        previous.is_none(),
        "a stale socket removal pause is already installed"
    );
    (pause, StaleSocketRemovalPauseGuard)
}

#[cfg(test)]
fn pause_before_stale_socket_removal() {
    let pause = STALE_SOCKET_REMOVAL_PAUSE
        .lock()
        .expect("stale socket removal pause lock must not be poisoned")
        .clone();
    if let Some(pause) = pause {
        pause.reached.wait();
        pause.resumed.wait();
    }
}

pub struct ManagedServer {
    coordinator: Arc<ShutdownCoordinator>,
}

struct ShutdownCoordinator {
    inner: Arc<ManagedServerInner>,
    control_task: Mutex<Option<JoinHandle<Result<(), ServerRuntimeError>>>>,
    phase: Mutex<ShutdownPhase>,
    result: watch::Sender<Option<SharedShutdownResult>>,
    control_exit: watch::Sender<Option<SharedShutdownResult>>,
    #[cfg(test)]
    started: AtomicBool,
    #[cfg(test)]
    started_notify: Notify,
}

struct ManagedServerConfig {
    config: ServerConfig,
    restart_required: bool,
}

struct ManagedServerInner {
    paths: ServerPaths,
    config: RwLock<ManagedServerConfig>,
    server_public_key: TunnelPublicKey,
    registry: Arc<UserRegistry>,
    session: Arc<Session>,
    shutdown: CancellationToken,
    control_socket_identity: SocketIdentity,
    cleanup_gate: Mutex<()>,
    cleanup_complete: AtomicBool,
    #[cfg(test)]
    config_assignment_pause: Mutex<Option<Arc<ConfigAssignmentPause>>>,
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
                code: ShutdownFailureCode::Cleanup,
                message: "the shutdown coordinator exited before completing cleanup".to_owned(),
            }));
        }
    }
}

impl ManagedServer {
    pub async fn start(paths: ServerPaths) -> Result<Self, ServerRuntimeError> {
        let config = load_server_config(paths.config_path()).await?;
        let server_key = load_server_key(paths.server_key_path()).await?;
        let server_public_key = tunnel_public_key(&server_key);
        let store = ServerStore::open(paths.database_path()).await?;
        let registry = UserRegistry::open(store).await?;
        let shutdown = CancellationToken::new();
        let tunnel_options = TunnelServerOptions {
            peer_listen: config.peer_listen,
            identity_key: server_key,
            allowed_client_keys: HashSet::new(),
            authorizer: Some(Arc::clone(&registry) as Arc<dyn TunnelServerAuthorizer>),
            egress_policy: egress_policy(&config.egress),
            carrier_root: paths.carrier_root(),
        };
        let session = match Session::new_with_opts(
            paths.data_dir.clone(),
            SessionOptions {
                disable_trackers: true,
                persistence: None,
                listen: None,
                connect: None,
                cancellation_token: Some(shutdown.clone()),
                disable_local_service_discovery: true,
                tunnel: Some(TunnelOptions::Server(tunnel_options)),
                ..Default::default()
            },
        )
        .await
        {
            Ok(session) => session,
            Err(_) => {
                let _ = registry.shutdown().await;
                return Err(ServerRuntimeError::SessionStart);
            }
        };

        let (listener, control_socket_identity) =
            match bind_control_socket(&paths.control_socket_path()) {
                Ok(listener) => listener,
                Err(error) => {
                    session.stop().await;
                    let _ = registry.shutdown().await;
                    return Err(error);
                }
            };
        let inner = Arc::new(ManagedServerInner {
            paths,
            config: RwLock::new(ManagedServerConfig {
                config,
                restart_required: false,
            }),
            server_public_key,
            registry,
            session,
            shutdown,
            control_socket_identity,
            cleanup_gate: Mutex::new(()),
            cleanup_complete: AtomicBool::new(false),
            #[cfg(test)]
            config_assignment_pause: Mutex::new(None),
        });
        let (result, _) = watch::channel(None);
        let (control_exit, _) = watch::channel(None);
        let control_exit_sender = control_exit.clone();
        let control_inner = Arc::clone(&inner);
        let control_task = tokio::spawn(async move {
            let outcome = serve_control_socket(listener, control_inner).await;
            control_exit_sender.send_replace(Some(SharedShutdownResult::from_result(&outcome)));
            outcome
        });
        Ok(Self {
            coordinator: Arc::new(ShutdownCoordinator {
                inner,
                control_task: Mutex::new(Some(control_task)),
                phase: Mutex::new(ShutdownPhase::Active),
                result,
                control_exit,
                #[cfg(test)]
                started: AtomicBool::new(false),
                #[cfg(test)]
                started_notify: Notify::new(),
            }),
        })
    }

    pub async fn shutdown(&self) -> Result<(), ServerRuntimeError> {
        self.coordinator.request_shutdown().await
    }

    /// Waits until the managed control socket exits, whether it stopped cleanly
    /// (for example after an IPC shutdown request) or failed.
    pub async fn wait_for_control_exit(&self) -> Result<(), ServerRuntimeError> {
        self.coordinator.wait_for_control_exit().await
    }

    #[cfg(test)]
    async fn wait_until_shutdown_coordinator_started(&self) {
        self.coordinator.wait_until_started().await;
    }
}

impl ShutdownCoordinator {
    async fn request_shutdown(self: &Arc<Self>) -> Result<(), ServerRuntimeError> {
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
                return Err(ServerRuntimeError::SharedShutdownFailure {
                    code: ShutdownFailureCode::Cleanup,
                    message: "the shutdown coordinator stopped before publishing a result"
                        .to_owned(),
                });
            }
        }
    }

    async fn wait_for_control_exit(&self) -> Result<(), ServerRuntimeError> {
        let mut control_exit = self.control_exit.subscribe();
        loop {
            if let Some(shared) = control_exit.borrow().clone() {
                return shared.into_result();
            }
            if control_exit.changed().await.is_err() {
                return Err(ServerRuntimeError::SharedShutdownFailure {
                    code: ShutdownFailureCode::ControlTask,
                    message: "the managed control socket stopped without publishing an exit result"
                        .to_owned(),
                });
            }
        }
    }

    async fn run_shutdown(self: Arc<Self>) {
        #[cfg(test)]
        {
            self.started.store(true, Ordering::Release);
            self.started_notify.notify_one();
        }

        let mut publication = ShutdownResultPublication::new(self.result.clone());
        let outcome = self.shutdown_once().await;
        publication.publish(SharedShutdownResult::from_result(&outcome));
    }

    async fn shutdown_once(&self) -> Result<(), ServerRuntimeError> {
        let cleanup_result = self.inner.cleanup().await;
        let control_task = self.control_task.lock().await.take();
        let task_result = match control_task {
            Some(task) => match task.await {
                Ok(result) => result,
                Err(error) => Err(ServerRuntimeError::ControlTask(error)),
            },
            None => Ok(()),
        };

        cleanup_result?;
        task_result
    }

    #[cfg(test)]
    async fn wait_until_started(&self) {
        if self.started.load(Ordering::Acquire) {
            return;
        }
        self.started_notify.notified().await;
    }
}

impl ManagedServerInner {
    async fn cleanup(&self) -> Result<(), ServerRuntimeError> {
        let _gate = self.cleanup_gate.lock().await;
        if self.cleanup_complete.load(Ordering::Acquire) {
            return Ok(());
        }

        self.shutdown.cancel();
        self.session.stop().await;
        let registry_result = self
            .registry
            .shutdown()
            .await
            .map_err(ServerRuntimeError::Registry);
        let socket_result = remove_owned_control_socket(
            &self.paths.control_socket_path(),
            self.control_socket_identity,
        );
        self.cleanup_complete.store(true, Ordering::Release);

        registry_result?;
        socket_result
    }

    async fn execute(&self, request: ServerRequest) -> Result<ServerResponse, ServerRuntimeError> {
        match request {
            ServerRequest::Snapshot => {
                let page = self
                    .registry
                    .snapshot_page(None, DEFAULT_USER_PAGE_SIZE)
                    .await?;
                if page.next_page.is_some() {
                    return Err(ServerRuntimeError::Registry(
                        RegistryError::PaginationRequired,
                    ));
                }
                Ok(ServerResponse::Snapshot(ServerSnapshot {
                    users: page.users,
                }))
            }
            ServerRequest::SnapshotPage => {
                let page = self
                    .registry
                    .snapshot_page(None, DEFAULT_USER_PAGE_SIZE)
                    .await?;
                Ok(ServerResponse::SnapshotPage(page))
            }
            ServerRequest::ListUsers => {
                let page = self
                    .registry
                    .snapshot_page(None, DEFAULT_USER_PAGE_SIZE)
                    .await?;
                if page.next_page.is_some() {
                    return Err(ServerRuntimeError::Registry(
                        RegistryError::PaginationRequired,
                    ));
                }
                Ok(ServerResponse::Users(page.users))
            }
            ServerRequest::ListUserPage { after, limit } => {
                let page = self
                    .registry
                    .snapshot_page(after, limit.unwrap_or(DEFAULT_USER_PAGE_SIZE))
                    .await?;
                Ok(ServerResponse::UserPage(page))
            }
            ServerRequest::AddUser { name, export_path } => self.add_user(name, export_path).await,
            ServerRequest::SetEnabled { id, enabled } => {
                self.registry.set_enabled(id, enabled).await?;
                Ok(ServerResponse::User(self.registry.snapshot(id).await?))
            }
            ServerRequest::DeleteUser { id } => {
                self.registry.delete_user(id).await?;
                Ok(ServerResponse::Deleted { id })
            }
            ServerRequest::ResetTraffic { id } => {
                self.registry.reset_traffic(id).await?;
                Ok(ServerResponse::User(self.registry.snapshot(id).await?))
            }
            ServerRequest::GetConfig => {
                let state = self.config.read().await;
                Ok(ServerResponse::Config(ServerConfigResponse {
                    config: state.config.clone(),
                    restart_required: state.restart_required,
                }))
            }
            ServerRequest::SetConfig { config } => {
                let mut state = self.config.write().await;
                config.validate().map_err(ConfigError::from)?;
                let persistence =
                    persist_server_config(self.paths.config_path(), config.clone()).await?;
                #[cfg(test)]
                self.pause_before_config_assignment().await;
                state.config = config.clone();
                state.restart_required = true;
                if let AtomicWriteOutcome::CommittedButUnsynced(source) = persistence {
                    return Err(ServerRuntimeError::Config(
                        ConfigError::ConfigCommittedButUnsynced(source),
                    ));
                }
                Ok(ServerResponse::Config(ServerConfigResponse {
                    config,
                    restart_required: true,
                }))
            }
            ServerRequest::Shutdown => unreachable!("shutdown is handled before command dispatch"),
        }
    }

    #[cfg(test)]
    async fn pause_next_config_assignment(&self) -> Arc<ConfigAssignmentPause> {
        let pause = Arc::new(ConfigAssignmentPause {
            paused: Notify::new(),
            resumed: Notify::new(),
        });
        *self.config_assignment_pause.lock().await = Some(Arc::clone(&pause));
        pause
    }

    #[cfg(test)]
    async fn pause_before_config_assignment(&self) {
        let pause = { self.config_assignment_pause.lock().await.take() };
        if let Some(pause) = pause {
            pause.paused.notify_one();
            pause.resumed.notified().await;
        }
    }

    async fn add_user(
        &self,
        name: String,
        export_path: PathBuf,
    ) -> Result<ServerResponse, ServerRuntimeError> {
        let created = self.registry.create_user(name).await?;
        let user_id = created.user.id;
        let snapshot = self.registry.snapshot(user_id).await?;
        let config = self.config.read().await.config.clone();
        let bundle = EnrollmentBundle {
            schema_version: BUNDLE_SCHEMA_VERSION,
            user_name: created.user.name,
            client_private_key: created.client_private_key.0,
            server_public_key: self.server_public_key.0,
            server_addr: config.peer_listen,
            socks_listen: config.default_client_socks_listen,
            carriers: config.default_client_carriers,
        };

        match write_enrollment_bundle(export_path.clone(), bundle).await {
            Ok(AtomicWriteOutcome::Durable) => {}
            Ok(AtomicWriteOutcome::CommittedButUnsynced(source)) => {
                return Err(ServerRuntimeError::EnrollmentCommittedButUnsynced {
                    path: export_path,
                    source,
                });
            }
            Err(source) => {
                return match self.registry.delete_user(user_id).await {
                    Ok(()) => Err(ServerRuntimeError::EnrollmentExport {
                        path: export_path,
                        source,
                    }),
                    Err(rollback) => Err(ServerRuntimeError::EnrollmentRollback {
                        path: export_path,
                        user_id,
                        source,
                        rollback,
                    }),
                };
            }
        }

        Ok(ServerResponse::User(snapshot))
    }
}

async fn serve_control_socket(
    listener: UnixListener,
    inner: Arc<ManagedServerInner>,
) -> Result<(), ServerRuntimeError> {
    let mut connections = JoinSet::new();
    let mut result = loop {
        tokio::select! {
            _ = inner.shutdown.cancelled() => break Ok(()),
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(source) => break Err(ServerRuntimeError::ControlSocket {
                        path: inner.paths.control_socket_path(),
                        source,
                    }),
                };
                let connection_inner = Arc::clone(&inner);
                connections.spawn(async move {
                    let mut stream = stream;
                    serve_control_connection(&mut stream, connection_inner.as_ref()).await
                });
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                match joined.expect("non-empty join set returned no task") {
                    Ok(Ok(true)) => break Ok(()),
                    Ok(Ok(false)) => {}
                    Ok(Err(error)) => break Err(error),
                    Err(error) => break Err(ServerRuntimeError::ControlTask(error)),
                }
            }
        }
    };

    inner.shutdown.cancel();
    while let Some(joined) = connections.join_next().await {
        if result.is_ok() {
            match joined {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => result = Err(error),
                Err(error) => result = Err(ServerRuntimeError::ControlTask(error)),
            }
        }
    }
    if result.is_err() {
        let _ = inner.cleanup().await;
    }
    result
}

async fn serve_control_connection(
    stream: &mut UnixStream,
    inner: &ManagedServerInner,
) -> Result<bool, ServerRuntimeError> {
    let request = tokio::select! {
        _ = inner.shutdown.cancelled() => return Ok(true),
        result = read_request(stream) => match result {
            Ok(request) => request,
            Err(UnixControlError::Protocol(error)) => {
                let _ = write_response_until_shutdown(
                    stream,
                    &ServerResponse::Error(error.response()),
                    &inner.shutdown,
                )
                .await;
                return Ok(false);
            }
            Err(_) => return Ok(false),
        },
    };

    if matches!(&request, ServerRequest::Shutdown) {
        return match inner.cleanup().await {
            Ok(()) => {
                let _ = write_response_with_deadline(
                    stream,
                    &ServerResponse::Shutdown,
                    Duration::from_secs(1),
                )
                .await;
                Ok(true)
            }
            Err(error) => {
                let response = ServerResponse::Error(error.response());
                let _ =
                    write_response_with_deadline(stream, &response, Duration::from_secs(1)).await;
                Err(error)
            }
        };
    }

    let response = match inner.execute(request).await {
        Ok(response) => response,
        Err(error) => ServerResponse::Error(error.response()),
    };
    let _ = write_response_until_shutdown(stream, &response, &inner.shutdown).await;
    Ok(false)
}

fn egress_policy(config: &ServerEgressConfig) -> EgressPolicy {
    EgressPolicy {
        allow_private: config.allow_private,
        allow_loopback: config.allow_loopback,
        allow_link_local: config.allow_link_local,
        allow_multicast: config.allow_multicast,
    }
}

async fn load_server_config(path: PathBuf) -> Result<ServerConfig, ConfigError> {
    tokio::task::spawn_blocking(move || {
        inspect_regular_file(&path, "configuration")?;
        let bytes = fs::read(&path).map_err(|source| ConfigError::ReadFile {
            kind: "configuration",
            path: path.clone(),
            source,
        })?;
        let config: ServerConfig =
            serde_json::from_slice(&bytes).map_err(|source| ConfigError::DeserializeConfig {
                path: path.clone(),
                source,
            })?;
        config.validate()?;
        Ok(config)
    })
    .await
    .map_err(|source| ConfigError::Blocking {
        operation: "read server configuration",
        source,
    })?
}

async fn load_server_key(path: PathBuf) -> Result<TunnelPrivateKey, ConfigError> {
    tokio::task::spawn_blocking(move || {
        let metadata = inspect_regular_file(&path, "key")?;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(ConfigError::InsecureKeyPermissions {
                path: path.clone(),
                mode,
            });
        }
        let bytes = fs::read(&path).map_err(|source| ConfigError::ReadFile {
            kind: "key",
            path: path.clone(),
            source,
        })?;
        if bytes.len() != 64 {
            return Err(ConfigError::InvalidKeyLength {
                path: path.clone(),
                actual: bytes.len(),
            });
        }
        let encoded = std::str::from_utf8(&bytes)
            .map_err(|_| ConfigError::InvalidKeyHex { path: path.clone() })?;
        let mut key = [0_u8; 32];
        hex::decode_to_slice(encoded, &mut key)
            .map_err(|_| ConfigError::InvalidKeyHex { path: path.clone() })?;
        Ok(TunnelPrivateKey(key))
    })
    .await
    .map_err(|source| ConfigError::Blocking {
        operation: "read server key",
        source,
    })?
}

async fn persist_server_config(
    path: PathBuf,
    config: ServerConfig,
) -> Result<AtomicWriteOutcome, ConfigError> {
    config.validate()?;
    let encoded = serde_json::to_vec(&config).map_err(ConfigError::SerializeConfig)?;
    let outcome = tokio::task::spawn_blocking(move || atomic_write_file(&path, &encoded))
        .await
        .map_err(|source| ConfigError::Blocking {
            operation: "write server configuration",
            source,
        })??;
    Ok(outcome)
}

async fn write_enrollment_bundle(
    path: PathBuf,
    bundle: EnrollmentBundle,
) -> Result<AtomicWriteOutcome, AtomicWriteError> {
    let encoded = serde_json::to_vec(&bundle).map_err(AtomicWriteError::SerializeBundle)?;
    let write_path = path.clone();
    tokio::task::spawn_blocking(move || atomic_write_file(&write_path, &encoded))
        .await
        .map_err(|source| AtomicWriteError::WriteTemporary {
            path,
            source: io::Error::other(source),
        })?
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

fn atomic_write_file(path: &Path, bytes: &[u8]) -> Result<AtomicWriteOutcome, AtomicWriteError> {
    let final_component = path
        .as_os_str()
        .as_bytes()
        .rsplit(|byte| *byte == b'/')
        .next()
        .filter(|component| {
            let component = *component;
            !component.is_empty() && component != b"." && component != b".."
        })
        .ok_or_else(|| AtomicWriteError::MissingFinalComponent {
            path: path.to_path_buf(),
        })?;
    let final_component =
        CString::new(final_component).map_err(|_| AtomicWriteError::MissingFinalComponent {
            path: path.to_path_buf(),
        })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| AtomicWriteError::MissingParent {
            path: path.to_path_buf(),
        })?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|source| AtomicWriteError::OpenParent {
            path: parent.to_path_buf(),
            source,
        })?;
    if !parent_metadata.file_type().is_dir() {
        return Err(AtomicWriteError::ParentNotDirectory {
            path: parent.to_path_buf(),
        });
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
        .map_err(|source| AtomicWriteError::OpenParent {
            path: parent.to_path_buf(),
            source,
        })?;
    #[cfg(test)]
    run_atomic_write_parent_open_hook(path);

    let temporary_component = format!(".rqbit-tunnel-{}.tmp", Uuid::new_v4());
    let temporary_path = parent.join(&temporary_component);
    let temporary_component =
        CString::new(temporary_component).expect("generated UUID temporary names contain no NUL");
    let result = (|| {
        // SAFETY: `directory` owns a valid directory descriptor and the generated component
        // contains no slash or NUL bytes.
        let temporary_descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                temporary_component.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if temporary_descriptor < 0 {
            return Err(AtomicWriteError::CreateTemporary {
                path: temporary_path.clone(),
                source: io::Error::last_os_error(),
            });
        }
        // SAFETY: `openat` returned this descriptor exclusively, transferring ownership to File.
        let mut file = unsafe { File::from_raw_fd(temporary_descriptor) };
        file.write_all(bytes)
            .map_err(|source| AtomicWriteError::WriteTemporary {
                path: temporary_path.clone(),
                source,
            })?;
        file.sync_all()
            .map_err(|source| AtomicWriteError::SyncTemporary {
                path: temporary_path.clone(),
                source,
            })?;
        // SAFETY: both names are NUL-terminated single components and both directory
        // descriptors refer to the same validated parent directory.
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary_component.as_ptr(),
                directory.as_raw_fd(),
                final_component.as_ptr(),
            )
        } < 0
        {
            return Err(AtomicWriteError::Rename {
                path: path.to_path_buf(),
                source: io::Error::last_os_error(),
            });
        }
        match directory.sync_all() {
            Ok(()) => Ok(AtomicWriteOutcome::Durable),
            Err(source) => Ok(AtomicWriteOutcome::CommittedButUnsynced(
                AtomicWriteError::SyncParent {
                    path: parent.to_path_buf(),
                    source,
                },
            )),
        }
    })();
    if result.is_err() {
        // SAFETY: the temporary component and parent descriptor are the same ones used for
        // creation, so cleanup cannot traverse a replaced parent path.
        let _ = unsafe { libc::unlinkat(directory.as_raw_fd(), temporary_component.as_ptr(), 0) };
    }
    result
}

fn control_socket_lock_path(path: &Path) -> PathBuf {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

/// Serializes stale-socket recovery and binding between managed-server starters.
fn lock_control_socket(path: &Path) -> Result<File, ServerRuntimeError> {
    let lock_path = control_socket_lock_path(path);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|source| ServerRuntimeError::ControlSocket {
            path: lock_path.clone(),
            source,
        })?;
    lock.lock()
        .map_err(|source| ServerRuntimeError::ControlSocket {
            path: lock_path,
            source,
        })?;
    Ok(lock)
}

fn bind_control_socket(path: &Path) -> Result<(UnixListener, SocketIdentity), ServerRuntimeError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| ServerRuntimeError::UnsafeControlSocketPath {
            path: path.to_path_buf(),
            kind: "path without a parent directory",
        })?;
    fs::create_dir_all(parent).map_err(|source| ServerRuntimeError::ControlSocket {
        path: parent.to_path_buf(),
        source,
    })?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o750)).map_err(|source| {
        ServerRuntimeError::ControlSocket {
            path: parent.to_path_buf(),
            source,
        }
    })?;
    let _lock = lock_control_socket(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            let stale_identity = SocketIdentity::from_metadata(&metadata);
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => {
                    return Err(ServerRuntimeError::ActiveControlSocket {
                        path: path.to_path_buf(),
                    });
                }
                Err(source) if source.kind() == io::ErrorKind::ConnectionRefused => {
                    #[cfg(test)]
                    pause_before_stale_socket_removal();
                    remove_stale_control_socket(path, stale_identity)?;
                }
                Err(source) if source.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(ServerRuntimeError::ControlSocket {
                        path: path.to_path_buf(),
                        source,
                    });
                }
            }
        }
        Ok(metadata) => {
            return Err(ServerRuntimeError::UnsafeControlSocketPath {
                path: path.to_path_buf(),
                kind: socket_path_kind(&metadata),
            });
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ServerRuntimeError::ControlSocket {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    let listener =
        UnixListener::bind(path).map_err(|source| ServerRuntimeError::ControlSocket {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| ServerRuntimeError::ControlSocket {
            path: path.to_path_buf(),
            source,
        })?;
    if !metadata.file_type().is_socket() {
        return Err(ServerRuntimeError::UnsafeControlSocketPath {
            path: path.to_path_buf(),
            kind: socket_path_kind(&metadata),
        });
    }
    let identity = SocketIdentity::from_metadata(&metadata);
    if let Err(source) = fs::set_permissions(path, fs::Permissions::from_mode(0o660)) {
        let _ = remove_owned_control_socket(path, identity);
        return Err(ServerRuntimeError::ControlSocket {
            path: path.to_path_buf(),
            source,
        });
    }
    Ok((listener, identity))
}

fn remove_stale_control_socket(
    path: &Path,
    expected_identity: SocketIdentity,
) -> Result<(), ServerRuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && SocketIdentity::from_metadata(&metadata) == expected_identity =>
        {
            fs::remove_file(path).map_err(|source| ServerRuntimeError::ControlSocket {
                path: path.to_path_buf(),
                source,
            })
        }
        Ok(metadata) if metadata.file_type().is_socket() => {
            Err(ServerRuntimeError::ActiveControlSocket {
                path: path.to_path_buf(),
            })
        }
        Ok(metadata) => Err(ServerRuntimeError::UnsafeControlSocketPath {
            path: path.to_path_buf(),
            kind: socket_path_kind(&metadata),
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ServerRuntimeError::ControlSocket {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn remove_owned_control_socket(
    path: &Path,
    expected_identity: SocketIdentity,
) -> Result<(), ServerRuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && SocketIdentity::from_metadata(&metadata) == expected_identity =>
        {
            fs::remove_file(path).map_err(|source| ServerRuntimeError::ControlSocket {
                path: path.to_path_buf(),
                source,
            })
        }
        Ok(_) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ServerRuntimeError::ControlSocket {
            path: path.to_path_buf(),
            source,
        }),
    }
}

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

#[cfg(test)]
static TEST_SERVER_START_GATE: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

#[cfg(test)]
pub(crate) async fn spawn_test_server(socket: &Path) -> ManagedServer {
    let run_dir = socket.parent().expect("test socket has a parent directory");
    assert_eq!(
        socket.file_name().and_then(|name| name.to_str()),
        Some("server.sock")
    );
    let paths = ServerPaths {
        config_dir: run_dir.join("config"),
        data_dir: run_dir.join("data"),
        run_dir: run_dir.to_path_buf(),
    };
    write_test_server_material(&paths).await;
    start_test_server(paths)
        .await
        .expect("start test managed server")
}

/// Serializes local test startup and retries a real bind failure; a released
/// ephemeral port is never treated as a reservation.
#[cfg(test)]
async fn start_test_server(paths: ServerPaths) -> Result<ManagedServer, ServerRuntimeError> {
    let _start_gate = TEST_SERVER_START_GATE.lock().await;
    start_test_server_with_candidates_locked(&paths, std::iter::empty()).await
}

#[cfg(test)]
async fn start_test_server_with_peer_candidates<I>(
    paths: ServerPaths,
    candidates: I,
) -> Result<ManagedServer, ServerRuntimeError>
where
    I: IntoIterator<Item = std::net::SocketAddr>,
{
    let _start_gate = TEST_SERVER_START_GATE.lock().await;
    start_test_server_with_candidates_locked(&paths, candidates).await
}

#[cfg(test)]
async fn start_test_server_with_candidates_locked<I>(
    paths: &ServerPaths,
    candidates: I,
) -> Result<ManagedServer, ServerRuntimeError>
where
    I: IntoIterator<Item = std::net::SocketAddr>,
{
    let mut last_error = None;
    for peer_listen in candidates {
        if let Some(server) = try_start_test_server(paths, peer_listen, &mut last_error).await? {
            return Ok(server);
        }
    }

    for _ in 0..8 {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("allocate a test tunnel port");
        let peer_listen = listener
            .local_addr()
            .expect("read test tunnel listener address");
        drop(listener);
        if let Some(server) = try_start_test_server(paths, peer_listen, &mut last_error).await? {
            return Ok(server);
        }
    }

    Err(last_error.expect("test server startup exhausted its peer-port retries"))
}

#[cfg(test)]
async fn try_start_test_server(
    paths: &ServerPaths,
    peer_listen: std::net::SocketAddr,
    last_error: &mut Option<ServerRuntimeError>,
) -> Result<Option<ManagedServer>, ServerRuntimeError> {
    write_test_server_config(paths, peer_listen);
    match ManagedServer::start(paths.clone()).await {
        Ok(server) => Ok(Some(server)),
        Err(error @ ServerRuntimeError::SessionStart) => {
            *last_error = Some(error);
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
async fn write_test_server_material(paths: &ServerPaths) {
    write_test_server_config(paths, std::net::SocketAddr::from(([127, 0, 0, 1], 49152)));
    let (key, _) = librqbit::tunnel_generate_keypair();
    fs::write(paths.server_key_path(), hex::encode(key.0)).expect("write test server key");
    fs::set_permissions(paths.server_key_path(), fs::Permissions::from_mode(0o600))
        .expect("restrict test server key");
}

#[cfg(test)]
fn write_test_server_config(paths: &ServerPaths, peer_listen: std::net::SocketAddr) {
    let config = ServerConfig {
        schema_version: crate::model::SERVER_CONFIG_SCHEMA_VERSION,
        peer_listen,
        egress: ServerEgressConfig {
            allow_private: false,
            allow_loopback: false,
            allow_link_local: false,
            allow_multicast: false,
        },
        default_client_socks_listen: "127.0.0.1:1080".parse().expect("valid test SOCKS listener"),
        default_client_carriers: 4,
    };
    fs::create_dir_all(&paths.config_dir).expect("create test config directory");
    fs::write(
        paths.config_path(),
        serde_json::to_vec(&config).expect("serialize test configuration"),
    )
    .expect("write test configuration");
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        os::unix::fs::{FileTypeExt, OpenOptionsExt},
        path::Path,
        sync::Arc,
        time::Duration,
    };

    use crate::{
        ipc::{
            protocol::{ServerRequest, ServerResponse},
            unix::UnixControlClient,
        },
        model::{EnrollmentBundle, SERVER_CONFIG_SCHEMA_VERSION, ServerConfig, ServerEgressConfig},
        paths::ServerPaths,
    };
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, UnixListener, UnixStream};

    use super::{
        AtomicWriteError, AtomicWriteOutcome, ConfigError, ManagedServer, ServerRuntimeError,
        atomic_write_file, bind_control_socket, install_atomic_write_parent_open_hook,
        install_stale_socket_removal_pause, start_test_server,
        start_test_server_with_peer_candidates, write_test_server_material,
    };

    #[tokio::test]
    async fn add_user_exports_bundle_only_to_disk_and_rolls_back_a_failed_export() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = start_test_server(paths.clone()).await.unwrap();

        let export_path = directory.path().join("alice.bundle");
        let response = request(
            &paths,
            ServerRequest::AddUser {
                name: "alice".to_owned(),
                export_path: export_path.clone(),
            },
        )
        .await;
        let alice = match response {
            ServerResponse::User(snapshot) => snapshot,
            other => panic!("expected a secret-free user snapshot, got {other:?}"),
        };
        assert_eq!(alice.name, "alice");

        let response_json = serde_json::to_string(&ServerResponse::User(alice.clone())).unwrap();
        assert!(!response_json.contains("client_private_key"));
        assert!(!response_json.contains("server_public_key"));

        let bundle_bytes = std::fs::read(&export_path).unwrap();
        let bundle: EnrollmentBundle = serde_json::from_slice(&bundle_bytes).unwrap();
        assert_eq!(bundle.user_name, "alice");
        assert!(!response_json.contains(&hex::encode(bundle.client_private_key)));
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(
                &std::fs::metadata(&export_path).unwrap().permissions()
            ) & 0o777,
            0o600
        );

        let malformed_export_path = directory.path().join("not-a-bundle-file");
        std::fs::create_dir(&malformed_export_path).unwrap();
        let failed_export = request(
            &paths,
            ServerRequest::AddUser {
                name: "bob".to_owned(),
                export_path: malformed_export_path.clone(),
            },
        )
        .await;
        assert!(matches!(failed_export, ServerResponse::Error(_)));
        assert!(
            !serde_json::to_string(&failed_export)
                .unwrap()
                .contains("client_private_key")
        );
        assert_eq!(
            std::fs::read_dir(&malformed_export_path).unwrap().count(),
            0
        );

        let users = request(
            &paths,
            ServerRequest::ListUserPage {
                after: None,
                limit: None,
            },
        )
        .await;
        let expected_users = vec![alice];
        assert!(matches!(
            &users,
            ServerResponse::UserPage(page)
                if page.users == expected_users && page.next_page.is_none()
        ));

        server.shutdown().await.unwrap();
        assert!(!paths.control_socket_path().exists());
    }

    #[tokio::test]
    async fn invalid_config_update_leaves_existing_config_file_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = start_test_server(paths.clone()).await.unwrap();
        let original = std::fs::read(paths.config_path()).unwrap();

        let invalid = ServerConfig {
            schema_version: SERVER_CONFIG_SCHEMA_VERSION,
            peer_listen: SocketAddr::from(([127, 0, 0, 1], 4242)),
            egress: ServerEgressConfig {
                allow_private: false,
                allow_loopback: false,
                allow_link_local: false,
                allow_multicast: false,
            },
            default_client_socks_listen: SocketAddr::from(([127, 0, 0, 1], 1080)),
            default_client_carriers: 0,
        };
        let response = request(&paths, ServerRequest::SetConfig { config: invalid }).await;

        assert!(matches!(response, ServerResponse::Error(_)));
        assert_eq!(std::fs::read(paths.config_path()).unwrap(), original);

        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn valid_config_update_persists_and_advertises_a_required_restart() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = start_test_server(paths.clone()).await.unwrap();
        let updated = ServerConfig {
            schema_version: SERVER_CONFIG_SCHEMA_VERSION,
            peer_listen: SocketAddr::from(([127, 0, 0, 1], 4242)),
            egress: ServerEgressConfig {
                allow_private: true,
                allow_loopback: false,
                allow_link_local: false,
                allow_multicast: false,
            },
            default_client_socks_listen: SocketAddr::from(([127, 0, 0, 1], 1081)),
            default_client_carriers: 5,
        };

        let response = request(
            &paths,
            ServerRequest::SetConfig {
                config: updated.clone(),
            },
        )
        .await;

        match response {
            ServerResponse::Config(config) => {
                assert_eq!(config.config, updated);
                assert!(config.restart_required);
            }
            other => panic!("expected a configuration response, got {other:?}"),
        }
        assert_eq!(
            serde_json::from_slice::<ServerConfig>(&std::fs::read(paths.config_path()).unwrap())
                .unwrap(),
            updated
        );

        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn startup_rejects_missing_and_invalid_key_material_with_typed_errors() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        std::fs::remove_file(paths.server_key_path()).unwrap();

        let missing_key = ManagedServer::start(paths.clone()).await;
        assert!(matches!(
            &missing_key,
            Err(ServerRuntimeError::Config(ConfigError::MissingFile {
                kind: "key",
                ..
            }))
        ));

        std::fs::write(paths.server_key_path(), "g".repeat(64)).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(
            paths.server_key_path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let invalid_key = ManagedServer::start(paths).await;
        assert!(matches!(
            &invalid_key,
            Err(ServerRuntimeError::Config(
                ConfigError::InvalidKeyHex { .. }
            ))
        ));
    }

    #[tokio::test]
    async fn shutdown_request_removes_the_exact_control_socket_before_replying() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = start_test_server(paths.clone()).await.unwrap();

        let response = request(&paths, ServerRequest::Shutdown).await;

        assert!(matches!(response, ServerResponse::Shutdown));
        assert!(!paths.control_socket_path().exists());
        tokio::time::timeout(Duration::from_millis(100), server.wait_for_control_exit())
            .await
            .expect("IPC shutdown must wake the control-exit observer")
            .unwrap();
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn startup_refuses_to_replace_an_active_control_socket() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = start_test_server(paths.clone()).await.unwrap();
        let second_paths = ServerPaths {
            config_dir: directory.path().join("second-config"),
            data_dir: directory.path().join("second-data"),
            run_dir: paths.run_dir.clone(),
        };
        write_test_server_material(&second_paths).await;

        match start_test_server(second_paths).await {
            Err(ServerRuntimeError::ActiveControlSocket { .. }) => {}
            Err(other) => {
                server.shutdown().await.unwrap();
                panic!("expected an active-control-socket error, got {other:?}");
            }
            Ok(second_server) => {
                second_server.shutdown().await.unwrap();
                server.shutdown().await.unwrap();
                panic!("a second managed server replaced an active control socket");
            }
        }
        assert!(matches!(
            request(&paths, ServerRequest::Snapshot).await,
            ServerResponse::Snapshot(_)
        ));

        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn an_idle_control_connection_does_not_block_other_local_requests() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = start_test_server(paths.clone()).await.unwrap();
        let idle_connection = UnixStream::connect(paths.control_socket_path())
            .await
            .unwrap();
        let snapshot = tokio::time::timeout(
            Duration::from_secs(2),
            request(&paths, ServerRequest::Snapshot),
        )
        .await;
        drop(idle_connection);

        match snapshot {
            Ok(response) => assert!(matches!(response, ServerResponse::Snapshot(_))),
            Err(_) => {
                server.shutdown().await.unwrap();
                panic!("an idle control connection blocked a snapshot request");
            }
        }

        server.shutdown().await.unwrap();
    }

    #[test]
    fn socket_binding_rejects_non_socket_paths_without_removing_them() {
        let directory = tempfile::tempdir().unwrap();

        let regular_file = directory.path().join("regular.sock");
        std::fs::write(&regular_file, b"do not remove").unwrap();
        assert!(matches!(
            bind_control_socket(&regular_file),
            Err(ServerRuntimeError::UnsafeControlSocketPath {
                kind: "regular file",
                ..
            })
        ));
        assert_eq!(std::fs::read(&regular_file).unwrap(), b"do not remove");

        let directory_path = directory.path().join("directory.sock");
        std::fs::create_dir(&directory_path).unwrap();
        assert!(matches!(
            bind_control_socket(&directory_path),
            Err(ServerRuntimeError::UnsafeControlSocketPath {
                kind: "directory",
                ..
            })
        ));
        assert!(directory_path.is_dir());

        let target = directory.path().join("target");
        std::fs::write(&target, b"not a socket").unwrap();
        let symbolic_link = directory.path().join("link.sock");
        std::os::unix::fs::symlink(&target, &symbolic_link).unwrap();
        assert!(matches!(
            bind_control_socket(&symbolic_link),
            Err(ServerRuntimeError::UnsafeControlSocketPath {
                kind: "symbolic link",
                ..
            })
        ));
        assert!(
            std::fs::symlink_metadata(&symbolic_link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[tokio::test]
    async fn snapshot_page_returns_a_bounded_view_with_a_continuation() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = start_test_server(paths.clone()).await.unwrap();

        for index in 0..33 {
            server
                .coordinator
                .inner
                .registry
                .create_user(format!("user-{index:02}"))
                .await
                .unwrap();
        }

        assert!(matches!(
            request(&paths, ServerRequest::Snapshot).await,
            ServerResponse::Error(error) if error.code == "pagination_required"
        ));
        match request(&paths, ServerRequest::SnapshotPage).await {
            ServerResponse::SnapshotPage(page) => {
                assert_eq!(page.users.len(), 32);
                assert!(page.next_page.is_some());
            }
            other => panic!("expected a bounded server snapshot page, got {other:?}"),
        }

        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_config_updates_never_split_disk_and_memory_state() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = start_test_server(paths.clone()).await.unwrap();
        let config_a = ServerConfig {
            schema_version: SERVER_CONFIG_SCHEMA_VERSION,
            peer_listen: SocketAddr::from(([127, 0, 0, 1], 4242)),
            egress: ServerEgressConfig {
                allow_private: true,
                allow_loopback: false,
                allow_link_local: false,
                allow_multicast: false,
            },
            default_client_socks_listen: SocketAddr::from(([127, 0, 0, 1], 1081)),
            default_client_carriers: 5,
        };
        let config_b = ServerConfig {
            schema_version: SERVER_CONFIG_SCHEMA_VERSION,
            peer_listen: SocketAddr::from(([127, 0, 0, 1], 4343)),
            egress: ServerEgressConfig {
                allow_private: false,
                allow_loopback: true,
                allow_link_local: false,
                allow_multicast: false,
            },
            default_client_socks_listen: SocketAddr::from(([127, 0, 0, 1], 1082)),
            default_client_carriers: 6,
        };
        let pause = server
            .coordinator
            .inner
            .pause_next_config_assignment()
            .await;
        let first_socket = paths.control_socket_path();
        let first = tokio::spawn(async move {
            UnixControlClient::connect(first_socket)
                .await
                .unwrap()
                .request(ServerRequest::SetConfig { config: config_a })
                .await
                .unwrap()
        });

        pause.wait_until_paused().await;
        let second_socket = paths.control_socket_path();
        let mut second = tokio::spawn(async move {
            UnixControlClient::connect(second_socket)
                .await
                .unwrap()
                .request(ServerRequest::SetConfig {
                    config: config_b.clone(),
                })
                .await
                .unwrap()
        });
        tokio::task::yield_now().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut second)
                .await
                .is_err(),
            "the second update completed while the first persisted update was pending assignment"
        );

        pause.resume();
        assert!(matches!(first.await.unwrap(), ServerResponse::Config(_)));
        assert!(matches!(second.await.unwrap(), ServerResponse::Config(_)));
        assert_eq!(
            serde_json::from_slice::<ServerConfig>(&std::fs::read(paths.config_path()).unwrap())
                .unwrap(),
            ServerConfig {
                schema_version: SERVER_CONFIG_SCHEMA_VERSION,
                peer_listen: SocketAddr::from(([127, 0, 0, 1], 4343)),
                egress: ServerEgressConfig {
                    allow_private: false,
                    allow_loopback: true,
                    allow_link_local: false,
                    allow_multicast: false,
                },
                default_client_socks_listen: SocketAddr::from(([127, 0, 0, 1], 1082)),
                default_client_carriers: 6,
            }
        );
        let response = request(&paths, ServerRequest::GetConfig).await;
        assert!(matches!(
            response,
            ServerResponse::Config(response)
                if response.config.peer_listen == SocketAddr::from(([127, 0, 0, 1], 4343))
        ));

        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_shutdown_waits_for_shared_completion() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = Arc::new(start_test_server(paths.clone()).await.unwrap());
        let cleanup_gate = server.coordinator.inner.cleanup_gate.lock().await;
        let first_server = Arc::clone(&server);
        let first = tokio::spawn(async move { first_server.shutdown().await });

        server.wait_until_shutdown_coordinator_started().await;
        let second_server = Arc::clone(&server);
        let mut second = Box::pin(async move { second_server.shutdown().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut second)
                .await
                .is_err(),
            "a concurrent shutdown returned before the shared shutdown completed"
        );

        drop(cleanup_gate);
        first.await.unwrap().unwrap();
        second.await.unwrap();
        assert!(!paths.control_socket_path().exists());
    }

    #[tokio::test]
    async fn aborting_the_shutdown_leader_does_not_strand_followers() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = Arc::new(start_test_server(paths.clone()).await.unwrap());
        let cleanup_gate = server.coordinator.inner.cleanup_gate.lock().await;
        let leader_server = Arc::clone(&server);
        let leader = tokio::spawn(async move { leader_server.shutdown().await });

        server.wait_until_shutdown_coordinator_started().await;
        leader.abort();
        assert!(leader.await.unwrap_err().is_cancelled());

        drop(cleanup_gate);
        let follower = tokio::time::timeout(Duration::from_secs(2), server.shutdown())
            .await
            .expect("a follower must observe the detached shutdown coordinator");
        follower.unwrap();
        assert!(!paths.control_socket_path().exists());
    }

    #[tokio::test]
    async fn shutdown_leaves_a_replacement_control_socket_untouched() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = start_test_server(paths.clone()).await.unwrap();
        let socket = paths.control_socket_path();

        std::fs::remove_file(&socket).unwrap();
        let replacement = UnixListener::bind(&socket).unwrap();

        server.shutdown().await.unwrap();
        assert!(
            std::fs::symlink_metadata(&socket)
                .unwrap()
                .file_type()
                .is_socket()
        );

        drop(replacement);
        std::fs::remove_file(socket).unwrap();
    }
    #[tokio::test]
    async fn stale_socket_recovery_preserves_a_replacement_listener() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("server.sock");
        let stale = UnixListener::bind(&socket).unwrap();
        drop(stale);
        let (pause, _pause_guard) = install_stale_socket_removal_pause();

        let contender_socket = socket.clone();
        let contender = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .unwrap()
                .block_on(async { bind_control_socket(&contender_socket) })
        });
        pause.wait_until_reached();

        std::fs::remove_file(&socket).unwrap();
        let replacement = UnixListener::bind(&socket).unwrap();
        pause.resume();

        let result = contender.join().unwrap();
        assert!(matches!(
            result,
            Err(ServerRuntimeError::ActiveControlSocket { .. })
        ));
        assert!(
            std::fs::symlink_metadata(&socket)
                .unwrap()
                .file_type()
                .is_socket()
        );

        drop(replacement);
        std::fs::remove_file(socket).unwrap();
    }

    #[tokio::test]
    async fn add_user_rolls_back_when_the_bundle_parent_is_missing() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = start_test_server(paths.clone()).await.unwrap();
        let missing_parent = directory.path().join("missing");

        let response = request(
            &paths,
            ServerRequest::AddUser {
                name: "alice".to_owned(),
                export_path: missing_parent.join("alice.bundle"),
            },
        )
        .await;

        assert!(matches!(response, ServerResponse::Error(_)));
        assert!(!missing_parent.exists());
        assert!(matches!(
            request(&paths, ServerRequest::Snapshot).await,
            ServerResponse::Snapshot(snapshot) if snapshot.users.is_empty()
        ));

        server.shutdown().await.unwrap();
    }
    #[test]
    fn atomic_write_stays_in_the_opened_parent_after_a_parent_swap() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().join("original-parent");
        let moved_parent = directory.path().join("opened-parent");
        std::fs::create_dir(&parent).unwrap();

        let destination = parent.join("bundle.json");
        let parent_to_swap = parent.clone();
        let moved_parent_for_hook = moved_parent.clone();
        let _hook = install_atomic_write_parent_open_hook(&destination, move || {
            std::fs::rename(&parent_to_swap, &moved_parent_for_hook).unwrap();
            std::fs::create_dir(&parent_to_swap).unwrap();
        });

        assert!(matches!(
            atomic_write_file(&destination, b"enrollment"),
            Ok(AtomicWriteOutcome::Durable)
        ));
        assert_eq!(
            std::fs::read(moved_parent.join("bundle.json")).unwrap(),
            b"enrollment"
        );
        assert!(!destination.exists());
    }

    #[test]
    fn atomic_write_rejects_a_path_without_a_normal_final_component() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let destination = parent.join("..");

        assert!(matches!(
            atomic_write_file(&destination, b"enrollment"),
            Err(AtomicWriteError::MissingFinalComponent { path }) if path == destination
        ));
    }
    #[test]
    fn atomic_write_rejects_a_trailing_dot_component_without_retargeting() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let target = parent.join("target");
        std::fs::write(&target, b"original").unwrap();
        let malformed_destination = target.join(".");

        assert!(matches!(
            atomic_write_file(&malformed_destination, b"replacement"),
            Err(AtomicWriteError::MissingFinalComponent { path }) if path == malformed_destination
        ));
        assert_eq!(std::fs::read(target).unwrap(), b"original");
    }

    #[tokio::test]
    async fn add_user_rejects_a_fifo_bundle_parent_without_blocking() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = start_test_server(paths.clone()).await.unwrap();
        let fifo_parent = directory.path().join("bundle-parent");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo_parent)
                .status()
                .unwrap()
                .success()
        );

        let response = tokio::time::timeout(
            Duration::from_secs(2),
            request(
                &paths,
                ServerRequest::AddUser {
                    name: "alice".to_owned(),
                    export_path: fifo_parent.clone().join("alice.bundle"),
                },
            ),
        )
        .await;
        if response.is_err() {
            let fifo_opener = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo_parent)
                .unwrap();
            drop(fifo_opener);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert!(matches!(response, Ok(ServerResponse::Error(_))));
        assert!(matches!(
            request(&paths, ServerRequest::Snapshot).await,
            ServerResponse::Snapshot(snapshot) if snapshot.users.is_empty()
        ));

        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn get_config_reports_a_pending_restart_after_a_valid_update() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = start_test_server(paths.clone()).await.unwrap();
        let updated = ServerConfig {
            schema_version: SERVER_CONFIG_SCHEMA_VERSION,
            peer_listen: SocketAddr::from(([127, 0, 0, 1], 4242)),
            egress: ServerEgressConfig {
                allow_private: true,
                allow_loopback: false,
                allow_link_local: false,
                allow_multicast: false,
            },
            default_client_socks_listen: SocketAddr::from(([127, 0, 0, 1], 1081)),
            default_client_carriers: 5,
        };

        assert!(matches!(
            request(
                &paths,
                ServerRequest::SetConfig {
                    config: updated.clone()
                }
            )
            .await,
            ServerResponse::Config(_)
        ));
        assert!(matches!(
            request(&paths, ServerRequest::GetConfig).await,
            ServerResponse::Config(response)
                if response.config == updated && response.restart_required
        ));

        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn failed_ipc_shutdown_remains_a_terminal_shutdown_failure() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = start_test_server(paths.clone()).await.unwrap();
        let mut client = UnixControlClient::connect(paths.control_socket_path())
            .await
            .unwrap();
        let moved_run_dir = directory.path().join("moved-run");

        std::fs::rename(&paths.run_dir, &moved_run_dir).unwrap();
        std::fs::write(&paths.run_dir, b"not a directory").unwrap();
        let response = client.request(ServerRequest::Shutdown).await.unwrap();
        drop(client);
        let follow_up = server.shutdown().await;
        std::fs::remove_file(&paths.run_dir).unwrap();
        std::fs::rename(&moved_run_dir, &paths.run_dir).unwrap();
        let _ = std::fs::remove_file(paths.control_socket_path());

        assert!(matches!(response, ServerResponse::Error(_)));
        assert!(matches!(
            follow_up,
            Err(ServerRuntimeError::SharedShutdownFailure {
                code: super::ShutdownFailureCode::Cleanup,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn list_user_page_returns_bounded_pages_with_a_continuation() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = start_test_server(paths.clone()).await.unwrap();

        for index in 0..33 {
            server
                .coordinator
                .inner
                .registry
                .create_user(format!("user-{index:02}"))
                .await
                .unwrap();
        }

        let first = request_json(
            &paths,
            serde_json::json!({"type": "list_user_page", "limit": 32}),
        )
        .await;
        let first = serde_json::to_value(first).unwrap();
        let users = first
            .pointer("/payload/users")
            .and_then(serde_json::Value::as_array)
            .expect("a user page payload");
        assert_eq!(users.len(), 32);
        let first_id = users[0]["id"].clone();
        let continuation = first
            .pointer("/payload/next_page")
            .and_then(serde_json::Value::as_str)
            .expect("a continuation for the second page");

        let second = request_json(
            &paths,
            serde_json::json!({"type": "list_user_page", "after": continuation, "limit": 32}),
        )
        .await;
        let second = serde_json::to_value(second).unwrap();
        let users = second
            .pointer("/payload/users")
            .and_then(serde_json::Value::as_array)
            .expect("a user page payload");
        assert_eq!(users.len(), 1);
        assert_ne!(users[0]["id"], first_id);
        assert_eq!(
            second.pointer("/payload/next_page"),
            Some(&serde_json::Value::Null)
        );

        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_server_startup_retries_a_busy_peer_port() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let busy_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let busy_address = busy_listener.local_addr().unwrap();
        let server = start_test_server_with_peer_candidates(paths.clone(), [busy_address])
            .await
            .unwrap();
        drop(busy_listener);

        assert!(matches!(
            request(&paths, ServerRequest::Snapshot).await,
            ServerResponse::Snapshot(_)
        ));
        server.shutdown().await.unwrap();
    }

    async fn request_json(paths: &ServerPaths, request: serde_json::Value) -> ServerResponse {
        let mut stream = UnixStream::connect(paths.control_socket_path())
            .await
            .unwrap();
        let body = serde_json::to_vec(&serde_json::json!({
            "protocol_version": 1,
            "request": request,
        }))
        .unwrap();
        stream
            .write_all(&(body.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&body).await.unwrap();
        crate::ipc::unix::read_response(&mut stream).await.unwrap()
    }

    async fn request(paths: &ServerPaths, request: ServerRequest) -> ServerResponse {
        UnixControlClient::connect(&paths.control_socket_path())
            .await
            .unwrap()
            .request(request)
            .await
            .unwrap()
    }

    fn test_paths(root: &Path) -> ServerPaths {
        ServerPaths {
            config_dir: root.join("config"),
            data_dir: root.join("data"),
            run_dir: root.join("run"),
        }
    }
}
