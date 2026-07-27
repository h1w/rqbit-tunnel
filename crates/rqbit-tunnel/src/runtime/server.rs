use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
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
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{Mutex, RwLock, watch},
    task::{JoinHandle, JoinSet},
    time::Duration,
};
#[cfg(test)]
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    ipc::{
        protocol::{
            ServerConfigResponse, ServerError, ServerRequest, ServerResponse,
        },
        unix::{
            UnixControlError, read_request, write_response_until_shutdown,
            write_response_with_deadline,
        },
    },
    model::{
        BUNDLE_SCHEMA_VERSION, EnrollmentBundle, ServerConfig, ServerConfigError,
        ServerEgressConfig, ServerSnapshot,
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
    #[error("failed to create output directory {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
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

pub struct ManagedServer {
    inner: Arc<ManagedServerInner>,
    control_task: Mutex<Option<JoinHandle<Result<(), ServerRuntimeError>>>>,
    shutdown_phase: Mutex<ShutdownPhase>,
    shutdown_result: watch::Sender<Option<SharedShutdownResult>>,
}

struct ManagedServerInner {
    paths: ServerPaths,
    config: RwLock<ServerConfig>,
    config_mutation: Mutex<()>,
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

        let (listener, control_socket_identity) = match bind_control_socket(&paths.control_socket_path()) {
            Ok(listener) => listener,
            Err(error) => {
                session.stop().await;
                let _ = registry.shutdown().await;
                return Err(error);
            }
        };
        let inner = Arc::new(ManagedServerInner {
            paths,
            config: RwLock::new(config),
            config_mutation: Mutex::new(()),
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
        let control_task = tokio::spawn(serve_control_socket(listener, Arc::clone(&inner)));
        let (shutdown_result, _) = watch::channel(None);

        Ok(Self {
            inner,
            control_task: Mutex::new(Some(control_task)),
            shutdown_phase: Mutex::new(ShutdownPhase::Active),
            shutdown_result,
        })
    }

    pub async fn shutdown(&self) -> Result<(), ServerRuntimeError> {
        let mut result = self.shutdown_result.subscribe();
        let leader = {
            let mut phase = self.shutdown_phase.lock().await;
            match *phase {
                ShutdownPhase::Active => {
                    *phase = ShutdownPhase::ShuttingDown;
                    true
                }
                ShutdownPhase::ShuttingDown => false,
            }
        };

        if leader {
            let outcome = self.shutdown_once().await;
            let shared = SharedShutdownResult::from_result(&outcome);
            self.shutdown_result.send_replace(Some(shared));
            return outcome;
        }

        loop {
            if let Some(shared) = result.borrow().clone() {
                return shared.into_result();
            }
            if result.changed().await.is_err() {
                return Err(ServerRuntimeError::SharedShutdownFailure {
                    code: ShutdownFailureCode::Cleanup,
                    message: "the shutdown coordinator stopped before publishing a result".to_owned(),
                });
            }
        }
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
    async fn wait_until_shutdown_started(&self) {
        loop {
            if matches!(*self.shutdown_phase.lock().await, ShutdownPhase::ShuttingDown) {
                return;
            }
            tokio::task::yield_now().await;
        }
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
        let registry_result = self.registry.shutdown().await.map_err(ServerRuntimeError::Registry);
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
                let users = self.registry.snapshots().await?;
                Ok(ServerResponse::Snapshot(ServerSnapshot { users }))
            }
            ServerRequest::ListUsers => Ok(ServerResponse::Users(self.registry.snapshots().await?)),
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
                let config = self.config.read().await.clone();
                Ok(ServerResponse::Config(ServerConfigResponse {
                    config,
                    restart_required: false,
                }))
            }
            ServerRequest::SetConfig { config } => {
                let _mutation = self.config_mutation.lock().await;
                config.validate().map_err(ConfigError::from)?;
                let persistence =
                    persist_server_config(self.paths.config_path(), config.clone()).await?;
                #[cfg(test)]
                self.pause_before_config_assignment().await;
                *self.config.write().await = config.clone();
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
        let config = self.config.read().await.clone();
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
        let response = match inner.cleanup().await {
            Ok(()) => ServerResponse::Shutdown,
            Err(error) => ServerResponse::Error(error.response()),
        };
        let _ = write_response_with_deadline(stream, &response, Duration::from_secs(1)).await;
        return Ok(true);
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
        let encoded = std::str::from_utf8(&bytes).map_err(|_| ConfigError::InvalidKeyHex {
            path: path.clone(),
        })?;
        let mut key = [0_u8; 32];
        hex::decode_to_slice(encoded, &mut key).map_err(|_| ConfigError::InvalidKeyHex {
            path: path.clone(),
        })?;
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

fn atomic_write_file(
    path: &Path,
    bytes: &[u8],
) -> Result<AtomicWriteOutcome, AtomicWriteError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| AtomicWriteError::MissingParent {
            path: path.to_path_buf(),
        })?;
    fs::create_dir_all(parent).map_err(|source| AtomicWriteError::CreateDirectory {
        path: parent.to_path_buf(),
        source,
    })?;
    let temporary = parent.join(format!(".rqbit-tunnel-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|source| AtomicWriteError::CreateTemporary {
                path: temporary.clone(),
                source,
            })?;
        file.write_all(bytes)
            .map_err(|source| AtomicWriteError::WriteTemporary {
                path: temporary.clone(),
                source,
            })?;
        file.sync_all()
            .map_err(|source| AtomicWriteError::SyncTemporary {
                path: temporary.clone(),
                source,
            })?;
        fs::rename(&temporary, path).map_err(|source| AtomicWriteError::Rename {
            path: path.to_path_buf(),
            source,
        })?;
        match File::open(parent).and_then(|directory| directory.sync_all()) {
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
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn bind_control_socket(path: &Path) -> Result<(UnixListener, SocketIdentity), ServerRuntimeError> {
    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty()).ok_or_else(|| {
        ServerRuntimeError::UnsafeControlSocketPath {
            path: path.to_path_buf(),
            kind: "path without a parent directory",
        }
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
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => {
                    return Err(ServerRuntimeError::ActiveControlSocket {
                        path: path.to_path_buf(),
                    });
                }
                Err(source) if source.kind() == io::ErrorKind::ConnectionRefused => {
                    remove_control_socket(path)?;
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
    let listener = UnixListener::bind(path).map_err(|source| ServerRuntimeError::ControlSocket {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|source| ServerRuntimeError::ControlSocket {
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

fn remove_control_socket(path: &Path) -> Result<(), ServerRuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path).map_err(|source| ServerRuntimeError::ControlSocket {
                path: path.to_path_buf(),
                source,
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
pub(crate) async fn spawn_test_server(socket: &Path) -> ManagedServer {
    let run_dir = socket.parent().expect("test socket has a parent directory");
    assert_eq!(socket.file_name().and_then(|name| name.to_str()), Some("server.sock"));
    let paths = ServerPaths {
        config_dir: run_dir.join("config"),
        data_dir: run_dir.join("data"),
        run_dir: run_dir.to_path_buf(),
    };
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("allocate a test tunnel port");
    let peer_listen = listener.local_addr().expect("test tunnel listener address");
    drop(listener);
    let config = ServerConfig {
        schema_version: crate::model::SERVER_CONFIG_SCHEMA_VERSION,
        peer_listen,
        egress: ServerEgressConfig {
            allow_private: false,
            allow_loopback: false,
            allow_link_local: false,
            allow_multicast: false,
        },
        default_client_socks_listen: "127.0.0.1:1080"
            .parse()
            .expect("valid test SOCKS listener"),
        default_client_carriers: 4,
    };
    fs::create_dir_all(&paths.config_dir).expect("create test config directory");
    fs::write(
        paths.config_path(),
        serde_json::to_vec(&config).expect("serialize test configuration"),
    )
    .expect("write test configuration");
    let (key, _) = librqbit::tunnel_generate_keypair();
    fs::write(paths.server_key_path(), hex::encode(key.0)).expect("write test server key");
    fs::set_permissions(
        paths.server_key_path(),
        fs::Permissions::from_mode(0o600),
    )
    .expect("restrict test server key");

    ManagedServer::start(paths).await.expect("start test managed server")
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        os::unix::fs::FileTypeExt,
        path::Path,
        sync::Arc,
        time::Duration,
    };

    use librqbit::tunnel_generate_keypair;
    use tokio::net::{UnixListener, UnixStream};
    use crate::{
        ipc::{
            protocol::{ServerRequest, ServerResponse},
            unix::UnixControlClient,
        },
        model::{
            EnrollmentBundle, ServerConfig, ServerEgressConfig, SERVER_CONFIG_SCHEMA_VERSION,
        },
        paths::ServerPaths,
    };

    use super::{ConfigError, ManagedServer, ServerRuntimeError, bind_control_socket};

    #[tokio::test]
    async fn add_user_exports_bundle_only_to_disk_and_rolls_back_a_failed_export() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = ManagedServer::start(paths.clone()).await.unwrap();

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
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&export_path).unwrap().permissions())
                & 0o777,
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
        assert_eq!(std::fs::read_dir(&malformed_export_path).unwrap().count(), 0);

        let users = request(&paths, ServerRequest::ListUsers).await;
        let expected_users = vec![alice];
        assert!(matches!(
            &users,
            ServerResponse::Users(actual_users) if actual_users == &expected_users
        ));

        server.shutdown().await.unwrap();
        assert!(!paths.control_socket_path().exists());
    }

    #[tokio::test]
    async fn invalid_config_update_leaves_existing_config_file_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let original = std::fs::read(paths.config_path()).unwrap();
        let server = ManagedServer::start(paths.clone()).await.unwrap();

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
        let server = ManagedServer::start(paths.clone()).await.unwrap();
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
            Err(ServerRuntimeError::Config(ConfigError::MissingFile { kind: "key", .. }))
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
            Err(ServerRuntimeError::Config(ConfigError::InvalidKeyHex { .. }))
        ));
    }

    #[tokio::test]
    async fn shutdown_request_removes_the_exact_control_socket_before_replying() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = ManagedServer::start(paths.clone()).await.unwrap();

        let response = request(&paths, ServerRequest::Shutdown).await;

        assert!(matches!(response, ServerResponse::Shutdown));
        assert!(!paths.control_socket_path().exists());
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn startup_refuses_to_replace_an_active_control_socket() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = ManagedServer::start(paths.clone()).await.unwrap();
        let second_paths = ServerPaths {
            config_dir: directory.path().join("second-config"),
            data_dir: directory.path().join("second-data"),
            run_dir: paths.run_dir.clone(),
        };
        write_test_server_material(&second_paths).await;

        match ManagedServer::start(second_paths).await {
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
        let server = ManagedServer::start(paths.clone()).await.unwrap();
        let idle_connection = UnixStream::connect(paths.control_socket_path()).await.unwrap();
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
        assert!(std::fs::symlink_metadata(&symbolic_link)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[tokio::test]
    async fn oversized_list_users_response_becomes_a_typed_bounded_error() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = ManagedServer::start(paths.clone()).await.unwrap();

        for index in 0..160 {
            server
                .inner
                .registry
                .create_user(format!("{index:04}-{}", "x".repeat(512)))
                .await
                .unwrap();
        }

        let response = request(&paths, ServerRequest::ListUsers).await;
        match response {
            ServerResponse::Error(error) => {
                assert_eq!(error.code, "response_too_large");
                assert!(error.recovery.contains("Narrow"));
            }
            other => panic!("expected a bounded typed response error, got {other:?}"),
        }

        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_config_updates_never_split_disk_and_memory_state() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = ManagedServer::start(paths.clone()).await.unwrap();
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
        let pause = server.inner.pause_next_config_assignment().await;
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
        let server = Arc::new(ManagedServer::start(paths.clone()).await.unwrap());
        let cleanup_gate = server.inner.cleanup_gate.lock().await;
        let first_server = Arc::clone(&server);
        let first = tokio::spawn(async move { first_server.shutdown().await });

        server.wait_until_shutdown_started().await;
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
    async fn shutdown_leaves_a_replacement_control_socket_untouched() {
        let directory = tempfile::tempdir().unwrap();
        let paths = test_paths(directory.path());
        write_test_server_material(&paths).await;
        let server = ManagedServer::start(paths.clone()).await.unwrap();
        let socket = paths.control_socket_path();

        std::fs::remove_file(&socket).unwrap();
        let replacement = UnixListener::bind(&socket).unwrap();

        server.shutdown().await.unwrap();
        assert!(std::fs::symlink_metadata(&socket)
            .unwrap()
            .file_type()
            .is_socket());

        drop(replacement);
        std::fs::remove_file(socket).unwrap();
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

    async fn write_test_server_material(paths: &ServerPaths) {
        let config = ServerConfig {
            schema_version: SERVER_CONFIG_SCHEMA_VERSION,
            peer_listen: SocketAddr::from(([127, 0, 0, 1], unused_local_port().await)),
            egress: ServerEgressConfig {
                allow_private: false,
                allow_loopback: false,
                allow_link_local: false,
                allow_multicast: false,
            },
            default_client_socks_listen: SocketAddr::from(([127, 0, 0, 1], 1080)),
            default_client_carriers: 4,
        };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(paths.config_path(), serde_json::to_vec(&config).unwrap()).unwrap();
        let (key, _) = tunnel_generate_keypair();
        std::fs::write(paths.server_key_path(), hex::encode(key.0)).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(
            paths.server_key_path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
    }

    async fn unused_local_port() -> u16 {
        tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
}
