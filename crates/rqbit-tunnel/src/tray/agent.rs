#[cfg(any(windows, all(target_os = "linux", feature = "tray-linux")))]
use std::io;
#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
use std::process::Command;
#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
use std::{
    ffi::OsStr,
    path::{Component, Path, PathBuf},
};

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
use semver::Version;
use thiserror::Error;

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
use crate::version::ActiveReleaseError;

#[cfg(all(target_os = "linux", feature = "tray-linux"))]
use std::ffi::OsString;

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
use super::state::{ICON_SIZE, TrayInput, TrayState, rgba_circle};
#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
use crate::{
    cli::{observed_client_service_state, request_client_snapshot},
    model::ClientSnapshot,
    paths::ClientPaths,
    platform::ServiceState,
    version::read_active_release,
};
#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
use std::{
    future::Future,
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
    thread,
    time::Duration,
};

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedPayload {
    pub(crate) install_root: PathBuf,
    pub(crate) current_version: Version,
    pub(crate) launcher: PathBuf,
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
impl ManagedPayload {
    pub(crate) fn from_payload_executable(executable: &Path) -> Result<Self, TrayAgentError> {
        if !executable.is_absolute()
            || executable
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(TrayAgentError::InvalidPayloadPath {
                path: executable.to_path_buf(),
            });
        }

        if !matches!(
            executable.file_name(),
            Some(name)
                if name == OsStr::new(payload_executable_name())
                    || name == OsStr::new(tray_executable_name())
        ) {
            return Err(TrayAgentError::InvalidPayloadPath {
                path: executable.to_path_buf(),
            });
        }
        let payload_dir =
            executable
                .parent()
                .ok_or_else(|| TrayAgentError::InvalidPayloadPath {
                    path: executable.to_path_buf(),
                })?;
        if payload_dir.file_name() != Some(OsStr::new("payload")) {
            return Err(TrayAgentError::InvalidPayloadPath {
                path: executable.to_path_buf(),
            });
        }
        let release_dir =
            payload_dir
                .parent()
                .ok_or_else(|| TrayAgentError::InvalidPayloadPath {
                    path: executable.to_path_buf(),
                })?;
        let version = release_dir
            .file_name()
            .and_then(OsStr::to_str)
            .and_then(|version| Version::parse(version).ok())
            .ok_or_else(|| TrayAgentError::InvalidPayloadPath {
                path: executable.to_path_buf(),
            })?;
        let releases_dir =
            release_dir
                .parent()
                .ok_or_else(|| TrayAgentError::InvalidPayloadPath {
                    path: executable.to_path_buf(),
                })?;
        if releases_dir.file_name() != Some(OsStr::new("releases")) {
            return Err(TrayAgentError::InvalidPayloadPath {
                path: executable.to_path_buf(),
            });
        }
        let install_root =
            releases_dir
                .parent()
                .ok_or_else(|| TrayAgentError::InvalidPayloadPath {
                    path: executable.to_path_buf(),
                })?;

        Ok(Self {
            install_root: install_root.to_path_buf(),
            current_version: version,
            launcher: install_root.join(stable_launcher_name()),
        })
    }
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
pub(crate) fn replacement_needed(current: &Version, active: &Version) -> bool {
    current != active
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrayAction {
    OpenControl,
    Successor,
}

#[cfg(all(target_os = "linux", feature = "tray-linux"))]
fn launcher_arguments(action: TrayAction) -> &'static [&'static str] {
    match action {
        TrayAction::OpenControl => &["client", "tui"],
        TrayAction::Successor => &["tray"],
    }
}

#[cfg(all(target_os = "linux", feature = "tray-linux"))]
const LINUX_TERMINALS: &[(&str, &[&str])] = &[
    ("x-terminal-emulator", &["-e"]),
    ("gnome-terminal", &["--"]),
    ("konsole", &["-e"]),
    ("xfce4-terminal", &["-x"]),
    ("xterm", &["-e"]),
];

#[cfg(all(target_os = "linux", feature = "tray-linux"))]
fn terminal_arguments(
    prefix: &[&str],
    launcher: &Path,
    launcher_arguments: &[&str],
) -> Vec<OsString> {
    let mut arguments = Vec::with_capacity(prefix.len() + launcher_arguments.len() + 1);
    arguments.extend(prefix.iter().map(OsString::from));
    arguments.push(launcher.as_os_str().to_owned());
    arguments.extend(launcher_arguments.iter().map(OsString::from));
    arguments
}

#[cfg(all(target_os = "linux", feature = "tray-linux"))]
fn spawn_linux_terminal(
    launcher: &Path,
    launcher_arguments: &[&str],
) -> Result<(), TrayAgentError> {
    for (terminal, prefix) in LINUX_TERMINALS {
        match Command::new(terminal)
            .args(terminal_arguments(prefix, launcher, launcher_arguments))
            .spawn()
        {
            Ok(_) => return Ok(()),
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(TrayAgentError::LaunchTerminal { source }),
        }
    }
    Err(TrayAgentError::LaunchTerminal {
        source: io::Error::new(
            io::ErrorKind::NotFound,
            "no supported terminal emulator was found",
        ),
    })
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
#[cfg(windows)]
const fn payload_executable_name() -> &'static str {
    "rqbit-tunnel.exe"
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
#[cfg(not(windows))]
const fn payload_executable_name() -> &'static str {
    "rqbit-tunnel"
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
#[cfg(windows)]
const fn tray_executable_name() -> &'static str {
    "rqbit-tunnel-tray.exe"
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
#[cfg(not(windows))]
const fn tray_executable_name() -> &'static str {
    "rqbit-tunnel-tray"
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
#[cfg(windows)]
const fn stable_launcher_name() -> &'static str {
    "launcher.exe"
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
#[cfg(not(windows))]
const fn stable_launcher_name() -> &'static str {
    "launcher"
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrayRunOutcome {
    Unavailable,
    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    Exited,
}

pub(crate) async fn run() -> Result<TrayRunOutcome, TrayAgentError> {
    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    {
        let payload = current_managed_payload()?;
        return run_with_backend(payload).await;
    }

    #[cfg(not(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    )))]
    {
        Ok(TrayRunOutcome::Unavailable)
    }
}

pub(crate) fn set_autostart(enabled: bool) -> Result<(), TrayAgentError> {
    #[cfg(all(target_os = "linux", feature = "tray-linux"))]
    {
        let payload = current_managed_payload()?;
        crate::platform::linux::set_current_user_tray_autostart(&payload.launcher, enabled)
            .map_err(TrayAgentError::Autostart)
    }

    #[cfg(all(windows, feature = "tray-windows"))]
    {
        let payload = current_managed_payload()?;
        crate::platform::windows::set_current_user_tray_autostart(&payload.launcher, enabled)
            .map_err(TrayAgentError::Autostart)
    }

    #[cfg(not(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    )))]
    {
        let _ = enabled;
        Err(TrayAgentError::BackendUnavailable)
    }
}

pub(crate) fn ensure_user_session() -> Result<(), TrayAgentError> {
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            return Err(TrayAgentError::ElevatedSession);
        }
        return Ok(());
    }

    #[cfg(windows)]
    {
        if crate::cli::is_elevated().map_err(TrayAgentError::ElevationCheck)? {
            return Err(TrayAgentError::ElevatedSession);
        }
        if !crate::platform::windows::current_process_is_user_session()
            .map_err(TrayAgentError::SessionCheck)?
        {
            return Err(TrayAgentError::SessionZero);
        }
        return Ok(());
    }

    #[cfg(not(any(unix, windows)))]
    Err(TrayAgentError::UnsupportedPlatform)
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
fn current_managed_payload() -> Result<ManagedPayload, TrayAgentError> {
    let executable = std::env::current_exe().map_err(TrayAgentError::CurrentExecutable)?;
    ManagedPayload::from_payload_executable(&executable)
}

#[derive(Debug, Error)]
pub(crate) enum TrayAgentError {
    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    #[error("the tray must be launched from a managed versioned payload: {path}")]
    InvalidPayloadPath { path: PathBuf },
    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    #[error("failed to resolve the current tray payload: {0}")]
    CurrentExecutable(#[source] io::Error),
    #[error("the tray must run as a non-elevated user-session process")]
    ElevatedSession,
    #[cfg(windows)]
    #[error("the tray cannot run in Windows Session 0")]
    SessionZero,
    #[cfg(windows)]
    #[error("failed to determine whether the tray process is elevated: {0}")]
    ElevationCheck(#[source] crate::cli::PrivilegeError),
    #[cfg(windows)]
    #[error("failed to determine the tray process session: {0}")]
    SessionCheck(#[source] io::Error),
    #[cfg(not(any(target_os = "linux", windows)))]
    #[error("tray autostart is not supported on this platform")]
    UnsupportedPlatform,
    #[cfg(not(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    )))]
    #[error("the tray backend is unavailable in this rqbit-tunnel build")]
    BackendUnavailable,
    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    #[error("failed to change tray autostart: {0}")]
    Autostart(#[source] io::Error),
    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    #[error(transparent)]
    ActiveRelease(#[from] ActiveReleaseError),
    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    #[error("failed to launch the stable tray command through {launcher}: {source}")]
    Launch {
        launcher: PathBuf,
        #[source]
        source: io::Error,
    },
    #[cfg(all(windows, feature = "tray-windows"))]
    #[error(
        "failed to launch the protected Windows dashboard wrapper {wrapper} through powershell.exe: {source}"
    )]
    LaunchDashboard {
        wrapper: PathBuf,
        #[source]
        source: io::Error,
    },
    #[cfg(all(target_os = "linux", feature = "tray-linux"))]
    #[error("failed to launch the tunnel dashboard in a terminal: {source}")]
    LaunchTerminal {
        #[source]
        source: io::Error,
    },
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
const TRAY_ID: &str = "rqbit-tunnel-tray";
#[cfg(all(windows, feature = "tray-windows"))]
const OPEN_CONTROL_ID: &str = "rqbit-tunnel-open-control";
#[cfg(all(windows, feature = "tray-windows"))]
const EXIT_TRAY_ID: &str = "rqbit-tunnel-exit";

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
enum BackendCommand {
    State(TrayState),
    Exit,
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
enum BackendEvent {
    OpenControl,
    Exit,
    Unavailable,
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
struct TrayBackend {
    commands: Sender<BackendCommand>,
    events: Receiver<BackendEvent>,
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
impl TrayBackend {
    fn start(initial: TrayState) -> Option<Self> {
        let (commands, command_receiver) = mpsc::channel();
        let (event_sender, events) = mpsc::channel();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        if thread::Builder::new()
            .name("rqbit-tunnel-tray".to_owned())
            .spawn(move || {
                run_backend_thread(initial, command_receiver, event_sender, ready_sender);
            })
            .is_err()
        {
            return None;
        }

        match ready_receiver.recv_timeout(Duration::from_secs(2)) {
            Ok(Ok(())) => Some(Self { commands, events }),
            Ok(Err(())) | Err(_) => None,
        }
    }

    fn update(&self, state: TrayState) -> bool {
        self.commands.send(BackendCommand::State(state)).is_ok()
    }

    fn shutdown(&self) {
        let _ = self.commands.send(BackendCommand::Exit);
    }
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
fn tray_state_from_observation(
    snapshot: Option<ClientSnapshot>,
    observed_service: Option<ServiceState>,
) -> TrayState {
    if observed_service == Some(ServiceState::Failed) {
        return TrayState::Red;
    }

    let input = match snapshot {
        Some(snapshot) => TrayInput::Snapshot(snapshot),
        None => TrayInput::Unavailable,
    };
    TrayState::from_input(input)
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
const STATUS_IPC_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
async fn snapshot_with_timeout<F, E>(request: F) -> Option<ClientSnapshot>
where
    F: Future<Output = Result<ClientSnapshot, E>>,
{
    tokio::time::timeout(STATUS_IPC_TIMEOUT, request)
        .await
        .ok()
        .and_then(Result::ok)
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
async fn run_with_backend(payload: ManagedPayload) -> Result<TrayRunOutcome, TrayAgentError> {
    let backend = match TrayBackend::start(TrayState::Gray) {
        Some(backend) => backend,
        None => return Ok(TrayRunOutcome::Unavailable),
    };
    let mut poll = tokio::time::interval(Duration::from_secs(1));

    loop {
        match drain_backend_events(&backend, &payload)? {
            Some(outcome) => return Ok(outcome),
            None => {}
        }

        tokio::select! {
            _ = poll.tick() => {
                let paths = ClientPaths::system();
                let snapshot = snapshot_with_timeout(request_client_snapshot(&paths)).await;
                let observed_service = if snapshot.is_none() {
                    tokio::task::spawn_blocking(observed_client_service_state)
                        .await
                        .ok()
                        .and_then(Result::ok)
                } else {
                    None
                };
                let state = tray_state_from_observation(snapshot, observed_service);
                if !backend.update(state) {
                    return Ok(TrayRunOutcome::Unavailable);
                }

                match active_release_changed(&payload) {
                    Ok(true) => match spawn_launcher(&payload, TrayAction::Successor) {
                        Ok(()) => {
                            backend.shutdown();
                            return Ok(TrayRunOutcome::Exited);
                        }
                        Err(error) => eprintln!("tray successor launch failed: {error}"),
                    },
                    Ok(false) => {}
                    Err(error) => eprintln!("tray update check failed: {error}"),
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
fn drain_backend_events(
    backend: &TrayBackend,
    payload: &ManagedPayload,
) -> Result<Option<TrayRunOutcome>, TrayAgentError> {
    loop {
        match backend.events.try_recv() {
            Ok(BackendEvent::OpenControl) => {
                if let Err(error) = spawn_launcher(payload, TrayAction::OpenControl) {
                    eprintln!("tray control launch failed: {error}");
                }
            }
            Ok(BackendEvent::Exit) => {
                backend.shutdown();
                return Ok(Some(TrayRunOutcome::Exited));
            }
            Ok(BackendEvent::Unavailable) | Err(TryRecvError::Disconnected) => {
                return Ok(Some(TrayRunOutcome::Unavailable));
            }
            Err(TryRecvError::Empty) => return Ok(None),
        }
    }
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
fn active_release_changed(payload: &ManagedPayload) -> Result<bool, TrayAgentError> {
    let active = read_active_release(&payload.install_root)?;
    active.payload_executable(&payload.install_root)?;
    Ok(replacement_needed(
        &payload.current_version,
        active.version(),
    ))
}

#[cfg(all(windows, feature = "tray-windows"))]
fn windows_dashboard_command(wrapper: &Path) -> Command {
    let mut command = Command::new("powershell.exe");
    command
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-WindowStyle",
            "Hidden",
            "-File",
        ])
        .arg(wrapper)
        .arg("-OpenDashboard");
    command
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
fn spawn_launcher(payload: &ManagedPayload, action: TrayAction) -> Result<(), TrayAgentError> {
    #[cfg(all(target_os = "linux", feature = "tray-linux"))]
    if action == TrayAction::OpenControl {
        return spawn_linux_terminal(&payload.launcher, launcher_arguments(action));
    }

    #[cfg(all(windows, feature = "tray-windows"))]
    if action == TrayAction::OpenControl {
        let wrapper = payload.install_root.join("client-run.ps1");
        return windows_dashboard_command(&wrapper)
            .spawn()
            .map(|_| ())
            .map_err(|source| TrayAgentError::LaunchDashboard { wrapper, source });
    }

    #[cfg(all(target_os = "linux", feature = "tray-linux"))]
    let arguments = launcher_arguments(action);
    #[cfg(all(windows, feature = "tray-windows"))]
    let arguments: &[&str] = &["tray"];

    Command::new(&payload.launcher)
        .args(arguments)
        .spawn()
        .map(|_| ())
        .map_err(|source| TrayAgentError::Launch {
            launcher: payload.launcher.clone(),
            source,
        })
}

#[cfg(all(target_os = "linux", feature = "tray-linux"))]
fn run_backend_thread(
    initial: TrayState,
    commands: Receiver<BackendCommand>,
    events: Sender<BackendEvent>,
    ready: mpsc::SyncSender<Result<(), ()>>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            let _ = ready.send(Err(()));
            return;
        }
    };
    runtime.block_on(run_linux_backend(initial, commands, events, ready));
}

#[cfg(all(target_os = "linux", feature = "tray-linux"))]
async fn run_linux_backend(
    initial: TrayState,
    commands: Receiver<BackendCommand>,
    events: Sender<BackendEvent>,
    ready: mpsc::SyncSender<Result<(), ()>>,
) {
    use ksni::TrayMethods;

    let tray = LinuxTray {
        state: initial,
        events: events.clone(),
    };
    let handle = match tray.spawn().await {
        Ok(handle) => handle,
        Err(_) => {
            let _ = ready.send(Err(()));
            return;
        }
    };
    let _ = ready.send(Ok(()));

    loop {
        match receive_linux_backend_commands(&commands, &handle, &events).await {
            BackendLoop::Continue => {}
            BackendLoop::Exit => {
                handle.shutdown().await;
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(all(target_os = "linux", feature = "tray-linux"))]
struct LinuxTray {
    state: TrayState,
    events: Sender<BackendEvent>,
}

#[cfg(all(target_os = "linux", feature = "tray-linux"))]
impl LinuxTray {
    fn emit(&self, event: BackendEvent) {
        let _ = self.events.send(event);
    }
}

#[cfg(all(target_os = "linux", feature = "tray-linux"))]
impl ksni::Tray for LinuxTray {
    fn id(&self) -> String {
        TRAY_ID.to_owned()
    }

    fn title(&self) -> String {
        "Rqbit tunnel".to_owned()
    }

    fn status(&self) -> ksni::Status {
        match self.state {
            TrayState::Red => ksni::Status::NeedsAttention,
            TrayState::Gray | TrayState::Yellow | TrayState::Green => ksni::Status::Active,
        }
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![linux_icon(self.state)]
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            icon_name: String::new(),
            icon_pixmap: self.icon_pixmap(),
            title: self.title(),
            description: self.state.tooltip().to_owned(),
        }
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;

        vec![
            StandardItem {
                label: "Open control".to_owned(),
                activate: Box::new(|tray: &mut LinuxTray| tray.emit(BackendEvent::OpenControl)),
                ..Default::default()
            }
            .into(),
            ksni::MenuItem::Separator,
            StandardItem {
                label: "Exit tray".to_owned(),
                activate: Box::new(|tray: &mut LinuxTray| tray.emit(BackendEvent::Exit)),
                ..Default::default()
            }
            .into(),
        ]
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.emit(BackendEvent::OpenControl);
    }
}

#[cfg(all(target_os = "linux", feature = "tray-linux"))]
fn linux_icon(state: TrayState) -> ksni::Icon {
    let mut data = rgba_circle(state);
    for pixel in data.chunks_exact_mut(4) {
        pixel.rotate_right(1);
    }
    ksni::Icon {
        width: ICON_SIZE as i32,
        height: ICON_SIZE as i32,
        data,
    }
}

#[cfg(all(target_os = "linux", feature = "tray-linux"))]
async fn receive_linux_backend_commands(
    commands: &Receiver<BackendCommand>,
    tray: &ksni::Handle<LinuxTray>,
    events: &Sender<BackendEvent>,
) -> BackendLoop {
    loop {
        match commands.try_recv() {
            Ok(BackendCommand::State(state)) => {
                if tray.update(|tray| tray.state = state).await.is_none() {
                    let _ = events.send(BackendEvent::Unavailable);
                    return BackendLoop::Exit;
                }
            }
            Ok(BackendCommand::Exit) | Err(TryRecvError::Disconnected) => {
                return BackendLoop::Exit;
            }
            Err(TryRecvError::Empty) => return BackendLoop::Continue,
        }
    }
}

#[cfg(all(windows, feature = "tray-windows"))]
fn run_backend_thread(
    initial: TrayState,
    commands: Receiver<BackendCommand>,
    events: Sender<BackendEvent>,
    ready: mpsc::SyncSender<Result<(), ()>>,
) {
    initialize_windows_message_queue();

    let mut tray = match create_tray_icon(initial) {
        Ok(tray) => tray,
        Err(()) => {
            let _ = ready.send(Err(()));
            return;
        }
    };
    let _ = ready.send(Ok(()));

    loop {
        pump_platform_events();
        match receive_backend_commands(&commands, &mut tray, &events) {
            BackendLoop::Continue => {}
            BackendLoop::Exit => return,
        }
        receive_menu_events(&events);
        receive_primary_clicks(&events);
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
enum BackendLoop {
    Continue,
    Exit,
}

#[cfg(all(windows, feature = "tray-windows"))]
fn create_tray_icon(state: TrayState) -> Result<tray_icon::TrayIcon, ()> {
    use tray_icon::{
        Icon, TrayIconBuilder,
        menu::{Menu, MenuItem},
    };

    let menu = Menu::new();
    menu.append(&MenuItem::with_id(
        OPEN_CONTROL_ID,
        "Open control",
        true,
        None,
    ))
    .map_err(|_| ())?;
    menu.append(&MenuItem::with_id(EXIT_TRAY_ID, "Exit tray", true, None))
        .map_err(|_| ())?;
    let icon =
        Icon::from_rgba(rgba_circle(state), ICON_SIZE as u32, ICON_SIZE as u32).map_err(|_| ())?;

    TrayIconBuilder::new()
        .with_id(TRAY_ID)
        .with_icon(icon)
        .with_tooltip(state.tooltip())
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .build()
        .map_err(|_| ())
}

#[cfg(all(windows, feature = "tray-windows"))]
fn receive_backend_commands(
    commands: &Receiver<BackendCommand>,
    tray: &mut tray_icon::TrayIcon,
    events: &Sender<BackendEvent>,
) -> BackendLoop {
    loop {
        match commands.try_recv() {
            Ok(BackendCommand::State(state)) => {
                let icon = match tray_icon::Icon::from_rgba(
                    rgba_circle(state),
                    ICON_SIZE as u32,
                    ICON_SIZE as u32,
                ) {
                    Ok(icon) => icon,
                    Err(_) => {
                        let _ = events.send(BackendEvent::Unavailable);
                        return BackendLoop::Exit;
                    }
                };
                if tray.set_icon(Some(icon)).is_err()
                    || tray.set_tooltip(Some(state.tooltip())).is_err()
                {
                    let _ = events.send(BackendEvent::Unavailable);
                    return BackendLoop::Exit;
                }
            }
            Ok(BackendCommand::Exit) | Err(TryRecvError::Disconnected) => {
                return BackendLoop::Exit;
            }
            Err(TryRecvError::Empty) => return BackendLoop::Continue,
        }
    }
}

#[cfg(all(windows, feature = "tray-windows"))]
fn receive_menu_events(events: &Sender<BackendEvent>) {
    use tray_icon::menu::MenuEvent;

    while let Ok(event) = MenuEvent::receiver().try_recv() {
        match event.id.as_ref() {
            OPEN_CONTROL_ID => {
                let _ = events.send(BackendEvent::OpenControl);
            }
            EXIT_TRAY_ID => {
                let _ = events.send(BackendEvent::Exit);
            }
            _ => {}
        }
    }
}

#[cfg(all(windows, feature = "tray-windows"))]
fn receive_primary_clicks(events: &Sender<BackendEvent>) {
    use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent};

    while let Ok(event) = TrayIconEvent::receiver().try_recv() {
        if let TrayIconEvent::Click {
            id,
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } = event
        {
            if id.as_ref() == TRAY_ID {
                let _ = events.send(BackendEvent::OpenControl);
            }
        }
    }
}

#[cfg(all(windows, feature = "tray-windows"))]
fn initialize_windows_message_queue() {
    use windows::Win32::UI::WindowsAndMessaging::{MSG, PM_NOREMOVE, PeekMessageW};

    let mut message = MSG::default();
    unsafe {
        let _ = PeekMessageW(&mut message, None, 0, 0, PM_NOREMOVE);
    }
}

#[cfg(all(windows, feature = "tray-windows"))]
fn pump_platform_events() {
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, MSG, PM_REMOVE, PeekMessageW, TranslateMessage,
    };

    let mut message = MSG::default();
    while unsafe { PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() } {
        unsafe {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}
#[cfg(test)]
mod tests {
    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    use std::path::{Path, PathBuf};

    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    use semver::Version;
    #[cfg(all(windows, feature = "tray-windows"))]
    use std::ffi::OsStr;

    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    use super::ManagedPayload;
    #[cfg(all(target_os = "linux", feature = "tray-linux"))]
    use super::{TrayAction, launcher_arguments};
    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    use super::{TrayState, replacement_needed};
    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    use crate::platform::ServiceState;

    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    #[test]
    fn managed_payload_path_selects_the_stable_launcher() {
        #[cfg(all(windows, feature = "tray-windows"))]
        let executable =
            Path::new(r"C:\Program Files\rqbit-tunnel\releases\1.2.3\payload\rqbit-tunnel.exe");
        #[cfg(all(target_os = "linux", feature = "tray-linux"))]
        let executable = Path::new("/opt/rqbit-tunnel/releases/1.2.3/payload/rqbit-tunnel");
        let payload =
            ManagedPayload::from_payload_executable(executable).expect("managed payload layout");

        #[cfg(all(windows, feature = "tray-windows"))]
        let expected_install_root = PathBuf::from(r"C:\Program Files\rqbit-tunnel");
        #[cfg(all(target_os = "linux", feature = "tray-linux"))]
        let expected_install_root = PathBuf::from("/opt/rqbit-tunnel");
        #[cfg(all(windows, feature = "tray-windows"))]
        let expected_launcher = PathBuf::from(r"C:\Program Files\rqbit-tunnel\launcher.exe");
        #[cfg(all(target_os = "linux", feature = "tray-linux"))]
        let expected_launcher = PathBuf::from("/opt/rqbit-tunnel/launcher");

        assert_eq!(payload.install_root, expected_install_root);
        assert_eq!(payload.current_version, Version::parse("1.2.3").unwrap());
        assert_eq!(payload.launcher, expected_launcher);
    }

    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    #[test]
    fn tray_companion_path_selects_the_same_stable_launcher() {
        #[cfg(all(windows, feature = "tray-windows"))]
        let executable = Path::new(
            r"C:\Program Files\rqbit-tunnel\releases\1.2.3\payload\rqbit-tunnel-tray.exe",
        );
        #[cfg(all(target_os = "linux", feature = "tray-linux"))]
        let executable = Path::new("/opt/rqbit-tunnel/releases/1.2.3/payload/rqbit-tunnel-tray");
        let payload = ManagedPayload::from_payload_executable(executable)
            .expect("managed tray companion layout");

        #[cfg(all(windows, feature = "tray-windows"))]
        let expected_install_root = PathBuf::from(r"C:\Program Files\rqbit-tunnel");
        #[cfg(all(target_os = "linux", feature = "tray-linux"))]
        let expected_install_root = PathBuf::from("/opt/rqbit-tunnel");
        #[cfg(all(windows, feature = "tray-windows"))]
        let expected_launcher = PathBuf::from(r"C:\Program Files\rqbit-tunnel\launcher.exe");
        #[cfg(all(target_os = "linux", feature = "tray-linux"))]
        let expected_launcher = PathBuf::from("/opt/rqbit-tunnel/launcher");

        assert_eq!(payload.install_root, expected_install_root);
        assert_eq!(payload.current_version, Version::parse("1.2.3").unwrap());
        assert_eq!(payload.launcher, expected_launcher);
    }

    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    #[test]
    fn malformed_payload_path_cannot_select_a_launcher() {
        #[cfg(all(windows, feature = "tray-windows"))]
        let executable =
            Path::new(r"C:\Program Files\rqbit-tunnel\releases\1.2.3\rqbit-tunnel.exe");
        #[cfg(all(target_os = "linux", feature = "tray-linux"))]
        let executable = Path::new("/opt/rqbit-tunnel/releases/1.2.3/rqbit-tunnel");

        assert!(ManagedPayload::from_payload_executable(executable).is_err());
    }

    #[test]
    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    fn release_change_requires_a_successor_but_same_release_does_not() {
        let current = Version::parse("1.2.3").unwrap();

        assert!(!replacement_needed(
            &current,
            &Version::parse("1.2.3").unwrap()
        ));
        assert!(replacement_needed(
            &current,
            &Version::parse("1.2.4").unwrap()
        ));
        assert!(replacement_needed(
            &current,
            &Version::parse("1.2.2").unwrap()
        ));
    }

    #[cfg(all(target_os = "linux", feature = "tray-linux"))]
    #[test]
    fn linux_control_action_passes_the_tui_to_a_terminal_emulator() {
        let arguments = super::terminal_arguments(
            &["-e"],
            Path::new("/opt/rqbit-tunnel/launcher"),
            launcher_arguments(TrayAction::OpenControl),
        );

        assert_eq!(
            arguments,
            [
                std::ffi::OsString::from("-e"),
                std::ffi::OsString::from("/opt/rqbit-tunnel/launcher"),
                std::ffi::OsString::from("client"),
                std::ffi::OsString::from("tui"),
            ]
        );
    }

    #[cfg(all(target_os = "linux", feature = "tray-linux"))]
    #[test]
    fn linux_primary_activation_opens_control() {
        let (events, receiver) = std::sync::mpsc::channel();
        let mut tray = super::LinuxTray {
            state: TrayState::Gray,
            events,
        };

        <super::LinuxTray as ksni::Tray>::activate(&mut tray, 0, 0);

        assert!(matches!(
            receiver.try_recv(),
            Ok(super::BackendEvent::OpenControl)
        ));
    }

    #[test]
    #[cfg(all(target_os = "linux", feature = "tray-linux"))]
    fn linux_tray_actions_use_only_fixed_stable_launcher_arguments() {
        assert_eq!(
            launcher_arguments(TrayAction::OpenControl),
            ["client", "tui"]
        );
        assert_eq!(launcher_arguments(TrayAction::Successor), ["tray"]);
    }

    #[cfg(all(windows, feature = "tray-windows"))]
    #[test]
    fn windows_control_action_uses_the_protected_wrapper_with_fixed_powershell_arguments() {
        let wrapper = Path::new(r"C:\Program Files\rqbit-tunnel\client-run.ps1");
        let command = super::windows_dashboard_command(wrapper);

        assert_eq!(command.get_program(), OsStr::new("powershell.exe"));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![
                OsStr::new("-NoProfile"),
                OsStr::new("-ExecutionPolicy"),
                OsStr::new("Bypass"),
                OsStr::new("-WindowStyle"),
                OsStr::new("Hidden"),
                OsStr::new("-File"),
                wrapper.as_os_str(),
                OsStr::new("-OpenDashboard"),
            ]
        );
    }

    #[test]
    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    fn failed_service_without_ipc_renders_a_red_tray_state() {
        assert_eq!(
            super::tray_state_from_observation(None, Some(ServiceState::Failed)),
            TrayState::Red
        );
        assert_eq!(
            super::tray_state_from_observation(None, None),
            TrayState::Gray
        );
    }

    #[cfg(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    ))]
    #[tokio::test(start_paused = true)]
    async fn tray_snapshot_poll_times_out_without_blocking() {
        let observation = super::snapshot_with_timeout(std::future::pending::<
            Result<crate::model::ClientSnapshot, ()>,
        >());
        tokio::pin!(observation);

        tokio::time::advance(super::STATUS_IPC_TIMEOUT).await;

        assert!(observation.await.is_none());
    }

    #[cfg(not(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    )))]
    #[test]
    fn autostart_requires_a_compiled_tray_backend() {
        assert!(matches!(
            super::set_autostart(true),
            Err(super::TrayAgentError::BackendUnavailable)
        ));
    }

    #[cfg(not(any(
        all(target_os = "linux", feature = "tray-linux"),
        all(windows, feature = "tray-windows")
    )))]
    #[tokio::test]
    async fn missing_backend_is_reported_as_unavailable() {
        assert_eq!(
            super::run().await.expect("fallback tray result"),
            super::TrayRunOutcome::Unavailable
        );
    }
}
