use std::{
    future::Future,
    io::{self, IsTerminal},
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
};
use thiserror::Error;

use crate::{
    cli::{ClientControlError, observed_client_service_state, request_client_snapshot},
    config::load_client_config,
    model::{ClientConfig, ClientSnapshot, LocalServiceState, LocalTunnelState},
    paths::ClientPaths,
    platform::ServiceState,
};

const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(1);
const EVENT_TICK: Duration = Duration::from_millis(250);
const FOOTER: &str = "[i]mport [c]onfigure [s]tart/stop [a]utostart [l]ogs [u]pdate q";
const LAN_SECURITY_BANNER: &str =
    "CRITICAL: unauthenticated LAN SOCKS proxy is enabled; hosts on this network can use it.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientTuiAction {
    Quit,
    Refresh,
    Import { bundle: PathBuf },
    Configure(ClientTuiConfigUpdate),
    Start,
    Stop,
    EnableAutostart,
    DisableAutostart,
    Logs,
    CheckUpdate,
    InstallUpdate { version: String },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientTuiConfigUpdate {
    pub server_addr: Option<String>,
    pub socks_listen: Option<String>,
    pub carriers: Option<String>,
    pub allow_unauthenticated_lan_socks: Option<bool>,
}

/// Non-sensitive update outcome rendered by the client dashboard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientUpdateFeedback {
    Available { version: String },
    Installed { version: String },
    NoUpdate,
    Failed { message: String },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientTuiState {
    snapshot: Option<ClientSnapshot>,
    observed_service: Option<ServiceState>,
    endpoint: ClientEndpoint,
    configured_socks_listen: Option<SocketAddr>,
    configured_lan_socks_acknowledged: Option<bool>,
    configuration: ClientConfigForm,
    modal: Option<ClientModal>,
    pub last_error: Option<String>,
    snapshot_error: Option<String>,
    update_notice: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ClientModal {
    Import { bundle: String },
    Configure(ClientConfigForm),
    Autostart,
    CheckUpdate,
    Update { version: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientConfigField {
    ServerAddress,
    SocksListen,
    Carriers,
    LanAcknowledgement,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ClientEndpoint {
    #[default]
    Unavailable,
    DhtDiscovery,
    Address(SocketAddr),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ClientConfigForm {
    server_addr: String,
    server_addr_changed: bool,
    socks_listen: String,
    socks_listen_changed: bool,
    carriers: String,
    carriers_changed: bool,
    allow_unauthenticated_lan_socks: bool,
    acknowledgement_changed: bool,
    field: Option<ClientConfigField>,
}

impl Default for ClientConfigForm {
    fn default() -> Self {
        Self {
            server_addr: String::new(),
            server_addr_changed: false,
            socks_listen: String::new(),
            socks_listen_changed: false,
            carriers: String::new(),
            carriers_changed: false,
            allow_unauthenticated_lan_socks: false,
            acknowledgement_changed: false,
            field: Some(ClientConfigField::ServerAddress),
        }
    }
}

impl ClientConfigForm {
    fn from_config(config: &ClientConfig) -> Self {
        Self {
            server_addr: config
                .server_addr
                .map(|address| address.to_string())
                .unwrap_or_default(),
            socks_listen: config.socks_listen.to_string(),
            carriers: config.carriers.to_string(),
            allow_unauthenticated_lan_socks: config.allow_unauthenticated_lan_socks,
            ..Self::default()
        }
    }

    fn select_next(&mut self) {
        self.field = Some(
            match self.field.unwrap_or(ClientConfigField::ServerAddress) {
                ClientConfigField::ServerAddress => ClientConfigField::SocksListen,
                ClientConfigField::SocksListen => ClientConfigField::Carriers,
                ClientConfigField::Carriers => ClientConfigField::LanAcknowledgement,
                ClientConfigField::LanAcknowledgement => ClientConfigField::ServerAddress,
            },
        );
    }

    fn push_selected(&mut self, character: char) {
        match self.field {
            Some(ClientConfigField::ServerAddress) => {
                self.server_addr.push(character);
                self.server_addr_changed = true;
            }
            Some(ClientConfigField::SocksListen) => {
                self.socks_listen.push(character);
                self.socks_listen_changed = true;
            }
            Some(ClientConfigField::Carriers) => {
                self.carriers.push(character);
                self.carriers_changed = true;
            }
            Some(ClientConfigField::LanAcknowledgement) | None => {}
        }
    }

    fn backspace_selected(&mut self) {
        match self.field {
            Some(ClientConfigField::ServerAddress) => {
                self.server_addr.pop();
                self.server_addr_changed = true;
            }
            Some(ClientConfigField::SocksListen) => {
                self.socks_listen.pop();
                self.socks_listen_changed = true;
            }
            Some(ClientConfigField::Carriers) => {
                self.carriers.pop();
                self.carriers_changed = true;
            }
            Some(ClientConfigField::LanAcknowledgement) | None => {}
        }
    }

    fn update(self) -> ClientTuiConfigUpdate {
        ClientTuiConfigUpdate {
            server_addr: self
                .server_addr_changed
                .then_some(self.server_addr)
                .and_then(non_empty),
            socks_listen: self
                .socks_listen_changed
                .then_some(self.socks_listen)
                .and_then(non_empty),
            carriers: self
                .carriers_changed
                .then_some(self.carriers)
                .and_then(non_empty),
            allow_unauthenticated_lan_socks: self
                .acknowledgement_changed
                .then_some(self.allow_unauthenticated_lan_socks),
        }
    }
}

impl ClientTuiState {
    pub fn from_snapshot(snapshot: ClientSnapshot) -> Self {
        let mut state = Self::default();
        state.apply_snapshot(snapshot);
        state
    }

    pub fn apply_snapshot(&mut self, snapshot: ClientSnapshot) {
        self.observed_service = Some(local_service_state(snapshot.service));
        self.snapshot = Some(snapshot);
    }

    fn apply_successful_snapshot_refresh(&mut self, snapshot: ClientSnapshot) {
        self.apply_snapshot(snapshot);
        self.snapshot_error = None;
    }

    fn clear_snapshot(&mut self) {
        self.snapshot = None;
    }

    fn clear_config(&mut self) {
        self.endpoint = ClientEndpoint::Unavailable;
        self.configured_socks_listen = None;
        self.configured_lan_socks_acknowledged = None;
        self.configuration = ClientConfigForm::default();
    }

    fn apply_config_refresh(&mut self, config: Option<&ClientConfig>) {
        match config {
            Some(config) => self.apply_config(config),
            None => self.clear_config(),
        }
    }

    fn apply_observed_service(&mut self, service: ServiceState) {
        self.observed_service = Some(service);
    }

    pub fn apply_config(&mut self, config: &ClientConfig) {
        self.endpoint = match config.server_addr {
            Some(address) => ClientEndpoint::Address(address),
            None => ClientEndpoint::DhtDiscovery,
        };
        self.configured_socks_listen = Some(config.socks_listen);
        self.configured_lan_socks_acknowledged = Some(config.allow_unauthenticated_lan_socks);
        self.configuration = ClientConfigForm::from_config(config);
    }

    pub fn security_banner(&self) -> &'static str {
        let configured_lan_socks = self
            .configured_socks_listen
            .is_some_and(|address| !address.ip().is_loopback())
            && self.configured_lan_socks_acknowledged == Some(true);
        let live_lan_socks = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.socks_listen)
            .is_some_and(|address| !address.ip().is_loopback());
        (configured_lan_socks || live_lan_socks)
            .then_some(LAN_SECURITY_BANNER)
            .unwrap_or("")
    }

    pub fn set_error(&mut self, error: impl Into<String>) {
        self.last_error = Some(error.into());
    }

    fn set_snapshot_error(&mut self, error: impl Into<String>) {
        self.snapshot_error = Some(error.into());
    }

    fn displayed_error(&self) -> Option<&str> {
        self.last_error
            .as_deref()
            .or(self.snapshot_error.as_deref())
    }

    pub fn apply_update_feedback(&mut self, feedback: ClientUpdateFeedback) {
        match feedback {
            ClientUpdateFeedback::Available { version } => {
                self.update_notice = Some(format!("update {version} is available"));
                self.modal = Some(ClientModal::Update { version });
            }
            ClientUpdateFeedback::Installed { version } => {
                self.update_notice = Some(format!("installed update {version}"));
            }
            ClientUpdateFeedback::NoUpdate => {
                self.update_notice = Some("already running the latest release".to_owned());
            }
            ClientUpdateFeedback::Failed { message } => {
                self.update_notice = None;
                self.set_error(message);
            }
        }
    }

    pub fn handle_key(&mut self, key: KeyCode) -> Option<ClientTuiAction> {
        if let Some(modal) = self.modal.take() {
            return self.handle_modal_key(modal, key);
        }

        match key {
            KeyCode::Char('i') => {
                self.modal = Some(ClientModal::Import {
                    bundle: String::new(),
                });
                None
            }
            KeyCode::Char('c') => {
                self.modal = Some(ClientModal::Configure(self.configuration.clone()));
                None
            }
            KeyCode::Char('s') => {
                let service_is_running = self
                    .snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.service == LocalServiceState::Running)
                    || matches!(
                        self.observed_service,
                        Some(ServiceState::Running) | Some(ServiceState::Starting)
                    );
                Some(if service_is_running {
                    ClientTuiAction::Stop
                } else {
                    ClientTuiAction::Start
                })
            }
            KeyCode::Char('a') => {
                self.modal = Some(ClientModal::Autostart);
                None
            }
            KeyCode::Char('l') => Some(ClientTuiAction::Logs),
            KeyCode::Char('u') => {
                self.modal = Some(ClientModal::CheckUpdate);
                None
            }
            KeyCode::F(5) => Some(ClientTuiAction::Refresh),
            KeyCode::Esc | KeyCode::Char('q') => Some(ClientTuiAction::Quit),
            _ => None,
        }
    }

    fn handle_modal_key(&mut self, modal: ClientModal, key: KeyCode) -> Option<ClientTuiAction> {
        match modal {
            ClientModal::Import { mut bundle } => match key {
                KeyCode::Esc => None,
                KeyCode::Backspace => {
                    bundle.pop();
                    self.modal = Some(ClientModal::Import { bundle });
                    None
                }
                KeyCode::Char(character) => {
                    bundle.push(character);
                    self.modal = Some(ClientModal::Import { bundle });
                    None
                }
                KeyCode::Enter => {
                    if bundle.trim().is_empty() {
                        self.set_error("an enrollment bundle path is required");
                        self.modal = Some(ClientModal::Import { bundle });
                        None
                    } else {
                        Some(ClientTuiAction::Import {
                            bundle: PathBuf::from(bundle),
                        })
                    }
                }
                _ => {
                    self.modal = Some(ClientModal::Import { bundle });
                    None
                }
            },
            ClientModal::Configure(mut form) => match key {
                KeyCode::Esc => None,
                KeyCode::Tab => {
                    form.select_next();
                    self.modal = Some(ClientModal::Configure(form));
                    None
                }
                KeyCode::Char(' ') if form.field == Some(ClientConfigField::LanAcknowledgement) => {
                    form.allow_unauthenticated_lan_socks = !form.allow_unauthenticated_lan_socks;
                    form.acknowledgement_changed = true;
                    self.modal = Some(ClientModal::Configure(form));
                    None
                }
                KeyCode::Backspace => {
                    form.backspace_selected();
                    self.modal = Some(ClientModal::Configure(form));
                    None
                }
                KeyCode::Char(character) => {
                    form.push_selected(character);
                    self.modal = Some(ClientModal::Configure(form));
                    None
                }
                KeyCode::Enter => {
                    let update = form.clone().update();
                    if update.server_addr.is_none()
                        && update.socks_listen.is_none()
                        && update.carriers.is_none()
                        && update.allow_unauthenticated_lan_socks.is_none()
                    {
                        self.set_error("change at least one configuration value before saving");
                        self.modal = Some(ClientModal::Configure(form));
                        None
                    } else {
                        Some(ClientTuiAction::Configure(update))
                    }
                }
                _ => {
                    self.modal = Some(ClientModal::Configure(form));
                    None
                }
            },
            ClientModal::Autostart => match key {
                KeyCode::Char('e') => Some(ClientTuiAction::EnableAutostart),
                KeyCode::Char('d') => Some(ClientTuiAction::DisableAutostart),
                KeyCode::Esc | KeyCode::Char('q') => None,
                _ => {
                    self.modal = Some(ClientModal::Autostart);
                    None
                }
            },
            ClientModal::CheckUpdate => match key {
                KeyCode::Enter => Some(ClientTuiAction::CheckUpdate),
                KeyCode::Esc | KeyCode::Char('q') => None,
                _ => {
                    self.modal = Some(ClientModal::CheckUpdate);
                    None
                }
            },
            ClientModal::Update { version } => match key {
                KeyCode::Enter => Some(ClientTuiAction::InstallUpdate { version }),
                KeyCode::Esc | KeyCode::Char('q') => None,
                _ => {
                    self.modal = Some(ClientModal::Update { version });
                    None
                }
            },
        }
    }
}

fn non_empty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

#[derive(Debug, Error)]
pub enum ClientTuiError {
    #[error(transparent)]
    Control(#[from] ClientControlError),
    #[error("client TUI requires both stdin and stdout to be terminals")]
    NotTerminal,
    #[error("terminal I/O failed: {0}")]
    Terminal(#[from] io::Error),
    #[error("terminal event reader stopped unexpectedly")]
    EventReaderStopped,
    #[error("terminal event reader task failed: {0}")]
    EventReaderTask(#[source] tokio::task::JoinError),
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalSession {
    fn enter() -> Result<Self, ClientTuiError> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(ClientTuiError::NotTerminal);
        }
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(ClientTuiError::Terminal(error));
        }

        match Terminal::new(CrosstermBackend::new(stdout)) {
            Ok(terminal) => Ok(Self { terminal }),
            Err(error) => {
                let mut stdout = io::stdout();
                let _ = execute!(stdout, LeaveAlternateScreen);
                let _ = disable_raw_mode();
                Err(ClientTuiError::Terminal(error))
            }
        }
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = self.terminal.show_cursor();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

#[cfg(unix)]
struct TuiShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl TuiShutdownSignals {
    fn register() -> Result<Self, ClientTuiError> {
        Ok(Self {
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
        })
    }

    async fn wait(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
    }
}

#[cfg(not(unix))]
struct TuiShutdownSignals;

#[cfg(not(unix))]
impl TuiShutdownSignals {
    fn register() -> Result<Self, ClientTuiError> {
        Ok(Self)
    }

    async fn wait(&mut self) {
        std::future::pending::<()>().await;
    }
}

type TerminalEvent = Result<KeyEvent, io::Error>;

struct TerminalEventReader {
    receiver: tokio::sync::mpsc::Receiver<TerminalEvent>,
    task: tokio::task::JoinHandle<()>,
}

impl TerminalEventReader {
    fn spawn() -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let task = tokio::task::spawn_blocking(move || {
            while !sender.is_closed() {
                match event::poll(EVENT_TICK) {
                    Ok(true) => match event::read() {
                        Ok(Event::Key(key)) => match sender.try_send(Ok(key)) {
                            Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
                        },
                        Ok(_) => {}
                        Err(error) => {
                            let _ = sender.try_send(Err(error));
                            break;
                        }
                    },
                    Ok(false) => {}
                    Err(error) => {
                        let _ = sender.try_send(Err(error));
                        break;
                    }
                }
            }
        });
        Self { receiver, task }
    }

    async fn recv(&mut self) -> Option<TerminalEvent> {
        self.receiver.recv().await
    }

    async fn shutdown(mut self) -> Result<(), ClientTuiError> {
        self.receiver.close();
        self.task.await.map_err(ClientTuiError::EventReaderTask)
    }
}

pub async fn run_client_tui(
    paths: ClientPaths,
    feedback: Option<ClientUpdateFeedback>,
) -> Result<ClientTuiAction, ClientTuiError> {
    let mut signals = TuiShutdownSignals::register()?;
    let mut terminal = TerminalSession::enter()?;
    let mut events = TerminalEventReader::spawn();
    let result =
        run_client_tui_loop(&paths, feedback, &mut terminal, &mut signals, &mut events).await;
    let reader_shutdown = events.shutdown().await;
    let action = result?;
    reader_shutdown?;
    Ok(action)
}

async fn await_client_refresh_or_shutdown<T>(
    refresh: impl Future<Output = T>,
    shutdown: impl Future<Output = ()>,
) -> Option<T> {
    tokio::select! {
        result = refresh => Some(result),
        _ = shutdown => None,
    }
}

async fn run_client_tui_loop(
    paths: &ClientPaths,
    feedback: Option<ClientUpdateFeedback>,
    terminal: &mut TerminalSession,
    signals: &mut TuiShutdownSignals,
    events: &mut TerminalEventReader,
) -> Result<ClientTuiAction, ClientTuiError> {
    let mut state = ClientTuiState::default();
    if let Some(feedback) = feedback {
        state.apply_update_feedback(feedback);
    }
    let mut refresh_due = true;
    let mut next_snapshot = Instant::now();

    loop {
        if refresh_due || Instant::now() >= next_snapshot {
            if await_client_refresh_or_shutdown(
                refresh_client_state(paths, &mut state),
                signals.wait(),
            )
            .await
            .is_none()
            {
                return Ok(ClientTuiAction::Quit);
            }
            refresh_due = false;
            next_snapshot = Instant::now() + SNAPSHOT_INTERVAL;
        }

        terminal
            .terminal
            .draw(|frame| render_client(frame, &state))?;
        let wait = next_snapshot
            .saturating_duration_since(Instant::now())
            .min(EVENT_TICK);
        tokio::select! {
            _ = signals.wait() => return Ok(ClientTuiAction::Quit),
            event = events.recv() => match event {
                Some(Ok(key)) => {
                    if let Some(action) = global_action_for_event(key) {
                        return Ok(action);
                    }
                    if let Some(action) = key_code_for_event(key).and_then(|key| state.handle_key(key)) {
                        match action {
                            ClientTuiAction::Refresh => refresh_due = true,
                            ClientTuiAction::Quit => return Ok(ClientTuiAction::Quit),
                            action => return Ok(action),
                        }
                    }
                }
                Some(Err(error)) => return Err(ClientTuiError::Terminal(error)),
                None => return Err(ClientTuiError::EventReaderStopped),
            },
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

async fn refresh_client_state(paths: &ClientPaths, state: &mut ClientTuiState) {
    let config_paths = paths.clone();
    let config = match tokio::task::spawn_blocking(move || load_client_config(&config_paths)).await
    {
        Ok(Ok(config)) => Some(config),
        _ => None,
    };
    state.apply_config_refresh(config.as_ref());
    match request_client_snapshot(paths).await {
        Ok(snapshot) => state.apply_successful_snapshot_refresh(snapshot),
        Err(error) => {
            state.clear_snapshot();
            if let Ok(Ok(observed_service)) =
                tokio::task::spawn_blocking(observed_client_service_state).await
            {
                state.apply_observed_service(observed_service);
            }
            state.set_snapshot_error(error.to_string());
        }
    }
}

fn global_action_for_event(key: KeyEvent) -> Option<ClientTuiAction> {
    (key.kind == KeyEventKind::Press
        && key.code == KeyCode::Char('c')
        && key.modifiers.contains(KeyModifiers::CONTROL))
    .then_some(ClientTuiAction::Quit)
}

fn key_code_for_event(key: KeyEvent) -> Option<KeyCode> {
    (key.kind == KeyEventKind::Press).then_some(key.code)
}

fn footer_height(state: &ClientTuiState) -> u16 {
    if state.displayed_error().is_some() || state.update_notice.is_some() {
        4
    } else {
        3
    }
}

fn render_client(frame: &mut ratatui::Frame, state: &ClientTuiState) {
    let banner = state.security_banner();
    let areas = if banner.is_empty() {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(8), Constraint::Length(footer_height(state))])
            .split(frame.area())
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(8),
                Constraint::Length(footer_height(state)),
            ])
            .split(frame.area())
    };
    let (banner_area, content_area, footer_area) = if banner.is_empty() {
        (None, areas[0], areas[1])
    } else {
        (Some(areas[0]), areas[1], areas[2])
    };

    if let Some(area) = banner_area {
        frame.render_widget(
            Paragraph::new(Span::styled(
                banner,
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            ))
            .block(Block::bordered().title("Open proxy warning"))
            .wrap(Wrap { trim: true }),
            area,
        );
    }

    let snapshot = state.snapshot.as_ref();
    let service = snapshot.map_or_else(
        || {
            state
                .observed_service
                .map(observed_service_state)
                .unwrap_or("unavailable")
        },
        |value| service_state(value.service),
    );
    let tunnel = snapshot.map_or("unavailable", |value| tunnel_state(value.tunnel));
    let socks_listen = snapshot
        .and_then(|value| value.socks_listen)
        .or(state.configured_socks_listen)
        .map(|address| address.to_string())
        .unwrap_or_else(|| "unavailable".to_owned());
    let endpoint = match state.endpoint {
        ClientEndpoint::Unavailable => "unavailable".to_owned(),
        ClientEndpoint::DhtDiscovery => "DHT discovery".to_owned(),
        ClientEndpoint::Address(address) => address.to_string(),
    };
    let version = snapshot
        .map(|value| value.version.as_str())
        .unwrap_or("unavailable");
    let carriers = snapshot.map_or_else(
        || "unavailable".to_owned(),
        |value| format!("{}/{} live", value.live_carriers, value.configured_carriers),
    );
    let error = snapshot
        .and_then(|value| value.error.as_deref())
        .unwrap_or("none");
    let details = vec![
        Line::from(format!("Service: {service}")),
        Line::from(format!("Tunnel: {tunnel}")),
        Line::from(format!("Server endpoint: {endpoint}")),
        Line::from(format!("SOCKS bind: {socks_listen}")),
        Line::from(format!("Carriers: {carriers}")),
        Line::from(format!("Version: {version}")),
        Line::from(format!("Last error: {error}")),
    ];
    frame.render_widget(
        Paragraph::new(details)
            .block(Block::bordered().title("rqbit tunnel client"))
            .wrap(Wrap { trim: true }),
        content_area,
    );

    let mut footer = vec![Line::from(FOOTER)];
    if let Some(error) = state.displayed_error() {
        footer.push(Line::from(Span::styled(
            format!("error: {error}"),
            Style::default().fg(Color::Red),
        )));
    }
    if let Some(notice) = &state.update_notice {
        footer.push(Line::from(Span::styled(
            notice,
            Style::default().fg(Color::Green),
        )));
    }
    frame.render_widget(
        Paragraph::new(footer)
            .block(Block::bordered().title("Controls"))
            .wrap(Wrap { trim: true }),
        footer_area,
    );

    if let Some(modal) = &state.modal {
        render_modal(frame, modal);
    }
}

fn service_state(state: LocalServiceState) -> &'static str {
    match state {
        LocalServiceState::Running => "running",
        LocalServiceState::Stopped => "stopped",
        LocalServiceState::Failed => "failed",
    }
}

fn local_service_state(state: LocalServiceState) -> ServiceState {
    match state {
        LocalServiceState::Running => ServiceState::Running,
        LocalServiceState::Stopped => ServiceState::Stopped,
        LocalServiceState::Failed => ServiceState::Failed,
    }
}

fn observed_service_state(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Running => "running",
        ServiceState::Stopped => "stopped",
        ServiceState::Starting => "starting",
        ServiceState::Stopping => "stopping",
        ServiceState::Failed => "failed",
        ServiceState::Unknown => "unknown",
    }
}

fn tunnel_state(state: LocalTunnelState) -> &'static str {
    match state {
        LocalTunnelState::Connected => "connected",
        LocalTunnelState::Reconnecting => "reconnecting",
        LocalTunnelState::Error => "error",
    }
}

fn render_modal(frame: &mut ratatui::Frame, modal: &ClientModal) {
    let area = centered_rect(72, 34, frame.area());
    let lines = match modal {
        ClientModal::Import { bundle } => vec![
            Line::from("Import a server-issued enrollment bundle."),
            Line::from(format!("Bundle: {bundle}")),
            Line::from("Enter imports; Esc cancels."),
        ],
        ClientModal::Configure(form) => vec![
            Line::from("Tab selects a field; Space changes LAN acknowledgement; Enter saves."),
            form_line(
                "Server endpoint",
                &form.server_addr,
                form.field == Some(ClientConfigField::ServerAddress),
            ),
            form_line(
                "SOCKS bind",
                &form.socks_listen,
                form.field == Some(ClientConfigField::SocksListen),
            ),
            form_line(
                "Carriers",
                &form.carriers,
                form.field == Some(ClientConfigField::Carriers),
            ),
            form_line(
                "Allow unauthenticated LAN SOCKS",
                if form.allow_unauthenticated_lan_socks {
                    "true"
                } else {
                    "false"
                },
                form.field == Some(ClientConfigField::LanAcknowledgement),
            ),
        ],
        ClientModal::Autostart => vec![
            Line::from("Change managed-service autostart."),
            Line::from("[e]nable [d]isable Esc"),
        ],
        ClientModal::CheckUpdate => vec![
            Line::from("Check GitHub for a signed client update?"),
            Line::from("Enter checks; Esc cancels."),
        ],
        ClientModal::Update { version } => vec![
            Line::from(format!("Install signed release {version}?")),
            Line::from("Enter installs; Esc cancels."),
        ],
    };
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title("Client action"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn form_line(label: &str, value: &str, selected: bool) -> Line<'static> {
    let prefix = if selected { "> " } else { "  " };
    Line::from(format!("{prefix}{label}: {value}"))
}

fn centered_rect(width_percent: u16, height_percent: u16, area: Rect) -> Rect {
    let vertical_margin = (100 - height_percent) / 2;
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(vertical_margin),
            Constraint::Percentage(height_percent),
            Constraint::Percentage(100 - height_percent - vertical_margin),
        ])
        .split(area);
    let horizontal_margin = (100 - width_percent) / 2;
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(horizontal_margin),
            Constraint::Percentage(width_percent),
            Constraint::Percentage(100 - width_percent - horizontal_margin),
        ])
        .split(vertical[1])[1]
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::model::{
        CLIENT_CONFIG_SCHEMA_VERSION, ClientConfig, ClientSnapshot, LocalServiceState,
        LocalTunnelState,
    };

    use super::{ClientTuiState, render_client};

    fn lan_snapshot() -> ClientSnapshot {
        ClientSnapshot {
            service: LocalServiceState::Running,
            tunnel: LocalTunnelState::Connected,
            socks_listen: Some("192.0.2.10:1080".parse().unwrap()),
            configured_carriers: 4,
            live_carriers: 4,
            version: "rqbit-tunnel test".to_owned(),
            error: None,
        }
    }

    fn lan_config() -> ClientConfig {
        ClientConfig {
            schema_version: CLIENT_CONFIG_SCHEMA_VERSION,
            status_owner: None,
            server_addr: Some("203.0.113.8:4242".parse().unwrap()),
            server_public_key: [7; 32],
            client_key_path: PathBuf::from("/etc/rqbit-tunnel/client.key"),
            socks_listen: "192.0.2.10:1080".parse().unwrap(),
            carriers: 4,
            carrier_root: PathBuf::from("/var/lib/rqbit-tunnel/client-carrier"),
            allow_unauthenticated_lan_socks: true,
        }
    }

    fn render_text(state: &ClientTuiState) -> String {
        let backend = ratatui::backend::TestBackend::new(80, 20);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_client(frame, state)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn readable_dht_config_renders_dht_discovery_endpoint() {
        let mut config = lan_config();
        config.server_addr = None;
        config.socks_listen = "127.0.0.1:1080".parse().unwrap();
        config.allow_unauthenticated_lan_socks = false;
        let mut view = ClientTuiState::default();

        view.apply_config_refresh(Some(&config));

        assert!(render_text(&view).contains("Server endpoint: DHT discovery"));
    }

    #[test]
    fn lan_listener_renders_a_persistent_critical_banner() {
        let mut stopped_snapshot = lan_snapshot();
        stopped_snapshot.service = LocalServiceState::Stopped;
        stopped_snapshot.socks_listen = None;
        let mut view = ClientTuiState::from_snapshot(stopped_snapshot);
        view.apply_config(&lan_config());

        assert!(
            view.security_banner()
                .contains("unauthenticated LAN SOCKS proxy")
        );
    }

    #[test]
    fn unreadable_config_clears_dht_discovery_endpoint() {
        let mut config = lan_config();
        config.server_addr = None;
        let mut view = ClientTuiState::default();
        view.apply_config_refresh(Some(&config));

        view.apply_config_refresh(None);

        let rendered = render_text(&view);
        assert!(rendered.contains("Server endpoint: unavailable"));
        assert!(!rendered.contains("Server endpoint: DHT discovery"));
    }

    #[tokio::test]
    async fn shutdown_cancels_a_stalled_refresh() {
        assert!(
            super::await_client_refresh_or_shutdown(std::future::pending::<()>(), async {})
                .await
                .is_none()
        );
    }

    #[test]
    fn update_key_requires_confirmation_before_spawning_an_updater() {
        let mut view = ClientTuiState::default();

        assert_eq!(view.handle_key(crossterm::event::KeyCode::Char('u')), None);
        assert!(matches!(view.modal, Some(super::ClientModal::CheckUpdate)));
        assert_eq!(
            view.handle_key(crossterm::event::KeyCode::Enter),
            Some(super::ClientTuiAction::CheckUpdate)
        );

        view.apply_update_feedback(super::ClientUpdateFeedback::Available {
            version: "1.2.3".to_owned(),
        });

        assert_eq!(
            view.handle_key(crossterm::event::KeyCode::Enter),
            Some(super::ClientTuiAction::InstallUpdate {
                version: "1.2.3".to_owned(),
            })
        );
    }

    #[test]
    fn quit_key_returns_a_dashboard_quit_action() {
        let mut view = ClientTuiState::default();

        assert_eq!(
            view.handle_key(crossterm::event::KeyCode::Char('q')),
            Some(super::ClientTuiAction::Quit)
        );
    }

    #[test]
    fn ctrl_c_quits_before_modal_key_routing() {
        let mut view = ClientTuiState::default();
        assert_eq!(view.handle_key(crossterm::event::KeyCode::Char('i')), None);

        let ctrl_c = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('c'),
            crossterm::event::KeyModifiers::CONTROL,
        );
        assert_eq!(
            super::global_action_for_event(ctrl_c),
            Some(super::ClientTuiAction::Quit)
        );

        assert_eq!(view.handle_key(crossterm::event::KeyCode::Char('q')), None);
        assert!(matches!(
            view.modal,
            Some(super::ClientModal::Import { ref bundle }) if bundle == "q"
        ));
    }

    #[test]
    fn update_failure_remains_displayed_after_snapshot_failure() {
        let mut view = ClientTuiState::default();
        view.apply_update_feedback(super::ClientUpdateFeedback::Failed {
            message: "signed release verification failed".to_owned(),
        });
        view.set_snapshot_error("status socket unavailable");

        assert_eq!(
            view.displayed_error(),
            Some("signed release verification failed")
        );
    }

    #[test]
    fn successful_snapshot_refresh_keeps_an_update_failure_visible() {
        let mut view = ClientTuiState::default();
        view.apply_update_feedback(super::ClientUpdateFeedback::Failed {
            message: "signed release verification failed".to_owned(),
        });

        view.apply_successful_snapshot_refresh(lan_snapshot());

        assert_eq!(
            view.last_error.as_deref(),
            Some("signed release verification failed")
        );
    }
}
