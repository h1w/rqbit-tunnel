use std::{
    collections::{HashMap, HashSet},
    io::{self, IsTerminal},
    path::{Path, PathBuf},
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
    widgets::{Block, Clear, Paragraph, Row, Table, TableState, Wrap},
};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    cli::{ControlError, request_server},
    ipc::protocol::{ServerRequest, ServerResponse},
    model::{ServerSnapshot, UserSnapshot},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Modal {
    ConfirmDelete(Uuid),
    ConfirmReset(Uuid),
    AddUser(AddUserForm),
    ConfirmExport(AddUserForm),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddUserField {
    Name,
    ExportPath,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddUserForm {
    pub name: String,
    pub export_path: String,
    pub field: AddUserField,
}

impl Default for AddUserForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            export_path: String::new(),
            field: AddUserField::Name,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrafficRate {
    pub upload_per_second: u64,
    pub download_per_second: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TuiAction {
    Quit,
    Refresh,
    SetEnabled { id: Uuid, enabled: bool },
    Delete(Uuid),
    ResetTraffic(Uuid),
    AddUser { name: String, export_path: PathBuf },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerTuiState {
    pub snapshot: ServerSnapshot,
    pub users: Vec<UserSnapshot>,
    pub selection: Option<usize>,
    pub modal: Option<Modal>,
    pub last_error: Option<String>,
    pub should_quit: bool,
    rates: HashMap<Uuid, TrafficRate>,
}

impl ServerTuiState {
    pub fn with_users(users: Vec<UserSnapshot>) -> Self {
        Self::with_snapshot(ServerSnapshot { users })
    }

    pub fn with_snapshot(snapshot: ServerSnapshot) -> Self {
        let users = snapshot.users.clone();
        Self {
            snapshot,
            selection: (!users.is_empty()).then_some(0),
            users,
            ..Self::default()
        }
    }

    pub fn apply_snapshot(&mut self, snapshot: ServerSnapshot, rates: HashMap<Uuid, TrafficRate>) {
        let selected_id = self.selected_user().map(|user| user.id);
        self.users = snapshot.users.clone();
        self.snapshot = snapshot;
        self.rates = rates;
        self.selection = selected_id
            .and_then(|id| self.users.iter().position(|user| user.id == id))
            .or_else(|| (!self.users.is_empty()).then_some(0));
    }

    pub fn rate_for(&self, id: Uuid) -> TrafficRate {
        self.rates.get(&id).copied().unwrap_or_default()
    }

    pub fn selected_user(&self) -> Option<&UserSnapshot> {
        self.selection.and_then(|index| self.users.get(index))
    }

    pub fn set_error(&mut self, error: impl Into<String>) {
        self.last_error = Some(error.into());
    }

    pub fn handle_key(&mut self, key: KeyCode) -> Option<TuiAction> {
        if let Some(modal) = self.modal.take() {
            return self.handle_modal_key(modal, key);
        }

        match key {
            KeyCode::Up | KeyCode::Char('k') => {
                self.select_previous();
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.select_next();
                None
            }
            KeyCode::Char('a') | KeyCode::Char('b') => {
                self.modal = Some(Modal::AddUser(AddUserForm::default()));
                None
            }
            KeyCode::Char('e') => self.selected_user().map(|user| TuiAction::SetEnabled {
                id: user.id,
                enabled: true,
            }),
            KeyCode::Char('d') => self.selected_user().map(|user| TuiAction::SetEnabled {
                id: user.id,
                enabled: false,
            }),
            KeyCode::Char('x') => {
                self.modal = self
                    .selected_user()
                    .map(|user| Modal::ConfirmDelete(user.id));
                None
            }
            KeyCode::Char('r') => {
                self.modal = self
                    .selected_user()
                    .map(|user| Modal::ConfirmReset(user.id));
                None
            }
            KeyCode::F(5) => Some(TuiAction::Refresh),
            KeyCode::Char('q') => {
                self.should_quit = true;
                Some(TuiAction::Quit)
            }
            _ => None,
        }
    }

    fn handle_modal_key(&mut self, modal: Modal, key: KeyCode) -> Option<TuiAction> {
        match modal {
            Modal::ConfirmDelete(id) => match key {
                KeyCode::Char('y') | KeyCode::Char('Y') => Some(TuiAction::Delete(id)),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => None,
                _ => {
                    self.modal = Some(Modal::ConfirmDelete(id));
                    None
                }
            },
            Modal::ConfirmReset(id) => match key {
                KeyCode::Char('y') | KeyCode::Char('Y') => Some(TuiAction::ResetTraffic(id)),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => None,
                _ => {
                    self.modal = Some(Modal::ConfirmReset(id));
                    None
                }
            },
            Modal::ConfirmExport(form) => match key {
                KeyCode::Char('y') | KeyCode::Char('Y') => Some(TuiAction::AddUser {
                    name: form.name,
                    export_path: PathBuf::from(form.export_path),
                }),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => None,
                _ => {
                    self.modal = Some(Modal::ConfirmExport(form));
                    None
                }
            },
            Modal::AddUser(mut form) => {
                match key {
                    KeyCode::Esc => return None,
                    KeyCode::Tab => {
                        form.field = match form.field {
                            AddUserField::Name => AddUserField::ExportPath,
                            AddUserField::ExportPath => AddUserField::Name,
                        };
                    }
                    KeyCode::Backspace => match form.field {
                        AddUserField::Name => {
                            form.name.pop();
                        }
                        AddUserField::ExportPath => {
                            form.export_path.pop();
                        }
                    },
                    KeyCode::Char(character) => match form.field {
                        AddUserField::Name => form.name.push(character),
                        AddUserField::ExportPath => form.export_path.push(character),
                    },
                    KeyCode::Enter => {
                        if form.name.trim().is_empty() || form.export_path.trim().is_empty() {
                            self.set_error("a user name and enrollment bundle path are required");
                            self.modal = Some(Modal::AddUser(form));
                            return None;
                        }
                        self.modal = Some(Modal::ConfirmExport(form));
                        return None;
                    }
                    _ => {}
                }
                self.modal = Some(Modal::AddUser(form));
                None
            }
        }
    }

    fn select_previous(&mut self) {
        let Some(selected) = self.selection else {
            return;
        };
        self.selection = Some(selected.saturating_sub(1));
    }

    fn select_next(&mut self) {
        let Some(selected) = self.selection else {
            return;
        };
        self.selection = Some((selected + 1).min(self.users.len().saturating_sub(1)));
    }
}

pub fn derive_rates(
    previous: &ServerSnapshot,
    current: &ServerSnapshot,
    elapsed: Duration,
) -> HashMap<Uuid, TrafficRate> {
    let previous_totals = previous
        .users
        .iter()
        .map(|user| (user.id, user.traffic))
        .collect::<HashMap<_, _>>();

    current
        .users
        .iter()
        .map(|user| {
            let rate = previous_totals
                .get(&user.id)
                .map(|previous| TrafficRate {
                    upload_per_second: bytes_per_second(
                        user.traffic.upload.saturating_sub(previous.upload),
                        elapsed,
                    ),
                    download_per_second: bytes_per_second(
                        user.traffic.download.saturating_sub(previous.download),
                        elapsed,
                    ),
                })
                .unwrap_or_default();
            (user.id, rate)
        })
        .collect()
}

fn apply_pending_reset_rates(
    rates: &mut HashMap<Uuid, TrafficRate>,
    pending_resets: &mut HashSet<Uuid>,
    snapshot: &ServerSnapshot,
) {
    for user in &snapshot.users {
        if pending_resets.remove(&user.id) {
            rates.insert(user.id, TrafficRate::default());
        }
    }
    pending_resets.clear();
}

fn bytes_per_second(bytes: u64, elapsed: Duration) -> u64 {
    let elapsed_nanos = elapsed.as_nanos();
    if elapsed_nanos == 0 {
        return 0;
    }
    let bytes_per_second = u128::from(bytes).saturating_mul(1_000_000_000) / elapsed_nanos;
    u64::try_from(bytes_per_second).unwrap_or(u64::MAX)
}

fn rates_for_snapshot(
    previous: Option<&(ServerSnapshot, Instant)>,
    current: &ServerSnapshot,
    completed_at: Instant,
    pending_resets: &mut HashSet<Uuid>,
) -> HashMap<Uuid, TrafficRate> {
    let mut rates = previous
        .map(|(snapshot, sampled_at)| {
            derive_rates(
                snapshot,
                current,
                completed_at.saturating_duration_since(*sampled_at),
            )
        })
        .unwrap_or_default();
    apply_pending_reset_rates(&mut rates, pending_resets, current);
    rates
}

fn key_code_for_event(key: KeyEvent) -> Option<KeyCode> {
    if key.kind != KeyEventKind::Press {
        return None;
    }
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return Some(KeyCode::Char('q'));
    }
    Some(key.code)
}

const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(1);
const EVENT_TICK: Duration = Duration::from_millis(250);
const FOOTER: &str = "[a]dd [e]nable [d]isable [x] delete [r]eset [b]undle F5 q";

#[derive(Debug, Error)]
pub enum TuiError {
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error("server TUI requires both stdin and stdout to be terminals")]
    NotTerminal,
    #[error("terminal I/O failed: {0}")]
    Terminal(#[from] io::Error),
    #[error("terminal event reader stopped unexpectedly")]
    EventReaderStopped,
    #[error("terminal event reader task failed: {0}")]
    EventReaderTask(#[source] tokio::task::JoinError),
    #[error("server returned an unexpected response: {0:?}")]
    UnexpectedResponse(ServerResponse),
}

fn require_terminal_io(stdin_is_terminal: bool, stdout_is_terminal: bool) -> Result<(), TuiError> {
    if stdin_is_terminal && stdout_is_terminal {
        Ok(())
    } else {
        Err(TuiError::NotTerminal)
    }
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalSession {
    fn enter() -> Result<Self, TuiError> {
        require_terminal_io(io::stdin().is_terminal(), io::stdout().is_terminal())?;
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(TuiError::Terminal(error));
        }

        match Terminal::new(CrosstermBackend::new(stdout)) {
            Ok(terminal) => Ok(Self { terminal }),
            Err(error) => {
                let mut stdout = io::stdout();
                let _ = execute!(stdout, LeaveAlternateScreen);
                let _ = disable_raw_mode();
                Err(TuiError::Terminal(error))
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
    fn register() -> Result<Self, TuiError> {
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
    fn register() -> Result<Self, TuiError> {
        Ok(Self)
    }

    async fn wait(&mut self) {
        std::future::pending::<()>().await;
    }
}

type TerminalEvent = Result<KeyEvent, io::Error>;

const TERMINAL_EVENT_QUEUE_CAPACITY: usize = 1;

struct TerminalEventReader {
    receiver: tokio::sync::mpsc::Receiver<TerminalEvent>,
    task: tokio::task::JoinHandle<()>,
}

fn terminal_event_channel() -> (
    tokio::sync::mpsc::Sender<TerminalEvent>,
    tokio::sync::mpsc::Receiver<TerminalEvent>,
) {
    tokio::sync::mpsc::channel(TERMINAL_EVENT_QUEUE_CAPACITY)
}

fn enqueue_terminal_event(
    sender: &tokio::sync::mpsc::Sender<TerminalEvent>,
    event: TerminalEvent,
) -> bool {
    match sender.try_send(event) {
        Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => true,
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
    }
}

impl TerminalEventReader {
    fn spawn() -> Self {
        let (sender, receiver) = terminal_event_channel();
        let task = tokio::task::spawn_blocking(move || {
            loop {
                if sender.is_closed() {
                    break;
                }
                match event::poll(EVENT_TICK) {
                    Ok(true) => match event::read() {
                        Ok(Event::Key(key)) => {
                            if !enqueue_terminal_event(&sender, Ok(key)) {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            let _ = enqueue_terminal_event(&sender, Err(error));
                            break;
                        }
                    },
                    Ok(false) => {}
                    Err(error) => {
                        let _ = enqueue_terminal_event(&sender, Err(error));
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

    async fn shutdown(mut self) -> Result<(), TuiError> {
        self.receiver.close();
        self.task.await.map_err(TuiError::EventReaderTask)
    }
}

pub async fn run_server_tui(socket: PathBuf) -> Result<(), TuiError> {
    let mut signals = TuiShutdownSignals::register()?;
    let mut terminal = TerminalSession::enter()?;
    let mut events = TerminalEventReader::spawn();
    let result = run_server_tui_loop(&socket, &mut terminal, &mut signals, &mut events).await;
    let reader_shutdown = events.shutdown().await;
    result?;
    reader_shutdown
}

async fn run_server_tui_loop(
    socket: &Path,
    terminal: &mut TerminalSession,
    signals: &mut TuiShutdownSignals,
    events: &mut TerminalEventReader,
) -> Result<(), TuiError> {
    let mut state = ServerTuiState::default();
    let mut previous_snapshot = None;
    let mut pending_reset_users = HashSet::new();
    let mut refresh_due = true;
    let mut next_snapshot = Instant::now();

    loop {
        if refresh_due || Instant::now() >= next_snapshot {
            match tokio::select! {
                snapshot = fetch_server_snapshot(socket) => Some(snapshot),
                _ = signals.wait() => None,
            } {
                Some(Ok(snapshot)) => {
                    let sampled_at = Instant::now();
                    let rates = rates_for_snapshot(
                        previous_snapshot.as_ref(),
                        &snapshot,
                        sampled_at,
                        &mut pending_reset_users,
                    );
                    state.apply_snapshot(snapshot.clone(), rates);
                    state.last_error = None;
                    previous_snapshot = Some((snapshot, sampled_at));
                }
                Some(Err(error)) => state.set_error(error.to_string()),
                None => break,
            }
            refresh_due = false;
            next_snapshot = Instant::now() + SNAPSHOT_INTERVAL;
        }

        terminal
            .terminal
            .draw(|frame| render_server(frame, &state))?;

        let wait = next_snapshot
            .saturating_duration_since(Instant::now())
            .min(EVENT_TICK);
        tokio::select! {
            _ = signals.wait() => break,
            event = events.recv() => match event {
                Some(Ok(key)) => {
                    if let Some(action) = key_code_for_event(key).and_then(|key| state.handle_key(key)) {
                        let reset_user = match &action {
                            TuiAction::ResetTraffic(id) => Some(*id),
                            _ => None,
                        };
                        match tokio::select! {
                            action_result = execute_tui_action(socket, action) => Some(action_result),
                            _ = signals.wait() => None,
                        } {
                            Some(Ok(TuiLoop::Quit)) => break,
                            Some(Ok(TuiLoop::Continue)) => {
                                if let Some(id) = reset_user {
                                    pending_reset_users.insert(id);
                                }
                                refresh_due = true;
                            }
                            Some(Err(error)) => state.set_error(error.to_string()),
                            None => break,
                        }
                    }
                }
                Some(Err(error)) => return Err(TuiError::Terminal(error)),
                None => return Err(TuiError::EventReaderStopped),
            },
            _ = tokio::time::sleep(wait) => {}
        }

        if state.should_quit {
            break;
        }
    }

    Ok(())
}

enum TuiLoop {
    Continue,
    Quit,
}

async fn fetch_server_snapshot(socket: &Path) -> Result<ServerSnapshot, TuiError> {
    let response = request_server(socket, ServerRequest::SnapshotPage).await?;
    let ServerResponse::SnapshotPage(first_page) = response else {
        return Err(TuiError::UnexpectedResponse(response));
    };

    let mut users = first_page.users;
    let mut after = first_page.next_page;
    while let Some(cursor) = after {
        let response = request_server(
            socket,
            ServerRequest::ListUserPage {
                after: Some(cursor),
                limit: None,
            },
        )
        .await?;
        let ServerResponse::UserPage(page) = response else {
            return Err(TuiError::UnexpectedResponse(response));
        };
        users.extend(page.users);
        after = page.next_page;
    }

    Ok(ServerSnapshot { users })
}

async fn execute_tui_action(socket: &Path, action: TuiAction) -> Result<TuiLoop, TuiError> {
    match action {
        TuiAction::Quit => Ok(TuiLoop::Quit),
        TuiAction::Refresh => Ok(TuiLoop::Continue),
        TuiAction::SetEnabled { id, enabled } => {
            let response =
                request_server(socket, ServerRequest::SetEnabled { id, enabled }).await?;
            if !matches!(response, ServerResponse::User(_)) {
                return Err(TuiError::UnexpectedResponse(response));
            }
            Ok(TuiLoop::Continue)
        }
        TuiAction::Delete(id) => {
            let response = request_server(socket, ServerRequest::DeleteUser { id }).await?;
            if !matches!(response, ServerResponse::Deleted { .. }) {
                return Err(TuiError::UnexpectedResponse(response));
            }
            Ok(TuiLoop::Continue)
        }
        TuiAction::ResetTraffic(id) => {
            let response = request_server(socket, ServerRequest::ResetTraffic { id }).await?;
            if !matches!(response, ServerResponse::User(_)) {
                return Err(TuiError::UnexpectedResponse(response));
            }
            Ok(TuiLoop::Continue)
        }
        TuiAction::AddUser { name, export_path } => {
            let response =
                request_server(socket, ServerRequest::AddUser { name, export_path }).await?;
            if !matches!(response, ServerResponse::User(_)) {
                return Err(TuiError::UnexpectedResponse(response));
            }
            Ok(TuiLoop::Continue)
        }
    }
}

fn footer_height(state: &ServerTuiState) -> u16 {
    if state.last_error.is_some() { 4 } else { 3 }
}

fn render_server(frame: &mut ratatui::Frame, state: &ServerTuiState) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(footer_height(state))])
        .split(frame.area());
    let header = Row::new([
        "Name",
        "State",
        "Upload total / rate",
        "Download total / rate",
        "Last seen",
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );
    let rows = state.users.iter().map(|user| {
        let rate = state.rate_for(user.id);
        Row::new([
            user.name.clone(),
            user_state(user),
            format!(
                "{} / {}/s",
                format_bytes(user.traffic.upload),
                format_bytes(rate.upload_per_second)
            ),
            format!(
                "{} / {}/s",
                format_bytes(user.traffic.download),
                format_bytes(rate.download_per_second)
            ),
            user.last_seen
                .map_or_else(|| "-".to_owned(), |seen| seen.to_string()),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(22),
            Constraint::Percentage(18),
            Constraint::Percentage(22),
            Constraint::Percentage(22),
            Constraint::Percentage(16),
        ],
    )
    .header(header)
    .block(Block::bordered().title("rqbit tunnel server"))
    .row_highlight_style(Style::default().bg(Color::DarkGray))
    .highlight_symbol("> ");
    let mut table_state = TableState::default();
    table_state.select(state.selection);
    frame.render_stateful_widget(table, areas[0], &mut table_state);

    let footer = match &state.last_error {
        Some(error) => vec![
            Line::from(FOOTER),
            Line::from(Span::styled(
                format!("error: {error}"),
                Style::default().fg(Color::Red),
            )),
        ],
        None => vec![Line::from(FOOTER)],
    };
    frame.render_widget(
        Paragraph::new(footer)
            .block(Block::bordered().title("Controls"))
            .wrap(Wrap { trim: true }),
        areas[1],
    );

    if let Some(modal) = &state.modal {
        render_modal(frame, modal);
    }
}

fn render_modal(frame: &mut ratatui::Frame, modal: &Modal) {
    let area = centered_rect(70, 30, frame.area());
    let lines = match modal {
        Modal::ConfirmDelete(id) => vec![
            Line::from(format!("Delete user {id}?")),
            Line::from("[y]es / [n]o"),
        ],
        Modal::ConfirmReset(id) => vec![
            Line::from(format!("Reset traffic for user {id}?")),
            Line::from("[y]es / [n]o"),
        ],
        Modal::AddUser(form) => vec![
            Line::from("Add user and create an enrollment bundle"),
            Line::from(format!("Name: {}", form.name)),
            Line::from(format!("Export file: {}", form.export_path)),
            Line::from("A bare filename is stored in /var/lib/rqbit-tunnel/enrollments."),
            Line::from("Tab changes field; Enter reviews the unencrypted export; Esc cancels."),
        ],
        Modal::ConfirmExport(form) => vec![
            Line::from("WARNING: the enrollment bundle contains an unencrypted client secret."),
            Line::from(format!("Write {} for {}?", form.export_path, form.name)),
            Line::from("[y]es / [n]o"),
        ],
    };
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title("Confirm"))
            .wrap(Wrap { trim: true }),
        area,
    );
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

fn user_state(user: &UserSnapshot) -> String {
    match (user.enabled, user.connected) {
        (false, _) => "disabled".to_owned(),
        (true, 0) => "enabled / disconnected".to_owned(),
        (true, connected) => format!("enabled / {connected} connected"),
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes;
    let mut unit = 0;
    while value >= 1024 && unit + 1 < UNITS.len() {
        value /= 1024;
        unit += 1;
    }
    format!("{value} {}", UNITS[unit])
}
#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::{
        collections::HashSet,
        time::{Duration, Instant},
    };

    use crate::model::{ServerSnapshot, TrafficTotals, UserSnapshot};

    use super::{
        Modal, ServerTuiState, TrafficRate, TuiAction, TuiError, apply_pending_reset_rates,
        derive_rates, enqueue_terminal_event, footer_height, key_code_for_event,
        rates_for_snapshot, require_terminal_io, terminal_event_channel,
    };

    #[cfg(unix)]
    use super::TuiShutdownSignals;

    fn sample_user() -> UserSnapshot {
        UserSnapshot {
            id: uuid::Uuid::nil(),
            name: "alice".to_owned(),
            name_truncated_bytes: None,
            enabled: true,
            connected: 1,
            traffic: TrafficTotals {
                upload: 12,
                download: 34,
            },
            last_seen: Some(1_700_000_000),
        }
    }

    fn user(id: uuid::Uuid, upload: u64, download: u64) -> UserSnapshot {
        UserSnapshot {
            id,
            name: id.to_string(),
            name_truncated_bytes: None,
            enabled: true,
            connected: 0,
            traffic: TrafficTotals { upload, download },
            last_seen: None,
        }
    }

    #[test]
    fn delete_key_opens_confirmation_before_mutating() {
        let mut state = ServerTuiState::with_users(vec![sample_user()]);
        state.handle_key(KeyCode::Char('x'));
        assert!(matches!(state.modal, Some(Modal::ConfirmDelete(_))));
    }

    #[test]
    fn delete_confirmation_emits_action_only_after_acceptance() {
        let user = sample_user();
        let mut state = ServerTuiState::with_users(vec![user.clone()]);

        assert_eq!(state.handle_key(KeyCode::Char('x')), None);
        assert_eq!(state.users.len(), 1);
        assert_eq!(
            state.handle_key(KeyCode::Char('y')),
            Some(TuiAction::Delete(user.id))
        );
        assert_eq!(state.users.len(), 1);
    }

    #[test]
    fn footer_reserves_an_interior_error_row() {
        let mut state = ServerTuiState::default();
        assert_eq!(footer_height(&state), 3);

        state.set_error("control socket unavailable");

        assert_eq!(footer_height(&state), 4);
    }

    #[test]
    fn terminal_setup_requires_stdin_and_stdout_terminals() {
        assert!(matches!(
            require_terminal_io(false, true),
            Err(TuiError::NotTerminal)
        ));
        assert!(matches!(
            require_terminal_io(true, false),
            Err(TuiError::NotTerminal)
        ));
        assert!(require_terminal_io(true, true).is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tui_shutdown_signals_register() {
        let _signals = TuiShutdownSignals::register().unwrap();
    }

    #[tokio::test]
    async fn terminal_event_queue_bounds_and_drops_congested_input() {
        let (sender, mut receiver) = terminal_event_channel();
        let first = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
        let second = KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE);

        assert!(enqueue_terminal_event(&sender, Ok(first)));
        assert!(enqueue_terminal_event(&sender, Ok(second)));
        assert_eq!(receiver.recv().await.unwrap().unwrap(), first);
        assert!(receiver.try_recv().is_err());

        receiver.close();
        assert!(!enqueue_terminal_event(&sender, Ok(second)));
    }

    #[test]
    fn ctrl_c_key_requests_tui_quit() {
        assert_eq!(
            key_code_for_event(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Some(KeyCode::Char('q'))
        );
    }

    #[test]
    fn rates_use_completed_snapshot_time_not_request_start_time() {
        let id = uuid::Uuid::from_u128(11);
        let requested_at = Instant::now();
        let completed_at = requested_at + Duration::from_secs(2);
        let previous = (
            ServerSnapshot {
                users: vec![user(id, 0, 0)],
            },
            requested_at,
        );
        let current = ServerSnapshot {
            users: vec![user(id, 100, 100)],
        };
        let mut pending_resets = HashSet::new();

        let rates =
            rates_for_snapshot(Some(&previous), &current, completed_at, &mut pending_resets);

        assert_eq!(
            rates.get(&id),
            Some(&TrafficRate {
                upload_per_second: 50,
                download_per_second: 50,
            })
        );
    }

    #[test]
    fn rates_are_per_user_saturating_deltas_over_elapsed_time() {
        let tracked = uuid::Uuid::from_u128(1);
        let reset = uuid::Uuid::from_u128(2);
        let new = uuid::Uuid::from_u128(3);
        let previous = ServerSnapshot {
            users: vec![user(tracked, 100, 200), user(reset, 100, 200)],
        };
        let current = ServerSnapshot {
            users: vec![
                user(tracked, 160, 300),
                user(reset, 10, 20),
                user(new, 999, 999),
            ],
        };

        let rates = derive_rates(&previous, &current, Duration::from_secs(2));

        assert_eq!(
            rates.get(&tracked),
            Some(&TrafficRate {
                upload_per_second: 30,
                download_per_second: 50,
            })
        );
        assert_eq!(rates.get(&reset), Some(&TrafficRate::default()));
        assert_eq!(rates.get(&new), Some(&TrafficRate::default()));
    }

    #[test]
    fn pending_reset_zeroes_the_first_successful_snapshot_rate() {
        let id = uuid::Uuid::from_u128(9);
        let previous = ServerSnapshot {
            users: vec![user(id, 100, 100)],
        };
        let current = ServerSnapshot {
            users: vec![user(id, 150, 150)],
        };
        let mut rates = derive_rates(&previous, &current, Duration::from_secs(1));
        let mut pending_resets = HashSet::from([id]);

        apply_pending_reset_rates(&mut rates, &mut pending_resets, &current);

        assert_eq!(rates.get(&id), Some(&TrafficRate::default()));
        assert!(pending_resets.is_empty());
    }
}
