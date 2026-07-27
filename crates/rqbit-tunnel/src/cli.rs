use std::{
    ffi::{OsStr, OsString},
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};

use clap::{Arg, ArgAction, ArgMatches, Command as ClapCommand, error::ErrorKind};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

#[cfg(unix)]
use crate::ipc::unix::{UnixControlClient, UnixControlError};
use crate::{
    ipc::protocol::{ServerRequest, ServerResponse},
    model::{ServerConfig, UserSnapshot},
    paths::ServerPaths,
    runtime::server::{ManagedServer, ServerRuntimeError},
    tui::server::{TuiError, run_server_tui},
};

#[derive(Debug)]
pub struct Cli {
    pub command: Command,
}

#[derive(Debug)]
pub enum Command {
    Server(ServerCommand),
}

#[derive(Debug)]
pub enum ServerCommand {
    Run(ServerRunOptions),
    Tui(ServerTuiOptions),
    Users {
        socket: Option<PathBuf>,
        command: ServerUsersCommand,
    },
    Settings {
        socket: Option<PathBuf>,
        command: ServerSettingsCommand,
    },
}

#[derive(Debug)]
pub struct ServerRunOptions {
    pub config: PathBuf,
}

#[derive(Debug)]
pub struct ServerTuiOptions {
    pub socket: Option<PathBuf>,
}

#[derive(Debug)]
pub enum ServerUsersCommand {
    List {
        json: bool,
    },
    Add {
        name: String,
        export: PathBuf,
        yes: bool,
        json: bool,
    },
    Enable {
        id: Uuid,
        json: bool,
    },
    Disable {
        id: Uuid,
        json: bool,
    },
    Delete {
        id: Uuid,
        yes: bool,
        json: bool,
    },
    Reset {
        id: Uuid,
        yes: bool,
        json: bool,
    },
}

#[derive(Debug)]
pub enum ServerSettingsCommand {
    Show { json: bool },
    Set { config: PathBuf, json: bool },
}

impl Cli {
    pub fn try_parse_from<I, T>(arguments: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let matches = cli_command().try_get_matches_from(arguments)?;
        Self::from_matches(&matches)
    }

    fn from_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
        let Some(("server", server_matches)) = matches.subcommand() else {
            return Err(clap::Error::raw(
                ErrorKind::MissingSubcommand,
                "a server subcommand is required",
            ));
        };

        let command = match server_matches.subcommand() {
            Some(("run", run_matches)) => ServerCommand::Run(ServerRunOptions {
                config: required_path(run_matches, "config"),
            }),
            Some(("tui", tui_matches)) => ServerCommand::Tui(ServerTuiOptions {
                socket: optional_path(tui_matches, "socket"),
            }),
            Some(("users", users_matches)) => ServerCommand::Users {
                socket: optional_path(users_matches, "socket"),
                command: parse_users_command(users_matches)?,
            },
            Some(("settings", settings_matches)) => ServerCommand::Settings {
                socket: optional_path(settings_matches, "socket"),
                command: parse_settings_command(settings_matches)?,
            },
            _ => {
                return Err(clap::Error::raw(
                    ErrorKind::MissingSubcommand,
                    "a server subcommand is required",
                ));
            }
        };

        Ok(Self {
            command: Command::Server(command),
        })
    }
}

fn parse_users_command(matches: &ArgMatches) -> Result<ServerUsersCommand, clap::Error> {
    let command = match matches.subcommand() {
        Some(("list", command_matches)) => ServerUsersCommand::List {
            json: command_matches.get_flag("json"),
        },
        Some(("add", command_matches)) => ServerUsersCommand::Add {
            name: required_string(command_matches, "name").to_owned(),
            export: required_path(command_matches, "export"),
            yes: command_matches.get_flag("yes"),
            json: command_matches.get_flag("json"),
        },
        Some(("enable", command_matches)) => ServerUsersCommand::Enable {
            id: required_uuid(command_matches)?,
            json: command_matches.get_flag("json"),
        },
        Some(("disable", command_matches)) => ServerUsersCommand::Disable {
            id: required_uuid(command_matches)?,
            json: command_matches.get_flag("json"),
        },
        Some(("delete", command_matches)) => ServerUsersCommand::Delete {
            id: required_uuid(command_matches)?,
            yes: command_matches.get_flag("yes"),
            json: command_matches.get_flag("json"),
        },
        Some(("reset", command_matches)) => ServerUsersCommand::Reset {
            id: required_uuid(command_matches)?,
            yes: command_matches.get_flag("yes"),
            json: command_matches.get_flag("json"),
        },
        _ => {
            return Err(clap::Error::raw(
                ErrorKind::MissingSubcommand,
                "a server users subcommand is required",
            ));
        }
    };

    Ok(command)
}

fn parse_settings_command(matches: &ArgMatches) -> Result<ServerSettingsCommand, clap::Error> {
    let command = match matches.subcommand() {
        Some(("show", command_matches)) => ServerSettingsCommand::Show {
            json: command_matches.get_flag("json"),
        },
        Some(("set", command_matches)) => ServerSettingsCommand::Set {
            config: required_path(command_matches, "config"),
            json: command_matches.get_flag("json"),
        },
        _ => {
            return Err(clap::Error::raw(
                ErrorKind::MissingSubcommand,
                "a server settings subcommand is required",
            ));
        }
    };

    Ok(command)
}

fn required_string<'a>(matches: &'a ArgMatches, name: &str) -> &'a str {
    matches
        .get_one::<String>(name)
        .expect("clap enforces required arguments")
}

fn required_path(matches: &ArgMatches, name: &str) -> PathBuf {
    PathBuf::from(required_string(matches, name))
}

fn optional_path(matches: &ArgMatches, name: &str) -> Option<PathBuf> {
    matches.get_one::<String>(name).map(PathBuf::from)
}

fn required_uuid(matches: &ArgMatches) -> Result<Uuid, clap::Error> {
    let value = required_string(matches, "id");
    Uuid::parse_str(value).map_err(|error| {
        clap::Error::raw(
            ErrorKind::InvalidValue,
            format!("invalid user ID {value:?}: {error}"),
        )
    })
}

fn cli_command() -> ClapCommand {
    ClapCommand::new("rqbit-tunnel")
        .about("Manage rqbit tunnel services")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(server_command())
}

fn server_command() -> ClapCommand {
    ClapCommand::new("server")
        .about("Manage the rqbit tunnel server")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            ClapCommand::new("run").about("Run the managed server").arg(
                Arg::new("config")
                    .long("config")
                    .value_name("PATH")
                    .default_value("/etc/rqbit-tunnel/server.json")
                    .action(ArgAction::Set),
            ),
        )
        .subcommand(
            ClapCommand::new("tui")
                .about("Open the server dashboard")
                .arg(socket_argument()),
        )
        .subcommand(
            ClapCommand::new("users")
                .about("Manage server users")
                .arg(socket_argument())
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    ClapCommand::new("list")
                        .about("List users")
                        .arg(json_argument()),
                )
                .subcommand(
                    ClapCommand::new("add")
                        .about("Add a user and write an enrollment bundle")
                        .arg(required_argument("name", "NAME"))
                        .arg(required_argument("export", "PATH"))
                        .arg(yes_argument())
                        .arg(json_argument()),
                )
                .subcommand(user_state_command("enable", "Enable a user"))
                .subcommand(user_state_command("disable", "Disable a user"))
                .subcommand(
                    ClapCommand::new("delete")
                        .about("Delete a user")
                        .arg(user_id_argument())
                        .arg(yes_argument())
                        .arg(json_argument()),
                )
                .subcommand(
                    ClapCommand::new("reset")
                        .about("Reset a user's traffic totals")
                        .arg(user_id_argument())
                        .arg(yes_argument())
                        .arg(json_argument()),
                ),
        )
        .subcommand(
            ClapCommand::new("settings")
                .about("Show or replace server settings")
                .arg(socket_argument())
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    ClapCommand::new("show")
                        .about("Show server settings")
                        .arg(json_argument()),
                )
                .subcommand(
                    ClapCommand::new("set")
                        .about("Replace server settings from a JSON file")
                        .arg(required_argument("config", "PATH"))
                        .arg(json_argument()),
                ),
        )
}

fn socket_argument() -> Arg {
    Arg::new("socket")
        .long("socket")
        .value_name("PATH")
        .global(true)
        .action(ArgAction::Set)
        .help("Path to the managed server control socket")
}

fn json_argument() -> Arg {
    Arg::new("json")
        .long("json")
        .action(ArgAction::SetTrue)
        .help("Write only JSON to stdout")
}

fn yes_argument() -> Arg {
    Arg::new("yes")
        .long("yes")
        .action(ArgAction::SetTrue)
        .help("Skip the interactive confirmation")
}

fn required_argument(name: &'static str, value_name: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .value_name(value_name)
        .required(true)
        .action(ArgAction::Set)
}

fn user_state_command(name: &'static str, about: &'static str) -> ClapCommand {
    ClapCommand::new(name)
        .about(about)
        .arg(user_id_argument())
        .arg(json_argument())
}

fn user_id_argument() -> Arg {
    Arg::new("id")
        .value_name("USER_ID")
        .required(true)
        .action(ArgAction::Set)
}

pub(crate) fn render_json(response: &ServerResponse) -> String {
    #[derive(Serialize)]
    struct DeletedUser {
        id: Uuid,
    }

    match response {
        ServerResponse::Snapshot(snapshot) => serde_json::to_string(snapshot),
        ServerResponse::SnapshotPage(page) => serde_json::to_string(page),
        ServerResponse::Users(users) => serde_json::to_string(users),
        ServerResponse::UserPage(page) => serde_json::to_string(page),
        ServerResponse::User(user) => serde_json::to_string(user),
        ServerResponse::Deleted { id } => serde_json::to_string(&DeletedUser { id: *id }),
        ServerResponse::Config(config) => serde_json::to_string(config),
        ServerResponse::Shutdown => serde_json::to_string(&()),
        ServerResponse::Error(error) => serde_json::to_string(error),
    }
    .expect("server control DTOs must be serializable")
}

#[derive(Debug, Error)]
pub enum ControlError {
    #[cfg(unix)]
    #[error(transparent)]
    Unix(#[from] UnixControlError),
    #[cfg(not(unix))]
    #[error("managed server control is only available on Unix")]
    UnsupportedPlatform,
    #[error("server rejected the request ({code}): {message}\nrecovery: {recovery}")]
    Server {
        code: String,
        message: String,
        recovery: String,
    },
}

pub(crate) async fn request_server(
    socket: &Path,
    request: ServerRequest,
) -> Result<ServerResponse, ControlError> {
    #[cfg(unix)]
    {
        let mut client = UnixControlClient::connect(socket).await?;
        match client.request(request).await? {
            ServerResponse::Error(error) => Err(ControlError::Server {
                code: error.code,
                message: error.message,
                recovery: error.recovery,
            }),
            response => Ok(response),
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (socket, request);
        Err(ControlError::UnsupportedPlatform)
    }
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error(transparent)]
    Runtime(#[from] ServerRuntimeError),
    #[error(transparent)]
    Tui(#[from] TuiError),
    #[error("server configuration path must be named server.json: {path}")]
    UnsupportedConfigPath { path: PathBuf },
    #[error("failed to read server settings from {path}: {source}")]
    ReadSettings {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("server settings in {path} are not valid JSON: {source}")]
    DecodeSettings {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize a server control DTO: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("failed to write command output: {0}")]
    Output(#[source] io::Error),
    #[error("failed to read interactive confirmation: {0}")]
    ConfirmationInput(#[source] io::Error),
    #[error("an interactive terminal confirmation is required; retry with --yes to proceed")]
    ConfirmationRequired,
    #[error("operation cancelled")]
    ConfirmationDeclined,
    #[error("failed to wait for a shutdown signal: {0}")]
    Signal(#[source] io::Error),
    #[error("server returned an unexpected response while expecting {expected}: {received:?}")]
    UnexpectedResponse {
        expected: &'static str,
        received: ServerResponse,
    },
}

pub async fn execute(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Server(command) => execute_server(command).await,
    }
}

async fn execute_server(command: ServerCommand) -> Result<(), CliError> {
    match command {
        ServerCommand::Run(options) => run_server(options).await,
        ServerCommand::Tui(options) => {
            run_server_tui(control_socket_path(options.socket)).await?;
            Ok(())
        }
        ServerCommand::Users { socket, command } => {
            execute_users(control_socket_path(socket), command).await
        }
        ServerCommand::Settings { socket, command } => {
            execute_settings(control_socket_path(socket), command).await
        }
    }
}

async fn run_server(options: ServerRunOptions) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        let mut signals = RegisteredShutdownSignals::register()?;
        let server = ManagedServer::start(server_paths_from_config(&options.config)?).await?;
        signals.wait().await;
        server.shutdown().await?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = options;
        Err(ControlError::UnsupportedPlatform.into())
    }
}

#[cfg(unix)]
struct RegisteredShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl RegisteredShutdownSignals {
    fn register() -> Result<Self, CliError> {
        use tokio::signal::unix::{SignalKind, signal};

        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).map_err(CliError::Signal)?,
            terminate: signal(SignalKind::terminate()).map_err(CliError::Signal)?,
        })
    }

    async fn wait(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
    }
}

fn server_paths_from_config(config: &Path) -> Result<ServerPaths, CliError> {
    if config.file_name() != Some(OsStr::new("server.json")) {
        return Err(CliError::UnsupportedConfigPath {
            path: config.to_path_buf(),
        });
    }
    let Some(config_dir) = config.parent() else {
        return Err(CliError::UnsupportedConfigPath {
            path: config.to_path_buf(),
        });
    };
    let mut paths = ServerPaths::system();
    paths.config_dir = config_dir.to_path_buf();
    Ok(paths)
}

fn control_socket_path(socket: Option<PathBuf>) -> PathBuf {
    socket.unwrap_or_else(|| ServerPaths::system().control_socket_path())
}

async fn execute_users(socket: PathBuf, command: ServerUsersCommand) -> Result<(), CliError> {
    match command {
        ServerUsersCommand::List { json } => {
            let users = list_users(&socket).await?;
            if json {
                emit_response_json(&ServerResponse::Users(users))
            } else {
                emit_users(&users)
            }
        }
        ServerUsersCommand::Add {
            name,
            export,
            yes,
            json,
        } => {
            confirm_mutation(
                yes,
                &format!(
                    "Write an unencrypted enrollment bundle to {}?",
                    export.display()
                ),
            )?;
            let response = match request_server(
                &socket,
                ServerRequest::AddUser {
                    name,
                    export_path: export.clone(),
                },
            )
            .await
            {
                Ok(response) => response,
                Err(error) => {
                    if is_bundle_durability_uncertain(&error) {
                        emit_bundle_export_diagnostics(&export, true);
                    }
                    return Err(error.into());
                }
            };
            let user = expect_user(response)?;
            emit_bundle_export_diagnostics(&export, false);
            emit_user(&user, json)
        }
        ServerUsersCommand::Enable { id, json } => {
            let user = expect_user(
                request_server(&socket, ServerRequest::SetEnabled { id, enabled: true }).await?,
            )?;
            emit_user(&user, json)
        }
        ServerUsersCommand::Disable { id, json } => {
            let user = expect_user(
                request_server(&socket, ServerRequest::SetEnabled { id, enabled: false }).await?,
            )?;
            emit_user(&user, json)
        }
        ServerUsersCommand::Delete { id, yes, json } => {
            confirm_mutation(yes, &format!("Delete user {id}?"))?;
            let deleted =
                expect_deleted(request_server(&socket, ServerRequest::DeleteUser { id }).await?)?;
            if json {
                emit_response_json(&ServerResponse::Deleted { id: deleted })
            } else {
                write_stdout_line(&format!("deleted user {deleted}"))
            }
        }
        ServerUsersCommand::Reset { id, yes, json } => {
            confirm_mutation(yes, &format!("Reset traffic totals for user {id}?"))?;
            let user =
                expect_user(request_server(&socket, ServerRequest::ResetTraffic { id }).await?)?;
            emit_user(&user, json)
        }
    }
}

async fn execute_settings(socket: PathBuf, command: ServerSettingsCommand) -> Result<(), CliError> {
    match command {
        ServerSettingsCommand::Show { json } => {
            let settings = expect_config(request_server(&socket, ServerRequest::GetConfig).await?)?;
            emit_settings(&settings, json)
        }
        ServerSettingsCommand::Set { config, json } => {
            let contents = std::fs::read(&config).map_err(|source| CliError::ReadSettings {
                path: config.clone(),
                source,
            })?;
            let settings = serde_json::from_slice::<ServerConfig>(&contents).map_err(|source| {
                CliError::DecodeSettings {
                    path: config.clone(),
                    source,
                }
            })?;
            let updated = expect_config(
                request_server(&socket, ServerRequest::SetConfig { config: settings }).await?,
            )?;
            emit_settings(&updated, json)
        }
    }
}

async fn list_users(socket: &Path) -> Result<Vec<UserSnapshot>, CliError> {
    let mut users = Vec::new();
    let mut after = None;
    loop {
        let response =
            request_server(socket, ServerRequest::ListUserPage { after, limit: None }).await?;
        let ServerResponse::UserPage(page) = response else {
            return Err(CliError::UnexpectedResponse {
                expected: "a user page",
                received: response,
            });
        };
        after = page.next_page;
        users.extend(page.users);
        if after.is_none() {
            return Ok(users);
        }
    }
}

fn expect_user(response: ServerResponse) -> Result<UserSnapshot, CliError> {
    let ServerResponse::User(user) = response else {
        return Err(CliError::UnexpectedResponse {
            expected: "a user",
            received: response,
        });
    };
    Ok(user)
}

fn expect_deleted(response: ServerResponse) -> Result<Uuid, CliError> {
    let ServerResponse::Deleted { id } = response else {
        return Err(CliError::UnexpectedResponse {
            expected: "a deleted user confirmation",
            received: response,
        });
    };
    Ok(id)
}

fn expect_config(
    response: ServerResponse,
) -> Result<crate::ipc::protocol::ServerConfigResponse, CliError> {
    let ServerResponse::Config(config) = response else {
        return Err(CliError::UnexpectedResponse {
            expected: "server settings",
            received: response,
        });
    };
    Ok(config)
}

fn confirm_mutation(yes: bool, prompt: &str) -> Result<(), CliError> {
    if yes {
        return Ok(());
    }
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(CliError::ConfirmationRequired);
    }

    {
        let mut stderr = io::stderr().lock();
        write!(stderr, "{prompt} [y/N]: ").map_err(CliError::ConfirmationInput)?;
        stderr.flush().map_err(CliError::ConfirmationInput)?;
    }
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(CliError::ConfirmationInput)?;
    if matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "Yes") {
        Ok(())
    } else {
        Err(CliError::ConfirmationDeclined)
    }
}

fn is_bundle_durability_uncertain(error: &ControlError) -> bool {
    matches!(
        error,
        ControlError::Server { code, .. } if code == "bundle_durability_uncertain"
    )
}

fn bundle_export_diagnostics(export: &Path, durability_uncertain: bool) -> [String; 2] {
    let destination = if durability_uncertain {
        format!(
            "Enrollment bundle destination may contain the bundle: {}",
            export.display()
        )
    } else {
        format!("Enrollment bundle written to {}", export.display())
    };
    let warning = if durability_uncertain {
        "WARNING: this bundle contains an unencrypted client secret; its durability is uncertain, so inspect the destination before retrying.".to_owned()
    } else {
        "WARNING: this bundle contains an unencrypted client secret; protect it until import."
            .to_owned()
    };
    [destination, warning]
}

fn emit_bundle_export_diagnostics(export: &Path, durability_uncertain: bool) {
    for diagnostic in bundle_export_diagnostics(export, durability_uncertain) {
        eprintln!("{diagnostic}");
    }
}

fn emit_response_json(response: &ServerResponse) -> Result<(), CliError> {
    write_stdout_line(&render_json(response))
}

fn emit_user(user: &UserSnapshot, json: bool) -> Result<(), CliError> {
    if json {
        emit_json(user)
    } else {
        write_stdout_line(&format_user(user))
    }
}

fn emit_users(users: &[UserSnapshot]) -> Result<(), CliError> {
    let mut output = io::stdout().lock();
    for user in users {
        writeln!(output, "{}", format_user(user)).map_err(CliError::Output)?;
    }
    output.flush().map_err(CliError::Output)
}

fn emit_settings(
    settings: &crate::ipc::protocol::ServerConfigResponse,
    json: bool,
) -> Result<(), CliError> {
    if json {
        emit_json(settings)
    } else {
        let text = serde_json::to_string_pretty(settings)?;
        write_stdout_line(&text)
    }
}

fn emit_json<T: Serialize>(dto: &T) -> Result<(), CliError> {
    write_stdout_line(&serde_json::to_string(dto)?)
}

fn write_stdout_line(line: &str) -> Result<(), CliError> {
    let mut output = io::stdout().lock();
    writeln!(output, "{line}").map_err(CliError::Output)?;
    output.flush().map_err(CliError::Output)
}

fn format_user(user: &UserSnapshot) -> String {
    let state = match (user.enabled, user.connected) {
        (false, _) => "disabled".to_owned(),
        (true, 0) => "enabled/disconnected".to_owned(),
        (true, connected) => format!("enabled/{connected} connected"),
    };
    format!(
        "{}\t{}\tupload={}\tdownload={}\tlast_seen={}",
        user.name,
        state,
        user.traffic.upload,
        user.traffic.download,
        user.last_seen
            .map_or_else(|| "-".to_owned(), |seen| seen.to_string())
    )
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::RegisteredShutdownSignals;

    use std::path::Path;

    use crate::{
        ipc::protocol::ServerResponse,
        model::{TrafficTotals, UserSnapshot},
    };

    use super::{
        Cli, Command, ControlError, ServerCommand, ServerSettingsCommand, ServerUsersCommand,
        bundle_export_diagnostics, is_bundle_durability_uncertain, render_json,
    };

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

    #[test]
    fn list_users_json_is_machine_readable_without_terminal_escape_bytes() {
        let stdout = render_json(&ServerResponse::Users(vec![sample_user()]));
        assert!(!stdout.contains('\u{1b}'));
        assert_eq!(
            serde_json::from_str::<Vec<UserSnapshot>>(&stdout).unwrap()[0].name,
            "alice"
        );
    }

    #[test]
    fn durability_uncertain_bundle_diagnostics_include_destination_and_secret_warning() {
        let error = ControlError::Server {
            code: "bundle_durability_uncertain".to_owned(),
            message: "bundle sync failed".to_owned(),
            recovery: "inspect the destination".to_owned(),
        };

        assert!(is_bundle_durability_uncertain(&error));
        let diagnostics = bundle_export_diagnostics(Path::new("/secure/alice.bundle"), true);
        assert!(diagnostics[0].contains("/secure/alice.bundle"));
        assert!(diagnostics[1].contains("unencrypted client secret"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn registers_server_shutdown_signals() {
        let _signals = RegisteredShutdownSignals::register().unwrap();
    }

    #[test]
    fn parses_server_management_command_surface() {
        let id = "00000000-0000-0000-0000-000000000001";

        assert!(matches!(
            Cli::try_parse_from([
                "rqbit-tunnel",
                "server",
                "run",
                "--config",
                "/etc/rqbit-tunnel/server.json"
            ]),
            Ok(Cli {
                command: Command::Server(ServerCommand::Run(_))
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["rqbit-tunnel", "server", "tui"]),
            Ok(Cli {
                command: Command::Server(ServerCommand::Tui(_))
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["rqbit-tunnel", "server", "users", "list", "--json"]),
            Ok(Cli {
                command: Command::Server(ServerCommand::Users {
                    command: ServerUsersCommand::List { json: true },
                    ..
                })
            })
        ));
        assert!(matches!(
            Cli::try_parse_from([
                "rqbit-tunnel",
                "server",
                "users",
                "add",
                "--name",
                "alice",
                "--export",
                "/secure/alice.bundle",
                "--yes",
            ]),
            Ok(Cli {
                command: Command::Server(ServerCommand::Users {
                    command: ServerUsersCommand::Add { .. },
                    ..
                })
            })
        ));
        for command in ["enable", "disable"] {
            assert!(matches!(
                Cli::try_parse_from(["rqbit-tunnel", "server", "users", command, id]),
                Ok(Cli {
                    command: Command::Server(ServerCommand::Users {
                        command: ServerUsersCommand::Enable { .. }
                            | ServerUsersCommand::Disable { .. },
                        ..
                    })
                })
            ));
        }
        for command in ["delete", "reset"] {
            assert!(matches!(
                Cli::try_parse_from(["rqbit-tunnel", "server", "users", command, id, "--yes"]),
                Ok(Cli {
                    command: Command::Server(ServerCommand::Users {
                        command: ServerUsersCommand::Delete { yes: true, .. }
                            | ServerUsersCommand::Reset { yes: true, .. },
                        ..
                    })
                })
            ));
        }
        assert!(matches!(
            Cli::try_parse_from(["rqbit-tunnel", "server", "settings", "show", "--json"]),
            Ok(Cli {
                command: Command::Server(ServerCommand::Settings {
                    command: ServerSettingsCommand::Show { json: true },
                    ..
                })
            })
        ));
        assert!(matches!(
            Cli::try_parse_from([
                "rqbit-tunnel",
                "server",
                "settings",
                "set",
                "--config",
                "/tmp/server.json",
            ]),
            Ok(Cli {
                command: Command::Server(ServerCommand::Settings {
                    command: ServerSettingsCommand::Set { .. },
                    ..
                })
            })
        ));
    }
}
