#[path = "tray/mod.rs"]
mod tray;

use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
};

use clap::{Arg, ArgAction, ArgMatches, Command as ClapCommand, error::ErrorKind};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::{
    fs::OpenOptions,
    io::{IsTerminal, Read},
};

#[cfg(windows)]
use crate::config::current_windows_status_owner_sid;
#[cfg(unix)]
use crate::ipc::unix::{UnixClientControlClient, UnixControlClient, UnixControlError};
#[cfg(windows)]
use crate::ipc::windows::{WindowsClientControlClient, WindowsClientControlError};
use crate::{
    config::{
        ConfigError, import_bundle_for_current_status_owner, load_client_config,
        write_client_config,
    },
    ipc::protocol::{ClientRequest, ClientResponse},
    model::{ClientConfig, ClientSnapshot, EnrollmentBundle},
    paths::ClientPaths,
    platform::{CLIENT_SERVICE, ServiceError, ServiceInstallSpec, ServiceManager, ServiceState},
    runtime::client::{ClientRuntimeError, ManagedClient},
    tui::client::{
        ClientTuiAction, ClientTuiConfigUpdate, ClientTuiError, ClientUpdateFeedback,
        run_client_tui,
    },
    update::orchestrator::{UpdaterFailureCode, UpdaterResult},
    version::{current_exe_suffix, read_active_release},
};
#[cfg(unix)]
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
    Client(ClientCommand),
    Tray(TrayCommand),
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

#[derive(Debug)]
pub enum ClientCommand {
    Run(ClientRunOptions),
    PayloadHost(ClientPayloadHostOptions),
    Import(ClientImportOptions),
    Config(ClientConfigCommand),
    Service(ClientServiceCommand),
    Update(ClientUpdateCommand),
    Tui,
}

#[derive(Debug)]
pub struct ClientRunOptions {
    pub config: PathBuf,
}

#[derive(Debug)]
pub struct ClientPayloadHostOptions {
    pub config: PathBuf,
    pub launcher_ready_event: String,
    pub launcher_stop_event: String,
}

#[derive(Debug)]
pub struct ClientImportOptions {
    pub bundle: PathBuf,
    pub json: bool,
}

#[derive(Debug)]
pub enum ClientConfigCommand {
    Show { json: bool },
    Set(ClientConfigSetOptions),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientUpdateCommand {
    Check,
    Install { target_version: String },
}

#[derive(Clone, Debug, Default)]
pub struct ClientConfigSetOptions {
    pub server_addr: Option<SocketAddr>,
    pub socks_listen: Option<SocketAddr>,
    pub carriers: Option<usize>,
    pub allow_unauthenticated_lan_socks: Option<bool>,
    pub json: bool,
}

#[derive(Debug)]
pub enum ClientServiceCommand {
    Install,
    Start,
    Stop,
    Restart,
    Status { json: bool },
    EnableAutostart,
    DisableAutostart,
}

#[derive(Debug)]
pub enum TrayCommand {
    Run,
    EnableAutostart,
    DisableAutostart,
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
        let command = match matches.subcommand() {
            Some(("server", server_matches)) => {
                Command::Server(parse_server_command(server_matches)?)
            }
            Some(("client", client_matches)) => {
                Command::Client(parse_client_command(client_matches)?)
            }
            Some(("tray", tray_matches)) => Command::Tray(parse_tray_command(tray_matches)?),
            _ => {
                return Err(clap::Error::raw(
                    ErrorKind::MissingSubcommand,
                    "a command subcommand is required",
                ));
            }
        };

        Ok(Self { command })
    }
}

fn parse_server_command(matches: &ArgMatches) -> Result<ServerCommand, clap::Error> {
    match matches.subcommand() {
        Some(("run", run_matches)) => Ok(ServerCommand::Run(ServerRunOptions {
            config: required_path(run_matches, "config"),
        })),
        Some(("tui", tui_matches)) => Ok(ServerCommand::Tui(ServerTuiOptions {
            socket: optional_path(tui_matches, "socket"),
        })),
        Some(("users", users_matches)) => Ok(ServerCommand::Users {
            socket: optional_path(users_matches, "socket"),
            command: parse_users_command(users_matches)?,
        }),
        Some(("settings", settings_matches)) => Ok(ServerCommand::Settings {
            socket: optional_path(settings_matches, "socket"),
            command: parse_settings_command(settings_matches)?,
        }),
        _ => Err(clap::Error::raw(
            ErrorKind::MissingSubcommand,
            "a server subcommand is required",
        )),
    }
}

fn parse_client_command(matches: &ArgMatches) -> Result<ClientCommand, clap::Error> {
    match matches.subcommand() {
        Some(("run", run_matches)) => Ok(ClientCommand::Run(ClientRunOptions {
            config: required_path(run_matches, "config"),
        })),
        Some(("payload-host", payload_matches)) => {
            Ok(ClientCommand::PayloadHost(ClientPayloadHostOptions {
                config: required_path(payload_matches, "config"),
                launcher_ready_event: required_string(payload_matches, "launcher-ready-event")
                    .to_owned(),
                launcher_stop_event: required_string(payload_matches, "launcher-stop-event")
                    .to_owned(),
            }))
        }
        Some(("import", import_matches)) => Ok(ClientCommand::Import(ClientImportOptions {
            bundle: required_path(import_matches, "bundle"),
            json: import_matches.get_flag("json"),
        })),
        Some(("config", config_matches)) => Ok(ClientCommand::Config(parse_client_config_command(
            config_matches,
        )?)),
        Some(("service", service_matches)) => Ok(ClientCommand::Service(
            parse_client_service_command(service_matches)?,
        )),
        Some(("update", update_matches)) => Ok(ClientCommand::Update(parse_client_update_command(
            update_matches,
        )?)),
        Some(("tui", _)) => Ok(ClientCommand::Tui),
        _ => Err(clap::Error::raw(
            ErrorKind::MissingSubcommand,
            "a client subcommand is required",
        )),
    }
}

fn parse_tray_command(matches: &ArgMatches) -> Result<TrayCommand, clap::Error> {
    match matches.subcommand() {
        None => Ok(TrayCommand::Run),
        Some(("enable-autostart", _)) => Ok(TrayCommand::EnableAutostart),
        Some(("disable-autostart", _)) => Ok(TrayCommand::DisableAutostart),
        _ => Err(clap::Error::raw(
            ErrorKind::InvalidSubcommand,
            "a tray subcommand must be enable-autostart or disable-autostart",
        )),
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

fn parse_client_config_command(matches: &ArgMatches) -> Result<ClientConfigCommand, clap::Error> {
    match matches.subcommand() {
        Some(("show", command_matches)) => Ok(ClientConfigCommand::Show {
            json: command_matches.get_flag("json"),
        }),
        Some(("set", command_matches)) => Ok(ClientConfigCommand::Set(ClientConfigSetOptions {
            server_addr: optional_socket_address(command_matches, "server-addr")?,
            socks_listen: optional_socket_address(command_matches, "socks-listen")?,
            carriers: optional_usize(command_matches, "carriers")?,
            allow_unauthenticated_lan_socks: command_matches
                .get_one::<String>("allow-unauthenticated-lan-socks")
                .map(|value| {
                    value.parse::<bool>().map_err(|error| {
                        clap::Error::raw(
                            ErrorKind::InvalidValue,
                            format!("invalid LAN SOCKS acknowledgement {value:?}: {error}"),
                        )
                    })
                })
                .transpose()?,
            json: command_matches.get_flag("json"),
        })),
        _ => Err(clap::Error::raw(
            ErrorKind::MissingSubcommand,
            "a client config subcommand is required",
        )),
    }
}

fn parse_client_service_command(matches: &ArgMatches) -> Result<ClientServiceCommand, clap::Error> {
    match matches.subcommand() {
        Some(("install", _)) => Ok(ClientServiceCommand::Install),
        Some(("start", _)) => Ok(ClientServiceCommand::Start),
        Some(("stop", _)) => Ok(ClientServiceCommand::Stop),
        Some(("restart", _)) => Ok(ClientServiceCommand::Restart),
        Some(("status", command_matches)) => Ok(ClientServiceCommand::Status {
            json: command_matches.get_flag("json"),
        }),
        Some(("enable-autostart", _)) => Ok(ClientServiceCommand::EnableAutostart),
        Some(("disable-autostart", _)) => Ok(ClientServiceCommand::DisableAutostart),
        _ => Err(clap::Error::raw(
            ErrorKind::MissingSubcommand,
            "a client service subcommand is required",
        )),
    }
}

fn parse_client_update_command(matches: &ArgMatches) -> Result<ClientUpdateCommand, clap::Error> {
    match matches.subcommand() {
        Some(("check", _)) => Ok(ClientUpdateCommand::Check),
        Some(("install", install_matches)) => Ok(ClientUpdateCommand::Install {
            target_version: required_string(install_matches, "target-version").to_owned(),
        }),
        _ => Err(clap::Error::raw(
            ErrorKind::MissingSubcommand,
            "a client update subcommand is required",
        )),
    }
}

fn optional_socket_address(
    matches: &ArgMatches,
    name: &str,
) -> Result<Option<SocketAddr>, clap::Error> {
    matches
        .get_one::<String>(name)
        .map(|value| {
            value.parse::<SocketAddr>().map_err(|error| {
                clap::Error::raw(
                    ErrorKind::InvalidValue,
                    format!("invalid {name} socket address {value:?}: {error}"),
                )
            })
        })
        .transpose()
}

fn optional_usize(matches: &ArgMatches, name: &str) -> Result<Option<usize>, clap::Error> {
    matches
        .get_one::<String>(name)
        .map(|value| {
            value.parse::<usize>().map_err(|error| {
                clap::Error::raw(
                    ErrorKind::InvalidValue,
                    format!("invalid {name} value {value:?}: {error}"),
                )
            })
        })
        .transpose()
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
        .subcommand(client_command())
        .subcommand(tray_command())
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

fn client_command() -> ClapCommand {
    ClapCommand::new("client")
        .about("Manage the rqbit tunnel client")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            ClapCommand::new("run").about("Run the managed client").arg(
                Arg::new("config")
                    .long("config")
                    .value_name("PATH")
                    .default_value("/etc/rqbit-tunnel/client.json")
                    .action(ArgAction::Set),
            ),
        )
        .subcommand(
            ClapCommand::new("payload-host")
                .hide(true)
                .arg(required_argument("config", "PATH"))
                .arg(required_argument("launcher-ready-event", "EVENT"))
                .arg(required_argument("launcher-stop-event", "EVENT")),
        )
        .subcommand(
            ClapCommand::new("import")
                .about("Import a server-issued enrollment bundle")
                .arg(required_argument("bundle", "PATH"))
                .arg(json_argument()),
        )
        .subcommand(
            ClapCommand::new("config")
                .about("Show or change protected client configuration")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    ClapCommand::new("show")
                        .about("Show non-secret client configuration")
                        .arg(json_argument()),
                )
                .subcommand(
                    ClapCommand::new("set")
                        .about("Change one or more client configuration values")
                        .arg(
                            Arg::new("server-addr")
                                .long("server-addr")
                                .value_name("HOST:PORT")
                                .action(ArgAction::Set),
                        )
                        .arg(
                            Arg::new("socks-listen")
                                .long("socks-listen")
                                .value_name("HOST:PORT")
                                .action(ArgAction::Set),
                        )
                        .arg(
                            Arg::new("carriers")
                                .long("carriers")
                                .value_name("COUNT")
                                .action(ArgAction::Set),
                        )
                        .arg(
                            Arg::new("allow-unauthenticated-lan-socks")
                                .long("allow-unauthenticated-lan-socks")
                                .value_name("true|false")
                                .value_parser(["true", "false"])
                                .action(ArgAction::Set),
                        )
                        .arg(json_argument()),
                ),
        )
        .subcommand(
            ClapCommand::new("service")
                .about("Control the managed client service")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    ClapCommand::new("install").about("Install or reload the managed service"),
                )
                .subcommand(ClapCommand::new("start").about("Start the managed service"))
                .subcommand(ClapCommand::new("stop").about("Stop the managed service"))
                .subcommand(ClapCommand::new("restart").about("Restart the managed service"))
                .subcommand(
                    ClapCommand::new("status")
                        .about("Read managed-client status")
                        .arg(json_argument()),
                )
                .subcommand(
                    ClapCommand::new("enable-autostart").about("Enable managed-service autostart"),
                )
                .subcommand(
                    ClapCommand::new("disable-autostart")
                        .about("Disable managed-service autostart"),
                ),
        )
        .subcommand(
            ClapCommand::new("update")
                .about("Check or install a signed managed-client release")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(ClapCommand::new("check").about(
                    "Check GitHub for a newer signed release without changing service state",
                ))
                .subcommand(
                    ClapCommand::new("install")
                        .about("Install one checked signed release")
                        .arg(required_argument("target-version", "SEMVER")),
                ),
        )
        .subcommand(ClapCommand::new("tui").about("Open the client dashboard"))
}

fn tray_command() -> ClapCommand {
    ClapCommand::new("tray")
        .about("Run the per-user tunnel status tray")
        .subcommand(
            ClapCommand::new("enable-autostart")
                .about("Enable tray autostart for the current user"),
        )
        .subcommand(
            ClapCommand::new("disable-autostart")
                .about("Disable tray autostart for the current user"),
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

#[cfg(unix)]
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

pub(crate) fn render_client_json(snapshot: &ClientSnapshot) -> String {
    serde_json::to_string(snapshot).expect("client status snapshots must be serializable")
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

#[derive(Debug, Error)]
pub enum ClientControlError {
    #[cfg(unix)]
    #[error(transparent)]
    Unix(#[from] UnixControlError),
    #[cfg(windows)]
    #[error(transparent)]
    Windows(#[from] WindowsClientControlError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[cfg(not(any(unix, windows)))]
    #[error("managed client control is unavailable on this platform")]
    UnsupportedPlatform,
    #[error("client rejected the snapshot request ({code}): {message}\nrecovery: {recovery}")]
    Client {
        code: String,
        message: String,
        recovery: String,
    },
}

pub(crate) async fn request_client_snapshot(
    paths: &ClientPaths,
) -> Result<ClientSnapshot, ClientControlError> {
    #[cfg(unix)]
    {
        let mut client = UnixClientControlClient::connect(paths.control_socket_path()).await?;
        match client.request(ClientRequest::Snapshot).await? {
            ClientResponse::Snapshot(snapshot) => Ok(snapshot),
            ClientResponse::Error(error) => Err(ClientControlError::Client {
                code: error.code,
                message: error.message,
                recovery: error.recovery,
            }),
        }
    }

    #[cfg(windows)]
    {
        let _ = paths;
        let owner_sid = current_windows_status_owner_sid()?;
        let mut client = WindowsClientControlClient::connect(&owner_sid)?;
        match client.request(ClientRequest::Snapshot).await? {
            ClientResponse::Snapshot(snapshot) => Ok(snapshot),
            ClientResponse::Error(error) => Err(ClientControlError::Client {
                code: error.code,
                message: error.message,
                recovery: error.recovery,
            }),
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = paths;
        Err(ClientControlError::UnsupportedPlatform)
    }
}

#[cfg(unix)]
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
}

#[cfg(unix)]
const MAX_SERVER_SETTINGS_BYTES: u64 = 64 * 1024;

#[cfg(unix)]
#[derive(Debug, Error)]
pub enum SettingsFileError {
    #[error("failed to inspect server settings file {path}: {source}")]
    Inspect {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("server settings input must be a regular, non-symlink file: {path}")]
    NotRegular { path: PathBuf },
    #[error("server settings file {path} exceeds the {limit}-byte limit")]
    TooLarge { path: PathBuf, limit: u64 },
    #[error("failed to read server settings file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivilegeAction {
    Continue,
    Reexec {
        program: OsString,
        args: Vec<OsString>,
    },
}

#[derive(Debug, Error)]
pub enum PrivilegeError {
    #[cfg(windows)]
    #[error("failed to determine whether the process is elevated: {0}")]
    ElevationCheck(#[source] windows::core::Error),
    #[cfg(not(windows))]
    #[error("privilege elevation cannot be inspected on this platform")]
    UnsupportedElevationCheck,
}

pub fn ensure_privileged(
    program: &OsStr,
    args: &[OsString],
) -> Result<PrivilegeAction, PrivilegeError> {
    if is_elevated()? {
        return Ok(PrivilegeAction::Continue);
    }

    #[cfg(unix)]
    {
        let mut sudo_args = Vec::with_capacity(args.len() + 2);
        sudo_args.push(OsString::from("--"));
        sudo_args.push(program.to_os_string());
        sudo_args.extend(args.iter().cloned());
        return Ok(PrivilegeAction::Reexec {
            program: OsString::from("sudo"),
            args: sudo_args,
        });
    }

    #[cfg(windows)]
    {
        return Ok(PrivilegeAction::Reexec {
            program: program.to_os_string(),
            args: args.to_vec(),
        });
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (program, args);
        Err(PrivilegeError::UnsupportedElevationCheck)
    }
}

fn is_elevated() -> Result<bool, PrivilegeError> {
    #[cfg(unix)]
    {
        return Ok(unsafe { libc::geteuid() == 0 });
    }

    #[cfg(windows)]
    {
        use windows::Win32::{
            Foundation::{CloseHandle, HANDLE},
            Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        };

        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
                .map_err(PrivilegeError::ElevationCheck)?;
            let result = (|| -> windows::core::Result<bool> {
                let mut elevation = TOKEN_ELEVATION::default();
                let mut length = 0;
                GetTokenInformation(
                    token,
                    TokenElevation,
                    Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut length,
                )?;
                Ok(elevation.TokenIsElevated != 0)
            })();
            let _ = CloseHandle(token);
            return result.map_err(PrivilegeError::ElevationCheck);
        }
    }

    #[cfg(not(any(unix, windows)))]
    Err(PrivilegeError::UnsupportedElevationCheck)
}

fn reexecute_privileged_if_needed(arguments: &[OsString]) -> Result<bool, CliError> {
    let Some((program, args)) = arguments.split_first() else {
        return Err(CliError::MissingInvocation);
    };
    match ensure_privileged(program, args)? {
        PrivilegeAction::Continue => Ok(false),
        PrivilegeAction::Reexec { program, args } => {
            #[cfg(unix)]
            {
                let status = ProcessCommand::new(&program)
                    .args(&args)
                    .status()
                    .map_err(|source| CliError::PrivilegeReexec { program, source })?;
                if status.success() {
                    Ok(true)
                } else {
                    Err(CliError::PrivilegeReexecFailed { status })
                }
            }

            #[cfg(windows)]
            {
                let _ = (program, args);
                Err(CliError::ElevationRequired)
            }

            #[cfg(not(any(unix, windows)))]
            {
                let _ = (program, args);
                Err(CliError::ElevationRequired)
            }
        }
    }
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct TrayError(Box<dyn std::error::Error + Send + Sync>);

impl TrayError {
    fn from_agent(error: tray::agent::TrayAgentError) -> Self {
        Self(Box::new(error))
    }
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Control(#[from] ControlError),
    #[cfg(unix)]
    #[error(transparent)]
    Runtime(#[from] ServerRuntimeError),
    #[cfg(unix)]
    #[error(transparent)]
    Tui(#[from] TuiError),
    #[cfg(unix)]
    #[error("server configuration path must be named server.json: {path}")]
    UnsupportedConfigPath { path: PathBuf },
    #[cfg(unix)]
    #[error(transparent)]
    SettingsFile(#[from] SettingsFileError),
    #[cfg(unix)]
    #[error("settings file reader task failed: {0}")]
    SettingsReadTask(#[source] tokio::task::JoinError),
    #[cfg(unix)]
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
    #[cfg(unix)]
    #[error("failed to read interactive confirmation: {0}")]
    ConfirmationInput(#[source] io::Error),
    #[cfg(unix)]
    #[error("an interactive terminal confirmation is required; retry with --yes to proceed")]
    ConfirmationRequired,
    #[cfg(unix)]
    #[error("operation cancelled")]
    ConfirmationDeclined,
    #[error("failed to wait for a shutdown signal: {0}")]
    Signal(#[source] io::Error),
    #[cfg(unix)]
    #[error("managed server control socket exited unexpectedly")]
    ControlExited,
    #[cfg(unix)]
    #[error("server returned an unexpected response while expecting {expected}: {received:?}")]
    UnexpectedResponse {
        expected: &'static str,
        received: ServerResponse,
    },
    #[error(transparent)]
    ClientControl(#[from] ClientControlError),
    #[error(transparent)]
    ClientRuntime(#[from] ClientRuntimeError),
    #[error(transparent)]
    ClientTui(#[from] ClientTuiError),
    #[error(transparent)]
    ClientConfig(#[from] ConfigError),
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error(transparent)]
    Privilege(#[from] PrivilegeError),
    #[error("client configuration path must be named client.json: {path}")]
    UnsupportedClientConfigPath { path: PathBuf },
    #[error("failed to read enrollment bundle {path}: {source}")]
    ReadEnrollmentBundle {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("enrollment bundle {path} is not valid JSON: {source}")]
    DecodeEnrollmentBundle {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("client configuration update requires at least one setting")]
    NoClientConfigChanges,
    #[error("client {name} value {value:?} is invalid: {reason}")]
    InvalidClientSetting {
        name: &'static str,
        value: String,
        reason: String,
    },
    #[error("failed to resolve the current rqbit-tunnel executable: {0}")]
    CurrentExecutable(#[source] io::Error),
    #[error("failed to inspect managed client update path {path}: {source}")]
    ClientUpdatePath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read the active managed client release: {source}")]
    ClientUpdateActiveRelease {
        #[source]
        source: crate::version::ActiveReleaseError,
    },
    #[error("failed to resolve the active managed client payload: {source}")]
    ClientUpdateActivePayload {
        #[source]
        source: crate::version::ActiveReleaseError,
    },
    #[error("the current executable is not the active managed client payload")]
    ClientUpdateInactivePayload,
    #[error("managed client updater executable is missing or invalid: {path}")]
    ClientUpdateUpdaterMissing { path: PathBuf },
    #[error("failed to prepare the managed client updater: {source}")]
    ClientUpdatePrepare {
        #[source]
        source: io::Error,
    },
    #[error("failed to run the managed client updater {program:?}: {source}")]
    ClientUpdateLaunch {
        program: OsString,
        #[source]
        source: io::Error,
    },
    #[error("managed client updater returned an invalid result: {source}")]
    ClientUpdateDecode {
        #[source]
        source: serde_json::Error,
    },
    #[error("managed client updater exited unsuccessfully without a failure result: {status}")]
    ClientUpdateUnexpectedExit { status: std::process::ExitStatus },
    #[error("managed client updater task failed: {source}")]
    ClientUpdateTask {
        #[source]
        source: tokio::task::JoinError,
    },
    #[cfg(any(windows, test))]
    #[error("current executable is not a versioned rqbit-tunnel payload: {payload}")]
    InvalidWindowsBundleLayout { payload: PathBuf },
    #[error("missing original command line for privilege handoff")]
    MissingInvocation,
    #[error("failed to re-execute the privileged command {program:?}: {source}")]
    PrivilegeReexec {
        program: OsString,
        #[source]
        source: io::Error,
    },
    #[error("privileged command exited unsuccessfully: {status}")]
    PrivilegeReexecFailed { status: std::process::ExitStatus },
    #[error(
        "this operation requires elevation; run it through scripts/tunnel/client-run.ps1 so it can relaunch with UAC"
    )]
    ElevationRequired,
    #[error("failed to open the managed client log viewer: {source}")]
    ClientLogs {
        #[source]
        source: io::Error,
    },
    #[error("managed client log viewer exited unsuccessfully: {status}")]
    ClientLogsFailed { status: std::process::ExitStatus },
    #[cfg(not(target_os = "linux"))]
    #[error("managed client log viewing is currently supported only on Linux")]
    ClientLogsUnsupported,
    #[cfg(windows)]
    #[error(transparent)]
    WindowsClientPayloadHost(#[from] crate::runtime::windows_service::WindowsClientPayloadError),
    #[cfg(not(windows))]
    #[error("the Windows managed-client payload host is unavailable on this platform")]
    ClientPayloadHostUnsupported,
    #[cfg(not(any(target_os = "linux", windows)))]
    #[error("managed client services are unsupported on this platform")]
    ClientServiceUnsupported,
    #[error(transparent)]
    Tray(#[from] TrayError),
}

pub async fn execute(cli: Cli) -> Result<(), CliError> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    execute_with_arguments(cli, &arguments).await
}

pub async fn execute_with_arguments(cli: Cli, arguments: &[OsString]) -> Result<(), CliError> {
    match cli.command {
        Command::Server(command) => execute_server(command).await,
        Command::Client(command) => execute_client(command, arguments).await,
        Command::Tray(command) => execute_tray(command).await,
    }
}

async fn execute_tray(command: TrayCommand) -> Result<(), CliError> {
    tray::ensure_user_session().map_err(TrayError::from_agent)?;
    match command {
        TrayCommand::Run => match tray::run().await.map_err(TrayError::from_agent)? {
            tray::TrayRunOutcome::Unavailable => {
                eprintln!("tray unavailable");
                Ok(())
            }
            #[cfg(any(
                all(target_os = "linux", feature = "tray-linux"),
                all(windows, feature = "tray-windows")
            ))]
            tray::TrayRunOutcome::Exited => Ok(()),
        },
        TrayCommand::EnableAutostart => {
            tray::set_autostart(true).map_err(TrayError::from_agent)?;
            write_stdout_line("tray autostart enabled")
        }
        TrayCommand::DisableAutostart => {
            tray::set_autostart(false).map_err(TrayError::from_agent)?;
            write_stdout_line("tray autostart disabled")
        }
    }
}

#[cfg(unix)]
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

#[cfg(not(unix))]
async fn execute_server(_command: ServerCommand) -> Result<(), CliError> {
    Err(ControlError::UnsupportedPlatform.into())
}

impl ClientCommand {
    fn requires_privilege(&self) -> bool {
        match self {
            Self::Run(_) | Self::Import(_) | Self::Config(ClientConfigCommand::Set(_)) => true,
            Self::PayloadHost(_) | Self::Update(_) => false,
            Self::Service(ClientServiceCommand::Status { .. }) => false,
            Self::Config(ClientConfigCommand::Show { .. }) | Self::Tui => cfg!(windows),
            Self::Service(_) => true,
        }
    }
}

async fn execute_client(command: ClientCommand, arguments: &[OsString]) -> Result<(), CliError> {
    match command {
        ClientCommand::Tui => run_client_dashboard(ClientPaths::system()).await,
        ClientCommand::Update(command) => execute_client_update(command).await,
        command => {
            if command.requires_privilege() && reexecute_privileged_if_needed(arguments)? {
                return Ok(());
            }
            execute_client_operation(command).await
        }
    }
}

async fn execute_client_tui_mutation(
    command: ClientCommand,
    arguments: &[OsString],
) -> Result<(), CliError> {
    debug_assert!(command.requires_privilege());
    if reexecute_privileged_if_needed(arguments)? {
        return Ok(());
    }
    execute_client_operation(command).await
}

async fn execute_client_operation(command: ClientCommand) -> Result<(), CliError> {
    let paths = ClientPaths::system();
    match command {
        ClientCommand::Run(options) => run_client(options).await,
        ClientCommand::PayloadHost(options) => execute_client_payload_host(options).await,
        ClientCommand::Import(options) => execute_client_import(&paths, options),
        ClientCommand::Config(command) => execute_client_config(&paths, command),
        ClientCommand::Service(command) => execute_client_service(&paths, command).await,
        ClientCommand::Update(_) => unreachable!("client updates are dispatched before operations"),
        ClientCommand::Tui => unreachable!("the client dashboard is dispatched before operations"),
    }
}

async fn execute_client_payload_host(options: ClientPayloadHostOptions) -> Result<(), CliError> {
    #[cfg(windows)]
    {
        crate::runtime::windows_service::run_client_payload_host(
            options.config,
            options.launcher_ready_event,
            options.launcher_stop_event,
        )
        .await?;
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        let _ = options;
        Err(CliError::ClientPayloadHostUnsupported)
    }
}

async fn run_client(options: ClientRunOptions) -> Result<(), CliError> {
    let paths = client_paths_from_config(&options.config)?;

    #[cfg(unix)]
    {
        let mut signals = RegisteredShutdownSignals::register()?;
        let client = ManagedClient::start(paths).await?;
        signals.wait().await;
        client.shutdown().await?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let client = ManagedClient::start(paths).await?;
        tokio::signal::ctrl_c().await.map_err(CliError::Signal)?;
        client.shutdown().await?;
        Ok(())
    }
}

fn execute_client_import(
    paths: &ClientPaths,
    options: ClientImportOptions,
) -> Result<(), CliError> {
    let bytes = fs::read(&options.bundle).map_err(|source| CliError::ReadEnrollmentBundle {
        path: options.bundle.clone(),
        source,
    })?;
    let bundle = serde_json::from_slice::<EnrollmentBundle>(&bytes).map_err(|source| {
        CliError::DecodeEnrollmentBundle {
            path: options.bundle,
            source,
        }
    })?;
    let config = import_bundle_for_current_status_owner(paths, bundle)?;
    emit_client_config(&config, options.json)
}

fn execute_client_config(
    paths: &ClientPaths,
    command: ClientConfigCommand,
) -> Result<(), CliError> {
    match command {
        ClientConfigCommand::Show { json } => {
            let config = load_client_config(paths)?;
            emit_client_config(&config, json)
        }
        ClientConfigCommand::Set(changes) => {
            if changes.server_addr.is_none()
                && changes.socks_listen.is_none()
                && changes.carriers.is_none()
                && changes.allow_unauthenticated_lan_socks.is_none()
            {
                return Err(CliError::NoClientConfigChanges);
            }

            let mut config = load_client_config(paths)?;
            if let Some(server_addr) = changes.server_addr {
                config.server_addr = Some(server_addr);
            }
            if let Some(socks_listen) = changes.socks_listen {
                config.socks_listen = socks_listen;
            }
            if let Some(carriers) = changes.carriers {
                config.carriers = carriers;
            }
            if let Some(allow_lan_socks) = changes.allow_unauthenticated_lan_socks {
                config.allow_unauthenticated_lan_socks = allow_lan_socks;
            }
            write_client_config(paths, &config)?;
            emit_client_config(&config, changes.json)
        }
    }
}

async fn execute_client_service(
    paths: &ClientPaths,
    command: ClientServiceCommand,
) -> Result<(), CliError> {
    match command {
        ClientServiceCommand::Install => {
            let spec = client_service_install_spec()?;
            with_client_service_manager(|manager| manager.install(&spec))?;
            write_stdout_line("managed client service installed")
        }
        ClientServiceCommand::Start => {
            let state = with_client_service_manager(|manager| manager.start(CLIENT_SERVICE))?;
            emit_service_state(state, false)
        }
        ClientServiceCommand::Stop => {
            let state = with_client_service_manager(|manager| manager.stop(CLIENT_SERVICE))?;
            emit_service_state(state, false)
        }
        ClientServiceCommand::Restart => {
            let state = with_client_service_manager(|manager| manager.restart(CLIENT_SERVICE))?;
            emit_service_state(state, false)
        }
        ClientServiceCommand::Status { json } => execute_client_status(paths, json).await,
        ClientServiceCommand::EnableAutostart => {
            with_client_service_manager(|manager| manager.set_autostart(CLIENT_SERVICE, true))?;
            write_stdout_line("managed client autostart enabled")
        }
        ClientServiceCommand::DisableAutostart => {
            with_client_service_manager(|manager| manager.set_autostart(CLIENT_SERVICE, false))?;
            write_stdout_line("managed client autostart disabled")
        }
    }
}

pub(crate) fn observed_client_service_state() -> Result<ServiceState, CliError> {
    with_client_service_manager(|manager| manager.status(CLIENT_SERVICE))
}

async fn execute_client_status(paths: &ClientPaths, json: bool) -> Result<(), CliError> {
    match request_client_snapshot(paths).await {
        Ok(snapshot) => emit_client_snapshot(&snapshot, json),
        Err(_) => {
            let state = observed_client_service_state()?;
            emit_service_state(state, json)
        }
    }
}

#[cfg(any(windows, test))]
fn windows_client_service_payload() -> Vec<OsString> {
    vec![OsString::from("client"), OsString::from("service-host")]
}

#[cfg(any(windows, test))]
fn windows_client_service_install_spec_from_payload(
    payload: &Path,
) -> Result<ServiceInstallSpec, CliError> {
    if payload.file_name() != Some(OsStr::new("rqbit-tunnel.exe")) {
        return Err(CliError::InvalidWindowsBundleLayout {
            payload: payload.to_path_buf(),
        });
    }
    let payload_dir = payload
        .parent()
        .ok_or_else(|| CliError::InvalidWindowsBundleLayout {
            payload: payload.to_path_buf(),
        })?;
    if payload_dir.file_name() != Some(OsStr::new("payload")) {
        return Err(CliError::InvalidWindowsBundleLayout {
            payload: payload.to_path_buf(),
        });
    }
    let release_dir = payload_dir
        .parent()
        .ok_or_else(|| CliError::InvalidWindowsBundleLayout {
            payload: payload.to_path_buf(),
        })?;
    let releases_dir =
        release_dir
            .parent()
            .ok_or_else(|| CliError::InvalidWindowsBundleLayout {
                payload: payload.to_path_buf(),
            })?;
    if releases_dir.file_name() != Some(OsStr::new("releases")) {
        return Err(CliError::InvalidWindowsBundleLayout {
            payload: payload.to_path_buf(),
        });
    }
    let install_root =
        releases_dir
            .parent()
            .ok_or_else(|| CliError::InvalidWindowsBundleLayout {
                payload: payload.to_path_buf(),
            })?;

    Ok(ServiceInstallSpec {
        executable: install_root.join("launcher.exe"),
        arguments: windows_client_service_payload(),
        working_directory: install_root.to_path_buf(),
        display_name: "rqbit tunnel client".to_owned(),
    })
}

fn client_service_install_spec() -> Result<ServiceInstallSpec, CliError> {
    #[cfg(windows)]
    {
        let payload = std::env::current_exe().map_err(CliError::CurrentExecutable)?;
        return windows_client_service_install_spec_from_payload(&payload);
    }

    #[cfg(not(windows))]
    {
        Ok(ServiceInstallSpec {
            executable: PathBuf::from("/opt/rqbit-tunnel/launcher"),
            arguments: vec![
                OsString::from("client"),
                OsString::from("run"),
                OsString::from("--config"),
                OsString::from("/etc/rqbit-tunnel/client.json"),
            ],
            working_directory: PathBuf::from("/opt/rqbit-tunnel"),
            display_name: "rqbit tunnel client".to_owned(),
        })
    }
}

fn with_client_service_manager<T>(
    operation: impl FnOnce(&dyn ServiceManager) -> Result<T, ServiceError>,
) -> Result<T, CliError> {
    #[cfg(target_os = "linux")]
    {
        let manager = crate::platform::linux::LinuxServiceManager::system();
        return operation(&manager).map_err(CliError::Service);
    }

    #[cfg(windows)]
    {
        let manager = crate::platform::windows::WindowsServiceManager::new();
        return operation(&manager).map_err(CliError::Service);
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = operation;
        Err(CliError::ClientServiceUnsupported)
    }
}

fn emit_service_state(state: ServiceState, json: bool) -> Result<(), CliError> {
    let state = service_state_name(state);
    if json {
        #[derive(Serialize)]
        struct ServiceStateOutput<'a> {
            service: &'a str,
        }
        emit_json(&ServiceStateOutput { service: state })
    } else {
        write_stdout_line(&format!("service: {state}"))
    }
}

fn service_state_name(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Running => "running",
        ServiceState::Stopped => "stopped",
        ServiceState::Starting => "starting",
        ServiceState::Stopping => "stopping",
        ServiceState::Failed => "failed",
        ServiceState::Unknown => "unknown",
    }
}

fn emit_client_snapshot(snapshot: &ClientSnapshot, json: bool) -> Result<(), CliError> {
    if json {
        return write_stdout_line(&render_client_json(snapshot));
    }

    let service = match snapshot.service {
        crate::model::LocalServiceState::Running => "running",
        crate::model::LocalServiceState::Stopped => "stopped",
        crate::model::LocalServiceState::Failed => "failed",
    };
    let tunnel = match snapshot.tunnel {
        crate::model::LocalTunnelState::Connected => "connected",
        crate::model::LocalTunnelState::Reconnecting => "reconnecting",
        crate::model::LocalTunnelState::Error => "error",
    };
    let socks_listen = snapshot
        .socks_listen
        .map(|address| address.to_string())
        .unwrap_or_else(|| "unavailable".to_owned());
    let error = snapshot.error.as_deref().unwrap_or("none");
    let output = format!(
        "service: {service}\ntunnel: {tunnel}\nsocks: {socks_listen}\ncarriers: {}/{}\nversion: {}\nerror: {error}",
        snapshot.live_carriers, snapshot.configured_carriers, snapshot.version,
    );
    write_stdout_line(&output)
}

fn emit_client_config(config: &ClientConfig, json: bool) -> Result<(), CliError> {
    if json {
        return emit_json(config);
    }

    let endpoint = config
        .server_addr
        .map(|address| address.to_string())
        .unwrap_or_else(|| "DHT discovery".to_owned());
    write_stdout_line(&format!(
        "server endpoint: {endpoint}\nsocks: {}\ncarriers: {}\nallow unauthenticated LAN SOCKS: {}",
        config.socks_listen, config.carriers, config.allow_unauthenticated_lan_socks,
    ))
}

async fn run_client_dashboard(paths: ClientPaths) -> Result<(), CliError> {
    let mut feedback = None;
    loop {
        match run_client_tui(paths.clone(), feedback.take()).await? {
            ClientTuiAction::Quit => return Ok(()),
            ClientTuiAction::Refresh => continue,
            ClientTuiAction::CheckUpdate => {
                feedback = Some(run_dashboard_update(ClientUpdateCommand::Check).await);
            }
            ClientTuiAction::InstallUpdate { version } => {
                feedback = Some(
                    run_dashboard_update(ClientUpdateCommand::Install {
                        target_version: version,
                    })
                    .await,
                );
            }
            action => execute_client_tui_action(action).await?,
        }
    }
}

#[derive(Debug)]
struct ManagedClientUpdatePayload {
    install_root: PathBuf,
    payload: PathBuf,
    updater: PathBuf,
}

async fn execute_client_update(command: ClientUpdateCommand) -> Result<(), CliError> {
    let result = run_client_update(command).await?;
    write_stdout_line(&serde_json::to_string(&result)?)
}

async fn run_dashboard_update(command: ClientUpdateCommand) -> ClientUpdateFeedback {
    match run_client_update(command).await {
        Ok(result) => client_update_feedback(result),
        Err(error) => ClientUpdateFeedback::Failed {
            message: client_update_error_message(&error),
        },
    }
}

async fn run_client_update(command: ClientUpdateCommand) -> Result<UpdaterResult, CliError> {
    tokio::task::spawn_blocking(move || run_client_update_blocking(command))
        .await
        .map_err(|source| CliError::ClientUpdateTask { source })?
}

fn run_client_update_blocking(command: ClientUpdateCommand) -> Result<UpdaterResult, CliError> {
    let payload = managed_client_update_payload()?;
    if matches!(&command, ClientUpdateCommand::Install { .. }) && !is_elevated()? {
        return run_client_update_via_privilege_handoff(payload.payload, command);
    }
    run_client_update_from_payload(&payload, command)
}

fn managed_client_update_payload() -> Result<ManagedClientUpdatePayload, CliError> {
    let install_root = ClientPaths::install_root();
    let install_root =
        fs::canonicalize(&install_root).map_err(|source| CliError::ClientUpdatePath {
            path: install_root,
            source,
        })?;
    let current = std::env::current_exe().map_err(CliError::CurrentExecutable)?;
    let current = fs::canonicalize(&current).map_err(|source| CliError::ClientUpdatePath {
        path: current,
        source,
    })?;
    let active = read_active_release(&install_root)
        .map_err(|source| CliError::ClientUpdateActiveRelease { source })?;
    let active_payload = active
        .payload_executable(&install_root)
        .map_err(|source| CliError::ClientUpdateActivePayload { source })?;
    let active_payload =
        fs::canonicalize(&active_payload).map_err(|source| CliError::ClientUpdatePath {
            path: active_payload,
            source,
        })?;
    if current != active_payload {
        return Err(CliError::ClientUpdateInactivePayload);
    }

    let updater =
        active_payload.with_file_name(format!("rqbit-tunnel-updater{}", current_exe_suffix()));
    let metadata = fs::metadata(&updater).map_err(|source| CliError::ClientUpdatePath {
        path: updater.clone(),
        source,
    })?;
    #[cfg(unix)]
    let executable = metadata.is_file() && metadata.permissions().mode() & 0o111 != 0;
    #[cfg(not(unix))]
    let executable = metadata.is_file();
    if !executable {
        return Err(CliError::ClientUpdateUpdaterMissing { path: updater });
    }

    Ok(ManagedClientUpdatePayload {
        install_root,
        payload: active_payload,
        updater,
    })
}

fn run_client_update_via_privilege_handoff(
    payload: PathBuf,
    command: ClientUpdateCommand,
) -> Result<UpdaterResult, CliError> {
    #[cfg(unix)]
    {
        let output = ProcessCommand::new("sudo")
            .arg("--")
            .arg(&payload)
            .args(client_update_arguments(&command))
            .output()
            .map_err(|source| CliError::ClientUpdateLaunch {
                program: OsString::from("sudo"),
                source,
            })?;
        return decode_updater_output(output);
    }

    #[cfg(not(unix))]
    {
        let _ = (payload, command);
        Err(CliError::ElevationRequired)
    }
}

fn run_client_update_from_payload(
    payload: &ManagedClientUpdatePayload,
    command: ClientUpdateCommand,
) -> Result<UpdaterResult, CliError> {
    let temporary_updater = prepare_temporary_updater(&payload.updater)?;
    let temporary_path = temporary_updater.to_path_buf();
    let output = ProcessCommand::new(&temporary_path)
        .args(updater_arguments(&payload.install_root, &command))
        .output()
        .map_err(|source| CliError::ClientUpdateLaunch {
            program: temporary_path.into_os_string(),
            source,
        })?;
    decode_updater_output(output)
}

fn prepare_temporary_updater(updater: &Path) -> Result<tempfile::TempPath, CliError> {
    let mut temporary = tempfile::Builder::new()
        .prefix("rqbit-tunnel-updater-")
        .suffix(current_exe_suffix())
        .tempfile()
        .map_err(|source| CliError::ClientUpdatePrepare { source })?;
    let mut source =
        fs::File::open(updater).map_err(|source| CliError::ClientUpdatePrepare { source })?;
    io::copy(&mut source, temporary.as_file_mut())
        .map_err(|source| CliError::ClientUpdatePrepare { source })?;
    #[cfg(unix)]
    {
        let mut permissions = temporary
            .as_file()
            .metadata()
            .map_err(|source| CliError::ClientUpdatePrepare { source })?
            .permissions();
        permissions.set_mode(0o700);
        temporary
            .as_file()
            .set_permissions(permissions)
            .map_err(|source| CliError::ClientUpdatePrepare { source })?;
    }
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| CliError::ClientUpdatePrepare { source })?;
    Ok(temporary.into_temp_path())
}

fn updater_arguments(install_root: &Path, command: &ClientUpdateCommand) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("--install-root"),
        install_root.as_os_str().to_os_string(),
    ];
    match command {
        ClientUpdateCommand::Check => arguments.push(OsString::from("check")),
        ClientUpdateCommand::Install { target_version } => {
            arguments.push(OsString::from("install"));
            arguments.push(OsString::from("--target-version"));
            arguments.push(OsString::from(target_version));
        }
    }
    arguments
}

#[cfg(unix)]
fn client_update_arguments(command: &ClientUpdateCommand) -> Vec<OsString> {
    let mut arguments = vec![OsString::from("client"), OsString::from("update")];
    match command {
        ClientUpdateCommand::Check => arguments.push(OsString::from("check")),
        ClientUpdateCommand::Install { target_version } => {
            arguments.push(OsString::from("install"));
            arguments.push(OsString::from("--target-version"));
            arguments.push(OsString::from(target_version));
        }
    }
    arguments
}

fn decode_updater_output(output: std::process::Output) -> Result<UpdaterResult, CliError> {
    let result = serde_json::from_slice::<UpdaterResult>(&output.stdout)
        .map_err(|source| CliError::ClientUpdateDecode { source })?;
    if !output.status.success() && !matches!(result, UpdaterResult::Failed { .. }) {
        return Err(CliError::ClientUpdateUnexpectedExit {
            status: output.status,
        });
    }
    Ok(result)
}

fn client_update_feedback(result: UpdaterResult) -> ClientUpdateFeedback {
    match result {
        UpdaterResult::UpdateAvailable { version } => ClientUpdateFeedback::Available {
            version: version.to_string(),
        },
        UpdaterResult::Installed { version } => ClientUpdateFeedback::Installed {
            version: version.to_string(),
        },
        UpdaterResult::NoUpdate => ClientUpdateFeedback::NoUpdate,
        UpdaterResult::Failed { code } => ClientUpdateFeedback::Failed {
            message: client_update_failure_message(code).to_owned(),
        },
    }
}

fn client_update_failure_message(code: UpdaterFailureCode) -> &'static str {
    match code {
        UpdaterFailureCode::InvalidSignature => {
            "release signature was invalid; no update was installed"
        }
        UpdaterFailureCode::InvalidManifest | UpdaterFailureCode::TargetVersionMismatch => {
            "release metadata was invalid; no update was installed"
        }
        UpdaterFailureCode::UnsupportedAbi => {
            "this bundle's launcher is too old; install a newer bundle manually"
        }
        UpdaterFailureCode::UnsupportedPlatform => {
            "no signed release is available for this platform"
        }
        UpdaterFailureCode::Checksum => {
            "downloaded release checksum did not match; retry the update"
        }
        UpdaterFailureCode::Download => "could not download the signed release; retry the update",
        UpdaterFailureCode::Staging => {
            "could not safely stage the release; no update was installed"
        }
        UpdaterFailureCode::UpdateInProgress => {
            "another update is already in progress; wait for it to finish"
        }
        UpdaterFailureCode::Service => {
            "could not stop or restart the managed service; no update was installed"
        }
        UpdaterFailureCode::HealthTimeout => {
            "updated client did not become healthy; inspect the managed-client logs"
        }
        UpdaterFailureCode::RolledBack => {
            "updated client did not become healthy; the old version was restored"
        }
        UpdaterFailureCode::RollbackFailed => {
            "update rollback needs manual recovery; inspect the managed-client logs"
        }
        UpdaterFailureCode::InvalidRequest => "updater request was invalid",
    }
}

fn client_update_error_message(error: &CliError) -> String {
    match error {
        CliError::ElevationRequired => {
            "update needs administrator approval; reopen client control through its launcher"
                .to_owned()
        }
        CliError::ClientUpdateInactivePayload
        | CliError::ClientUpdatePath { .. }
        | CliError::ClientUpdateActiveRelease { .. }
        | CliError::ClientUpdateActivePayload { .. }
        | CliError::ClientUpdateUpdaterMissing { .. } => {
            "managed update helper is unavailable; reinstall the current bundle".to_owned()
        }
        _ => "could not start the signed updater; retry or reinstall the current bundle".to_owned(),
    }
}

async fn execute_client_tui_action(action: ClientTuiAction) -> Result<(), CliError> {
    match action {
        ClientTuiAction::Quit | ClientTuiAction::Refresh => Ok(()),
        ClientTuiAction::Logs => show_client_logs(),
        ClientTuiAction::Import { bundle } => {
            let command = ClientCommand::Import(ClientImportOptions {
                bundle: bundle.clone(),
                json: false,
            });
            let arguments = client_invocation(vec![
                OsString::from("client"),
                OsString::from("import"),
                OsString::from("--bundle"),
                bundle.into_os_string(),
            ])?;
            execute_client_tui_mutation(command, &arguments).await
        }
        ClientTuiAction::Configure(update) => {
            let changes = client_config_changes_from_tui(update)?;
            let arguments = client_config_invocation(&changes)?;
            execute_client_tui_mutation(
                ClientCommand::Config(ClientConfigCommand::Set(changes)),
                &arguments,
            )
            .await
        }
        ClientTuiAction::Start => execute_client_service_action(ClientServiceCommand::Start).await,
        ClientTuiAction::Stop => execute_client_service_action(ClientServiceCommand::Stop).await,
        ClientTuiAction::EnableAutostart => {
            execute_client_service_action(ClientServiceCommand::EnableAutostart).await
        }
        ClientTuiAction::DisableAutostart => {
            execute_client_service_action(ClientServiceCommand::DisableAutostart).await
        }
        ClientTuiAction::CheckUpdate | ClientTuiAction::InstallUpdate { .. } => {
            unreachable!("dashboard dispatches update actions directly")
        }
    }
}

async fn execute_client_service_action(command: ClientServiceCommand) -> Result<(), CliError> {
    let operation = match command {
        ClientServiceCommand::Start => "start",
        ClientServiceCommand::Stop => "stop",
        ClientServiceCommand::EnableAutostart => "enable-autostart",
        ClientServiceCommand::DisableAutostart => "disable-autostart",
        _ => unreachable!("client TUI only emits mutating service actions"),
    };
    let arguments = client_invocation(vec![
        OsString::from("client"),
        OsString::from("service"),
        OsString::from(operation),
    ])?;
    execute_client_tui_mutation(ClientCommand::Service(command), &arguments).await
}

fn client_config_changes_from_tui(
    update: ClientTuiConfigUpdate,
) -> Result<ClientConfigSetOptions, CliError> {
    Ok(ClientConfigSetOptions {
        server_addr: parse_tui_socket("server address", update.server_addr)?,
        socks_listen: parse_tui_socket("SOCKS listener", update.socks_listen)?,
        carriers: parse_tui_usize("carrier count", update.carriers)?,
        allow_unauthenticated_lan_socks: update.allow_unauthenticated_lan_socks,
        json: false,
    })
}

fn parse_tui_socket(
    name: &'static str,
    value: Option<String>,
) -> Result<Option<SocketAddr>, CliError> {
    value
        .map(|value| {
            value
                .parse::<SocketAddr>()
                .map_err(|error| CliError::InvalidClientSetting {
                    name,
                    value,
                    reason: error.to_string(),
                })
        })
        .transpose()
}

fn parse_tui_usize(name: &'static str, value: Option<String>) -> Result<Option<usize>, CliError> {
    value
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|error| CliError::InvalidClientSetting {
                    name,
                    value,
                    reason: error.to_string(),
                })
        })
        .transpose()
}

fn client_config_invocation(changes: &ClientConfigSetOptions) -> Result<Vec<OsString>, CliError> {
    let mut arguments = vec![
        OsString::from("client"),
        OsString::from("config"),
        OsString::from("set"),
    ];
    if let Some(server_addr) = changes.server_addr {
        arguments.push(OsString::from("--server-addr"));
        arguments.push(server_addr.to_string().into());
    }
    if let Some(socks_listen) = changes.socks_listen {
        arguments.push(OsString::from("--socks-listen"));
        arguments.push(socks_listen.to_string().into());
    }
    if let Some(carriers) = changes.carriers {
        arguments.push(OsString::from("--carriers"));
        arguments.push(carriers.to_string().into());
    }
    if let Some(allow_lan_socks) = changes.allow_unauthenticated_lan_socks {
        arguments.push(OsString::from("--allow-unauthenticated-lan-socks"));
        arguments.push(allow_lan_socks.to_string().into());
    }
    client_invocation(arguments)
}

fn client_invocation(arguments: Vec<OsString>) -> Result<Vec<OsString>, CliError> {
    let mut invocation = Vec::with_capacity(arguments.len() + 1);
    invocation.push(
        std::env::current_exe()
            .map_err(CliError::CurrentExecutable)?
            .into_os_string(),
    );
    invocation.extend(arguments);
    Ok(invocation)
}

fn show_client_logs() -> Result<(), CliError> {
    #[cfg(target_os = "linux")]
    {
        let status = ProcessCommand::new("journalctl")
            .args(["--unit", CLIENT_SERVICE, "--no-pager", "--lines", "100"])
            .status()
            .map_err(|source| CliError::ClientLogs { source })?;
        if status.success() {
            Ok(())
        } else {
            Err(CliError::ClientLogsFailed { status })
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(CliError::ClientLogsUnsupported)
    }
}

#[cfg(unix)]
async fn run_server(options: ServerRunOptions) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        let mut signals = RegisteredShutdownSignals::register()?;
        let server = ManagedServer::start(server_paths_from_config(&options.config)?).await?;
        let control_exit = tokio::select! {
            _ = signals.wait() => None,
            result = server.wait_for_control_exit() => Some(result),
        };
        server.shutdown().await?;
        match control_exit {
            Some(result) => unexpected_control_exit(result),
            None => Ok(()),
        }
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

#[cfg(unix)]
fn unexpected_control_exit(control_exit: Result<(), ServerRuntimeError>) -> Result<(), CliError> {
    control_exit?;
    Err(CliError::ControlExited)
}

#[cfg(unix)]
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

fn client_paths_from_config(config: &Path) -> Result<ClientPaths, CliError> {
    if config.file_name() != Some(OsStr::new("client.json")) {
        return Err(CliError::UnsupportedClientConfigPath {
            path: config.to_path_buf(),
        });
    }
    let Some(config_dir) = config.parent() else {
        return Err(CliError::UnsupportedClientConfigPath {
            path: config.to_path_buf(),
        });
    };
    let mut paths = ClientPaths::system();
    paths.config_dir = config_dir.to_path_buf();
    Ok(paths)
}

#[cfg(unix)]
fn control_socket_path(socket: Option<PathBuf>) -> PathBuf {
    socket.unwrap_or_else(|| ServerPaths::system().control_socket_path())
}

#[cfg(unix)]
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
                    if let Some(status) = bundle_export_status(&error) {
                        emit_bundle_export_diagnostics(&export, status);
                    }
                    return Err(error.into());
                }
            };
            let user = expect_user(response)?;
            emit_bundle_export_diagnostics(&export, BundleExportStatus::Written);
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

#[cfg(unix)]
async fn execute_settings(socket: PathBuf, command: ServerSettingsCommand) -> Result<(), CliError> {
    match command {
        ServerSettingsCommand::Show { json } => {
            let settings = expect_config(request_server(&socket, ServerRequest::GetConfig).await?)?;
            emit_settings(&settings, json)
        }
        ServerSettingsCommand::Set { config, json } => {
            let contents = read_server_settings_file(config.clone()).await?;
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

#[cfg(unix)]
async fn read_server_settings_file(path: PathBuf) -> Result<Vec<u8>, CliError> {
    tokio::task::spawn_blocking(move || read_server_settings_file_blocking(path))
        .await
        .map_err(CliError::SettingsReadTask)?
        .map_err(CliError::SettingsFile)
}

#[cfg(unix)]
fn read_server_settings_file_blocking(path: PathBuf) -> Result<Vec<u8>, SettingsFileError> {
    read_server_settings_file_blocking_after_inspection(path, || {})
}

#[cfg(unix)]
fn read_server_settings_file_blocking_after_inspection<F>(
    path: PathBuf,
    after_inspection: F,
) -> Result<Vec<u8>, SettingsFileError>
where
    F: FnOnce(),
{
    let inspected = fs::symlink_metadata(&path).map_err(|source| SettingsFileError::Inspect {
        path: path.clone(),
        source,
    })?;
    if !inspected.file_type().is_file() {
        return Err(SettingsFileError::NotRegular { path });
    }
    after_inspection();

    #[cfg(unix)]
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|source| SettingsFileError::Read {
            path: path.clone(),
            source,
        })?;

    let metadata = file.metadata().map_err(|source| SettingsFileError::Read {
        path: path.clone(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(SettingsFileError::NotRegular { path });
    }
    if metadata.len() > MAX_SERVER_SETTINGS_BYTES {
        return Err(SettingsFileError::TooLarge {
            path,
            limit: MAX_SERVER_SETTINGS_BYTES,
        });
    }

    let mut contents = Vec::with_capacity(metadata.len() as usize);
    let mut reader = file.take(MAX_SERVER_SETTINGS_BYTES + 1);
    reader
        .read_to_end(&mut contents)
        .map_err(|source| SettingsFileError::Read {
            path: path.clone(),
            source,
        })?;
    if contents.len() as u64 > MAX_SERVER_SETTINGS_BYTES {
        return Err(SettingsFileError::TooLarge {
            path,
            limit: MAX_SERVER_SETTINGS_BYTES,
        });
    }
    Ok(contents)
}

#[cfg(unix)]
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

#[cfg(unix)]
fn expect_user(response: ServerResponse) -> Result<UserSnapshot, CliError> {
    let ServerResponse::User(user) = response else {
        return Err(CliError::UnexpectedResponse {
            expected: "a user",
            received: response,
        });
    };
    Ok(user)
}

#[cfg(unix)]
fn expect_deleted(response: ServerResponse) -> Result<Uuid, CliError> {
    let ServerResponse::Deleted { id } = response else {
        return Err(CliError::UnexpectedResponse {
            expected: "a deleted user confirmation",
            received: response,
        });
    };
    Ok(id)
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BundleExportStatus {
    Written,
    TransportUncertain,
    DurabilityUncertain,
}

#[cfg(unix)]
fn bundle_export_status(error: &ControlError) -> Option<BundleExportStatus> {
    match error {
        #[cfg(unix)]
        ControlError::Unix(_) => Some(BundleExportStatus::TransportUncertain),
        ControlError::Server { code, .. } if code == "bundle_durability_uncertain" => {
            Some(BundleExportStatus::DurabilityUncertain)
        }
        _ => None,
    }
}

#[cfg(unix)]
fn bundle_export_diagnostics(export: &Path, status: BundleExportStatus) -> [String; 2] {
    match status {
        BundleExportStatus::Written => [
            format!("Enrollment bundle written to {}", export.display()),
            "WARNING: this bundle contains an unencrypted client secret; protect it until import."
                .to_owned(),
        ],
        BundleExportStatus::TransportUncertain => [
            format!(
                "Enrollment bundle may have been created at {}",
                export.display()
            ),
            "WARNING: control transport failed after dispatch; an unencrypted client secret may have been created. Inspect the destination before retrying.".to_owned(),
        ],
        BundleExportStatus::DurabilityUncertain => [
            format!(
                "Enrollment bundle destination may contain the bundle: {}",
                export.display()
            ),
            "WARNING: this bundle contains an unencrypted client secret; its durability is uncertain, so inspect the destination before retrying.".to_owned(),
        ],
    }
}

#[cfg(unix)]
fn emit_bundle_export_diagnostics(export: &Path, status: BundleExportStatus) {
    for diagnostic in bundle_export_diagnostics(export, status) {
        eprintln!("{diagnostic}");
    }
}

#[cfg(unix)]
fn emit_response_json(response: &ServerResponse) -> Result<(), CliError> {
    write_stdout_line(&render_json(response))
}

#[cfg(unix)]
fn emit_user(user: &UserSnapshot, json: bool) -> Result<(), CliError> {
    if json {
        emit_json(user)
    } else {
        write_stdout_line(&format_user(user))
    }
}

#[cfg(unix)]
fn emit_users(users: &[UserSnapshot]) -> Result<(), CliError> {
    let mut output = io::stdout().lock();
    for user in users {
        writeln!(output, "{}", format_user(user)).map_err(CliError::Output)?;
    }
    output.flush().map_err(CliError::Output)
}

#[cfg(unix)]
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

#[cfg(unix)]
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
    use std::os::unix::fs::symlink;
    use std::{ffi::OsString, path::PathBuf};
    #[cfg(unix)]
    use std::{fs, io};

    #[cfg(unix)]
    use std::{ffi::CString, os::unix::ffi::OsStrExt, time::Duration};

    #[cfg(unix)]
    use super::RegisteredShutdownSignals;

    #[cfg(not(unix))]
    use super::{ServerRunOptions, execute_server};
    #[cfg(unix)]
    use crate::ipc::unix::UnixControlError;
    #[cfg(unix)]
    use std::path::Path;

    use crate::model::{ClientSnapshot, LocalServiceState, LocalTunnelState};
    #[cfg(unix)]
    use crate::{
        ipc::protocol::ServerResponse,
        model::{TrafficTotals, UserSnapshot},
    };

    #[cfg(unix)]
    use super::read_server_settings_file_blocking_after_inspection;
    #[cfg(unix)]
    use super::unexpected_control_exit;
    #[cfg(unix)]
    use super::{
        BundleExportStatus, SettingsFileError, bundle_export_diagnostics, bundle_export_status,
        read_server_settings_file, render_json,
    };
    use super::{
        Cli, CliError, ClientCommand, ClientUpdateCommand, Command, ControlError, ServerCommand,
        ServerSettingsCommand, ServerUsersCommand, TrayCommand, render_client_json,
        updater_arguments, windows_client_service_install_spec_from_payload,
    };
    #[cfg(not(windows))]
    use super::{ClientPayloadHostOptions, execute_client_operation};

    #[cfg(unix)]
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

    #[cfg(unix)]
    #[test]
    fn list_users_json_is_machine_readable_without_terminal_escape_bytes() {
        let stdout = render_json(&ServerResponse::Users(vec![sample_user()]));
        assert!(!stdout.contains('\u{1b}'));
        assert_eq!(
            serde_json::from_str::<Vec<UserSnapshot>>(&stdout).unwrap()[0].name,
            "alice"
        );
    }

    fn sample_client_snapshot() -> ClientSnapshot {
        ClientSnapshot {
            service: LocalServiceState::Running,
            tunnel: LocalTunnelState::Connected,
            socks_listen: Some("127.0.0.1:1080".parse().unwrap()),
            configured_carriers: 4,
            live_carriers: 4,
            version: "rqbit-tunnel test".to_owned(),
            error: None,
        }
    }

    #[test]
    fn client_service_status_json_has_stable_state_names_and_no_key_material() {
        let stdout = render_client_json(&sample_client_snapshot());
        let rendered: serde_json::Value = serde_json::from_str(&stdout).unwrap();

        assert_eq!(rendered["service"], "running");
        assert_eq!(rendered["tunnel"], "connected");
        assert!(serde_json::from_str::<ClientSnapshot>(&stdout).is_ok());
        assert!(!stdout.contains("client_private_key"));
    }

    #[test]
    fn update_failures_are_reduced_to_non_sensitive_dashboard_messages() {
        let feedback =
            super::client_update_feedback(crate::update::orchestrator::UpdaterResult::Failed {
                code: crate::update::orchestrator::UpdaterFailureCode::Checksum,
            });

        assert_eq!(
            feedback,
            crate::tui::client::ClientUpdateFeedback::Failed {
                message: "downloaded release checksum did not match; retry the update".to_owned(),
            }
        );
    }

    #[test]
    fn concurrent_update_failure_has_actionable_dashboard_feedback() {
        let feedback =
            super::client_update_feedback(crate::update::orchestrator::UpdaterResult::Failed {
                code: crate::update::orchestrator::UpdaterFailureCode::UpdateInProgress,
            });

        assert_eq!(
            feedback,
            crate::tui::client::ClientUpdateFeedback::Failed {
                message: "another update is already in progress; wait for it to finish".to_owned(),
            }
        );
    }

    #[test]
    fn client_update_install_requires_an_explicit_target_version() {
        assert!(matches!(
            Cli::try_parse_from([
                "rqbit-tunnel",
                "client",
                "update",
                "install",
                "--target-version",
                "1.2.3",
            ]),
            Ok(Cli {
                command: Command::Client(ClientCommand::Update(ClientUpdateCommand::Install {
                    target_version
                }))
            }) if target_version == "1.2.3"
        ));
        assert!(Cli::try_parse_from(["rqbit-tunnel", "client", "update", "install"]).is_err());
    }

    #[test]
    fn temporary_updater_receives_its_own_direct_subcommand() {
        let arguments = updater_arguments(
            &PathBuf::from("/opt/rqbit-tunnel"),
            &ClientUpdateCommand::Install {
                target_version: "1.2.3".to_owned(),
            },
        );

        assert_eq!(
            arguments,
            vec![
                OsString::from("--install-root"),
                OsString::from("/opt/rqbit-tunnel"),
                OsString::from("install"),
                OsString::from("--target-version"),
                OsString::from("1.2.3"),
            ]
        );
    }

    #[test]
    fn parses_hidden_client_payload_host_command_without_an_scm_fallback() {
        assert!(
            Cli::try_parse_from([
                "rqbit-tunnel",
                "client",
                "payload-host",
                "--config",
                r"C:\ProgramData\rqbit-tunnel\client.json",
                "--launcher-ready-event",
                r"Local\rqbit-tunnel-launcher-test-ready",
                "--launcher-stop-event",
                r"Local\rqbit-tunnel-launcher-test-stop",
            ])
            .is_ok(),
            "the versioned worker needs a private non-SCM payload-host command"
        );
        assert!(
            Cli::try_parse_from(["rqbit-tunnel", "client", "service-host"]).is_err(),
            "only the stable launcher may own the SCM service-host role"
        );
    }

    #[test]
    fn tray_commands_parse_as_a_user_session_role() {
        assert!(matches!(
            Cli::try_parse_from(["rqbit-tunnel", "tray"]),
            Ok(Cli {
                command: Command::Tray(TrayCommand::Run)
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["rqbit-tunnel", "tray", "enable-autostart"]),
            Ok(Cli {
                command: Command::Tray(TrayCommand::EnableAutostart)
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["rqbit-tunnel", "tray", "disable-autostart"]),
            Ok(Cli {
                command: Command::Tray(TrayCommand::DisableAutostart)
            })
        ));
    }

    #[test]
    fn registered_windows_client_service_targets_the_stable_launcher() {
        let spec = windows_client_service_install_spec_from_payload(&PathBuf::from(
            "/opt/rqbit-tunnel/releases/1.2.3/payload/rqbit-tunnel.exe",
        ))
        .unwrap();

        assert_eq!(
            spec.executable,
            PathBuf::from("/opt/rqbit-tunnel/launcher.exe")
        );
        assert_eq!(
            spec.arguments,
            vec![OsString::from("client"), OsString::from("service-host"),]
        );
        assert_eq!(spec.working_directory, PathBuf::from("/opt/rqbit-tunnel"));
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn client_payload_host_is_typed_unsupported_outside_windows() {
        let error =
            execute_client_operation(ClientCommand::PayloadHost(ClientPayloadHostOptions {
                config: PathBuf::from("/etc/rqbit-tunnel/client.json"),
                launcher_ready_event: "Local\\rqbit-tunnel-launcher-test-ready".to_owned(),
                launcher_stop_event: "Local\\rqbit-tunnel-launcher-test-stop".to_owned(),
            }))
            .await
            .unwrap_err();
        assert!(matches!(error, CliError::ClientPayloadHostUnsupported));
    }

    #[cfg(unix)]
    #[test]
    fn durability_uncertain_bundle_diagnostics_include_destination_and_secret_warning() {
        let error = ControlError::Server {
            code: "bundle_durability_uncertain".to_owned(),
            message: "bundle sync failed".to_owned(),
            recovery: "inspect the destination".to_owned(),
        };

        assert_eq!(
            bundle_export_status(&error),
            Some(BundleExportStatus::DurabilityUncertain)
        );
        let diagnostics = bundle_export_diagnostics(
            Path::new("/secure/alice.bundle"),
            BundleExportStatus::DurabilityUncertain,
        );
        assert!(diagnostics[0].contains("/secure/alice.bundle"));
        assert!(diagnostics[1].contains("unencrypted client secret"));
        assert!(diagnostics[1].contains("durability is uncertain"));
    }

    #[cfg(unix)]
    #[test]
    fn transport_uncertain_bundle_diagnostics_warn_before_error_propagates() {
        let error = ControlError::Unix(UnixControlError::Read(io::Error::other("peer closed")));

        assert_eq!(
            bundle_export_status(&error),
            Some(BundleExportStatus::TransportUncertain)
        );
        let diagnostics = bundle_export_diagnostics(
            Path::new("/secure/alice.bundle"),
            BundleExportStatus::TransportUncertain,
        );
        assert!(diagnostics[0].contains("/secure/alice.bundle"));
        assert!(diagnostics[1].contains("unencrypted client secret may have been created"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn registers_server_shutdown_signals() {
        let _signals = RegisteredShutdownSignals::register().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn clean_control_exit_is_an_error_for_the_foreground_server() {
        assert!(matches!(
            unexpected_control_exit(Ok(())),
            Err(CliError::ControlExited)
        ));
    }

    #[cfg(not(unix))]
    #[tokio::test]
    async fn server_commands_are_typed_unsupported_off_unix() {
        let error = execute_server(ServerCommand::Run(ServerRunOptions {
            config: PathBuf::from("/etc/rqbit-tunnel/server.json"),
        }))
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            CliError::Control(ControlError::UnsupportedPlatform)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn settings_reader_rejects_a_directory() {
        let directory = tempfile::tempdir().unwrap();
        let error = read_server_settings_file(directory.path().to_path_buf())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            CliError::SettingsFile(SettingsFileError::NotRegular { .. })
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn settings_reader_rejects_a_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("settings.json");
        fs::write(&target, b"{}").unwrap();
        let link = directory.path().join("settings-link.json");
        symlink(&target, &link).unwrap();

        let error = read_server_settings_file(PathBuf::from(&link))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            CliError::SettingsFile(SettingsFileError::NotRegular { .. })
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn settings_reader_rejects_fifo_replaced_after_inspection_without_blocking() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        fs::write(&path, b"{}").unwrap();
        let read_path = path.clone();
        let replacement_path = path.clone();
        let (ready, ready_signal) = tokio::sync::oneshot::channel();
        let mut reader = tokio::task::spawn_blocking(move || {
            read_server_settings_file_blocking_after_inspection(read_path, move || {
                fs::remove_file(&replacement_path).unwrap();
                let fifo_path = CString::new(replacement_path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
                ready.send(()).unwrap();
            })
        });

        tokio::time::timeout(Duration::from_secs(1), ready_signal)
            .await
            .expect("reader must reach the post-inspection replacement hook")
            .expect("replacement hook sender must stay connected");
        let result = match tokio::time::timeout(Duration::from_millis(100), &mut reader).await {
            Ok(joined) => joined.unwrap(),
            Err(_) => {
                let writer_path = path.clone();
                let writer = tokio::task::spawn_blocking(move || {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(writer_path)
                        .unwrap();
                });
                writer.await.unwrap();
                let _ = reader.await.unwrap();
                panic!("settings reader blocked while opening a substituted FIFO");
            }
        };

        assert!(matches!(result, Err(SettingsFileError::NotRegular { .. })));
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
