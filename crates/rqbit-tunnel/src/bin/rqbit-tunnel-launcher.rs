use std::{
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use rqbit_tunnel::version::{
    ActiveReleaseError, LAUNCHER_ABI, read_active_release, resolve_payload_executable,
};
use thiserror::Error;

const USAGE: &str = "Usage: rqbit-tunnel-launcher [--] <server|client|tray> [ARGS...]\n\nRuns the selected immutable rqbit-tunnel release.";

fn main() -> ExitCode {
    match run(std::env::args_os().collect()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("rqbit-tunnel-launcher: {error}");
            ExitCode::FAILURE
        }
    }
}

enum ParsedInvocation<'a> {
    Help,
    Payload { payload_arguments: &'a [OsString] },
    Tray { companion_arguments: &'a [OsString] },
}

fn parse_invocation(arguments: &[OsString]) -> Result<ParsedInvocation<'_>, LauncherError> {
    let arguments = if arguments.first().is_some_and(|argument| argument == "--") {
        &arguments[1..]
    } else {
        arguments
    };

    // Only top-level help avoids reading active.json. A role-specific help
    // flag belongs to the payload's CLI and is forwarded unchanged.
    if arguments.len() == 1 && (arguments[0] == "--help" || arguments[0] == "-h") {
        return Ok(ParsedInvocation::Help);
    }

    let Some(role) = arguments.first() else {
        return Err(LauncherError::MissingRole);
    };
    if role == "tray" {
        return Ok(ParsedInvocation::Tray {
            companion_arguments: &arguments[1..],
        });
    }
    if !matches!(role.as_os_str(), role if role == "server" || role == "client") {
        return Err(LauncherError::UnsupportedRole { role: role.clone() });
    }

    Ok(ParsedInvocation::Payload {
        payload_arguments: arguments,
    })
}

fn run(arguments: Vec<OsString>) -> Result<ExitCode, LauncherError> {
    let invocation = parse_invocation(arguments.get(1..).unwrap_or(&[]))?;
    match invocation {
        ParsedInvocation::Help => {
            println!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        ParsedInvocation::Payload { payload_arguments } => {
            #[cfg(windows)]
            if payload_arguments
                .first()
                .is_some_and(|argument| argument == "client")
                && payload_arguments
                    .get(1)
                    .is_some_and(|argument| argument == "service-host")
            {
                if payload_arguments.len() != 2 {
                    return Err(LauncherError::InvalidServiceHostArguments);
                }
                rqbit_tunnel::windows_launcher::run_client_service_host()?;
                return Ok(ExitCode::SUCCESS);
            }

            execute_payload(active_payload()?, payload_arguments)
        }
        ParsedInvocation::Tray {
            companion_arguments,
        } => {
            let payload = resolve_tray_payload(&active_payload()?)?;
            #[cfg(windows)]
            {
                spawn_windows_tray_payload(payload, companion_arguments)
            }
            #[cfg(not(windows))]
            {
                execute_payload(payload, companion_arguments)
            }
        }
    }
}

fn execute_payload(
    payload: PathBuf,
    payload_arguments: &[OsString],
) -> Result<ExitCode, LauncherError> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        let source = Command::new(&payload).args(payload_arguments).exec();
        return Err(LauncherError::LaunchPayload { payload, source });
    }

    #[cfg(not(unix))]
    {
        let status = Command::new(&payload)
            .args(payload_arguments)
            .status()
            .map_err(|source| LauncherError::LaunchPayload {
                payload: payload.clone(),
                source,
            })?;
        Ok(if status.success() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        })
    }
}

#[cfg(windows)]
fn windows_tray_payload_command(payload: &Path, payload_arguments: &[OsString]) -> Command {
    let mut command = Command::new(payload);
    command.args(payload_arguments);
    command
}

#[cfg(windows)]
fn spawn_windows_tray_payload(
    payload: PathBuf,
    payload_arguments: &[OsString],
) -> Result<ExitCode, LauncherError> {
    windows_tray_payload_command(&payload, payload_arguments)
        .spawn()
        .map_err(|source| LauncherError::LaunchPayload {
            payload: payload.clone(),
            source,
        })?;
    Ok(ExitCode::SUCCESS)
}

fn active_payload() -> Result<PathBuf, LauncherError> {
    let executable = std::env::current_exe().map_err(LauncherError::CurrentExecutable)?;
    let install_root = executable
        .parent()
        .map(PathBuf::from)
        .ok_or(LauncherError::MissingInstallRoot { executable })?;
    let active = read_active_release(&install_root)?;
    if active.launcher_abi() > LAUNCHER_ABI {
        return Err(LauncherError::UnsupportedLauncherAbi {
            required: active.launcher_abi(),
            available: LAUNCHER_ABI,
        });
    }

    resolve_payload_executable(&install_root, active.payload_dir()).map_err(LauncherError::from)
}

fn tray_payload_path(payload: &Path) -> PathBuf {
    payload.with_file_name(tray_payload_name())
}

#[cfg(windows)]
const fn tray_payload_name() -> &'static str {
    "rqbit-tunnel-tray.exe"
}

#[cfg(not(windows))]
const fn tray_payload_name() -> &'static str {
    "rqbit-tunnel-tray"
}

fn resolve_tray_payload(payload: &Path) -> Result<PathBuf, LauncherError> {
    let tray_payload = tray_payload_path(payload);
    let metadata = fs::symlink_metadata(&tray_payload).map_err(|source| {
        LauncherError::InspectTrayPayload {
            path: tray_payload.clone(),
            source,
        }
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(LauncherError::TrayPayloadNotRegular { path: tray_payload });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(LauncherError::TrayPayloadNotExecutable { path: tray_payload });
        }
    }
    Ok(tray_payload)
}

#[derive(Debug, Error)]
enum LauncherError {
    #[error("a server, client, or tray role is required")]
    MissingRole,
    #[error("unsupported launcher role {role:?}; expected server, client, or tray")]
    UnsupportedRole { role: OsString },
    #[error("failed to resolve the stable launcher executable: {0}")]
    CurrentExecutable(#[source] io::Error),
    #[error("stable launcher executable has no installation directory: {executable}")]
    MissingInstallRoot { executable: PathBuf },
    #[error(
        "active release requires launcher ABI {required}, but this launcher provides ABI {available}"
    )]
    UnsupportedLauncherAbi { required: u32, available: u32 },
    #[error("failed to launch active payload {payload}: {source}")]
    LaunchPayload {
        payload: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to inspect tray companion payload {path}: {source}")]
    InspectTrayPayload {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("tray companion payload is not a regular file {path}")]
    TrayPayloadNotRegular { path: PathBuf },
    #[cfg(unix)]
    #[error("tray companion payload is not executable {path}")]
    TrayPayloadNotExecutable { path: PathBuf },
    #[cfg(windows)]
    #[error("Windows client service-host accepts no arguments")]
    InvalidServiceHostArguments,
    #[cfg(windows)]
    #[error(transparent)]
    WindowsClientService(#[from] rqbit_tunnel::windows_launcher::WindowsClientServiceLauncherError),
    #[error(transparent)]
    ActiveRelease(#[from] ActiveReleaseError),
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, fs, path::Path};

    use super::{ParsedInvocation, parse_invocation, resolve_tray_payload, tray_payload_path};

    #[test]
    fn top_level_help_is_handled_without_a_payload_invocation() {
        let arguments = vec![OsString::from("--"), OsString::from("--help")];

        assert!(matches!(
            parse_invocation(&arguments),
            Ok(ParsedInvocation::Help)
        ));
    }

    #[test]
    fn payload_invocation_keeps_the_launcher_role_as_its_first_argument() {
        let arguments = vec![
            OsString::from("client"),
            OsString::from("run"),
            OsString::from("--config"),
            OsString::from("/etc/rqbit-tunnel/client.json"),
        ];

        let ParsedInvocation::Payload { payload_arguments } = parse_invocation(&arguments).unwrap()
        else {
            panic!("client invocation must route to the payload");
        };

        assert_eq!(payload_arguments, arguments.as_slice());
    }

    #[test]
    fn role_specific_help_is_forwarded_to_the_payload() {
        let arguments = vec![OsString::from("client"), OsString::from("--help")];

        let ParsedInvocation::Payload { payload_arguments } = parse_invocation(&arguments).unwrap()
        else {
            panic!("client help must route to the payload");
        };

        assert_eq!(payload_arguments, arguments.as_slice());
    }

    #[test]
    fn tray_selector_is_not_forwarded_to_the_companion() {
        let arguments = vec![OsString::from("tray"), OsString::from("--help")];

        let ParsedInvocation::Tray {
            companion_arguments,
        } = parse_invocation(&arguments).unwrap()
        else {
            panic!("tray invocation must route to the tray companion");
        };

        assert_eq!(companion_arguments, [OsString::from("--help")]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_tray_payload_command_keeps_the_companion_arguments() {
        use std::ffi::OsStr;

        let payload = Path::new(r"C:\Program Files\rqbit-tunnel\payload\rqbit-tunnel-tray.exe");
        let arguments = [OsString::from("--help")];
        let command = super::windows_tray_payload_command(payload, &arguments);

        assert_eq!(command.get_program(), payload.as_os_str());
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![OsStr::new("--help")]
        );
    }

    #[test]
    fn tray_invocation_selects_the_dedicated_tray_payload() {
        assert_eq!(
            tray_payload_path(Path::new(
                "/opt/rqbit-tunnel/releases/1.2.3/payload/rqbit-tunnel"
            )),
            Path::new("/opt/rqbit-tunnel/releases/1.2.3/payload/rqbit-tunnel-tray")
        );
    }

    #[test]
    fn tray_companion_must_be_a_regular_executable_file() {
        let sandbox = tempfile::tempdir().unwrap();
        let payload = sandbox.path().join("rqbit-tunnel");
        let tray_payload = tray_payload_path(&payload);
        fs::write(&tray_payload, b"tray companion").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = fs::metadata(&tray_payload).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&tray_payload, permissions).unwrap();
        }

        assert_eq!(resolve_tray_payload(&payload).unwrap(), tray_payload);
    }
}
