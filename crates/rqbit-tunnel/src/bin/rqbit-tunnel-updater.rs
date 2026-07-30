use std::{ffi::OsString, path::PathBuf, process::ExitCode};

use clap::{Arg, ArgMatches, Command as ClapCommand, error::ErrorKind};
use rqbit_tunnel::{
    paths::ClientPaths,
    update::{
        manifest::{UpdateError, parse_canonical_version, pinned_release_public_key},
        orchestrator::{
            GitHubReleaseSource, LocalClientHealth, Updater, UpdaterFailureCode, UpdaterResult,
            current_platform_target, validate_install_root,
        },
    },
};

struct Arguments {
    operation: Operation,
    install_root: PathBuf,
}

enum Operation {
    Check,
    Install { target_version: String },
}

impl Arguments {
    fn parse<I, T>(arguments: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let matches = updater_command().try_get_matches_from(arguments)?;
        Self::from_matches(&matches)
    }

    fn from_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
        let operation = match matches.subcommand() {
            Some(("check", _)) => Operation::Check,
            Some(("install", install)) => Operation::Install {
                target_version: install
                    .get_one::<String>("target-version")
                    .expect("required target version is present")
                    .clone(),
            },
            _ => {
                return Err(clap::Error::raw(
                    ErrorKind::MissingSubcommand,
                    "an updater subcommand is required",
                ));
            }
        };
        let install_root = matches.get_one::<String>("install-root").ok_or_else(|| {
            clap::Error::raw(
                ErrorKind::MissingRequiredArgument,
                "--install-root is required",
            )
        })?;
        Ok(Self {
            operation,
            install_root: PathBuf::from(install_root),
        })
    }
}

fn updater_command() -> ClapCommand {
    ClapCommand::new("rqbit-tunnel-updater")
        .about("Verify and install rqbit-tunnel releases")
        .arg(
            Arg::new("install-root")
                .long("install-root")
                .value_name("PATH")
                .global(true),
        )
        .subcommand_required(true)
        .subcommand(
            ClapCommand::new("check").about(
                "Verify whether a newer release is available without changing service state",
            ),
        )
        .subcommand(
            ClapCommand::new("install")
                .about("Independently verify, install, and activate this exact release version")
                .arg(
                    Arg::new("target-version")
                        .long("target-version")
                        .value_name("SEMVER")
                        .required(true),
                ),
        )
}

#[tokio::main]
async fn main() -> ExitCode {
    let arguments = match Arguments::parse(std::env::args_os()) {
        Ok(arguments) => arguments,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("{error}");
            return emit(UpdaterResult::Failed {
                code: UpdaterFailureCode::InvalidRequest,
            });
        }
    };

    let result = match execute(arguments).await {
        Ok(result) => result,
        Err(error) => {
            eprintln!("{error}");
            UpdaterResult::from_error(&error)
        }
    };
    emit(result)
}

async fn execute(arguments: Arguments) -> Result<UpdaterResult, UpdateError> {
    #[cfg(target_os = "linux")]
    {
        let service = rqbit_tunnel::platform::linux::LinuxServiceManager::system();
        return execute_with_service(arguments, &service).await;
    }

    #[cfg(windows)]
    {
        let service = rqbit_tunnel::platform::windows::WindowsServiceManager::new();
        return execute_with_service(arguments, &service).await;
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = arguments;
        Err(UpdateError::UnsupportedPlatformTarget)
    }
}

async fn execute_with_service(
    arguments: Arguments,
    service: &dyn rqbit_tunnel::platform::ServiceManager,
) -> Result<UpdaterResult, UpdateError> {
    let install_root = validate_install_root(&arguments.install_root)?;
    let target = current_platform_target()?;
    let source = GitHubReleaseSource::new()?;
    let verification_key = pinned_release_public_key()?;
    let health = LocalClientHealth::system(ClientPaths::system());
    let updater = Updater::new(
        &install_root,
        target,
        verification_key,
        &source,
        service,
        &health,
    )?;

    match arguments.operation {
        Operation::Check => match updater.check().await {
            Ok(result) => Ok(result),
            Err(UpdateError::NoUpdate) => Ok(UpdaterResult::NoUpdate),
            Err(error) => Err(error),
        },
        Operation::Install { target_version } => {
            let target_version = parse_canonical_version(&target_version)?;
            match updater.install(&target_version).await {
                Ok(result) => Ok(result),
                Err(UpdateError::NoUpdate) => Ok(UpdaterResult::NoUpdate),
                Err(error) => Err(error),
            }
        }
    }
}

fn emit(result: UpdaterResult) -> ExitCode {
    println!(
        "{}",
        serde_json::to_string(&result).expect("updater result schema must serialize")
    );
    match result {
        UpdaterResult::Failed { .. } => ExitCode::FAILURE,
        UpdaterResult::UpdateAvailable { .. }
        | UpdaterResult::Installed { .. }
        | UpdaterResult::NoUpdate => ExitCode::SUCCESS,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Arguments, Operation};

    #[test]
    fn updater_requires_an_explicit_install_root() {
        let arguments = Arguments::parse([
            "rqbit-tunnel-updater",
            "--install-root",
            "/opt/rqbit-tunnel",
            "check",
        ])
        .unwrap();

        assert_eq!(arguments.install_root, PathBuf::from("/opt/rqbit-tunnel"));
        assert!(matches!(arguments.operation, Operation::Check));
        assert!(Arguments::parse(["rqbit-tunnel-updater", "check"]).is_err());
    }
}
