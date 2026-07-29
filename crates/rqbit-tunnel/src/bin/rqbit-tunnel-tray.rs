#![cfg_attr(windows, windows_subsystem = "windows")]

use std::{ffi::OsString, process::ExitCode};

use rqbit_tunnel::cli::{Cli, execute_with_arguments};

#[tokio::main]
async fn main() -> ExitCode {
    run(std::env::args_os()).await
}

async fn run<I, T>(arguments: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let program = arguments
        .next()
        .unwrap_or_else(|| OsString::from("rqbit-tunnel-tray"));
    let (remaining, _) = arguments.size_hint();
    let mut tray_arguments = Vec::with_capacity(remaining + 2);
    tray_arguments.push(program);
    tray_arguments.push(OsString::from("tray"));
    tray_arguments.extend(arguments);

    match Cli::try_parse_from(tray_arguments.iter().cloned()) {
        Ok(cli) => match execute_with_arguments(cli, &tray_arguments).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("rqbit-tunnel-tray: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            ExitCode::from(code as u8)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    use super::run;

    #[tokio::test]
    async fn tray_help_returns_success() {
        assert_eq!(
            run(["rqbit-tunnel-tray", "--help"]).await,
            ExitCode::SUCCESS
        );
    }
}
