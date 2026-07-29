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
    let arguments = arguments
        .into_iter()
        .map(|argument| argument.into())
        .collect::<Vec<OsString>>();
    match Cli::try_parse_from(arguments.iter().cloned()) {
        Ok(cli) => match execute_with_arguments(cli, &arguments).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("rqbit-tunnel: {error}");
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
    async fn server_help_returns_success() {
        assert_eq!(
            run(["rqbit-tunnel", "server", "--help"]).await,
            ExitCode::SUCCESS
        );
    }
}
