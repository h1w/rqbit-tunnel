use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("rqbit-tunnel: server and client commands are unavailable until later tasks");
    run()
}

fn run() -> ExitCode {
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    use super::run;

    #[test]
    fn unavailable_harness_returns_failure() {
        assert_eq!(run(), ExitCode::FAILURE);
    }
}
