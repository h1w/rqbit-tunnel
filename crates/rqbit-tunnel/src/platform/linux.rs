#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        ffi::{OsStr, OsString},
        io,
        path::PathBuf,
        sync::Mutex,
    };

    #[cfg(feature = "tray-linux")]
    use std::path::Path;

    #[cfg(feature = "tray-linux")]
    use tempfile::tempdir;

    use super::{CommandOutput, CommandRunner, LinuxServiceManager};
    #[cfg(feature = "tray-linux")]
    use super::{set_tray_autostart_at, tray_autostart_path};
    use crate::platform::{
        CLIENT_SERVICE, ServiceError, ServiceInstallSpec, ServiceManager, ServiceState,
    };

    struct FakeRunner {
        states: Mutex<VecDeque<&'static str>>,
        calls: Mutex<Vec<(OsString, Vec<OsString>)>>,
    }

    impl FakeRunner {
        fn from_lines(lines: impl IntoIterator<Item = &'static str>) -> Self {
            Self {
                states: Mutex::new(lines.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().expect("calls mutex poisoned").len()
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &OsStr, args: &[OsString]) -> io::Result<CommandOutput> {
            self.calls
                .lock()
                .expect("calls mutex poisoned")
                .push((program.to_owned(), args.to_vec()));

            if args.first().is_some_and(|argument| argument == "show") {
                let state = self
                    .states
                    .lock()
                    .expect("states mutex poisoned")
                    .pop_front()
                    .unwrap_or("inactive");
                return Ok(CommandOutput::success(format!("{state}\n")));
            }

            Ok(CommandOutput::success(String::new()))
        }
    }

    #[test]
    fn systemctl_start_waits_for_active_state() {
        let runner = FakeRunner::from_lines(["activating", "active"]);
        let manager = LinuxServiceManager::new(runner);

        assert_eq!(
            manager.start(CLIENT_SERVICE).unwrap(),
            ServiceState::Running
        );
        assert_eq!(manager.runner.call_count(), 3);
    }

    #[test]
    fn service_stop_reports_failed_state_instead_of_success() {
        let runner = FakeRunner::from_lines(["stopping", "failed"]);
        let manager = LinuxServiceManager::new(runner);

        assert!(matches!(
            manager.stop(CLIENT_SERVICE),
            Err(ServiceError::FailedState)
        ));
    }

    #[test]
    fn install_rejects_unsafe_paths_and_arguments_before_running_systemctl() {
        let runner = FakeRunner::from_lines([]);
        let manager = LinuxServiceManager::new(runner);
        let spec = ServiceInstallSpec {
            executable: PathBuf::from("relative-launcher"),
            arguments: vec![OsString::from("safe"), OsString::from("bad\0argument")],
            working_directory: PathBuf::from("/var/lib/rqbit-tunnel"),
            display_name: "Rqbit tunnel client".to_owned(),
        };

        assert!(matches!(
            manager.install(&spec),
            Err(ServiceError::RelativePath {
                field: "executable",
                ..
            })
        ));
        assert_eq!(manager.runner.call_count(), 0);

        let spec = ServiceInstallSpec {
            executable: PathBuf::from("/usr/bin/rqbit-tunnel"),
            arguments: vec![OsString::from("bad\0argument")],
            working_directory: PathBuf::from("/var/lib/rqbit-tunnel"),
            display_name: "Rqbit tunnel client".to_owned(),
        };

        assert!(matches!(
            manager.install(&spec),
            Err(ServiceError::EmbeddedNul { field: "argument" })
        ));
        assert_eq!(manager.runner.call_count(), 0);
    }
    #[cfg(feature = "tray-linux")]
    #[test]
    fn tray_autostart_stays_under_the_invoking_users_home() {
        let home = tempdir().expect("temporary home");
        let launcher = Path::new("/opt/rqbit-tunnel/launcher");
        let entry = tray_autostart_path(home.path());

        set_tray_autostart_at(home.path(), launcher, true).expect("enable tray autostart");

        assert_eq!(
            entry,
            home.path()
                .join(".config")
                .join("autostart")
                .join("rqbit-tunnel-tray.desktop")
        );
        assert_eq!(
            std::fs::read_to_string(&entry).expect("desktop entry"),
            "[Desktop Entry]\nType=Application\nName=Rqbit tunnel tray\nExec=/opt/rqbit-tunnel/launcher tray\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
        );

        set_tray_autostart_at(home.path(), launcher, false).expect("disable tray autostart");
        assert!(!entry.exists());
    }

    #[cfg(feature = "tray-linux")]
    #[test]
    fn tray_autostart_rejects_a_non_absolute_launcher() {
        let home = tempdir().expect("temporary home");

        assert!(set_tray_autostart_at(home.path(), Path::new("launcher"), true).is_err());
        assert!(!tray_autostart_path(home.path()).exists());
    }
}

use std::{
    ffi::{OsStr, OsString},
    io,
    process::Command,
    thread,
    time::{Duration, Instant},
};

#[cfg(feature = "tray-linux")]
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::platform::{
    ServiceError, ServiceInstallSpec, ServiceManager, ServiceState, validate_service_name,
};

const STATE_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
#[cfg(feature = "tray-linux")]
const TRAY_AUTOSTART_FILE: &str = "rqbit-tunnel-tray.desktop";

#[cfg(feature = "tray-linux")]
pub(crate) fn tray_autostart_path(home: &Path) -> PathBuf {
    home.join(".config")
        .join("autostart")
        .join(TRAY_AUTOSTART_FILE)
}

#[cfg(feature = "tray-linux")]
pub(crate) fn set_current_user_tray_autostart(launcher: &Path, enabled: bool) -> io::Result<()> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    set_tray_autostart_at(&home, launcher, enabled)
}

#[cfg(feature = "tray-linux")]
pub(crate) fn set_tray_autostart_at(home: &Path, launcher: &Path, enabled: bool) -> io::Result<()> {
    if !home.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tray autostart home must be absolute",
        ));
    }

    let entry = tray_autostart_path(home);
    if !enabled {
        return match fs::remove_file(&entry) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
    }

    let exec = desktop_exec(launcher)?;
    let parent = entry.parent().expect("autostart entry has a parent");
    fs::create_dir_all(parent)?;
    if fs::symlink_metadata(&entry)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to replace a symlinked tray autostart entry",
        ));
    }
    fs::write(
        entry,
        format!(
            "[Desktop Entry]\nType=Application\nName=Rqbit tunnel tray\nExec={exec} tray\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
        ),
    )
}

#[cfg(feature = "tray-linux")]
fn desktop_exec(launcher: &Path) -> io::Result<String> {
    if !launcher.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tray launcher must be absolute",
        ));
    }
    let launcher = launcher.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "tray launcher must be valid UTF-8 for a desktop entry",
        )
    })?;
    if launcher.contains(['\0', '\n', '\r']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tray launcher contains a forbidden control character",
        ));
    }
    if !launcher.contains([' ', '\t', '"', '\\', '$', '`']) {
        return Ok(launcher.to_owned());
    }

    let mut escaped = String::with_capacity(launcher.len() + 2);
    escaped.push('"');
    for character in launcher.chars() {
        if matches!(character, '"' | '\\' | '$' | '`') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped.push('"');
    Ok(escaped)
}

#[derive(Clone, Debug)]
pub struct CommandOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

impl CommandOutput {
    pub fn success(stdout: String) -> Self {
        Self {
            success: true,
            stdout,
            stderr: String::new(),
        }
    }

    pub fn failure(stdout: String, stderr: String) -> Self {
        Self {
            success: false,
            stdout,
            stderr,
        }
    }
}

pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &OsStr, args: &[OsString]) -> io::Result<CommandOutput>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &OsStr, args: &[OsString]) -> io::Result<CommandOutput> {
        let output = Command::new(program).args(args).output()?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

pub struct LinuxServiceManager<R = SystemCommandRunner> {
    runner: R,
    timeout: Duration,
    poll_interval: Duration,
}

impl<R: CommandRunner> LinuxServiceManager<R> {
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            timeout: STATE_TIMEOUT,
            poll_interval: POLL_INTERVAL,
        }
    }

    fn run_systemctl(
        &self,
        operation: &'static str,
        args: Vec<OsString>,
    ) -> Result<CommandOutput, ServiceError> {
        let output = self
            .runner
            .run(OsStr::new("systemctl"), &args)
            .map_err(|source| ServiceError::CommandIo { operation, source })?;
        if output.success {
            return Ok(output);
        }

        let message = if output.stderr.trim().is_empty() {
            "systemctl returned an unsuccessful status".to_owned()
        } else {
            output.stderr.trim().to_owned()
        };
        Err(ServiceError::CommandFailed { operation, message })
    }

    fn wait_for_state(
        &self,
        name: &str,
        expected: ServiceState,
    ) -> Result<ServiceState, ServiceError> {
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.status(name)? {
                state if state == expected => return Ok(state),
                ServiceState::Failed => return Err(ServiceError::FailedState),
                _ => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(ServiceError::TimedOut {
                            name: name.to_owned(),
                            expected,
                        });
                    }
                    thread::sleep(self.poll_interval.min(deadline.duration_since(now)));
                }
            }
        }
    }
}

impl LinuxServiceManager<SystemCommandRunner> {
    pub fn system() -> Self {
        Self::new(SystemCommandRunner)
    }
}

impl<R: CommandRunner> ServiceManager for LinuxServiceManager<R> {
    fn install(&self, spec: &ServiceInstallSpec) -> Result<(), ServiceError> {
        spec.validate()?;
        self.run_systemctl("daemon-reload", vec![OsString::from("daemon-reload")])?;
        Ok(())
    }

    fn start(&self, name: &str) -> Result<ServiceState, ServiceError> {
        validate_service_name(name)?;
        self.run_systemctl("start", vec![OsString::from("start"), OsString::from(name)])?;
        self.wait_for_state(name, ServiceState::Running)
    }

    fn stop(&self, name: &str) -> Result<ServiceState, ServiceError> {
        validate_service_name(name)?;
        self.run_systemctl("stop", vec![OsString::from("stop"), OsString::from(name)])?;
        self.wait_for_state(name, ServiceState::Stopped)
    }

    fn restart(&self, name: &str) -> Result<ServiceState, ServiceError> {
        validate_service_name(name)?;
        self.run_systemctl(
            "restart",
            vec![OsString::from("restart"), OsString::from(name)],
        )?;
        self.wait_for_state(name, ServiceState::Running)
    }

    fn status(&self, name: &str) -> Result<ServiceState, ServiceError> {
        validate_service_name(name)?;
        let output = self.run_systemctl(
            "show",
            vec![
                OsString::from("show"),
                OsString::from("--property=ActiveState"),
                OsString::from("--value"),
                OsString::from(name),
            ],
        )?;

        Ok(match output.stdout.trim() {
            "active" => ServiceState::Running,
            "inactive" => ServiceState::Stopped,
            "activating" => ServiceState::Starting,
            "deactivating" => ServiceState::Stopping,
            "failed" => ServiceState::Failed,
            _ => ServiceState::Unknown,
        })
    }

    fn set_autostart(&self, name: &str, enabled: bool) -> Result<(), ServiceError> {
        validate_service_name(name)?;
        let operation = if enabled { "enable" } else { "disable" };
        self.run_systemctl(
            operation,
            vec![OsString::from(operation), OsString::from(name)],
        )?;
        Ok(())
    }
}
