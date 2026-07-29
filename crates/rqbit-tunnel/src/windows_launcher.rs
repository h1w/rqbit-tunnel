#[cfg(any(windows, test))]
use std::{ffi::OsString, path::Path};

/// Builds the only command shape the SCM launcher may give its payload worker.
/// The worker is deliberately a private non-SCM host; only the stable launcher
/// process is allowed to enter the service dispatcher.
#[cfg(any(windows, test))]
pub(crate) fn client_payload_host_arguments(
    config_path: &Path,
    ready_event_name: &str,
    stop_event_name: &str,
) -> Vec<OsString> {
    vec![
        OsString::from("client"),
        OsString::from("payload-host"),
        OsString::from("--config"),
        config_path.as_os_str().to_owned(),
        OsString::from("--launcher-ready-event"),
        OsString::from(ready_event_name),
        OsString::from("--launcher-stop-event"),
        OsString::from(stop_event_name),
    ]
}

#[cfg(windows)]
mod service_host {
    use std::{
        ffi::{OsStr, OsString},
        io, iter,
        os::windows::{ffi::OsStrExt, io::AsRawHandle},
        path::PathBuf,
        process::{Child, Command, ExitStatus},
        time::{Duration, Instant},
    };

    use thiserror::Error;
    use uuid::Uuid;
    use windows::{
        Win32::{
            Foundation::{
                CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, WAIT_FAILED,
                WAIT_OBJECT_0, WAIT_TIMEOUT,
            },
            System::{
                JobObjects::{
                    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
                },
                Threading::{
                    CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects, WaitForSingleObject,
                },
            },
        },
        core::PCWSTR,
    };
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode,
            ServiceState as WindowsServiceState, ServiceStatus, ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
        service_dispatcher,
    };

    use crate::{
        paths::ClientPaths,
        platform::CLIENT_SERVICE,
        version::{
            ActiveReleaseError, LAUNCHER_ABI, read_active_release, resolve_payload_executable,
        },
    };

    const SERVICE_WAIT_HINT: Duration = Duration::from_secs(30);
    const SERVICE_STATUS_PROGRESS_INTERVAL: Duration = Duration::from_secs(1);
    const WORKER_START_TIMEOUT: Duration = Duration::from_secs(30);
    const WORKER_STOP_TIMEOUT: Duration = Duration::from_secs(30);
    const SERVICE_FAILURE_EXIT_CODE: u32 = 1;
    const WORKER_TERMINATION_EXIT_CODE: u32 = 1;
    const EVENT_NAME_ATTEMPTS: usize = 16;
    const EVENT_NAME_PREFIX: &str = "Local\\rqbit-tunnel-launcher-";

    #[derive(Debug, Error)]
    pub enum WindowsClientServiceLauncherError {
        #[error("failed to start the Windows client service dispatcher: {source}")]
        Dispatcher {
            #[source]
            source: windows_service::Error,
        },
        #[error("failed to register the Windows client service control handler: {source}")]
        ControlHandler {
            #[source]
            source: windows_service::Error,
        },
        #[error("failed to report Windows client service status: {source}")]
        Status {
            #[source]
            source: windows_service::Error,
        },
        #[error("Windows service status checkpoint overflowed")]
        StatusCheckpointExhausted,
        #[error("failed to resolve the stable launcher executable: {source}")]
        CurrentExecutable {
            #[source]
            source: io::Error,
        },
        #[error("stable launcher executable has no installation directory: {executable}")]
        MissingInstallRoot { executable: PathBuf },
        #[error(
            "active release requires launcher ABI {required}, but this launcher provides ABI {available}"
        )]
        UnsupportedLauncherAbi { required: u32, available: u32 },
        #[error(transparent)]
        ActiveRelease(#[from] ActiveReleaseError),
        #[error("the system client configuration path is not absolute: {path}")]
        RelativeSystemConfigPath { path: PathBuf },
        #[error("failed to create launcher-private synchronization object: {source}")]
        Event {
            #[source]
            source: windows::core::Error,
        },
        #[error("could not allocate unique launcher-private synchronization object names")]
        EventNameExhausted,
        #[error("failed to start active payload worker {payload}: {source}")]
        SpawnWorker {
            payload: PathBuf,
            #[source]
            source: io::Error,
        },
        #[error("active payload worker executable has no parent directory: {payload}")]
        MissingPayloadDirectory { payload: PathBuf },
        #[error("Windows Job Object operation {operation} failed: {source}")]
        Job {
            operation: &'static str,
            #[source]
            source: windows::core::Error,
        },
        #[error("failed while waiting for payload worker during {phase}: {source}")]
        Wait {
            phase: &'static str,
            #[source]
            source: windows::core::Error,
        },
        #[error("Windows returned unexpected wait result {result} during {phase}")]
        UnexpectedWait { phase: &'static str, result: u32 },
        #[error("failed to reap payload worker: {source}")]
        ReapWorker {
            #[source]
            source: io::Error,
        },
        #[error("payload worker exited before reporting readiness: {status}")]
        WorkerExitedBeforeReady { status: ExitStatus },
        #[error("payload worker did not report readiness before the service startup timeout")]
        WorkerStartupTimedOut,
        #[error("payload worker exited unexpectedly: {status}")]
        WorkerExited { status: ExitStatus },
        #[error("payload worker did not stop before the bounded service shutdown timeout")]
        WorkerStopTimedOut,
    }

    /// Enters the SCM dispatcher from the stable launcher process. The
    /// dispatcher must never be entered by the versioned payload worker.
    pub fn run_client_service_host() -> Result<(), WindowsClientServiceLauncherError> {
        service_dispatcher::start(CLIENT_SERVICE, ffi_client_service_main)
            .map_err(|source| WindowsClientServiceLauncherError::Dispatcher { source })
    }

    define_windows_service!(ffi_client_service_main, client_service_main);

    fn client_service_main(_arguments: Vec<OsString>) {
        if let Err(error) = run_client_service() {
            tracing::error!(error = %error, "managed Windows client service stopped with an error");
        }
    }

    fn run_client_service() -> Result<(), WindowsClientServiceLauncherError> {
        let events = LauncherEvents::create()?;
        let stop_event = events.stop.raw().0 as usize;
        let status_handle = service_control_handler::register(CLIENT_SERVICE, move |control| {
            service_control_result(control, HANDLE(stop_event as *mut _))
        })
        .map_err(|source| WindowsClientServiceLauncherError::ControlHandler { source })?;

        let mut start_pending =
            match PendingServiceStatus::begin(&status_handle, WindowsServiceState::StartPending) {
                Ok(status) => status,
                Err(error) => {
                    report_failure(&status_handle);
                    return Err(error);
                }
            };

        let result = run_client_worker(&status_handle, &events, &mut start_pending);
        if result.is_err() {
            report_failure(&status_handle);
        }
        result
    }

    fn run_client_worker(
        status_handle: &ServiceStatusHandle,
        events: &LauncherEvents,
        start_pending: &mut PendingServiceStatus<'_>,
    ) -> Result<(), WindowsClientServiceLauncherError> {
        let payload = active_payload()?;
        let config_path = ClientPaths::system().config_path();
        if !config_path.is_absolute() {
            return Err(
                WindowsClientServiceLauncherError::RelativeSystemConfigPath { path: config_path },
            );
        }
        let arguments = super::client_payload_host_arguments(
            &config_path,
            &events.ready_name,
            &events.stop_name,
        );
        let mut worker = WorkerProcess::spawn(payload, arguments)?;

        match wait_for_worker_start(events, &mut worker, start_pending)? {
            WorkerStartup::Ready => {
                report_status(
                    status_handle,
                    WindowsServiceState::Running,
                    ServiceExitCode::NO_ERROR,
                )?;
                match wait_for_stop_or_worker_exit(events, &mut worker)? {
                    WorkerRun::StopRequested => stop_worker(status_handle, &mut worker),
                    WorkerRun::Exited(status) => {
                        Err(WindowsClientServiceLauncherError::WorkerExited { status })
                    }
                }
            }
            WorkerStartup::StopRequested => stop_worker(status_handle, &mut worker),
            WorkerStartup::Exited(status) => {
                Err(WindowsClientServiceLauncherError::WorkerExitedBeforeReady { status })
            }
            WorkerStartup::TimedOut => {
                Err(WindowsClientServiceLauncherError::WorkerStartupTimedOut)
            }
        }
    }

    fn stop_worker(
        status_handle: &ServiceStatusHandle,
        worker: &mut WorkerProcess,
    ) -> Result<(), WindowsClientServiceLauncherError> {
        let mut stop_pending =
            PendingServiceStatus::begin(status_handle, WindowsServiceState::StopPending)?;
        let deadline = Instant::now() + WORKER_STOP_TIMEOUT;

        loop {
            let Some(wait) = pending_wait_duration(deadline) else {
                worker.terminate_and_reap();
                return Err(WindowsClientServiceLauncherError::WorkerStopTimedOut);
            };

            match worker.wait_for_exit(wait)? {
                Some(status) if status.success() => {
                    return report_status(
                        status_handle,
                        WindowsServiceState::Stopped,
                        ServiceExitCode::NO_ERROR,
                    );
                }
                Some(status) => {
                    return Err(WindowsClientServiceLauncherError::WorkerExited { status });
                }
                None => stop_pending.advance()?,
            }
        }
    }

    struct PendingServiceStatus<'a> {
        status_handle: &'a ServiceStatusHandle,
        state: WindowsServiceState,
        checkpoint: u32,
    }

    impl<'a> PendingServiceStatus<'a> {
        fn begin(
            status_handle: &'a ServiceStatusHandle,
            state: WindowsServiceState,
        ) -> Result<Self, WindowsClientServiceLauncherError> {
            debug_assert!(matches!(
                state,
                WindowsServiceState::StartPending | WindowsServiceState::StopPending
            ));
            let status = Self {
                status_handle,
                state,
                checkpoint: 1,
            };
            status.report()?;
            Ok(status)
        }

        fn advance(&mut self) -> Result<(), WindowsClientServiceLauncherError> {
            self.checkpoint = self
                .checkpoint
                .checked_add(1)
                .ok_or(WindowsClientServiceLauncherError::StatusCheckpointExhausted)?;
            self.report()
        }

        fn report(&self) -> Result<(), WindowsClientServiceLauncherError> {
            report_status_with_checkpoint(
                self.status_handle,
                self.state,
                ServiceExitCode::NO_ERROR,
                self.checkpoint,
            )
        }
    }

    fn active_payload() -> Result<PathBuf, WindowsClientServiceLauncherError> {
        let executable = std::env::current_exe()
            .map_err(|source| WindowsClientServiceLauncherError::CurrentExecutable { source })?;
        let install_root = executable
            .parent()
            .map(PathBuf::from)
            .ok_or(WindowsClientServiceLauncherError::MissingInstallRoot { executable })?;
        let active = read_active_release(&install_root)?;
        if active.launcher_abi() > LAUNCHER_ABI {
            return Err(WindowsClientServiceLauncherError::UnsupportedLauncherAbi {
                required: active.launcher_abi(),
                available: LAUNCHER_ABI,
            });
        }

        resolve_payload_executable(&install_root, active.payload_dir()).map_err(Into::into)
    }

    struct LauncherEvents {
        ready: OwnedHandle,
        stop: OwnedHandle,
        ready_name: String,
        stop_name: String,
    }

    impl LauncherEvents {
        fn create() -> Result<Self, WindowsClientServiceLauncherError> {
            for _ in 0..EVENT_NAME_ATTEMPTS {
                let id = Uuid::new_v4();
                let ready_name = format!("{EVENT_NAME_PREFIX}{id}-ready");
                let stop_name = format!("{EVENT_NAME_PREFIX}{id}-stop");
                let Some(ready) = OwnedHandle::create_manual_reset_event(&ready_name)? else {
                    continue;
                };
                let Some(stop) = OwnedHandle::create_manual_reset_event(&stop_name)? else {
                    continue;
                };

                return Ok(Self {
                    ready,
                    stop,
                    ready_name,
                    stop_name,
                });
            }

            Err(WindowsClientServiceLauncherError::EventNameExhausted)
        }
    }

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn raw(&self) -> HANDLE {
            self.0
        }

        fn create_manual_reset_event(
            name: &str,
        ) -> Result<Option<Self>, WindowsClientServiceLauncherError> {
            let name = wide_terminated(name);
            let handle = unsafe {
                CreateEventW(None, true, false, PCWSTR(name.as_ptr()))
                    .map_err(|source| WindowsClientServiceLauncherError::Event { source })?
            };
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                drop(Self(handle));
                return Ok(None);
            }

            Ok(Some(Self(handle)))
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    struct JobObject(OwnedHandle);

    impl JobObject {
        fn create() -> Result<Self, WindowsClientServiceLauncherError> {
            let handle = unsafe {
                CreateJobObjectW(None, PCWSTR::null()).map_err(|source| {
                    WindowsClientServiceLauncherError::Job {
                        operation: "CreateJobObjectW",
                        source,
                    }
                })?
            };
            let object = Self(OwnedHandle(handle));
            let information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                    LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    ..Default::default()
                },
                ..Default::default()
            };
            unsafe {
                SetInformationJobObject(
                    object.0.raw(),
                    JobObjectExtendedLimitInformation,
                    (&information as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
                .map_err(|source| WindowsClientServiceLauncherError::Job {
                    operation: "SetInformationJobObject",
                    source,
                })?;
            }
            Ok(object)
        }

        fn assign(&self, process: HANDLE) -> Result<(), WindowsClientServiceLauncherError> {
            unsafe {
                AssignProcessToJobObject(self.0.raw(), process).map_err(|source| {
                    WindowsClientServiceLauncherError::Job {
                        operation: "AssignProcessToJobObject",
                        source,
                    }
                })
            }
        }

        fn terminate(&self) -> Result<(), windows::core::Error> {
            unsafe { TerminateJobObject(self.0.raw(), WORKER_TERMINATION_EXIT_CODE) }
        }
    }

    struct WorkerProcess {
        child: Child,
        job: JobObject,
        reaped: bool,
    }

    impl WorkerProcess {
        fn spawn(
            payload: PathBuf,
            arguments: Vec<OsString>,
        ) -> Result<Self, WindowsClientServiceLauncherError> {
            let job = JobObject::create()?;
            let working_directory = payload.parent().map(PathBuf::from).ok_or_else(|| {
                WindowsClientServiceLauncherError::MissingPayloadDirectory {
                    payload: payload.clone(),
                }
            })?;
            let child = Command::new(&payload)
                .args(arguments)
                .current_dir(working_directory)
                .spawn()
                .map_err(|source| WindowsClientServiceLauncherError::SpawnWorker {
                    payload: payload.clone(),
                    source,
                })?;
            let worker = Self {
                child,
                job,
                reaped: false,
            };
            worker.job.assign(worker.process_handle())?;
            Ok(worker)
        }

        fn process_handle(&self) -> HANDLE {
            HANDLE(self.child.as_raw_handle())
        }

        fn reap(&mut self) -> Result<ExitStatus, WindowsClientServiceLauncherError> {
            let status = self
                .child
                .wait()
                .map_err(|source| WindowsClientServiceLauncherError::ReapWorker { source })?;
            self.reaped = true;
            Ok(status)
        }

        fn wait_for_exit(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<ExitStatus>, WindowsClientServiceLauncherError> {
            match wait_for_handle(self.process_handle(), timeout, "payload worker shutdown")? {
                true => self.reap().map(Some),
                false => Ok(None),
            }
        }

        fn terminate_and_reap(&mut self) {
            if self.reaped {
                return;
            }
            let _ = self.job.terminate();
            // Assignment can fail after CreateProcess succeeds; terminate the
            // direct child as well so that failure path cannot block reaping
            // an unassigned worker forever.
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
    }

    impl Drop for WorkerProcess {
        fn drop(&mut self) {
            self.terminate_and_reap();
        }
    }

    enum WorkerStartup {
        Ready,
        StopRequested,
        Exited(ExitStatus),
        TimedOut,
    }

    fn wait_for_worker_start(
        events: &LauncherEvents,
        worker: &mut WorkerProcess,
        start_pending: &mut PendingServiceStatus<'_>,
    ) -> Result<WorkerStartup, WindowsClientServiceLauncherError> {
        let handles = [
            events.ready.raw(),
            events.stop.raw(),
            worker.process_handle(),
        ];
        let deadline = Instant::now() + WORKER_START_TIMEOUT;

        loop {
            let Some(wait) = pending_wait_duration(deadline) else {
                return Ok(WorkerStartup::TimedOut);
            };
            match unsafe { WaitForMultipleObjects(&handles, false, duration_millis(wait)) }.0 {
                result if result == WAIT_OBJECT_0.0 => return Ok(WorkerStartup::Ready),
                result if result == WAIT_OBJECT_0.0 + 1 => {
                    return Ok(WorkerStartup::StopRequested);
                }
                result if result == WAIT_OBJECT_0.0 + 2 => {
                    return worker.reap().map(WorkerStartup::Exited);
                }
                result if result == WAIT_TIMEOUT.0 => {
                    if Instant::now() >= deadline {
                        return Ok(WorkerStartup::TimedOut);
                    }
                    start_pending.advance()?;
                }
                result if result == WAIT_FAILED.0 => {
                    return Err(WindowsClientServiceLauncherError::Wait {
                        phase: "payload worker startup",
                        source: windows::core::Error::from_thread(),
                    });
                }
                result => {
                    return Err(WindowsClientServiceLauncherError::UnexpectedWait {
                        phase: "payload worker startup",
                        result,
                    });
                }
            }
        }
    }

    enum WorkerRun {
        StopRequested,
        Exited(ExitStatus),
    }

    fn wait_for_stop_or_worker_exit(
        events: &LauncherEvents,
        worker: &mut WorkerProcess,
    ) -> Result<WorkerRun, WindowsClientServiceLauncherError> {
        let handles = [events.stop.raw(), worker.process_handle()];
        match unsafe { WaitForMultipleObjects(&handles, false, INFINITE) }.0 {
            result if result == WAIT_OBJECT_0.0 => Ok(WorkerRun::StopRequested),
            result if result == WAIT_OBJECT_0.0 + 1 => worker.reap().map(WorkerRun::Exited),
            result if result == WAIT_FAILED.0 => Err(WindowsClientServiceLauncherError::Wait {
                phase: "payload worker runtime",
                source: windows::core::Error::from_thread(),
            }),
            result => Err(WindowsClientServiceLauncherError::UnexpectedWait {
                phase: "payload worker runtime",
                result,
            }),
        }
    }

    fn wait_for_handle(
        handle: HANDLE,
        timeout: Duration,
        phase: &'static str,
    ) -> Result<bool, WindowsClientServiceLauncherError> {
        match unsafe { WaitForSingleObject(handle, duration_millis(timeout)) }.0 {
            result if result == WAIT_OBJECT_0.0 => Ok(true),
            result if result == WAIT_TIMEOUT.0 => Ok(false),
            result if result == WAIT_FAILED.0 => Err(WindowsClientServiceLauncherError::Wait {
                phase,
                source: windows::core::Error::from_thread(),
            }),
            result => Err(WindowsClientServiceLauncherError::UnexpectedWait { phase, result }),
        }
    }

    fn duration_millis(duration: Duration) -> u32 {
        duration.as_millis().min(u128::from(u32::MAX)) as u32
    }

    fn pending_wait_duration(deadline: Instant) -> Option<Duration> {
        let now = Instant::now();
        (now < deadline).then(|| (deadline - now).min(SERVICE_STATUS_PROGRESS_INTERVAL))
    }

    fn service_control_result(
        control: ServiceControl,
        stop_event: HANDLE,
    ) -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Err(error) = unsafe { SetEvent(stop_event) } {
                    tracing::error!(error = %error, "failed to signal Windows payload worker shutdown");
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    }

    fn report_status(
        status_handle: &ServiceStatusHandle,
        state: WindowsServiceState,
        exit_code: ServiceExitCode,
    ) -> Result<(), WindowsClientServiceLauncherError> {
        report_status_with_checkpoint(status_handle, state, exit_code, 0)
    }

    fn report_status_with_checkpoint(
        status_handle: &ServiceStatusHandle,
        state: WindowsServiceState,
        exit_code: ServiceExitCode,
        checkpoint: u32,
    ) -> Result<(), WindowsClientServiceLauncherError> {
        status_handle
            .set_service_status(service_status_with_checkpoint(state, exit_code, checkpoint))
            .map_err(|source| WindowsClientServiceLauncherError::Status { source })
    }

    fn report_failure(status_handle: &ServiceStatusHandle) {
        let _ = status_handle.set_service_status(service_status(
            WindowsServiceState::Stopped,
            ServiceExitCode::Win32(SERVICE_FAILURE_EXIT_CODE),
        ));
    }

    fn service_status(state: WindowsServiceState, exit_code: ServiceExitCode) -> ServiceStatus {
        service_status_with_checkpoint(state, exit_code, 0)
    }

    fn service_status_with_checkpoint(
        state: WindowsServiceState,
        exit_code: ServiceExitCode,
        checkpoint: u32,
    ) -> ServiceStatus {
        let pending = matches!(
            state,
            WindowsServiceState::StartPending | WindowsServiceState::StopPending
        );
        let controls_accepted = if state == WindowsServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        };
        let wait_hint = if pending {
            SERVICE_WAIT_HINT
        } else {
            Duration::default()
        };

        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted,
            exit_code,
            checkpoint: pending.then_some(checkpoint).unwrap_or_default(),
            wait_hint,
            process_id: None,
        }
    }

    fn wide_terminated(value: &str) -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(iter::once(0))
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use windows_service::service::{
            ServiceControlAccept, ServiceExitCode, ServiceState as WindowsServiceState,
        };

        use super::{service_status, service_status_with_checkpoint};

        #[test]
        fn running_status_accepts_stop_and_shutdown_controls() {
            let status = service_status(WindowsServiceState::Running, ServiceExitCode::NO_ERROR);

            assert!(
                status
                    .controls_accepted
                    .contains(ServiceControlAccept::STOP)
            );
            assert!(
                status
                    .controls_accepted
                    .contains(ServiceControlAccept::SHUTDOWN)
            );
            assert!(matches!(status.exit_code, ServiceExitCode::Win32(0)));
        }

        #[test]
        fn pending_and_stopped_statuses_accept_no_controls_and_preserve_failure_code() {
            for state in [
                WindowsServiceState::StartPending,
                WindowsServiceState::StopPending,
            ] {
                assert!(
                    service_status(state, ServiceExitCode::NO_ERROR)
                        .controls_accepted
                        .is_empty()
                );
            }

            let stopped = service_status(WindowsServiceState::Stopped, ServiceExitCode::Win32(1));
            assert!(stopped.controls_accepted.is_empty());
            assert!(matches!(stopped.exit_code, ServiceExitCode::Win32(1)));
        }

        #[test]
        fn pending_statuses_report_an_advancing_checkpoint() {
            let starting = service_status_with_checkpoint(
                WindowsServiceState::StartPending,
                ServiceExitCode::NO_ERROR,
                3,
            );
            let stopping = service_status_with_checkpoint(
                WindowsServiceState::StopPending,
                ServiceExitCode::NO_ERROR,
                4,
            );
            let running = service_status_with_checkpoint(
                WindowsServiceState::Running,
                ServiceExitCode::NO_ERROR,
                5,
            );

            assert_eq!(starting.checkpoint, 3);
            assert_eq!(stopping.checkpoint, 4);
            assert_eq!(running.checkpoint, 0);
        }
    }
}

#[cfg(windows)]
pub use service_host::{WindowsClientServiceLauncherError, run_client_service_host};

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::Path};

    use super::client_payload_host_arguments;

    #[test]
    fn service_worker_is_a_payload_host_not_an_scm_service_host() {
        assert_eq!(
            client_payload_host_arguments(
                Path::new(r"C:\ProgramData\rqbit-tunnel\client.json"),
                r"Local\rqbit-tunnel-launcher-test-ready",
                r"Local\rqbit-tunnel-launcher-test-stop",
            ),
            vec![
                OsString::from("client"),
                OsString::from("payload-host"),
                OsString::from("--config"),
                OsString::from(r"C:\ProgramData\rqbit-tunnel\client.json"),
                OsString::from("--launcher-ready-event"),
                OsString::from(r"Local\rqbit-tunnel-launcher-test-ready"),
                OsString::from("--launcher-stop-event"),
                OsString::from(r"Local\rqbit-tunnel-launcher-test-stop"),
            ]
        );
    }
}
