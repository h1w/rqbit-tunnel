#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::PathBuf};

    #[cfg(feature = "tray-windows")]
    use std::path::Path;

    use windows::Win32::System::Services::{
        SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STOPPED,
    };

    #[cfg(feature = "tray-windows")]
    use super::tray_autostart_command_line;
    use super::{
        ObservationPhase, TransitionDecision, TransitionOperation, is_user_session_id,
        service_command_line, state_from_status, transition_decision,
    };
    use crate::platform::{ServiceInstallSpec, ServiceState};

    #[test]
    fn service_command_line_quotes_utf16_arguments_and_terminates_them() {
        let spec = ServiceInstallSpec {
            executable: PathBuf::from(r"C:\Program Files\rqbit-tunnel.exe"),
            arguments: vec![OsString::from("--mode"), OsString::from("client tunnel")],
            working_directory: PathBuf::from(r"C:\ProgramData\rqbit-tunnel"),
            display_name: "Rqbit tunnel client".to_owned(),
        };

        let command_line = service_command_line(&spec).unwrap();
        assert_eq!(command_line.last(), Some(&0));
        assert_eq!(
            String::from_utf16(&command_line[..command_line.len() - 1]).unwrap(),
            r#""C:\Program Files\rqbit-tunnel.exe" "--mode" "client tunnel""#
        );
    }

    #[test]
    fn scm_status_mapping_uses_reported_state_and_exit_code() {
        assert_eq!(
            state_from_status(SERVICE_START_PENDING, 0),
            ServiceState::Starting
        );
        assert_eq!(state_from_status(SERVICE_RUNNING, 0), ServiceState::Running);
        assert_eq!(state_from_status(SERVICE_STOPPED, 0), ServiceState::Stopped);
        assert_eq!(state_from_status(SERVICE_STOPPED, 1), ServiceState::Failed);
    }

    #[test]
    fn pending_scm_states_never_issue_start_or_stop_controls() {
        let initial = ObservationPhase::Initial;

        assert_eq!(
            transition_decision(TransitionOperation::Start, initial, ServiceState::Stopping),
            TransitionDecision::Wait
        );
        assert_eq!(
            transition_decision(TransitionOperation::Stop, initial, ServiceState::Starting),
            TransitionDecision::Wait
        );
        assert_eq!(
            transition_decision(
                TransitionOperation::Restart,
                initial,
                ServiceState::Starting
            ),
            TransitionDecision::Wait
        );
        assert_eq!(
            transition_decision(
                TransitionOperation::Restart,
                initial,
                ServiceState::Stopping
            ),
            TransitionDecision::Wait
        );

        assert_eq!(
            transition_decision(TransitionOperation::Start, initial, ServiceState::Running),
            TransitionDecision::Return(ServiceState::Running)
        );
        assert_eq!(
            transition_decision(TransitionOperation::Stop, initial, ServiceState::Stopped),
            TransitionDecision::Return(ServiceState::Stopped)
        );
        assert_eq!(
            transition_decision(TransitionOperation::Start, initial, ServiceState::Stopped),
            TransitionDecision::Start
        );
        assert_eq!(
            transition_decision(TransitionOperation::Stop, initial, ServiceState::Running),
            TransitionDecision::Stop
        );
        assert_eq!(
            transition_decision(TransitionOperation::Restart, initial, ServiceState::Stopped),
            TransitionDecision::Start
        );
        assert_eq!(
            transition_decision(TransitionOperation::Restart, initial, ServiceState::Running),
            TransitionDecision::Stop
        );
    }

    #[test]
    fn failed_state_after_pending_resolution_is_typed_but_direct_recovery_is_allowed() {
        for operation in [TransitionOperation::Start, TransitionOperation::Restart] {
            assert_eq!(
                transition_decision(operation, ObservationPhase::Initial, ServiceState::Failed),
                TransitionDecision::Start
            );
            assert_eq!(
                transition_decision(
                    operation,
                    ObservationPhase::AfterPending,
                    ServiceState::Failed
                ),
                TransitionDecision::Failed
            );
        }

        for phase in [ObservationPhase::Initial, ObservationPhase::AfterPending] {
            assert_eq!(
                transition_decision(TransitionOperation::Stop, phase, ServiceState::Failed),
                TransitionDecision::Failed
            );
        }
    }
    #[cfg(feature = "tray-windows")]
    #[test]
    fn tray_run_entry_quotes_the_stable_launcher_and_only_passes_tray() {
        let command_line =
            tray_autostart_command_line(Path::new(r"C:\Program Files\rqbit-tunnel\launcher.exe"))
                .expect("tray run entry");

        assert_eq!(command_line.last(), Some(&0));
        assert_eq!(
            String::from_utf16(&command_line[..command_line.len() - 1]).unwrap(),
            r#""C:\Program Files\rqbit-tunnel\launcher.exe" "tray""#
        );
    }

    #[test]
    fn session_zero_is_never_a_tray_user_session() {
        assert!(!is_user_session_id(0));
        assert!(is_user_session_id(1));
    }
}

use std::{
    ffi::OsStr,
    io, iter,
    os::windows::ffi::OsStrExt,
    slice, thread,
    time::{Duration, Instant},
};

#[cfg(feature = "tray-windows")]
use std::{path::Path, ptr};

use windows::{
    Win32::{
        Foundation::{ERROR_SERVICE_EXISTS, WIN32_ERROR},
        System::{
            RemoteDesktop::ProcessIdToSessionId,
            Services::{
                ChangeServiceConfigW, CloseServiceHandle, ControlService, CreateServiceW,
                ENUM_SERVICE_TYPE, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
                SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO,
                SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG, SERVICE_CONTROL_STOP,
                SERVICE_DEMAND_START, SERVICE_ERROR, SERVICE_ERROR_NORMAL, SERVICE_NO_CHANGE,
                SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING,
                SERVICE_START_TYPE, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE,
                SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED,
                SERVICE_WIN32_OWN_PROCESS, StartServiceW,
            },
            Threading::GetCurrentProcessId,
        },
    },
    core::PCWSTR,
};

#[cfg(feature = "tray-windows")]
use windows::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS},
    System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ, RegCloseKey, RegDeleteValueW,
        RegOpenKeyExW, RegSetValueExW,
    },
};

use crate::platform::{
    CLIENT_SERVICE, ServiceError, ServiceInstallSpec, ServiceManager, ServiceState,
    validate_service_name,
};

const STATE_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
#[cfg(feature = "tray-windows")]
const TRAY_RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(feature = "tray-windows")]
const TRAY_RUN_VALUE: &str = "rqbit-tunnel-tray";

pub(crate) const fn is_user_session_id(session_id: u32) -> bool {
    session_id != 0
}

#[cfg(feature = "tray-windows")]
pub(crate) fn set_current_user_tray_autostart(launcher: &Path, enabled: bool) -> io::Result<()> {
    if !current_process_is_user_session()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to configure tray autostart in Session 0",
        ));
    }

    let mut key = HKEY(ptr::null_mut());
    let key_path = wide_terminated(OsStr::new(TRAY_RUN_KEY));
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(key_path.as_ptr()),
            None,
            KEY_SET_VALUE,
            &mut key,
        )
    };
    registry_status(status)?;
    let _key = RegistryKey(key);
    let value_name = wide_terminated(OsStr::new(TRAY_RUN_VALUE));

    if !enabled {
        let status = unsafe { RegDeleteValueW(key, PCWSTR(value_name.as_ptr())) };
        return if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            Err(registry_error(status))
        };
    }

    let command_line = tray_autostart_command_line(launcher)?;
    let command_line_bytes = unsafe {
        slice::from_raw_parts(
            command_line.as_ptr().cast::<u8>(),
            command_line.len() * std::mem::size_of::<u16>(),
        )
    };
    let status = unsafe {
        RegSetValueExW(
            key,
            PCWSTR(value_name.as_ptr()),
            None,
            REG_SZ,
            Some(command_line_bytes),
        )
    };
    registry_status(status)
}

#[cfg(feature = "tray-windows")]
pub(crate) fn tray_autostart_command_line(launcher: &Path) -> io::Result<Vec<u16>> {
    if !launcher.is_absolute() || launcher.as_os_str().encode_wide().any(|unit| unit == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tray launcher must be an absolute path without NUL",
        ));
    }

    let mut command_line = Vec::new();
    append_quoted_argument(&mut command_line, launcher.as_os_str());
    command_line.push(u16::from(b' '));
    append_quoted_argument(&mut command_line, OsStr::new("tray"));
    command_line.push(0);
    Ok(command_line)
}

pub(crate) fn current_process_is_user_session() -> io::Result<bool> {
    let process_id = unsafe { GetCurrentProcessId() };
    let mut session_id = 0;
    unsafe { ProcessIdToSessionId(process_id, &mut session_id) }.map_err(windows_error)?;
    Ok(is_user_session_id(session_id))
}

#[cfg(feature = "tray-windows")]
fn registry_status(status: WIN32_ERROR) -> io::Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(registry_error(status))
    }
}

#[cfg(feature = "tray-windows")]
fn registry_error(status: WIN32_ERROR) -> io::Error {
    io::Error::from_raw_os_error(status.0 as i32)
}

fn windows_error(error: windows::core::Error) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(feature = "tray-windows")]
struct RegistryKey(HKEY);

#[cfg(feature = "tray-windows")]
impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransitionOperation {
    Start,
    Stop,
    Restart,
}

impl TransitionOperation {
    fn expected_state(self) -> ServiceState {
        match self {
            Self::Start | Self::Restart => ServiceState::Running,
            Self::Stop => ServiceState::Stopped,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObservationPhase {
    Initial,
    AfterPending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransitionDecision {
    Wait,
    Return(ServiceState),
    Start,
    Stop,
    Failed,
}

fn transition_decision(
    operation: TransitionOperation,
    phase: ObservationPhase,
    state: ServiceState,
) -> TransitionDecision {
    match (operation, phase, state) {
        (TransitionOperation::Start, _, ServiceState::Running) => {
            TransitionDecision::Return(ServiceState::Running)
        }
        (TransitionOperation::Start, _, ServiceState::Starting | ServiceState::Stopping) => {
            TransitionDecision::Wait
        }
        (TransitionOperation::Start, _, ServiceState::Stopped | ServiceState::Unknown) => {
            TransitionDecision::Start
        }
        (TransitionOperation::Start, ObservationPhase::Initial, ServiceState::Failed) => {
            TransitionDecision::Start
        }
        (TransitionOperation::Start, ObservationPhase::AfterPending, ServiceState::Failed) => {
            TransitionDecision::Failed
        }
        (TransitionOperation::Stop, _, ServiceState::Stopped) => {
            TransitionDecision::Return(ServiceState::Stopped)
        }
        (TransitionOperation::Stop, _, ServiceState::Starting | ServiceState::Stopping) => {
            TransitionDecision::Wait
        }
        (TransitionOperation::Stop, _, ServiceState::Running | ServiceState::Unknown) => {
            TransitionDecision::Stop
        }
        (TransitionOperation::Stop, _, ServiceState::Failed) => TransitionDecision::Failed,
        (TransitionOperation::Restart, _, ServiceState::Starting | ServiceState::Stopping) => {
            TransitionDecision::Wait
        }
        (TransitionOperation::Restart, _, ServiceState::Stopped) => TransitionDecision::Start,
        (TransitionOperation::Restart, _, ServiceState::Running | ServiceState::Unknown) => {
            TransitionDecision::Stop
        }
        (TransitionOperation::Restart, ObservationPhase::Initial, ServiceState::Failed) => {
            TransitionDecision::Start
        }
        (TransitionOperation::Restart, ObservationPhase::AfterPending, ServiceState::Failed) => {
            TransitionDecision::Failed
        }
    }
}

#[derive(Debug)]
struct ServiceHandle(SC_HANDLE);

impl ServiceHandle {
    fn raw(&self) -> SC_HANDLE {
        self.0
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct WindowsServiceManager {
    timeout: Duration,
    poll_interval: Duration,
}

impl Default for WindowsServiceManager {
    fn default() -> Self {
        Self {
            timeout: STATE_TIMEOUT,
            poll_interval: POLL_INTERVAL,
        }
    }
}

impl WindowsServiceManager {
    pub fn new() -> Self {
        Self::default()
    }

    fn open_manager(&self, access: u32) -> Result<ServiceHandle, ServiceError> {
        let handle = unsafe {
            OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access)
                .map_err(|source| platform_error("OpenSCManagerW", source))?
        };
        Ok(ServiceHandle(handle))
    }

    fn open_service(
        &self,
        manager: &ServiceHandle,
        name: &str,
        access: u32,
    ) -> Result<ServiceHandle, ServiceError> {
        let wide_name = wide_terminated(OsStr::new(name));
        let handle = unsafe {
            OpenServiceW(manager.raw(), PCWSTR(wide_name.as_ptr()), access)
                .map_err(|source| platform_error("OpenServiceW", source))?
        };
        Ok(ServiceHandle(handle))
    }

    fn query_state(&self, service: &ServiceHandle) -> Result<ServiceState, ServiceError> {
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut bytes_needed = 0;
        let buffer = unsafe {
            slice::from_raw_parts_mut(
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast::<u8>(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
            )
        };
        unsafe {
            QueryServiceStatusEx(
                service.raw(),
                SC_STATUS_PROCESS_INFO,
                Some(buffer),
                &mut bytes_needed,
            )
            .map_err(|source| platform_error("QueryServiceStatusEx", source))?;
        }
        Ok(state_from_status(
            status.dwCurrentState,
            status.dwWin32ExitCode,
        ))
    }

    fn sleep_until(
        &self,
        name: &str,
        expected: ServiceState,
        deadline: Instant,
    ) -> Result<(), ServiceError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(ServiceError::TimedOut {
                name: name.to_owned(),
                expected,
            });
        }
        thread::sleep(self.poll_interval.min(deadline.duration_since(now)));
        Ok(())
    }

    fn transition_until(
        &self,
        service: &ServiceHandle,
        name: &str,
        operation: TransitionOperation,
        deadline: Instant,
    ) -> Result<TransitionDecision, ServiceError> {
        let mut phase = ObservationPhase::Initial;
        loop {
            match transition_decision(operation, phase, self.query_state(service)?) {
                TransitionDecision::Wait => {
                    phase = ObservationPhase::AfterPending;
                    self.sleep_until(name, operation.expected_state(), deadline)?;
                }
                TransitionDecision::Failed => return Err(ServiceError::FailedState),
                decision => return Ok(decision),
            }
        }
    }

    fn wait_for_state_until(
        &self,
        service: &ServiceHandle,
        name: &str,
        expected: ServiceState,
        deadline: Instant,
    ) -> Result<ServiceState, ServiceError> {
        loop {
            match self.query_state(service)? {
                state if state == expected => return Ok(state),
                ServiceState::Failed => return Err(ServiceError::FailedState),
                _ => self.sleep_until(name, expected, deadline)?,
            }
        }
    }

    fn start_service(&self, service: &ServiceHandle) -> Result<(), ServiceError> {
        unsafe {
            StartServiceW(service.raw(), None)
                .map_err(|source| platform_error("StartServiceW", source))?;
        }
        Ok(())
    }

    fn stop_service(&self, service: &ServiceHandle) -> Result<(), ServiceError> {
        let mut control_status = SERVICE_STATUS::default();
        unsafe {
            ControlService(service.raw(), SERVICE_CONTROL_STOP, &mut control_status)
                .map_err(|source| platform_error("ControlService", source))?;
        }
        Ok(())
    }
}

impl ServiceManager for WindowsServiceManager {
    fn install(&self, spec: &ServiceInstallSpec) -> Result<(), ServiceError> {
        let command_line = service_command_line(spec)?;
        let service_name = wide_terminated(OsStr::new(CLIENT_SERVICE));
        let display_name = wide_terminated(OsStr::new(&spec.display_name));
        let manager = self.open_manager(SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT)?;
        let _service = match unsafe {
            CreateServiceW(
                manager.raw(),
                PCWSTR(service_name.as_ptr()),
                PCWSTR(display_name.as_ptr()),
                SERVICE_QUERY_STATUS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                PCWSTR(command_line.as_ptr()),
                PCWSTR::null(),
                None,
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
            )
        } {
            Ok(service) => ServiceHandle(service),
            Err(source) if WIN32_ERROR::from_error(&source) == Some(ERROR_SERVICE_EXISTS) => {
                let service = self.open_service(&manager, CLIENT_SERVICE, SERVICE_CHANGE_CONFIG)?;
                unsafe {
                    ChangeServiceConfigW(
                        service.raw(),
                        ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
                        SERVICE_START_TYPE(SERVICE_NO_CHANGE),
                        SERVICE_ERROR(SERVICE_NO_CHANGE),
                        PCWSTR(command_line.as_ptr()),
                        PCWSTR::null(),
                        None,
                        PCWSTR::null(),
                        PCWSTR::null(),
                        PCWSTR::null(),
                        PCWSTR(display_name.as_ptr()),
                    )
                    .map_err(|source| platform_error("ChangeServiceConfigW", source))?;
                }
                service
            }
            Err(source) => return Err(platform_error("CreateServiceW", source)),
        };
        Ok(())
    }

    fn start(&self, name: &str) -> Result<ServiceState, ServiceError> {
        validate_service_name(name)?;
        let manager = self.open_manager(SC_MANAGER_CONNECT)?;
        let service = self.open_service(&manager, name, SERVICE_START | SERVICE_QUERY_STATUS)?;
        let deadline = Instant::now() + self.timeout;
        match self.transition_until(&service, name, TransitionOperation::Start, deadline)? {
            TransitionDecision::Return(state) => Ok(state),
            TransitionDecision::Start => {
                self.start_service(&service)?;
                self.wait_for_state_until(&service, name, ServiceState::Running, deadline)
            }
            _ => unreachable!("start transition reducer returned an invalid action"),
        }
    }

    fn stop(&self, name: &str) -> Result<ServiceState, ServiceError> {
        validate_service_name(name)?;
        let manager = self.open_manager(SC_MANAGER_CONNECT)?;
        let service = self.open_service(&manager, name, SERVICE_STOP | SERVICE_QUERY_STATUS)?;
        let deadline = Instant::now() + self.timeout;
        match self.transition_until(&service, name, TransitionOperation::Stop, deadline)? {
            TransitionDecision::Return(state) => Ok(state),
            TransitionDecision::Stop => {
                self.stop_service(&service)?;
                self.wait_for_state_until(&service, name, ServiceState::Stopped, deadline)
            }
            _ => unreachable!("stop transition reducer returned an invalid action"),
        }
    }

    fn restart(&self, name: &str) -> Result<ServiceState, ServiceError> {
        validate_service_name(name)?;
        let manager = self.open_manager(SC_MANAGER_CONNECT)?;
        let service = self.open_service(
            &manager,
            name,
            SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS,
        )?;
        let deadline = Instant::now() + self.timeout;
        match self.transition_until(&service, name, TransitionOperation::Restart, deadline)? {
            TransitionDecision::Start => {
                self.start_service(&service)?;
                self.wait_for_state_until(&service, name, ServiceState::Running, deadline)
            }
            TransitionDecision::Stop => {
                self.stop_service(&service)?;
                self.wait_for_state_until(&service, name, ServiceState::Stopped, deadline)?;
                self.start_service(&service)?;
                self.wait_for_state_until(&service, name, ServiceState::Running, deadline)
            }
            _ => unreachable!("restart transition reducer returned an invalid action"),
        }
    }

    fn status(&self, name: &str) -> Result<ServiceState, ServiceError> {
        validate_service_name(name)?;
        let manager = self.open_manager(SC_MANAGER_CONNECT)?;
        let service = self.open_service(&manager, name, SERVICE_QUERY_STATUS)?;
        self.query_state(&service)
    }

    fn set_autostart(&self, name: &str, enabled: bool) -> Result<(), ServiceError> {
        validate_service_name(name)?;
        let manager = self.open_manager(SC_MANAGER_CONNECT)?;
        let service = self.open_service(&manager, name, SERVICE_CHANGE_CONFIG)?;
        let start_type = if enabled {
            SERVICE_AUTO_START
        } else {
            SERVICE_DEMAND_START
        };
        unsafe {
            ChangeServiceConfigW(
                service.raw(),
                ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
                start_type,
                SERVICE_ERROR(SERVICE_NO_CHANGE),
                PCWSTR::null(),
                PCWSTR::null(),
                None,
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
            )
            .map_err(|source| platform_error("ChangeServiceConfigW", source))?;
        }
        Ok(())
    }
}

fn platform_error(operation: &'static str, source: windows::core::Error) -> ServiceError {
    ServiceError::Platform {
        operation,
        source: io::Error::other(source),
    }
}

fn service_command_line(spec: &ServiceInstallSpec) -> Result<Vec<u16>, ServiceError> {
    spec.validate()?;

    let mut command_line = Vec::new();
    append_quoted_argument(&mut command_line, spec.executable.as_os_str());
    for argument in &spec.arguments {
        command_line.push(u16::from(b' '));
        append_quoted_argument(&mut command_line, argument);
    }
    command_line.push(0);
    Ok(command_line)
}

fn append_quoted_argument(command_line: &mut Vec<u16>, argument: &OsStr) {
    command_line.push(u16::from(b'"'));
    let mut backslashes: usize = 0;
    for code_unit in argument.encode_wide() {
        match code_unit {
            code_unit if code_unit == u16::from(b'\\') => backslashes += 1,
            code_unit if code_unit == u16::from(b'"') => {
                command_line.extend(std::iter::repeat_n(
                    u16::from(b'\\'),
                    backslashes.saturating_mul(2).saturating_add(1),
                ));
                command_line.push(code_unit);
                backslashes = 0;
            }
            _ => {
                command_line.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
                command_line.push(code_unit);
                backslashes = 0;
            }
        }
    }
    command_line.extend(std::iter::repeat_n(
        u16::from(b'\\'),
        backslashes.saturating_mul(2),
    ));
    command_line.push(u16::from(b'"'));
}

fn wide_terminated(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(iter::once(0)).collect()
}

fn state_from_status(
    current_state: SERVICE_STATUS_CURRENT_STATE,
    win32_exit_code: u32,
) -> ServiceState {
    if current_state == SERVICE_STOPPED && win32_exit_code != 0 {
        return ServiceState::Failed;
    }

    match current_state {
        SERVICE_RUNNING => ServiceState::Running,
        SERVICE_STOPPED => ServiceState::Stopped,
        SERVICE_START_PENDING => ServiceState::Starting,
        SERVICE_STOP_PENDING => ServiceState::Stopping,
        _ => ServiceState::Unknown,
    }
}
