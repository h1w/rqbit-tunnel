use std::{future::Future, path::Path, pin::Pin, time::Duration};

use crate::{
    platform::{CLIENT_SERVICE, ServiceError, ServiceManager, ServiceState},
    update::manifest::UpdateError,
    version::{ActiveRelease, read_active_release, write_active_release},
};

pub trait LocalHealth: Send + Sync {
    fn wait_for_ready<'a>(
        &'a self,
        deadline: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), UpdateError>> + Send + 'a>>;
}

pub async fn activate_release(
    install_root: &Path,
    candidate: &ActiveRelease,
    service: &dyn ServiceManager,
    health: &dyn LocalHealth,
    deadline: Duration,
) -> Result<(), UpdateError> {
    let previous = read_active_release(install_root)
        .map_err(|source| UpdateError::ReadActiveRelease { source })?;
    if candidate.version() <= previous.version() {
        return Err(UpdateError::NoUpdate);
    }
    validate_candidate_layout(candidate)?;
    candidate
        .payload_executable(install_root)
        .map_err(|source| UpdateError::ResolveCandidatePayload { source })?;

    stop_client(service)?;

    match activate_candidate(install_root, candidate, service, health, deadline).await {
        Ok(()) => Ok(()),
        Err(source) => Err(rollback(install_root, &previous, service, source)),
    }
}

async fn activate_candidate(
    install_root: &Path,
    candidate: &ActiveRelease,
    service: &dyn ServiceManager,
    health: &dyn LocalHealth,
    deadline: Duration,
) -> Result<(), UpdateError> {
    write_active_release(install_root, candidate)
        .map_err(|source| UpdateError::WriteCandidateActiveRelease { source })?;
    start_client(service)?;
    health.wait_for_ready(deadline).await
}

fn validate_candidate_layout(candidate: &ActiveRelease) -> Result<(), UpdateError> {
    let expected = Path::new("releases")
        .join(candidate.version().to_string())
        .join("payload");
    if candidate.payload_dir() != expected.as_path() {
        return Err(UpdateError::InvalidActivationPayloadDirectory {
            payload_dir: candidate.payload_dir().to_path_buf(),
            expected,
        });
    }
    Ok(())
}

fn rollback(
    install_root: &Path,
    previous: &ActiveRelease,
    service: &dyn ServiceManager,
    source: UpdateError,
) -> UpdateError {
    match restore_previous_release(install_root, previous, service) {
        Ok(()) => UpdateError::RolledBack {
            source: Box::new(source),
        },
        Err(recovery) => UpdateError::RollbackFailed {
            source: Box::new(source),
            recovery: Box::new(recovery),
        },
    }
}

fn restore_previous_release(
    install_root: &Path,
    previous: &ActiveRelease,
    service: &dyn ServiceManager,
) -> Result<(), UpdateError> {
    stop_client(service)?;
    write_active_release(install_root, previous)
        .map_err(|source| UpdateError::RestorePreviousActiveRelease { source })?;
    start_client(service)
}

fn stop_client(service: &dyn ServiceManager) -> Result<(), UpdateError> {
    let state = match service.stop(CLIENT_SERVICE) {
        Ok(state) => state,
        Err(ServiceError::FailedState) => return Ok(()),
        Err(source) => return Err(UpdateError::StopClientService { source }),
    };
    match state {
        ServiceState::Stopped => Ok(()),
        state => Err(UpdateError::UnexpectedClientStopState { state }),
    }
}

fn start_client(service: &dyn ServiceManager) -> Result<(), UpdateError> {
    match service
        .start(CLIENT_SERVICE)
        .map_err(|source| UpdateError::StartClientService { source })?
    {
        ServiceState::Running => Ok(()),
        state => Err(UpdateError::UnexpectedClientStartState { state }),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        path::{Path, PathBuf},
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use parking_lot::Mutex;
    use semver::Version;
    use tempfile::tempdir;

    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::{LocalHealth, activate_release};
    use crate::{
        platform::{
            CLIENT_SERVICE, ServiceError, ServiceInstallSpec, ServiceManager, ServiceState,
        },
        update::manifest::UpdateError,
        version::{ActiveRelease, current_exe_suffix, read_active_release, write_active_release},
    };

    #[tokio::test]
    async fn failed_health_check_restores_previous_active_release() {
        let install_root = tempdir().expect("installation root should be created");
        let previous = release("1.0.0");
        let candidate = release("1.1.0");
        create_payload(install_root.path(), &previous);
        create_payload(install_root.path(), &candidate);
        write_active_release(install_root.path(), &previous)
            .expect("previous active release should be written");

        let service = RecordingService::default();
        let health = AlwaysFailHealth;
        let error = activate_release(
            install_root.path(),
            &candidate,
            &service,
            &health,
            Duration::from_millis(1),
        )
        .await
        .expect_err("failed health must roll back");

        assert!(matches!(error, UpdateError::RolledBack { .. }));
        assert_eq!(read_active_release(install_root.path()).unwrap(), previous);
        assert_eq!(
            service.calls(),
            ["stop", "start", "stop", "start"],
            "rollback must stop the unhealthy new payload before restarting the old payload"
        );
    }

    #[tokio::test]
    async fn stale_candidate_does_not_stop_service() {
        let install_root = tempdir().expect("installation root should be created");
        let previous = release("1.1.0");
        let candidate = release("1.0.0");
        create_payload(install_root.path(), &previous);
        create_payload(install_root.path(), &candidate);
        write_active_release(install_root.path(), &previous)
            .expect("previous active release should be written");

        let service = RecordingService::default();
        let error = activate_release(
            install_root.path(),
            &candidate,
            &service,
            &AlwaysFailHealth,
            Duration::from_millis(1),
        )
        .await
        .expect_err("stale candidate must be rejected");

        assert!(matches!(error, UpdateError::NoUpdate));
        assert!(
            service.calls().is_empty(),
            "stale candidate must not stop the service"
        );
    }
    #[tokio::test]
    async fn stale_candidate_rejection_precedes_payload_layout_validation() {
        let install_root = tempdir().expect("installation root should be created");
        let previous = release("1.1.0");
        let candidate = ActiveRelease::new(
            Version::parse("1.0.0").expect("fixture version should parse"),
            PathBuf::from("other/1.0.0"),
            1,
        )
        .expect("fixture release should be safe");
        write_active_release(install_root.path(), &previous)
            .expect("previous active release should be written");

        let service = RecordingService::default();
        let error = activate_release(
            install_root.path(),
            &candidate,
            &service,
            &AlwaysFailHealth,
            Duration::from_millis(1),
        )
        .await
        .expect_err("stale candidate must be rejected before layout validation");

        assert!(matches!(error, UpdateError::NoUpdate));
        assert!(
            service.calls().is_empty(),
            "stale candidate must not call the service"
        );
    }

    #[tokio::test]
    async fn non_regular_candidate_payload_does_not_stop_service() {
        let install_root = tempdir().expect("installation root should be created");
        let previous = release("1.0.0");
        let candidate = release("1.1.0");
        create_payload(install_root.path(), &previous);
        let payload = payload_path(install_root.path(), &candidate);
        std::fs::create_dir_all(&payload).expect("candidate payload directory should be created");
        write_active_release(install_root.path(), &previous)
            .expect("previous active release should be written");

        let service = RecordingService::default();
        let error = activate_release(
            install_root.path(),
            &candidate,
            &service,
            &AlwaysFailHealth,
            Duration::from_millis(1),
        )
        .await
        .expect_err("candidate payload directory must be rejected");

        assert!(matches!(error, UpdateError::ResolveCandidatePayload { .. }));
        assert!(
            service.calls().is_empty(),
            "non-regular candidate payload must not stop the service"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_candidate_payload_does_not_stop_service() {
        let install_root = tempdir().expect("installation root should be created");
        let previous = release("1.0.0");
        let candidate = release("1.1.0");
        create_payload(install_root.path(), &previous);

        let target = install_root.path().join("payload-target");
        std::fs::write(&target, b"fixture payload").expect("payload target should be created");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("payload target should be executable");
        let payload = payload_path(install_root.path(), &candidate);
        std::fs::create_dir_all(payload.parent().expect("payload has a parent"))
            .expect("candidate payload directory should be created");
        symlink(&target, &payload).expect("candidate payload should be a symlink");
        write_active_release(install_root.path(), &previous)
            .expect("previous active release should be written");

        let service = RecordingService::default();
        let error = activate_release(
            install_root.path(),
            &candidate,
            &service,
            &AlwaysFailHealth,
            Duration::from_millis(1),
        )
        .await
        .expect_err("symlink candidate payload must be rejected");

        assert!(matches!(error, UpdateError::ResolveCandidatePayload { .. }));
        assert!(
            service.calls().is_empty(),
            "symlink candidate payload must not stop the service"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn non_executable_candidate_payload_does_not_stop_service() {
        let install_root = tempdir().expect("installation root should be created");
        let previous = release("1.0.0");
        let candidate = release("1.1.0");
        create_payload(install_root.path(), &previous);
        create_payload(install_root.path(), &candidate);
        let payload = payload_path(install_root.path(), &candidate);
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o644))
            .expect("candidate payload should be non-executable");
        write_active_release(install_root.path(), &previous)
            .expect("previous active release should be written");

        let service = RecordingService::default();
        let error = activate_release(
            install_root.path(),
            &candidate,
            &service,
            &AlwaysFailHealth,
            Duration::from_millis(1),
        )
        .await
        .expect_err("non-executable candidate payload must be rejected");

        assert!(matches!(error, UpdateError::ResolveCandidatePayload { .. }));
        assert!(
            service.calls().is_empty(),
            "non-executable candidate payload must not stop the service"
        );
    }

    #[tokio::test]
    async fn failed_state_while_stopping_during_rollback_restores_previous_release() {
        let install_root = tempdir().expect("installation root should be created");
        let previous = release("1.0.0");
        let candidate = release("1.1.0");
        create_payload(install_root.path(), &previous);
        create_payload(install_root.path(), &candidate);
        write_active_release(install_root.path(), &previous)
            .expect("previous active release should be written");

        let service = FailedStateOnSecondStopService::default();
        let error = activate_release(
            install_root.path(),
            &candidate,
            &service,
            &AlwaysFailHealth,
            Duration::from_millis(1),
        )
        .await
        .expect_err("failed health must roll back");

        assert!(matches!(error, UpdateError::RolledBack { .. }));
        assert_eq!(read_active_release(install_root.path()).unwrap(), previous);
        assert_eq!(
            service.calls(),
            ["stop", "start", "stop", "start"],
            "a failed service is already quiescent and rollback must restart the old payload"
        );
    }

    fn release(version: &str) -> ActiveRelease {
        let version = Version::parse(version).expect("fixture version should parse");
        ActiveRelease::new(
            version.clone(),
            PathBuf::from(format!("releases/{version}/payload")),
            1,
        )
        .expect("fixture release should be valid")
    }

    fn payload_path(install_root: &Path, release: &ActiveRelease) -> PathBuf {
        install_root
            .join(release.payload_dir())
            .join(format!("rqbit-tunnel{}", current_exe_suffix()))
    }

    fn create_payload(install_root: &Path, release: &ActiveRelease) {
        let payload = payload_path(install_root, release);
        std::fs::create_dir_all(payload.parent().expect("payload has a parent"))
            .expect("payload directory should be created");
        std::fs::write(&payload, b"fixture payload").expect("payload should be created");
        #[cfg(unix)]
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o755))
            .expect("payload should be executable");
    }

    #[derive(Default)]
    struct RecordingService {
        calls: Mutex<Vec<&'static str>>,
    }

    impl RecordingService {
        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().clone()
        }

        fn record(&self, operation: &'static str) {
            self.calls.lock().push(operation);
        }
    }

    impl ServiceManager for RecordingService {
        fn install(&self, _: &ServiceInstallSpec) -> Result<(), ServiceError> {
            Ok(())
        }

        fn start(&self, name: &str) -> Result<ServiceState, ServiceError> {
            assert_eq!(name, CLIENT_SERVICE);
            self.record("start");
            Ok(ServiceState::Running)
        }

        fn stop(&self, name: &str) -> Result<ServiceState, ServiceError> {
            assert_eq!(name, CLIENT_SERVICE);
            self.record("stop");
            Ok(ServiceState::Stopped)
        }

        fn restart(&self, _: &str) -> Result<ServiceState, ServiceError> {
            unreachable!("activation always uses an explicit stop/start sequence")
        }

        fn status(&self, _: &str) -> Result<ServiceState, ServiceError> {
            unreachable!("activation does not use manager status as health")
        }

        fn set_autostart(&self, _: &str, _: bool) -> Result<(), ServiceError> {
            unreachable!("activation does not change autostart")
        }
    }

    #[derive(Default)]
    struct FailedStateOnSecondStopService {
        calls: Mutex<Vec<&'static str>>,
        stop_count: AtomicUsize,
    }

    impl FailedStateOnSecondStopService {
        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().clone()
        }

        fn record(&self, operation: &'static str) {
            self.calls.lock().push(operation);
        }
    }

    impl ServiceManager for FailedStateOnSecondStopService {
        fn install(&self, _: &ServiceInstallSpec) -> Result<(), ServiceError> {
            Ok(())
        }

        fn start(&self, name: &str) -> Result<ServiceState, ServiceError> {
            assert_eq!(name, CLIENT_SERVICE);
            self.record("start");
            Ok(ServiceState::Running)
        }

        fn stop(&self, name: &str) -> Result<ServiceState, ServiceError> {
            assert_eq!(name, CLIENT_SERVICE);
            self.record("stop");
            if self.stop_count.fetch_add(1, Ordering::SeqCst) == 1 {
                Err(ServiceError::FailedState)
            } else {
                Ok(ServiceState::Stopped)
            }
        }

        fn restart(&self, _: &str) -> Result<ServiceState, ServiceError> {
            unreachable!("activation always uses an explicit stop/start sequence")
        }

        fn status(&self, _: &str) -> Result<ServiceState, ServiceError> {
            unreachable!("activation does not use manager status as health")
        }

        fn set_autostart(&self, _: &str, _: bool) -> Result<(), ServiceError> {
            unreachable!("activation does not change autostart")
        }
    }

    struct AlwaysFailHealth;

    impl LocalHealth for AlwaysFailHealth {
        fn wait_for_ready<'a>(
            &'a self,
            _: Duration,
        ) -> Pin<Box<dyn Future<Output = Result<(), UpdateError>> + Send + 'a>> {
            Box::pin(async { Err(UpdateError::HealthTimeout) })
        }
    }
}
