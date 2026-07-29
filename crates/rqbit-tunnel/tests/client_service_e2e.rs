#![cfg(unix)]

use std::{
    ffi::OsString,
    fs,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use librqbit::tunnel_generate_keypair;
use rqbit_tunnel::{
    config::{import_bundle, load_client_config, write_client_config},
    ipc::{
        protocol::{ClientRequest, ClientResponse, ServerRequest, ServerResponse},
        unix::{UnixClientControlClient, UnixControlClient},
    },
    model::{
        ClientSnapshot, EnrollmentBundle, LocalServiceState, LocalTunnelState, ServerConfig,
        ServerEgressConfig,
    },
    paths::{ClientPaths, ServerPaths},
    platform::{CLIENT_SERVICE, ServiceError, ServiceInstallSpec, ServiceManager, ServiceState},
    runtime::{
        client::{ClientRuntimeError, ManagedClient},
        server::{ManagedServer, ServerRuntimeError},
    },
};
use tempfile::TempDir;
use tokio::{
    net::TcpListener,
    time::{sleep, timeout},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(15);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires root to exercise the production Unix control-socket ownership policy"]
async fn imported_client_reports_reconnecting_then_connected_over_real_local_ipc() {
    // Managed client IPC is deliberately rooted in a root-owned runtime
    // directory. CI runs this ignored test as root; an explicit assertion keeps
    // manual non-root --ignored runs from becoming false successes.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "requires root to exercise the production Unix control-socket ownership policy"
    );

    let directory = tempfile::tempdir().unwrap();
    // Keep the staged Unix socket beneath a short, secure TempDir while the
    // client config and data remain under this test's temporary root.
    let client_runtime = shallow_client_runtime_root();
    let (server, server_paths, server_addr) = start_server(&directory).await;
    let bundle = issue_enrollment_bundle(&server_paths, directory.path()).await;
    assert_eq!(bundle.server_addr, server_addr);
    let mut client_paths = ClientPaths::under(directory.path().join("client"));
    client_paths.run_dir = client_runtime.path().to_path_buf();
    import_bundle(&client_paths, bundle).unwrap();

    let manager = RecordingServiceManager::default();
    manager.install(&managed_client_service_spec()).unwrap();
    assert_eq!(
        manager.start(CLIENT_SERVICE).unwrap(),
        ServiceState::Running
    );

    let unreachable_server = unused_loopback_address().await;
    let (first_client, configured_socks) =
        start_client_with_unreachable_endpoint(&client_paths, unreachable_server).await;
    let reconnecting = client_snapshot(&client_paths).await;
    assert_eq!(reconnecting.service, LocalServiceState::Running);
    assert_eq!(reconnecting.tunnel, LocalTunnelState::Reconnecting);
    assert_eq!(reconnecting.socks_listen, Some(configured_socks));
    assert_eq!(
        manager.status(CLIENT_SERVICE).unwrap(),
        ServiceState::Running
    );

    let mut config = load_client_config(&client_paths).unwrap();
    assert_eq!(config.server_addr, Some(unreachable_server));
    assert_eq!(config.socks_listen, configured_socks);
    config.server_addr = Some(server_addr);
    write_client_config(&client_paths, &config).unwrap();

    // The fake manager records the service API contract only. These explicit
    // managed-client instances remain the real tunnel runtime under test.
    first_client.shutdown().await.unwrap();
    assert_eq!(
        manager.restart(CLIENT_SERVICE).unwrap(),
        ServiceState::Running
    );

    let second_client = start_client(&client_paths).await;
    let connected = wait_for_connected(&client_paths).await;
    assert_eq!(connected.service, LocalServiceState::Running);
    assert_eq!(connected.tunnel, LocalTunnelState::Connected);
    assert_eq!(connected.socks_listen, Some(configured_socks));

    second_client.shutdown().await.unwrap();
    assert_eq!(manager.stop(CLIENT_SERVICE).unwrap(), ServiceState::Stopped);
    server.shutdown().await.unwrap();

    assert_eq!(
        manager.calls(),
        vec!["install", "start", "status", "restart", "stop"]
    );
}

#[derive(Default)]
struct RecordingServiceManager {
    calls: Mutex<Vec<&'static str>>,
}

impl RecordingServiceManager {
    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().expect("calls mutex poisoned").clone()
    }

    fn record(&self, call: &'static str) {
        self.calls.lock().expect("calls mutex poisoned").push(call);
    }

    fn require_client_service(name: &str) {
        assert_eq!(name, CLIENT_SERVICE);
    }
}

impl ServiceManager for RecordingServiceManager {
    fn install(&self, spec: &ServiceInstallSpec) -> Result<(), ServiceError> {
        spec.validate()?;
        assert_eq!(spec, &managed_client_service_spec());
        self.record("install");
        Ok(())
    }

    fn start(&self, name: &str) -> Result<ServiceState, ServiceError> {
        Self::require_client_service(name);
        self.record("start");
        Ok(ServiceState::Running)
    }

    fn stop(&self, name: &str) -> Result<ServiceState, ServiceError> {
        Self::require_client_service(name);
        self.record("stop");
        Ok(ServiceState::Stopped)
    }

    fn restart(&self, name: &str) -> Result<ServiceState, ServiceError> {
        Self::require_client_service(name);
        self.record("restart");
        Ok(ServiceState::Running)
    }

    fn status(&self, name: &str) -> Result<ServiceState, ServiceError> {
        Self::require_client_service(name);
        self.record("status");
        Ok(ServiceState::Running)
    }

    fn set_autostart(&self, name: &str, _enabled: bool) -> Result<(), ServiceError> {
        Self::require_client_service(name);
        Err(ServiceError::CommandFailed {
            operation: "set_autostart",
            message: "not part of this lifecycle acceptance test".to_owned(),
        })
    }
}

fn managed_client_service_spec() -> ServiceInstallSpec {
    ServiceInstallSpec {
        executable: PathBuf::from("/opt/rqbit-tunnel/launcher"),
        arguments: vec![
            OsString::from("client"),
            OsString::from("run"),
            OsString::from("--config"),
            OsString::from("/etc/rqbit-tunnel/client.json"),
        ],
        working_directory: PathBuf::from("/opt/rqbit-tunnel"),
        display_name: "rqbit tunnel client".to_owned(),
    }
}

fn shallow_client_runtime_root() -> TempDir {
    tempfile::Builder::new()
        .prefix("rqbt-")
        .tempdir_in("/tmp")
        .expect("secure shallow client runtime directory")
}

async fn start_server(directory: &TempDir) -> (ManagedServer, ServerPaths, SocketAddr) {
    let paths = ServerPaths::under(directory.path().join("server"));
    fs::create_dir_all(&paths.config_dir).unwrap();
    let (server_key, _) = tunnel_generate_keypair();
    fs::write(paths.server_key_path(), hex::encode(server_key.0)).unwrap();
    fs::set_permissions(paths.server_key_path(), fs::Permissions::from_mode(0o600)).unwrap();

    for _ in 0..8 {
        let peer_addr = unused_loopback_address().await;
        let config = ServerConfig {
            schema_version: 1,
            peer_listen: peer_addr,
            advertised_peer: Some(peer_addr),
            egress: ServerEgressConfig {
                allow_private: false,
                allow_loopback: true,
                allow_link_local: false,
                allow_multicast: false,
            },
            default_client_socks_listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            default_client_carriers: 1,
        };
        fs::write(
            paths.config_path(),
            serde_json::to_vec(&config).expect("server config serializes"),
        )
        .unwrap();

        match ManagedServer::start(paths.clone()).await {
            Ok(server) => return (server, paths, peer_addr),
            Err(ServerRuntimeError::SessionStart) => continue,
            Err(error) => panic!("managed server failed to start: {error}"),
        }
    }

    panic!("could not reserve a usable tunnel peer port");
}

async fn issue_enrollment_bundle(paths: &ServerPaths, directory: &Path) -> EnrollmentBundle {
    let bundle_path = directory.join("alice-enrollment.json");
    match server_request(
        paths,
        ServerRequest::AddUser {
            name: "alice".to_owned(),
            export_path: bundle_path.clone(),
        },
    )
    .await
    {
        ServerResponse::User(_) => {}
        other => panic!("expected user creation response, got {other:?}"),
    }

    serde_json::from_slice(&fs::read(bundle_path).unwrap()).unwrap()
}

async fn start_client_with_unreachable_endpoint(
    paths: &ClientPaths,
    unreachable_server: SocketAddr,
) -> (ManagedClient, SocketAddr) {
    for _ in 0..8 {
        let socks_listen = unused_loopback_address().await;
        let mut config = load_client_config(paths).unwrap();
        config.server_addr = Some(unreachable_server);
        config.socks_listen = socks_listen;
        write_client_config(paths, &config).unwrap();

        match ManagedClient::start(paths.clone()).await {
            Ok(client) => return (client, socks_listen),
            Err(ClientRuntimeError::SessionStart) => continue,
            Err(error) => panic!("managed client failed to start: {error}"),
        }
    }

    panic!("could not reserve a usable local SOCKS port");
}

async fn start_client(paths: &ClientPaths) -> ManagedClient {
    for _ in 0..8 {
        match ManagedClient::start(paths.clone()).await {
            Ok(client) => return client,
            Err(ClientRuntimeError::SessionStart) => sleep(Duration::from_millis(25)).await,
            Err(error) => panic!("managed client failed to restart: {error}"),
        }
    }

    panic!("managed client did not restart after its previous shutdown");
}

async fn wait_for_connected(paths: &ClientPaths) -> ClientSnapshot {
    timeout(TEST_TIMEOUT, async {
        loop {
            let snapshot = client_snapshot(paths).await;
            if snapshot.tunnel == LocalTunnelState::Connected {
                return snapshot;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("managed client did not establish a carrier before timeout")
}

async fn client_snapshot(paths: &ClientPaths) -> ClientSnapshot {
    let mut control = UnixClientControlClient::connect(paths.control_socket_path())
        .await
        .unwrap();
    match control.request(ClientRequest::Snapshot).await.unwrap() {
        ClientResponse::Snapshot(snapshot) => snapshot,
        ClientResponse::Error(error) => panic!("unexpected client snapshot error: {error:?}"),
    }
}

async fn unused_loopback_address() -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    listener.local_addr().unwrap()
}

async fn server_request(paths: &ServerPaths, request: ServerRequest) -> ServerResponse {
    UnixControlClient::connect(paths.control_socket_path())
        .await
        .unwrap()
        .request(request)
        .await
        .unwrap()
}
