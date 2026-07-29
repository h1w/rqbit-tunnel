#![cfg(unix)]

use std::{
    fs, io,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    sync::Arc,
    time::Duration,
};

use librqbit::{
    Session, SessionOptions, TunnelClientOptions, TunnelOptions, TunnelPrivateKey, TunnelPublicKey,
    tunnel_generate_keypair,
};
use rqbit_tunnel::{
    ipc::{
        protocol::{ServerRequest, ServerResponse},
        unix::UnixControlClient,
    },
    model::{EnrollmentBundle, ServerConfig, ServerEgressConfig, UserSnapshot},
    paths::ServerPaths,
    runtime::server::{ManagedServer, ServerRuntimeError},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

const TEST_TIMEOUT: Duration = Duration::from_secs(15);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_server_admits_bundle_client_meters_payload_and_revokes_active_tunnel() {
    let directory = tempfile::tempdir().unwrap();
    let (server, paths, peer_addr) = start_server(&directory).await;
    let bundle_path = directory.path().join("alice-enrollment.json");
    let user = match request(
        &paths,
        ServerRequest::AddUser {
            name: "alice".to_owned(),
            export_path: bundle_path.clone(),
        },
    )
    .await
    {
        ServerResponse::User(user) => user,
        other => panic!("expected user creation response, got {other:?}"),
    };
    assert_eq!(
        fs::metadata(&bundle_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let bundle: EnrollmentBundle =
        serde_json::from_slice(&fs::read(&bundle_path).unwrap()).unwrap();
    assert_eq!(bundle.server_addr, peer_addr);

    let (echo_addr, echo_shutdown, echo_task) = start_echo_server().await;
    let (client, socks_addr) = start_client(&directory, &bundle).await;

    let mut socks = connect_socks(socks_addr, echo_addr).await;
    let payload = b"managed-server-control-e2e";
    socks.write_all(payload).await.unwrap();
    let mut echoed = vec![0; payload.len()];
    socks.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);

    let metered = wait_for_metered_user(&paths, user.id, payload.len() as u64).await;
    assert_eq!(metered.connected, 1);
    assert_eq!(metered.traffic.upload, payload.len() as u64);
    assert_eq!(metered.traffic.download, payload.len() as u64);

    let mut idle_byte = [0; 1];
    assert!(
        matches!(
            timeout(Duration::from_millis(100), socks.read(&mut idle_byte)).await,
            Err(_)
        ),
        "SOCKS stream closed before user revocation"
    );

    match request(
        &paths,
        ServerRequest::SetEnabled {
            id: user.id,
            enabled: false,
        },
    )
    .await
    {
        ServerResponse::User(snapshot) => assert!(!snapshot.enabled),
        other => panic!("expected user update response, got {other:?}"),
    }

    let mut byte = [0; 1];
    match timeout(TEST_TIMEOUT, socks.read(&mut byte)).await {
        Ok(Ok(0) | Err(_)) => {}
        Ok(Ok(count)) => panic!("revoked SOCKS stream remained open and read {count} byte(s)"),
        Err(_) => panic!("revoked SOCKS stream did not close before timeout"),
    }
    let revoked = wait_for_disconnected_user(&paths, user.id).await;
    assert!(!revoked.enabled);
    assert_eq!(revoked.connected, 0);

    client.stop().await;
    echo_shutdown.cancel();
    echo_task.await.unwrap().unwrap();
    server.shutdown().await.unwrap();
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

async fn start_client(
    directory: &TempDir,
    bundle: &EnrollmentBundle,
) -> (Arc<Session>, SocketAddr) {
    for _ in 0..8 {
        let socks_addr = unused_loopback_address().await;
        let client = Session::new_with_opts(
            directory.path().join("client"),
            SessionOptions {
                dht: None,
                disable_trackers: true,
                persistence: None,
                listen: None,
                connect: None,
                disable_local_service_discovery: true,
                tunnel: Some(TunnelOptions::Client(TunnelClientOptions {
                    socks_listen: socks_addr,
                    server_addr: Some(bundle.server_addr),
                    identity_key: TunnelPrivateKey(bundle.client_private_key),
                    expected_server_key: TunnelPublicKey(bundle.server_public_key),
                    pairing: None,
                    carriers: bundle.carriers,
                    carrier_root: directory.path().join("client-carrier"),
                })),
                ..Default::default()
            },
        )
        .await;

        match client {
            Ok(client) => return (client, socks_addr),
            Err(error)
                if error.chain().any(|source| {
                    source
                        .downcast_ref::<io::Error>()
                        .is_some_and(|source| source.kind() == io::ErrorKind::AddrInUse)
                }) => {}
            Err(error) => panic!("bundle client failed to start: {error:#}"),
        }
    }

    panic!("could not reserve a usable local SOCKS port");
}

async fn start_echo_server() -> (
    SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut payload = vec![0; b"managed-server-control-e2e".len()];
        stream.read_exact(&mut payload).await?;
        stream.write_all(&payload).await?;
        tokio::select! {
            _ = task_shutdown.cancelled() => Ok(()),
            _ = stream.read_u8() => Ok(()),
        }
    });
    (address, shutdown, task)
}

async fn unused_loopback_address() -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    listener.local_addr().unwrap()
}

async fn request(paths: &ServerPaths, request: ServerRequest) -> ServerResponse {
    UnixControlClient::connect(paths.control_socket_path())
        .await
        .unwrap()
        .request(request)
        .await
        .unwrap()
}

async fn connect_socks(proxy: SocketAddr, destination: SocketAddr) -> TcpStream {
    timeout(TEST_TIMEOUT, async {
        loop {
            if let Ok(mut stream) = TcpStream::connect(proxy).await {
                if socks_connect(&mut stream, destination).await.is_ok() {
                    return stream;
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("bundle client did not establish a SOCKS tunnel before timeout")
}

async fn socks_connect(stream: &mut TcpStream, destination: SocketAddr) -> io::Result<()> {
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 0] {
        return Err(io::Error::other("SOCKS server rejected no-authentication"));
    }

    let SocketAddr::V4(destination) = destination else {
        unreachable!("echo server binds to IPv4 loopback");
    };
    let mut connect = vec![5, 1, 0, 1];
    connect.extend_from_slice(&destination.ip().octets());
    connect.extend_from_slice(&destination.port().to_be_bytes());
    stream.write_all(&connect).await?;

    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[..3] != [5, 0, 0] {
        return Err(io::Error::other("SOCKS server rejected tunnel destination"));
    }
    let remaining = match header[3] {
        1 => 6,
        3 => {
            let domain_length = stream.read_u8().await? as usize;
            domain_length + 2
        }
        4 => 18,
        other => {
            return Err(io::Error::other(format!(
                "unexpected SOCKS address type {other}"
            )));
        }
    };
    let mut ignored = vec![0; remaining];
    stream.read_exact(&mut ignored).await?;
    Ok(())
}

async fn wait_for_metered_user(
    paths: &ServerPaths,
    user_id: uuid::Uuid,
    expected: u64,
) -> UserSnapshot {
    timeout(TEST_TIMEOUT, async {
        loop {
            let user = snapshot_user(paths, user_id).await;
            if user.connected == 1
                && user.traffic.upload >= expected
                && user.traffic.download >= expected
            {
                return user;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("tunnel payload was not reflected in the server snapshot")
}

async fn wait_for_disconnected_user(paths: &ServerPaths, user_id: uuid::Uuid) -> UserSnapshot {
    timeout(TEST_TIMEOUT, async {
        loop {
            let user = snapshot_user(paths, user_id).await;
            if user.connected == 0 {
                return user;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("disabled user remained connected")
}

async fn snapshot_user(paths: &ServerPaths, user_id: uuid::Uuid) -> UserSnapshot {
    let ServerResponse::Snapshot(snapshot) = request(paths, ServerRequest::Snapshot).await else {
        panic!("expected server snapshot response");
    };
    snapshot
        .users
        .into_iter()
        .find(|user| user.id == user_id)
        .expect("created user is present in the server snapshot")
}
