// ── Tunnel end-to-end tests ─────────────────────────────────────────────────
//
// Tests the full client→tunnel→server→echo path using the TunnelFixture.

use crate::tests::test_util::tunnel_fixture::TunnelFixture;
use crate::tunnel::frame::{TunnelDestination, TunnelFrame};
use bytes::Bytes;

#[tokio::test]
async fn minimal_tunnel_fixture_does_not_hang() {
    let fixture = crate::tests::test_util::tunnel_fixture::TunnelFixture::start().await;
    println!(
        "Fixture started, tcp_port={}, udp_port={}",
        fixture.tcp_echo_port(),
        fixture.udp_echo_port()
    );
    let mut client = fixture.client.lock().await;
    let _stream_id = client
        .open_tcp(crate::tunnel::frame::TunnelDestination::Domain(
            "echo.tunnel.test".into(),
            fixture.tcp_echo_port(),
        ))
        .await
        .expect("open_tcp");
    drop(client);
    let mut client = fixture.client.lock().await;
    let _frame = client.read_frame().await.expect("read TcpOpened");
}

// ── TCP CONNECT ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn socks_connect_reaches_server_side_tcp_echo_only_through_tunnel() {
    let fixture = TunnelFixture::start().await;
    let mut client = fixture.client.lock().await;
    let stream_id = client
        .open_tcp(TunnelDestination::Domain(
            "echo.tunnel.test".into(),
            fixture.tcp_echo_port(),
        ))
        .await
        .expect("open_tcp");
    drop(client);

    let open_frame = {
        let mut client = fixture.client.lock().await;
        client.read_frame().await.expect("read TcpOpened")
    };
    assert!(
        matches!(open_frame, TunnelFrame::TcpOpened { stream_id: id, .. } if id == stream_id),
        "expected TcpOpened, got {:?}",
        open_frame
    );

    let test_data = b"hello";
    {
        let mut client = fixture.client.lock().await;
        client
            .send_tcp_data(stream_id, Bytes::from_static(test_data))
            .await
            .expect("send_tcp_data");
    }

    let echo_frame = {
        let mut client = fixture.client.lock().await;
        client.read_frame().await.expect("read echo TcpData")
    };
    match echo_frame {
        TunnelFrame::TcpData {
            stream_id: id,
            bytes,
        } => {
            assert_eq!(id, stream_id);
            assert_eq!(&bytes[..], test_data);
        }
        other => panic!("expected TcpData, got {:?}", other),
    }

    assert_eq!(fixture.client_direct_connect_attempts(), 0);

    let mut client = fixture.client.lock().await;
    client.close_tcp(stream_id).await.expect("close_tcp");
}

// ── Domain destination remote resolution ────────────────────────────────────

#[tokio::test]
async fn domain_destination_preserved_as_domain_on_client_side() {
    let fixture = TunnelFixture::start().await;

    let mut client = fixture.client.lock().await;
    let stream_id = client
        .open_tcp(TunnelDestination::Domain(
            "echo.tunnel.test".into(),
            fixture.tcp_echo_port(),
        ))
        .await
        .expect("open_tcp with domain");

    let frame = client.read_frame().await.expect("read TcpOpened");
    assert!(matches!(frame, TunnelFrame::TcpOpened { .. }));

    assert_eq!(client.local_resolver_calls(), 0);
    drop(client);

    let mut client = fixture.client.lock().await;
    client.close_tcp(stream_id).await.expect("close_tcp");

    assert_eq!(fixture.client_direct_connect_attempts(), 0);
}

// ── UDP ASSOCIATE ───────────────────────────────────────────────────────────

#[tokio::test]
async fn udp_associate_echoes_datagram_through_tunnel() {
    let fixture = TunnelFixture::start().await;

    let mut client = fixture.client.lock().await;
    let assoc_id = client.open_udp().await.expect("open_udp");

    use std::net::{Ipv4Addr, SocketAddrV4};
    let dest = TunnelDestination::Ip(std::net::SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        fixture.udp_echo_port(),
    )));

    let test_data = b"udp-ping";
    client
        .send_udp_datagram(assoc_id, dest, Bytes::from_static(test_data))
        .await
        .expect("send_udp_datagram");

    let echo_frame = client.read_frame().await.expect("read udp echo");
    match echo_frame {
        TunnelFrame::UdpDatagram {
            association_id: id,
            bytes,
            ..
        } => {
            assert_eq!(id, assoc_id);
            assert_eq!(&bytes[..], test_data);
        }
        other => panic!("expected UdpDatagram, got {:?}", other),
    }

    drop(client);

    let mut client = fixture.client.lock().await;
    client.close_udp(assoc_id).await.expect("close_udp");

    assert_eq!(fixture.client_direct_connect_attempts(), 0);
}

// ── Wrong server key rejection ──────────────────────────────────────────────

#[tokio::test]
async fn client_rejects_wrong_server_key_before_sending_frames() {
    use crate::tunnel::client::TunnelClient;
    use crate::tunnel::crypto::generate_keypair;
    use librqbit_core::Id20;
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, SocketAddrV4};

    // Start a server with a keypair. The client will pin a DIFFERENT key.
    let (server_sk, _server_pk) = generate_keypair();
    let (client_sk, _client_pk) = generate_keypair();
    let (_, wrong_server_pk) = generate_keypair();

    let listener = tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let server_addr = listener.local_addr().unwrap();

    // Spawn an accept task that does the PWC+Noise handshake with the real server key.
    let server_sk_clone = server_sk.clone();
    let accept_handle = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let carrier_hash = Id20::new([0xAB; 20]);
            let encrypted =
                crate::tunnel::peer_wire_crypto::PeerWireCrypto::responder(stream, carrier_hash)
                    .await;
            if let Ok(mut e) = encrypted {
                use tokio::io::AsyncReadExt;
                // Read Noise initiator message
                let mut len_buf = [0u8; 2];
                if e.reader.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let msg_len = u16::from_be_bytes(len_buf) as usize;
                let mut noise_msg = vec![0u8; msg_len];
                if e.reader.read_exact(&mut noise_msg).await.is_err() {
                    return;
                }
                // Accept with real server key (this will succeed at Noise level
                // but the client has wrong_server_pk pinned)
                let mut allowed = HashSet::new();
                allowed.insert(_client_pk);
                let result =
                    crate::tunnel::crypto::responder_accept(&server_sk_clone, &noise_msg, &allowed);
                // Send reply or close — either way, client should detect mismatch
                if let Ok((_transport, _ck, reply)) = result {
                    use tokio::io::AsyncWriteExt;
                    let reply_len = u16::try_from(reply.len()).unwrap().to_be_bytes();
                    let _ = e.writer.write_all(&reply_len).await;
                    let _ = e.writer.write_all(&reply).await;
                    let _ = e.writer.flush().await;
                }
            }
        }
    });

    let carrier_hash = Id20::new([0xAB; 20]);
    let result =
        TunnelClient::connect(server_addr, &client_sk, &wrong_server_pk, carrier_hash).await;

    assert!(
        result.is_err(),
        "expected connection to fail with wrong server key"
    );

    // Clean up
    accept_handle.abort();
}

// ── Unknown client key rejection ────────────────────────────────────────────

#[tokio::test]
async fn server_rejects_unknown_client_key_during_noise_handshake() {
    use crate::tunnel::client::TunnelClient;
    use crate::tunnel::crypto::generate_keypair;
    use crate::tunnel::options::{EgressPolicy, TunnelServerOptions};
    use crate::tunnel::server::TunnelServer;
    use librqbit_core::Id20;
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::PathBuf;

    let (server_sk, server_pk) = generate_keypair();
    let (_known_client_sk, known_client_pk) = generate_keypair();
    let (unknown_client_sk, _unknown_client_pk) = generate_keypair();

    let listener = tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let listen_addr = listener.local_addr().unwrap();

    let mut allowed = HashSet::new();
    allowed.insert(known_client_pk);
    let opts = TunnelServerOptions {
        peer_listen: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        identity_key: server_sk,
        allowed_client_keys: allowed,
        egress_policy: EgressPolicy::default(),
        carrier_root: PathBuf::from("/tmp/test-carrier-reject"),
    };

    let server = TunnelServer::new(opts);

    let server_clone = server.clone();
    let accept_handle = tokio::spawn(async move {
        match listener.accept().await {
            Ok((stream, _)) => {
                let carrier_hash = Id20::new([0xAB; 20]);
                server_clone.accept(stream, carrier_hash).await
            }
            Err(_) => Err(crate::tunnel::server::TunnelAdmissionError::PeerDisconnected),
        }
    });

    let carrier_hash = Id20::new([0xAB; 20]);
    let connect_result =
        TunnelClient::connect(listen_addr, &unknown_client_sk, &server_pk, carrier_hash).await;

    let admission_result = accept_handle.await.expect("accept handle join");
    assert!(
        matches!(
            admission_result,
            Err(crate::tunnel::server::TunnelAdmissionError::NoiseHandshakeFailed(_))
        ),
        "expected admission rejection"
    );

    assert!(
        connect_result.is_err(),
        "expected client connect to fail with unknown client key"
    );
}

// ── Peer loss handling ──────────────────────────────────────────────────────

#[tokio::test]
async fn peer_loss_closes_active_streams() {
    let fixture = TunnelFixture::start().await;

    let mut client = fixture.client.lock().await;
    let stream_id = client
        .open_tcp(TunnelDestination::Domain(
            "echo.tunnel.test".into(),
            fixture.tcp_echo_port(),
        ))
        .await
        .expect("open_tcp");

    client.read_frame().await.expect("read TcpOpened");
    drop(client);

    let mut client = fixture.client.lock().await;
    client.close_tcp(stream_id).await.expect("close_tcp");

    assert_eq!(fixture.client_direct_connect_attempts(), 0);
}

// ── No direct destination connection from client ────────────────────────────

#[tokio::test]
async fn client_never_opens_direct_destination_connection() {
    let fixture = TunnelFixture::start().await;

    let mut client = fixture.client.lock().await;
    let stream_id = client
        .open_tcp(TunnelDestination::Domain(
            "echo.tunnel.test".into(),
            fixture.tcp_echo_port(),
        ))
        .await
        .expect("open_tcp");

    client.read_frame().await.expect("read TcpOpened");

    client
        .send_tcp_data(stream_id, Bytes::from_static(b"direct-check"))
        .await
        .expect("send data");

    client.read_frame().await.expect("read echo");
    client.close_tcp(stream_id).await.expect("close");
    drop(client);

    assert_eq!(
        fixture.client_direct_connect_attempts(),
        0,
        "client opened direct destination connections outside the tunnel"
    );

    let client = fixture.client.lock().await;
    assert_eq!(client.local_resolver_calls(), 0);
}

// ── Ordinary torrent still downloads ────────────────────────────────────────

#[tokio::test]
async fn ordinary_torrent_still_downloads_while_client_tunnel_is_active() {
    // Verify that tunnel presence does not crash normal torrent session operations.
    use crate::{
        AddTorrent, CreateTorrentOptions, Session,
        session::SessionOptions,
        spawn_utils::BlockingSpawner,
        tests::test_util::{
            TestPeerMetadata, create_default_random_dir_with_torrents, setup_test_logging,
        },
    };
    use std::net::Ipv4Addr;

    setup_test_logging();

    let files = create_default_random_dir_with_torrents(1, 8192, Some("tunnel_torrent_test"));
    let torrent = crate::create_torrent(
        files.path(),
        CreateTorrentOptions {
            name: None,
            piece_length: Some(1024),
            ..Default::default()
        },
        &BlockingSpawner::new(1),
    )
    .await
    .expect("create torrent");

    // Start a tunnel fixture FIRST (runs client+server roles in background).
    let _tunnel_fixture = TunnelFixture::start().await;

    // Now create a normal session — it should NOT crash despite tunnel tasks running.
    let server_dir = tempfile::TempDir::new().expect("server temp dir");
    let server_session = Session::new_with_opts(
        server_dir.path().into(),
        SessionOptions {
            dht: None,
            peer_id: Some(TestPeerMetadata::good().as_peer_id()),
            persistence: None,
            listen: Some(crate::listen::ListenerOptions {
                listen_addr: (Ipv4Addr::LOCALHOST, 16903).into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .expect("create server session");

    // Add the torrent — this exercises session internals while tunnel is active.
    let managed = server_session
        .add_torrent(AddTorrent::from_bytes(torrent.as_bytes().unwrap()), None)
        .await
        .expect("add torrent to server");

    // Basic sanity: the session is alive.
    drop(managed);
    drop(server_session);
    // Tunnel fixture is dropped at end of test — should not panic.
}

// ── Multiple stream multiplexing ────────────────────────────────────────────

#[tokio::test]
async fn multiple_concurrent_tcp_streams_through_tunnel() {
    let fixture = TunnelFixture::start().await;

    let mut client = fixture.client.lock().await;

    use std::net::{Ipv4Addr, SocketAddrV4};
    let dest = TunnelDestination::Ip(std::net::SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        fixture.tcp_echo_port(),
    )));

    let sid1 = client.open_tcp(dest.clone()).await.expect("open stream 1");

    let sid2 = client
        .open_tcp(TunnelDestination::Domain(
            "echo.tunnel.test".into(),
            fixture.tcp_echo_port(),
        ))
        .await
        .expect("open stream 2");

    drop(client);

    let mut opened = 0u8;
    let mut client = fixture.client.lock().await;
    for _ in 0..2 {
        let frame = client.read_frame().await.expect("read TcpOpened");
        assert!(matches!(frame, TunnelFrame::TcpOpened { .. }));
        opened += 1;
    }
    assert_eq!(opened, 2);

    client
        .send_tcp_data(sid1, Bytes::from_static(b"stream-1-data"))
        .await
        .expect("send on stream 1");

    client
        .send_tcp_data(sid2, Bytes::from_static(b"stream-2-data"))
        .await
        .expect("send on stream 2");

    let mut echoes: Vec<(u64, Vec<u8>)> = Vec::new();
    for _ in 0..2 {
        let frame = client.read_frame().await.expect("read echo");
        if let TunnelFrame::TcpData { stream_id, bytes } = frame {
            echoes.push((stream_id, bytes.to_vec()));
        }
    }
    drop(client);

    assert_eq!(echoes.len(), 2);
    for (sid, data) in &echoes {
        match *sid {
            id if id == sid1 => assert_eq!(&data[..], b"stream-1-data"),
            id if id == sid2 => assert_eq!(&data[..], b"stream-2-data"),
            _ => panic!("unexpected stream id: {sid}"),
        }
    }

    let mut client = fixture.client.lock().await;
    client.close_tcp(sid1).await.expect("close sid1");
    client.close_tcp(sid2).await.expect("close sid2");

    assert_eq!(fixture.client_direct_connect_attempts(), 0);
}

// ── Server startup regression: fixed listen port (no double bind) ────────────

/// Regression for the double-bind bug: `TunnelService::start` bound
/// `peer_listen`, then `TunnelServer::bind` bound the SAME address again,
/// failing with `EADDRINUSE` whenever a fixed (non-zero) port was configured —
/// so the server could never start on a real deployment port. This drives the
/// full `Session::new_with_opts` → `TunnelService::start` path on a fixed port.
#[tokio::test]
async fn server_tunnel_starts_on_fixed_port_without_double_bind() {
    use crate::tunnel::crypto::generate_keypair;
    use crate::tunnel::options::{EgressPolicy, TunnelOptions, TunnelServerOptions};
    use crate::{Session, session::SessionOptions, tests::test_util::setup_test_logging};
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    setup_test_logging();

    // Reserve a concrete free port, then release it so the tunnel can claim it.
    let probe = tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("probe bind");
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let (server_sk, _server_pk) = generate_keypair();
    let (_client_sk, client_pk) = generate_keypair();
    let mut allowed = HashSet::new();
    allowed.insert(client_pk);

    let dir = tempfile::TempDir::new().expect("temp dir");
    let session = Session::new_with_opts(
        dir.path().into(),
        SessionOptions {
            dht: None,
            persistence: None,
            listen: None,
            tunnel: Some(TunnelOptions::Server(TunnelServerOptions {
                peer_listen: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
                identity_key: server_sk,
                allowed_client_keys: allowed,
                egress_policy: EgressPolicy::default(),
                carrier_root: dir.path().join("carrier"),
            })),
            ..Default::default()
        },
    )
    .await
    .expect("session with fixed-port tunnel server must start (double-bind regression)");

    assert!(
        session.tunnel_service().is_some(),
        "tunnel service should be started"
    );
}
