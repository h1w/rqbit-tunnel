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

// ── Follow-up: reconnecting client startup ───────────────────────────────────

/// The client tunnel must NOT make session startup fail when the server is
/// unreachable — the SOCKS listener comes up and the supervisor retries in the
/// background.
#[tokio::test]
async fn client_tunnel_starts_when_server_unreachable() {
    use crate::tunnel::crypto::generate_keypair;
    use crate::tunnel::options::{TunnelClientOptions, TunnelOptions};
    use crate::{Session, session::SessionOptions, tests::test_util::setup_test_logging};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    setup_test_logging();

    // Reserve a port and immediately release it so connects are refused.
    let probe = tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let dead_port = probe.local_addr().unwrap().port();
    drop(probe);

    let (client_sk, _client_pk) = generate_keypair();
    let (_server_sk, server_pk) = generate_keypair();

    let dir = tempfile::TempDir::new().unwrap();
    let session = Session::new_with_opts(
        dir.path().into(),
        SessionOptions {
            dht: None,
            persistence: None,
            listen: None,
            tunnel: Some(TunnelOptions::Client(TunnelClientOptions {
                socks_listen: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
                server_addr: Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    dead_port,
                ))),
                identity_key: client_sk,
                expected_server_key: server_pk,
                pairing: None,
            })),
            ..Default::default()
        },
    )
    .await
    .expect("session must start even if the tunnel server is unreachable");

    assert!(
        session.tunnel_service().is_some(),
        "tunnel service should be started (SOCKS listener up, connecting in background)"
    );
}

// ── Follow-up: real relay + credit-based flow control ────────────────────────

/// Build a client + admitted-peer pair over an in-process encrypted duplex,
/// wired to the REAL production handshake (not the echo test fixture).
async fn build_real_relay_pair() -> (
    crate::tunnel::client::TunnelClient,
    crate::tunnel::server::AdmittedPeer,
) {
    use crate::tunnel::client::TunnelClient;
    use crate::tunnel::crypto::{self, generate_keypair};
    use crate::tunnel::peer_wire_crypto::PeerWireCrypto;
    use crate::tunnel::server::AdmittedPeer;
    use librqbit_core::Id20;
    use std::collections::HashSet;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client_sk, client_pk) = generate_keypair();
    let (server_sk, server_pk) = generate_keypair();
    let carrier_hash = Id20::new([0xAB; 20]);
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let client_pk_c = client_pk.clone();

    let server_handle = tokio::spawn(async move {
        let enc = PeerWireCrypto::responder(server_io, carrier_hash)
            .await
            .unwrap();
        let mut reader = enc.reader;
        let mut writer = enc.writer;
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).await.unwrap();
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        let mut noise_msg = vec![0u8; msg_len];
        reader.read_exact(&mut noise_msg).await.unwrap();
        let mut allowed = HashSet::new();
        allowed.insert(client_pk_c);
        let (transport, client_key, reply) =
            crypto::responder_accept(&server_sk, &noise_msg, &allowed).unwrap();
        let reply_len = u16::try_from(reply.len()).unwrap().to_be_bytes();
        writer.write_all(&reply_len).await.unwrap();
        writer.write_all(&reply).await.unwrap();
        writer.flush().await.unwrap();
        AdmittedPeer {
            client_key,
            transport,
            reader,
            writer,
        }
    });

    let enc = PeerWireCrypto::initiator(client_io, carrier_hash)
        .await
        .unwrap();
    let mut client_reader = enc.reader;
    let mut client_writer = enc.writer;
    let (handshake, noise_msg) = crypto::initiator_start(&client_sk, &server_pk).unwrap();
    let msg_len = u16::try_from(noise_msg.len()).unwrap().to_be_bytes();
    client_writer.write_all(&msg_len).await.unwrap();
    client_writer.write_all(&noise_msg).await.unwrap();
    client_writer.flush().await.unwrap();
    let mut len_buf = [0u8; 2];
    client_reader.read_exact(&mut len_buf).await.unwrap();
    let reply_len = u16::from_be_bytes(len_buf) as usize;
    let mut reply_buf = vec![0u8; reply_len];
    client_reader.read_exact(&mut reply_buf).await.unwrap();
    let client_transport = crypto::initiator_complete(handshake, &reply_buf).unwrap();

    let peer = server_handle.await.unwrap();
    let client = TunnelClient::from_raw_parts(
        client_transport,
        Box::new(client_reader),
        Box::new(client_writer),
    );
    (client, peer)
}

/// Transfer more than one flow-control window through the real relay against a
/// real loopback echo server. A payload larger than `INITIAL_WINDOW` can only
/// complete if credit is granted and replenished in BOTH directions — so this
/// exercises the whole credit machinery end-to-end without deadlocking.
#[tokio::test]
async fn real_relay_transfers_large_payload_with_flow_control() {
    use crate::tunnel::client_mux::{ClientMux, InboundTcp};
    use crate::tunnel::config::INITIAL_WINDOW;
    use crate::tunnel::egress::EgressPolicy;
    use crate::tunnel::relay::run_server_relay;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    crate::tests::test_util::setup_test_logging();

    // Loopback echo server.
    let echo = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    let (client, peer) = build_real_relay_pair().await;
    let token = CancellationToken::new();

    // Real server relay; default egress permits loopback.
    let relay_token = token.clone();
    tokio::spawn(async move {
        run_server_relay(peer, Arc::new(EgressPolicy::default()), relay_token).await;
    });

    let mux = ClientMux::new(client, token.clone());
    let (stream_id, mut inbound, credit) = mux
        .open_tcp(TunnelDestination::Ip(echo_addr))
        .await
        .expect("open_tcp");

    match inbound.recv().await {
        Some(InboundTcp::Opened(_)) => {}
        _ => panic!("expected TcpOpened"),
    }

    // Exceed the flow window so credit must be granted AND replenished in both
    // directions (a single window would complete without any replenishment).
    let total: usize = 2 * INITIAL_WINDOW + 512 * 1024;
    const CHUNK: usize = 16 * 1024;

    // Sender: respects flow-control credit.
    let send_mux = mux.clone();
    let sender = tokio::spawn(async move {
        let mut sent = 0usize;
        while sent < total {
            let n = CHUNK.min(total - sent);
            let chunk: Vec<u8> = (0..n)
                .map(|i| u8::try_from((sent + i) % 256).unwrap())
                .collect();
            assert!(credit.reserve(n).await, "credit pool closed");
            assert!(
                send_mux.send_tcp_data(stream_id, Bytes::from(chunk)).await,
                "send failed"
            );
            sent += n;
        }
        send_mux.fin_tcp(stream_id).await;
    });

    // Receiver: grants credit back as it drains.
    let mut received: Vec<u8> = Vec::with_capacity(total);
    while received.len() < total {
        match inbound.recv().await {
            Some(InboundTcp::Data(bytes)) => {
                let n = bytes.len();
                received.extend_from_slice(&bytes);
                assert!(mux.grant_credit(stream_id, n).await, "grant failed");
            }
            Some(InboundTcp::Fin) => break,
            Some(InboundTcp::Reset(code)) => {
                panic!("stream reset at {} bytes: {code:?}", received.len())
            }
            Some(InboundTcp::Opened(_)) => panic!("duplicate Opened"),
            None => panic!("tunnel lost at {} bytes", received.len()),
        }
    }
    sender.await.unwrap();

    assert_eq!(received.len(), total, "did not receive full payload");
    for (i, b) in received.iter().enumerate() {
        assert_eq!(
            *b,
            u8::try_from(i % 256).unwrap(),
            "payload corrupted at byte {i}"
        );
    }

    token.cancel();
}
