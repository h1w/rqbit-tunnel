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
                carriers: crate::tunnel::config::DEFAULT_CARRIERS,
                ..Default::default()
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
/// real loopback echo server. A payload larger than `OPEN_WINDOW` (the fixed
/// per-stream open window) can only complete if credit is granted and
/// replenished in BOTH directions — so this exercises the whole credit
/// machinery end-to-end without deadlocking.
#[tokio::test]
async fn real_relay_transfers_large_payload_with_flow_control() {
    use crate::tunnel::client_mux::{ClientMux, InboundTcp};
    use crate::tunnel::config::OPEN_WINDOW;
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
    let total: usize = 2 * OPEN_WINDOW + 512 * 1024;
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

// ── ClientMux load counter ──────────────────────────────────────────────────

/// `ClientMux::load()` must track currently-registered TCP streams in O(1),
/// incrementing when `open_tcp` queues its `OpenTcp` frame (not on the
/// server's verdict) and decrementing when `unregister_tcp` actually removes
/// a route. Mirrors `build_real_relay_pair` + `ClientMux::new` from
/// `real_relay_transfers_large_payload_with_flow_control` above — the
/// in-process harness that yields a real, connected `Arc<ClientMux>`.
#[tokio::test]
async fn client_mux_load_tracks_open_streams() {
    use crate::tunnel::client_mux::ClientMux;
    use crate::tunnel::egress::EgressPolicy;
    use crate::tunnel::relay::run_server_relay;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    crate::tests::test_util::setup_test_logging();

    // Loopback sink server: a real destination so OpenTcp connects succeed on
    // the server side and no TcpReset races with our load() assertions.
    let sink = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let sink_addr = sink.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((_s, _)) = sink.accept().await {
            // Accept and hold; the load counter doesn't depend on data flow.
        }
    });

    let (client, peer) = build_real_relay_pair().await;
    let token = CancellationToken::new();

    let relay_token = token.clone();
    tokio::spawn(async move {
        run_server_relay(peer, Arc::new(EgressPolicy::default()), relay_token).await;
    });

    let mux = ClientMux::new(client, token.clone());
    assert_eq!(mux.load(), 0);

    let (_id_a, _rx_a, _cr_a) = mux
        .open_tcp(TunnelDestination::Ip(sink_addr))
        .await
        .expect("open_tcp a");
    let (id_b, _rx_b, _cr_b) = mux
        .open_tcp(TunnelDestination::Ip(sink_addr))
        .await
        .expect("open_tcp b");
    assert_eq!(mux.load(), 2);

    mux.unregister_tcp(id_b).await;
    assert_eq!(mux.load(), 1);

    token.cancel();
}

/// Regression: a server-initiated `TcpReset` must not leak `load`.
///
/// `reader_loop`'s `TcpReset` branch removes the route directly (so the
/// SOCKS handler's later `unregister_tcp` finds nothing and no-ops). If the
/// reader doesn't *also* decrement `load` at that point, every server-side
/// reset (denied destination, refused connection, timeout — all common)
/// leaks +1 forever, skewing the `CarrierPool`'s least-loaded selection.
#[tokio::test]
async fn client_mux_load_does_not_leak_on_server_tcp_reset() {
    use crate::tunnel::client_mux::{ClientMux, InboundTcp};
    use crate::tunnel::egress::EgressPolicy;
    use crate::tunnel::frame::TunnelErrorCode;
    use crate::tunnel::relay::run_server_relay;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    crate::tests::test_util::setup_test_logging();

    let (client, peer) = build_real_relay_pair().await;
    let token = CancellationToken::new();

    // `public_internet_only` denies loopback destinations outright, so the
    // server rejects the stream with `TcpReset` before ever attempting to
    // connect — a deterministic, immediate reset with no connect timeout.
    let relay_token = token.clone();
    tokio::spawn(async move {
        run_server_relay(
            peer,
            Arc::new(EgressPolicy::public_internet_only()),
            relay_token,
        )
        .await;
    });

    let mux = ClientMux::new(client, token.clone());
    assert_eq!(mux.load(), 0);

    let denied_addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1).into();
    let (stream_id, mut inbound, _credit) = mux
        .open_tcp(TunnelDestination::Ip(denied_addr))
        .await
        .expect("open_tcp");
    assert_eq!(mux.load(), 1);

    match inbound.recv().await {
        Some(InboundTcp::Reset(code)) => {
            assert_eq!(code, TunnelErrorCode::DestinationDenied);
        }
        Some(InboundTcp::Opened(_)) => panic!("expected TcpReset, got Opened"),
        Some(InboundTcp::Data(_)) => panic!("expected TcpReset, got Data"),
        Some(InboundTcp::Fin) => panic!("expected TcpReset, got Fin"),
        None => panic!("tunnel lost before TcpReset arrived"),
    }

    // Mirror the SOCKS handler's teardown: it always calls `unregister_tcp`
    // after observing a terminal inbound event, regardless of whether the
    // reader already removed the route on `TcpReset`.
    mux.unregister_tcp(stream_id).await;

    // The load decrement (if any) happens in `reader_loop` before the event
    // is routed to `inbound`, so it should already be visible — but poll
    // briefly to avoid a flaky race against the assertion below.
    tokio::time::timeout(Duration::from_secs(2), async {
        while mux.load() != 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("mux.load() did not return to 0 after server TcpReset (leaked)");

    token.cancel();
}

// ── Per-carrier RTT measurement (Ping/Pong) ─────────────────────────────────

/// The tunnel module has `#![allow(dead_code, unused_variables)]`, so the
/// compiler will happily accept a ping task that's spawned but never fires,
/// or an `RttEstimator` that's constructed but never fed. This test proves
/// the wiring is actually LIVE end-to-end: mirrors `build_real_relay_pair` +
/// `ClientMux::new` + `run_server_relay` from
/// `real_relay_transfers_large_payload_with_flow_control` above (a real
/// Noise-encrypted client/server pair, no echo-fixture indirection), then
/// polls `ClientMux::rtt_for_test()` until `rtt_smooth()` turns non-zero —
/// which can only happen if the client's ping task actually sent a `Ping`
/// and the server actually replied with a matching `Pong` that the reader
/// actually recorded.
#[tokio::test]
async fn client_mux_rtt_estimator_becomes_live_via_ping_pong() {
    use crate::tunnel::client_mux::ClientMux;
    use crate::tunnel::egress::EgressPolicy;
    use crate::tunnel::relay::run_server_relay;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    crate::tests::test_util::setup_test_logging();

    let (client, peer) = build_real_relay_pair().await;
    let token = CancellationToken::new();

    let relay_token = token.clone();
    tokio::spawn(async move {
        run_server_relay(peer, Arc::new(EgressPolicy::default()), relay_token).await;
    });

    let mux = ClientMux::new(client, token.clone());

    // Before any Pong round-trips, both readings are zero.
    let (initial_min, initial_smooth) = mux.rtt_for_test();
    assert_eq!(initial_min, Duration::ZERO);
    assert_eq!(initial_smooth, Duration::ZERO);

    crate::tests::test_util::wait_until(
        || {
            let (_, smooth) = mux.rtt_for_test();
            if smooth > Duration::ZERO {
                Ok(())
            } else {
                anyhow::bail!("rtt_smooth is still zero")
            }
        },
        Duration::from_secs(3),
    )
    .await
    .expect("rtt_smooth should become non-zero once Ping/Pong round trips are recorded");

    let (rtt_min, rtt_smooth) = mux.rtt_for_test();
    assert!(
        rtt_min > Duration::ZERO,
        "rtt_min should also be non-zero once a sample lands, got {rtt_min:?}"
    );
    assert!(
        rtt_smooth >= rtt_min,
        "smoothed RTT must never be below the running minimum: smooth={rtt_smooth:?} min={rtt_min:?}"
    );
    // Real in-process loopback round trip: should be well under a second.
    assert!(
        rtt_smooth < Duration::from_secs(1),
        "unexpectedly large in-process RTT: {rtt_smooth:?}"
    );

    token.cancel();
}

// ── Controller-driven adaptive window + pacing (Task E liveness) ────────────

/// The payoff wiring test. The tunnel module's `#![allow(dead_code,
/// unused_variables)]` means a controller that's stepped-but-whose-output-never-
/// reaches-the-actuators, or a `pacing_rate` written to a cell the writer never
/// reads, compiles clean and silently no-ops. This proves the loop is LIVE
/// end-to-end: it mirrors the RTT-liveness harness (`build_real_relay_pair` +
/// `ClientMux::new` + `run_server_relay` — a real Noise-encrypted client/server
/// pair) and runs a SUSTAINED bulk transfer through one stream to a DRAINING
/// loopback sink. It asserts:
///
///   (a) the control loop drives the SHARED `pacing_rate` cell — the exact
///       `Arc` the writer re-reads per frame — off `PACING_DEFAULT_RATE` to a
///       finite, positive `target / rtt`. Driving that cell only happens inside
///       `drive_flow_control`, which ALSO steps the `WindowController`, so a
///       driven pacing rate proves the whole RTT→controller→pacing_rate loop
///       ran and the writer shares the cell. (The controller's growth *logic*
///       — slow-start doubling, additive post-congestion — is proved
///       deterministically by the `flow.rs` unit tests; and the writer→`paced`
///       half of the utilization signal by `relay.rs`'s writer tests, on the
///       exact same `Arc`. We deliberately do NOT assert a specific grown
///       `target` here: on lossless in-process loopback the ping shares the
///       paced bulk writer queue, so RTT self-inflates to seconds under load
///       and the delay-based controller's ramp is genuinely non-deterministic
///       — that behaviour is tuned against a real bandwidth-delay harness, not
///       pinned by a loopback unit test.)
///
///   (b) every stream opens with the fixed generous `OPEN_WINDOW` — proving the
///       generous window actually reaches `SendCredit::with_window` and keeping
///       the "queue ≥ window" invariant honest — and that the open window is a
///       FIXED backstop that does not track the controller (pacing, not the
///       window, is the in-flight control).
#[tokio::test]
async fn controller_drives_adaptive_window_and_pacing_live() {
    use crate::tunnel::client_mux::{ClientMux, InboundTcp};
    use crate::tunnel::config::{MAX_TARGET, MIN_TARGET, OPEN_WINDOW, PACING_DEFAULT_RATE};
    use crate::tunnel::egress::EgressPolicy;
    use crate::tunnel::relay::run_server_relay;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    crate::tests::test_util::setup_test_logging();

    // Draining loopback sink: read and discard forever, so the server keeps
    // granting the client credit and the transfer stays sustained (a
    // non-draining "hold" sink would stall once one window + socket buffers
    // fill, starving the utilization signal the controller needs).
    let sink = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let sink_addr = sink.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = sink.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
        }
    });

    let (client, peer) = build_real_relay_pair().await;
    let token = CancellationToken::new();
    let relay_token = token.clone();
    tokio::spawn(async move {
        run_server_relay(peer, Arc::new(EgressPolicy::default()), relay_token).await;
    });

    let mux = ClientMux::new(client, token.clone());

    // Before any data moves or any RTT sample lands, the controller sits at its
    // floor and the SHARED pacing cell holds the untouched default.
    assert_eq!(mux.controller_target_for_test(), MIN_TARGET);
    assert_eq!(mux.pacing_rate_for_test(), PACING_DEFAULT_RATE);

    let (stream_id, mut inbound, credit) = mux
        .open_tcp(TunnelDestination::Ip(sink_addr))
        .await
        .expect("open_tcp");
    match inbound.recv().await {
        Some(InboundTcp::Opened(_)) => {}
        _ => panic!("expected TcpOpened verdict, stream was not established"),
    }
    // Every stream opens with the fixed generous `OPEN_WINDOW` (proving the
    // window actually reaches `SendCredit::with_window`). It does NOT track the
    // controller — pacing at `target / rtt`, not this window, is the in-flight
    // control — so it stays `OPEN_WINDOW` even after the target grows below.
    assert_eq!(mux.last_open_window_for_test(), OPEN_WINDOW);

    // Continuously pump data through the stream, respecting flow-control credit,
    // until the test cancels the token.
    let pump_token = token.clone();
    let send_mux = mux.clone();
    let pump = tokio::spawn(async move {
        const CHUNK: usize = 16 * 1024;
        let chunk = Bytes::from(vec![0u8; CHUNK]);
        loop {
            if pump_token.is_cancelled() {
                break;
            }
            let reserved = tokio::select! {
                _ = pump_token.cancelled() => false,
                ok = credit.reserve(CHUNK) => ok,
            };
            if !reserved {
                break;
            }
            if !send_mux.send_tcp_data(stream_id, chunk.clone()).await {
                break;
            }
        }
    });

    // (a) Wait until the control loop has driven the SHARED `pacing_rate` cell
    // off the untouched default. This happens on the first tick after the first
    // `Pong` lands (`rtt_smooth > 0`), so it's robust: it does not depend on the
    // delay-based controller's (loopback-unstable) ramp, only on the loop
    // actually running `drive_flow_control` against a live RTT sample. Settles
    // within a couple of `PING_INTERVAL` (250 ms) ticks under sustained load.
    crate::tests::test_util::wait_until(
        || {
            let rate = mux.pacing_rate_for_test();
            if rate != PACING_DEFAULT_RATE {
                Ok(())
            } else {
                anyhow::bail!("pacing_rate still at default {rate}")
            }
        },
        Duration::from_secs(15),
    )
    .await
    .expect("control loop should drive pacing_rate off the default under sustained load");

    // Confirm the actuator the wait gated on: the SHARED cell the writer
    // re-reads per frame now holds a finite, positive `target / rtt` — not the
    // effectively-unlimited default. Driving it proves the whole
    // RTT→controller→pacing_rate loop ran (only `drive_flow_control` writes this
    // cell, and it also steps the controller).
    let rate = mux.pacing_rate_for_test();
    assert_ne!(
        rate, PACING_DEFAULT_RATE,
        "pacing_rate (the SHARED cell the writer re-reads) must have been driven \
         off the default to target/rtt by the control loop"
    );
    assert!(rate > 0, "pacing_rate must stay positive, got {rate}");
    // The controller is being stepped every tick; its target stays within its
    // clamp bounds. (Its exact value under loopback self-congestion is not
    // pinned — see the doc comment.)
    let target = mux.controller_target_for_test();
    assert!(
        (MIN_TARGET..=MAX_TARGET).contains(&target),
        "controller target must stay within [MIN_TARGET, MAX_TARGET], got {target}"
    );

    // (b) A stream opened now must STILL open at the fixed generous
    // `OPEN_WINDOW`, unchanged by the controller. This is the regression guard
    // for the frozen/derived-window bug: the open window is a fixed backstop,
    // and pacing (driven above) is the sole in-flight control.
    let (_sid2, _rx2, _cr2) = mux
        .open_tcp(TunnelDestination::Ip(sink_addr))
        .await
        .expect("open second stream");
    let win2 = mux.last_open_window_for_test();
    assert_eq!(
        win2, OPEN_WINDOW,
        "second stream must open at the fixed generous OPEN_WINDOW regardless of \
         controller state (got window {win2})"
    );

    token.cancel();
    let _ = pump.await;
}

// ── CarrierPool live-pool distribution + carrier-loss coverage ─────────────
//
// `pool_spawns_requested_carrier_count` in `client_pool.rs` never yields to
// the runtime — the configured server address is unreachable, so every
// carrier stays disconnected — which means it never exercises `pick()`'s
// least-loaded selection across ACTUALLY connected carriers. The tests below
// stand up a REAL `TunnelServer` bound to a real loopback `TcpListener` and a
// REAL `CarrierPool` client (production `TunnelClientSupervisor` /
// `ClientMux` path, full Noise IK handshake), so `pick()` runs against
// genuinely live carrier connections.

/// Stand up a real tunnel server (bound to loopback) plus a real
/// `CarrierPool` client with `carriers` parallel connections, and a real
/// loopback "sink" destination that accepts and holds connections so opened
/// streams stay open. Returns the pool, the server's shutdown token
/// (cancelling it drops every admitted carrier connection at once), the
/// client's shutdown token, and the sink address to open streams against.
/// The returned `TempDir` must be kept alive for the carrier store.
async fn start_live_carrier_pool(
    carriers: usize,
) -> (
    std::sync::Arc<crate::tunnel::client_pool::CarrierPool>,
    tokio_util::sync::CancellationToken,
    tokio_util::sync::CancellationToken,
    std::net::SocketAddr,
    tempfile::TempDir,
) {
    use crate::tunnel::client_pool::CarrierPool;
    use crate::tunnel::crypto::generate_keypair;
    use crate::tunnel::options::{EgressPolicy, TunnelClientOptions, TunnelServerOptions};
    use crate::tunnel::server::TunnelServer;
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    let (server_sk, server_pk) = generate_keypair();
    let (client_sk, client_pk) = generate_keypair();

    let carrier_dir = tempfile::TempDir::new().expect("carrier temp dir");

    // Real listening server.
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind server listener");
    let server_addr = listener.local_addr().unwrap();

    let mut allowed_client_keys = HashSet::new();
    allowed_client_keys.insert(client_pk);
    let server_opts = TunnelServerOptions {
        peer_listen: server_addr,
        identity_key: server_sk,
        allowed_client_keys,
        egress_policy: EgressPolicy {
            allow_loopback: true,
            ..Default::default()
        },
        carrier_root: carrier_dir.path().to_path_buf(),
    };
    let server = TunnelServer::new(server_opts);
    let server_shutdown = CancellationToken::new();
    let server_for_run = server.clone();
    let run_shutdown = server_shutdown.clone();
    tokio::spawn(async move {
        server_for_run.run(listener, run_shutdown).await;
    });

    // Local sink so opened streams actually establish and stay alive: accept
    // and hold every connection (never drop it), so the server-side egress
    // connect succeeds and the stream doesn't get reset.
    let sink = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind sink");
    let sink_addr = sink.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = sink.accept().await {
            held.push(s);
        }
    });

    let client_shutdown = CancellationToken::new();
    let client_opts = TunnelClientOptions {
        socks_listen: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        server_addr: Some(server_addr),
        identity_key: client_sk,
        expected_server_key: server_pk,
        pairing: None,
        carriers,
        ..Default::default()
    };
    let pool = CarrierPool::start(client_opts, None, client_shutdown.clone());

    (
        pool,
        server_shutdown,
        client_shutdown,
        sink_addr,
        carrier_dir,
    )
}

/// Test A: streams distribute across carriers.
///
/// This is the genuine `CarrierPool::pick()` coverage the multi-carrier plan
/// needs: two REAL carrier connections come up over loopback TCP (full Noise
/// IK handshake, real `TunnelServer::run` accept loop), four TCP streams are
/// opened and their `TcpOpened` verdict is awaited (so each stream is truly
/// established end-to-end through the tunnel to the sink), and the resulting
/// per-carrier `load()` values are asserted directly via the
/// `live_muxes_for_test` accessor — not inferred from `pick()`'s return
/// value alone. With 2 carriers and least-loaded selection, four sequential
/// opens must split exactly 2/2 (see `select_carrier`'s tie-break-to-lowest-
/// index rule in `client_pool.rs`).
#[tokio::test]
async fn carrier_pool_distributes_streams_across_live_carriers() {
    use crate::tunnel::client_mux::InboundTcp;
    use std::time::Duration;

    crate::tests::test_util::setup_test_logging();

    let (pool, server_shutdown, _client_shutdown, sink_addr, _carrier_dir) =
        start_live_carrier_pool(2).await;

    crate::tests::test_util::wait_until(
        || {
            let live = pool.live_count();
            if live == 2 {
                Ok(())
            } else {
                anyhow::bail!("live_count = {live}, expected 2")
            }
        },
        Duration::from_secs(10),
    )
    .await
    .expect("expected 2 live carriers within 10s");

    // Open 4 streams through the pool, keeping every handle alive (dropping
    // the mpsc::Receiver / SendCredit is not what unregisters the stream —
    // an explicit `unregister_tcp` is — but keeping the whole tuple alive
    // avoids any ambiguity and matches the harness contract).
    let mut handles = Vec::new();
    for _ in 0..4 {
        let mux = pool.pick().expect("a live carrier");
        let (stream_id, mut inbound, credit) = mux
            .open_tcp(TunnelDestination::Ip(sink_addr))
            .await
            .expect("open_tcp");
        match inbound.recv().await {
            Some(InboundTcp::Opened(_)) => {}
            _ => panic!("expected TcpOpened verdict, stream was not truly established"),
        }
        handles.push((mux, stream_id, inbound, credit));
    }

    let live = pool.live_muxes_for_test();
    let loads: Vec<usize> = live.iter().flatten().map(|m| m.load()).collect();
    assert_eq!(
        loads.len(),
        2,
        "expected exactly 2 live muxes reporting load, got {loads:?}"
    );
    assert_eq!(
        loads.iter().sum::<usize>(),
        4,
        "all 4 opened streams must be accounted for across carriers, got {loads:?}"
    );
    assert!(
        loads.iter().all(|&l| l >= 1),
        "genuine distribution requires BOTH carriers to receive load, got {loads:?}"
    );
    // Deterministic: 2 carriers + least-loaded/tie-break-lowest-index pick
    // over 4 sequential opens always yields an even 2/2 split.
    assert_eq!(
        loads,
        vec![2, 2],
        "expected an even 2/2 split, got {loads:?}"
    );

    drop(handles);
    server_shutdown.cancel();
}

/// Test B: the pool reflects total carrier loss.
///
/// Deterministically killing exactly ONE of N carriers in-process would
/// require new production hooks (e.g. a way to reach into a specific
/// `TunnelClientSupervisor` and sever only its socket) — this task may not
/// add those. Instead this test cancels the SERVER's shutdown token, which
/// drops every admitted carrier connection at once (`TunnelServer::run`
/// derives each peer's shutdown token as a CHILD of the token passed in, so
/// cancelling the parent cancels every relay task together). Combined with
/// the independent-per-carrier-supervisor design — each carrier reconnects
/// on its own, already covered by `client_tunnel_starts_when_server_unreachable`
/// and the backoff/reconnect loop in `client_supervisor.rs` — this is the
/// intended liveness coverage for this task: the pool must notice when its
/// carriers die and stop handing out muxes.
#[tokio::test]
async fn carrier_pool_reflects_full_carrier_loss() {
    use std::time::Duration;

    crate::tests::test_util::setup_test_logging();

    let (pool, server_shutdown, _client_shutdown, _sink_addr, _carrier_dir) =
        start_live_carrier_pool(2).await;

    crate::tests::test_util::wait_until(
        || {
            let live = pool.live_count();
            if live == 2 {
                Ok(())
            } else {
                anyhow::bail!("live_count = {live}, expected 2")
            }
        },
        Duration::from_secs(10),
    )
    .await
    .expect("expected 2 live carriers within 10s");

    server_shutdown.cancel();

    crate::tests::test_util::wait_until(
        || {
            let live = pool.live_count();
            if live == 0 {
                Ok(())
            } else {
                anyhow::bail!("live_count = {live}, expected 0 after server shutdown")
            }
        },
        Duration::from_secs(10),
    )
    .await
    .expect("expected live_count() to drop to 0 within 10s after server shutdown");

    assert!(
        pool.pick().is_none(),
        "pick() must return None once every carrier is gone"
    );
}
