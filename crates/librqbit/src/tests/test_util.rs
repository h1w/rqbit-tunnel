use std::{
    io::Write,
    path::Path,
    sync::{Arc, Weak},
    time::Duration,
};

use anyhow::bail;
use librqbit_core::{Id20, crate_version, peer_id::generate_azereus_style};
use parking_lot::RwLock;
use rand::{Rng, RngCore, SeedableRng, rng};
use tempfile::TempDir;
use tracing::{info, trace};

pub fn setup_test_logging() {
    if std::env::var("RUST_LOG").is_err() {
        unsafe { std::env::set_var("RUST_LOG", "info") };
    }
    let _ = tracing_subscriber::fmt::try_init();
}

pub fn create_new_file_with_random_content(path: &Path, mut size: usize) {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .unwrap();

    trace!(?path, "creating temp file");

    const BUF_SIZE: usize = 8192 * 16;
    let mut rng = rand::rngs::SmallRng::from_os_rng();
    let mut write_buf = [0; BUF_SIZE];
    while size > 0 {
        rng.fill_bytes(&mut write_buf[..]);
        let written = file.write(&write_buf[..size.min(BUF_SIZE)]).unwrap();
        size -= written;
    }
}

pub fn create_default_random_dir_with_torrents(
    num_files: usize,
    file_size: usize,
    tempdir_prefix: Option<&str>,
) -> TempDir {
    let dir = TempDir::with_prefix(tempdir_prefix.unwrap_or("rqbit_test")).unwrap();
    info!(path=?dir.path(), "created tempdir");
    for f in 0..num_files {
        create_new_file_with_random_content(&dir.path().join(format!("{f}.data")), file_size);
    }
    dir
}

#[derive(Debug)]
pub struct TestPeerMetadata {
    pub server_id: u8,
    pub max_random_sleep_ms: u8,
}

impl TestPeerMetadata {
    pub fn good() -> Self {
        Self {
            server_id: 0,
            max_random_sleep_ms: 0,
        }
    }

    pub fn as_peer_id(&self) -> Id20 {
        let mut peer_id = generate_azereus_style(*b"rQ", crate_version!());
        peer_id.0[15..19].copy_from_slice(b"test");
        rng().fill(&mut peer_id.0);
        peer_id.0[14] = self.server_id;
        peer_id.0[13] = self.max_random_sleep_ms;
        peer_id
    }

    pub fn from_peer_id(peer_id: Id20) -> Self {
        if &peer_id.0[15..19] != b"test" {
            return Self::good();
        }
        Self {
            server_id: peer_id.0[14],
            max_random_sleep_ms: peer_id.0[13],
        }
    }

    pub fn disconnect_probability(&self) -> f64 {
        if self.server_id % 2 == 1 {
            return 0.05f64;
        }
        0f64
    }

    pub fn bad_data_probability(&self) -> f64 {
        if self.server_id % 2 == 1 {
            return 0.05f64;
        }
        0f64
    }
}

#[cfg(feature = "http-api")]
async fn debug_server() -> anyhow::Result<()> {
    use anyhow::Context;
    use axum::{Router, response::IntoResponse, routing::get};
    async fn backtraces() -> impl IntoResponse {
        #[cfg(feature = "async-bt")]
        {
            async_backtrace::taskdump_tree(true)
        }
        #[cfg(not(feature = "async-bt"))]
        {
            use crate::ApiError;
            ApiError::from(anyhow::anyhow!(
                "backtraces not enabled, enable async-bt feature"
            ))
        }
    }

    let app = Router::new().route("/backtrace", get(backtraces));
    let app = app.into_make_service();

    let addr = "127.0.0.1:3032";

    info!(%addr, "starting HTTP server");

    use tokio::net::TcpListener;

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("error binding to {addr}"))?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(not(feature = "http-api"))]
async fn debug_server() -> anyhow::Result<()> {
    Ok(())
}

#[allow(dead_code)]
pub fn spawn_debug_server() -> tokio::task::JoinHandle<anyhow::Result<()>> {
    tokio::spawn(debug_server())
}

pub trait DropPlaceholder: Send + Sync {}
impl<T: Send + Sync> DropPlaceholder for T {}

struct DropCheck {
    obj: Weak<dyn DropPlaceholder>,
    name: String,
}

#[derive(Default, Clone)]
pub struct DropChecks(Arc<RwLock<Vec<DropCheck>>>);

impl DropChecks {
    pub fn add<T: DropPlaceholder + 'static, S: Into<String>>(&self, obj: &Arc<T>, name: S) {
        let weak = Arc::downgrade(obj);
        self.0.write().push(DropCheck {
            obj: weak as Weak<dyn DropPlaceholder>,
            name: name.into(),
        })
    }

    pub fn check(&self) -> anyhow::Result<()> {
        let mut still_running = Vec::new();
        for dc in self.0.read().iter() {
            if dc.obj.upgrade().is_some() {
                still_running.push(dc.name.clone())
            }
        }
        if !still_running.is_empty() {
            anyhow::bail!(
                "still existing objects that were supposed to be dropped: {still_running:#?}"
            )
        }
        Ok(())
    }
}

pub async fn wait_until(
    mut cond: impl FnMut() -> anyhow::Result<()>,
    timeout: Duration,
) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(Duration::from_millis(10));
    let mut last_err: Option<anyhow::Error> = None;
    let res = tokio::time::timeout(timeout, async {
        loop {
            interval.tick().await;
            match cond() {
                Ok(()) => return Ok::<_, anyhow::Error>(()),
                Err(e) => last_err = Some(e),
            }
        }
    })
    .await;
    if res.is_err() {
        bail!("wait_until timeout: last result = {last_err:?}")
    }
    Ok(())
}

pub async fn wait_until_i_am_the_last_task() -> anyhow::Result<()> {
    let metrics = tokio::runtime::Handle::current().metrics();
    wait_until(
        || {
            let num_alive = metrics.num_alive_tasks();
            if num_alive != 0 {
                bail!("metrics.num_alive_tasks() = {num_alive}, expected 0")
            }
            Ok(())
        },
        // This needs to be higher than the timeout the tasks print "still running"
        Duration::from_secs(15),
    )
    .await
}

// ── Tunnel E2E test fixture ────────────────────────────────────────────────

pub mod tunnel_fixture {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use std::collections::VecDeque;

    use crate::tunnel::carrier_peer::CoverMessage;
    use librqbit_core::Id20;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::{Mutex, mpsc};

    use crate::tunnel::carrier_chunk::{
        CarrierDefragmenter, MAX_CARRIER_CIPHERTEXT, chunk_ciphertext, recv_one_ciphertext,
    };
    use crate::tunnel::carrier_peer::TunnelCarrierPeer;
    use crate::tunnel::carrier_wire::{CarrierReadHalf, CarrierWire, CarrierWriteHalf};
    use crate::tunnel::client::TunnelClient;
    use crate::tunnel::crypto::{NoiseTransport, generate_keypair};
    use crate::tunnel::frame::{TunnelDestination, TunnelFrame, TunnelPublicKey};
    use crate::tunnel::peer_wire_crypto::PeerWireCrypto;
    use crate::tunnel::relay::next_tunnel_frame;

    #[allow(dead_code)]
    pub struct TunnelFixture {
        _temp_dir: tempfile::TempDir,
        pub client: Arc<Mutex<TunnelClient>>,
        pub server_transport: Arc<Mutex<NoiseTransport>>,
        pub client_public_key: TunnelPublicKey,
        pub server_public_key: TunnelPublicKey,
        tcp_echo_port: u16,
        udp_echo_port: u16,
        pub direct_connect_attempts: Arc<AtomicUsize>,
        _tcp_echo_handle: tokio::task::JoinHandle<()>,
        _udp_echo_handle: tokio::task::JoinHandle<()>,
        _relay_handle: tokio::task::JoinHandle<()>,
    }

    impl TunnelFixture {
        pub async fn start() -> Self {
            let temp_dir = tempfile::TempDir::new().expect("create temp dir");

            let (client_sk, client_pk) = generate_keypair();
            let (server_sk, server_pk) = generate_keypair();

            // TCP echo
            let tcp_listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind tcp echo");
            let tcp_echo_port = tcp_listener.local_addr().unwrap().port();
            let tcp_echo_handle = tokio::spawn(async move {
                while let Ok((mut stream, _)) = tcp_listener.accept().await {
                    tokio::spawn(async move {
                        let (mut r, mut w) = stream.split();
                        let mut buf = vec![0u8; 65536];
                        loop {
                            match r.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if w.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
            });

            // UDP echo
            let udp_echo = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind udp echo");
            let udp_echo_port = udp_echo.local_addr().unwrap().port();
            let udp_echo_handle = tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                while let Ok((n, src)) = udp_echo.recv_from(&mut buf).await {
                    let _ = udp_echo.send_to(&buf[..n], src).await;
                }
            });

            // Tunnel pair over the live BitTorrent-masquerade carrier.
            let carrier_hash = Id20::new([0xAB; 20]);
            let (client_io, server_io) = tokio::io::duplex(256 * 1024);
            let client_pk_c = client_pk.clone();

            // Deterministic carrier store shared by both ends (same `info_hash`).
            let carrier_store =
                crate::tunnel::carrier_identity::build_carrier_store(temp_dir.path(), &server_pk)
                    .await
                    .expect("build carrier store");
            let info_hash = carrier_store.descriptor().handshake_info_hash;
            let server_store = carrier_store.clone();

            let server_handle = tokio::spawn(async move {
                let enc = PeerWireCrypto::responder(server_io, carrier_hash)
                    .await
                    .unwrap();
                let wire = CarrierWire::establish(enc.reader, enc.writer, server_store, info_hash)
                    .await
                    .unwrap();
                let (mut read_half, mut write_half, carrier_peer) = wire.into_halves();

                let mut defrag = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
                let noise_msg = recv_one_ciphertext(&mut read_half, &mut defrag)
                    .await
                    .unwrap();
                let mut allowed = std::collections::HashSet::new();
                allowed.insert(client_pk_c);
                let (transport, _ck, reply) =
                    crate::tunnel::crypto::responder_accept(&server_sk, &noise_msg, &allowed)
                        .unwrap();
                for chunk in chunk_ciphertext(&reply) {
                    write_half.send_tunnel(&chunk).await.unwrap();
                }
                (transport, read_half, write_half, carrier_peer)
            });

            let enc = PeerWireCrypto::initiator(client_io, carrier_hash)
                .await
                .unwrap();
            let wire = CarrierWire::establish(enc.reader, enc.writer, carrier_store, info_hash)
                .await
                .unwrap();
            let (mut read_half, mut write_half, carrier_peer) = wire.into_halves();

            let (handshake, noise_msg) =
                crate::tunnel::crypto::initiator_start(&client_sk, &server_pk).unwrap();
            for chunk in chunk_ciphertext(&noise_msg) {
                write_half.send_tunnel(&chunk).await.unwrap();
            }
            let mut defrag = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
            let reply = recv_one_ciphertext(&mut read_half, &mut defrag)
                .await
                .unwrap();
            let client_transport =
                crate::tunnel::crypto::initiator_complete(handshake, &reply).unwrap();

            let (server_transport, server_read, server_write, server_peer) =
                server_handle.await.unwrap();

            let client = TunnelClient::from_carrier_parts(
                client_transport,
                read_half,
                write_half,
                carrier_peer,
            );

            let server_transport: Arc<Mutex<NoiseTransport>> =
                Arc::new(Mutex::new(server_transport));
            let st = server_transport.clone();
            let direct_connect_attempts = Arc::new(AtomicUsize::new(0));

            let relay_handle = tokio::spawn(async move {
                run_server_relay(
                    st,
                    server_read,
                    server_write,
                    server_peer,
                    tcp_echo_port,
                    udp_echo_port,
                )
                .await;
            });

            Self {
                _temp_dir: temp_dir,
                client: Arc::new(Mutex::new(client)),
                server_transport,
                client_public_key: client_pk,
                server_public_key: server_pk,
                tcp_echo_port,
                udp_echo_port,
                direct_connect_attempts,
                _tcp_echo_handle: tcp_echo_handle,
                _udp_echo_handle: udp_echo_handle,
                _relay_handle: relay_handle,
            }
        }

        pub fn tcp_echo_port(&self) -> u16 {
            self.tcp_echo_port
        }
        pub fn udp_echo_port(&self) -> u16 {
            self.udp_echo_port
        }
        pub fn client_direct_connect_attempts(&self) -> usize {
            self.direct_connect_attempts.load(Ordering::SeqCst)
        }
    }

    /// Minimal echo relay running over the BitTorrent-masquerade carrier:
    /// reads decrypted tunnel frames via [`next_tunnel_frame`] and echoes them
    /// back by encrypting + chunking over the carrier write half.
    async fn run_server_relay(
        transport: Arc<Mutex<NoiseTransport>>,
        mut read_half: CarrierReadHalf,
        mut write_half: CarrierWriteHalf,
        carrier_peer: TunnelCarrierPeer,
        _tcp_echo_port: u16,
        _udp_echo_port: u16,
    ) {
        // Encrypt one frame and write it as chunked `rq_tunnel` messages.
        async fn send_frame(
            write_half: &mut CarrierWriteHalf,
            transport: &Mutex<NoiseTransport>,
            frame: &TunnelFrame,
        ) -> bool {
            let blob = {
                let mut t = transport.lock().await;
                match t.encrypt(frame) {
                    Ok(b) => b,
                    Err(_) => return false,
                }
            };
            for chunk in chunk_ciphertext(&blob) {
                if write_half.send_tunnel(&chunk).await.is_err() {
                    return false;
                }
            }
            true
        }

        let mut defrag = CarrierDefragmenter::new(MAX_CARRIER_CIPHERTEXT);
        let mut pending: VecDeque<Vec<u8>> = VecDeque::new();
        let mut carrier_peer = carrier_peer;
        // These fixtures never drive piece cover (no Request messages), so the
        // cover lane stays empty; a small buffered channel suffices.
        let (cover_tx, _cover_rx) = mpsc::channel::<CoverMessage>(16);

        loop {
            let frame = match next_tunnel_frame(
                &mut read_half,
                &mut defrag,
                &mut pending,
                &transport,
                &mut carrier_peer,
                &cover_tx,
            )
            .await
            {
                Some(f) => f,
                None => break,
            };

            match frame {
                TunnelFrame::OpenTcp { stream_id, .. } => {
                    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
                    let _ = send_frame(
                        &mut write_half,
                        &transport,
                        &TunnelFrame::TcpOpened {
                            stream_id,
                            bind_addr,
                        },
                    )
                    .await;
                }
                TunnelFrame::TcpData { stream_id, bytes } => {
                    // Echo data back directly.
                    if !send_frame(
                        &mut write_half,
                        &transport,
                        &TunnelFrame::TcpData { stream_id, bytes },
                    )
                    .await
                    {
                        break;
                    }
                }
                TunnelFrame::TcpFin { stream_id } => {
                    let _ = send_frame(
                        &mut write_half,
                        &transport,
                        &TunnelFrame::TcpFin { stream_id },
                    )
                    .await;
                }
                TunnelFrame::OpenUdp { association_id: _ } => {}
                TunnelFrame::UdpDatagram {
                    association_id,
                    bytes,
                    ..
                } => {
                    let dest = TunnelDestination::Ip(SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::LOCALHOST,
                        0,
                    )));
                    let _ = send_frame(
                        &mut write_half,
                        &transport,
                        &TunnelFrame::UdpDatagram {
                            association_id,
                            destination: dest,
                            bytes,
                        },
                    )
                    .await;
                }
                TunnelFrame::CloseUdp { association_id: _ } => {}
                TunnelFrame::Ping { nonce } => {
                    let _ =
                        send_frame(&mut write_half, &transport, &TunnelFrame::Pong { nonce }).await;
                }
                _ => {}
            }
        }
    }
}
