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
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use librqbit_core::Id20;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::sync::{Mutex, mpsc};

    use crate::tunnel::client::TunnelClient;
    use crate::tunnel::crypto::{NoiseTransport, generate_keypair};
    use crate::tunnel::frame::{TunnelDestination, TunnelFrame, TunnelPublicKey};
    use crate::tunnel::server;

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
                loop {
                    match tcp_listener.accept().await {
                        Ok((mut stream, _)) => {
                            tokio::spawn(async move {
                                let (mut r, mut w) = stream.split();
                                let mut buf = vec![0u8; 65536];
                                loop {
                                    match r.read(&mut buf).await {
                                        Ok(0) | Err(_) => break,
                                        Ok(n) => {
                                            eprintln!("echo: recv {} bytes, echoing back", n);
                                            if w.write_all(&buf[..n]).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                }
                            });
                        }
                        Err(_) => break,
                    }
                }
            });

            // UDP echo
            let udp_echo = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind udp echo");
            let udp_echo_port = udp_echo.local_addr().unwrap().port();
            let udp_echo_handle = tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match udp_echo.recv_from(&mut buf).await {
                        Ok((n, src)) => {
                            let _ = udp_echo.send_to(&buf[..n], src).await;
                        }
                        Err(_) => break,
                    }
                }
            });

            // Tunnel pair
            let carrier_hash = Id20::new([0xAB; 20]);
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let client_pk_c = client_pk.clone();

            let server_handle = tokio::spawn(async move {
                let encrypted = crate::tunnel::peer_wire_crypto::PeerWireCrypto::responder(
                    server_io,
                    carrier_hash,
                )
                .await
                .unwrap();
                let mut reader = encrypted.reader;
                let mut writer = encrypted.writer;

                let mut len_buf = [0u8; 2];
                reader.read_exact(&mut len_buf).await.unwrap();
                let msg_len = u16::from_be_bytes(len_buf) as usize;
                let mut noise_msg = vec![0u8; msg_len];
                reader.read_exact(&mut noise_msg).await.unwrap();

                let mut allowed = std::collections::HashSet::new();
                allowed.insert(client_pk_c);
                let (transport, _ck, reply) =
                    crate::tunnel::crypto::responder_accept(&server_sk, &noise_msg, &allowed)
                        .unwrap();

                let reply_len = (reply.len() as u16).to_be_bytes();
                writer.write_all(&reply_len).await.unwrap();
                writer.write_all(&reply).await.unwrap();
                writer.flush().await.unwrap();

                (transport, reader, writer)
            });

            let encrypted =
                crate::tunnel::peer_wire_crypto::PeerWireCrypto::initiator(client_io, carrier_hash)
                    .await
                    .unwrap();
            let mut client_reader = encrypted.reader;
            let mut client_writer = encrypted.writer;

            let (handshake, noise_msg) =
                crate::tunnel::crypto::initiator_start(&client_sk, &server_pk).unwrap();

            let msg_len = (noise_msg.len() as u16).to_be_bytes();
            client_writer.write_all(&msg_len).await.unwrap();
            client_writer.write_all(&noise_msg).await.unwrap();
            client_writer.flush().await.unwrap();

            let mut len_buf = [0u8; 2];
            client_reader.read_exact(&mut len_buf).await.unwrap();
            let reply_len = u16::from_be_bytes(len_buf) as usize;
            let mut reply_buf = vec![0u8; reply_len];
            client_reader.read_exact(&mut reply_buf).await.unwrap();

            let client_transport =
                crate::tunnel::crypto::initiator_complete(handshake, &reply_buf).unwrap();

            let (server_transport, server_reader, server_writer) = server_handle.await.unwrap();

            let client = TunnelClient::from_raw_parts(
                client_transport,
                Box::new(client_reader),
                Box::new(client_writer),
            );

            let server_transport: Arc<Mutex<NoiseTransport>> =
                Arc::new(Mutex::new(server_transport));
            let st = server_transport.clone();
            let direct_connect_attempts = Arc::new(AtomicUsize::new(0));

            let relay_handle = tokio::spawn(async move {
                run_server_relay(
                    st,
                    Box::new(server_reader),
                    Box::new(server_writer),
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

    struct TcpRelayState {
        data_tx: mpsc::Sender<Bytes>,
    }

    async fn run_server_relay(
        transport: Arc<Mutex<NoiseTransport>>,
        reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
        tcp_echo_port: u16,
        udp_echo_port: u16,
    ) {
        let reader = Arc::new(Mutex::new(reader));
        let writer = Arc::new(Mutex::new(writer));

        let mut tcp_relays: HashMap<u64, TcpRelayState> = HashMap::new();
        let mut udp_sockets: HashMap<u64, Arc<UdpSocket>> = HashMap::new();

        loop {
            let frame = {
                let mut t = transport.lock().await;
                let mut r = reader.lock().await;
                match server::read_frame(&mut *t, &mut **r).await {
                    Ok(f) => {
                        eprintln!("relay: got frame");
                        f
                    }
                    Err(e) => {
                        eprintln!("relay: read error: {e}, exiting");
                        break;
                    }
                }
            };

            match frame {
                TunnelFrame::OpenTcp {
                    stream_id,
                    host: _,
                    port: _,
                } => {
                    eprintln!("relay: OpenTcp stream={}", stream_id);
                    let target_addr =
                        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, tcp_echo_port));
                    match TcpStream::connect(target_addr).await {
                        Ok(stream) => {
                            let (target_reader, target_writer) = tokio::io::split(stream);
                            let (data_tx, mut data_rx) = mpsc::channel::<Bytes>(64);

                            {
                                let mut t = transport.lock().await;
                                let mut w = writer.lock().await;
                                eprintln!("relay: sending TcpOpened");
                                let _ = server::write_frame(
                                    &mut *t,
                                    &mut **w,
                                    &TunnelFrame::TcpOpened {
                                        stream_id,
                                        bind_addr: target_addr,
                                    },
                                )
                                .await;
                            }

                            tcp_relays.insert(stream_id, TcpRelayState { data_tx });

                            let t1 = transport.clone();
                            let w1 = writer.clone();
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 65536];
                                let mut rdr = target_reader;
                                loop {
                                    match rdr.read(&mut buf).await {
                                        Ok(0) => {
                                            eprintln!("relay: target eof, sending TcpFin");
                                            let mut t = t1.lock().await;
                                            let mut w = w1.lock().await;
                                            let _ = server::write_frame(
                                                &mut *t,
                                                &mut **w,
                                                &TunnelFrame::TcpFin { stream_id },
                                            )
                                            .await;
                                            break;
                                        }
                                        Ok(n) => {
                                            eprintln!(
                                                "relay: target recv {} bytes, forwarding to client",
                                                n
                                            );
                                            let mut t = t1.lock().await;
                                            let mut w = w1.lock().await;
                                            if server::write_frame(
                                                &mut *t,
                                                &mut **w,
                                                &TunnelFrame::TcpData {
                                                    stream_id,
                                                    bytes: Bytes::copy_from_slice(&buf[..n]),
                                                },
                                            )
                                            .await
                                            .is_err()
                                            {
                                                eprintln!("relay: failed to forward to client");
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("relay: target read error: {e}");
                                            break;
                                        }
                                    }
                                }
                            });

                            tokio::spawn(async move {
                                let mut wrtr = target_writer;
                                while let Some(data) = data_rx.recv().await {
                                    eprintln!("relay: forwarding {} bytes to target", data.len());
                                    if wrtr.write_all(&data).await.is_err() {
                                        eprintln!("relay: target write error");
                                        break;
                                    }
                                }
                                eprintln!("relay: data channel closed");
                            });
                        }
                        Err(e) => {
                            eprintln!("relay: failed to connect to echo: {e}");
                            let mut t = transport.lock().await;
                            let mut w = writer.lock().await;
                            let _ = server::write_frame(
                                &mut *t,
                                &mut **w,
                                &TunnelFrame::TcpReset {
                                    stream_id,
                                    code: crate::tunnel::frame::TunnelErrorCode::ConnectionRefused,
                                },
                            )
                            .await;
                        }
                    }
                }
                TunnelFrame::TcpData { stream_id, bytes } => {
                    eprintln!("relay: TcpData stream={} len={}", stream_id, bytes.len());
                    if let Some(state) = tcp_relays.get(&stream_id) {
                        eprintln!("relay: sending to data channel");
                        let _ = state.data_tx.send(bytes).await;
                    } else {
                        eprintln!("relay: no relay state for stream {}", stream_id);
                    }
                }
                TunnelFrame::TcpFin { stream_id } => {
                    eprintln!("relay: TcpFin stream={}", stream_id);
                    tcp_relays.remove(&stream_id);
                }
                TunnelFrame::TcpReset { stream_id, .. } => {
                    eprintln!("relay: TcpReset stream={}", stream_id);
                    tcp_relays.remove(&stream_id);
                }
                TunnelFrame::OpenUdp { association_id } => {
                    eprintln!("relay: OpenUdp assoc={}", association_id);
                    match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await {
                        Ok(socket) => {
                            let socket = Arc::new(socket);
                            udp_sockets.insert(association_id, socket.clone());
                            let t1 = transport.clone();
                            let w1 = writer.clone();
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 65536];
                                loop {
                                    match socket.recv_from(&mut buf).await {
                                        Ok((n, src)) => {
                                            let mut t = t1.lock().await;
                                            let mut w = w1.lock().await;
                                            if server::write_frame(
                                                &mut *t,
                                                &mut **w,
                                                &TunnelFrame::UdpDatagram {
                                                    association_id,
                                                    destination: TunnelDestination::Ip(src),
                                                    bytes: Bytes::copy_from_slice(&buf[..n]),
                                                },
                                            )
                                            .await
                                            .is_err()
                                            {
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });
                        }
                        Err(_) => {
                            let mut t = transport.lock().await;
                            let mut w = writer.lock().await;
                            let _ = server::write_frame(
                                &mut *t,
                                &mut **w,
                                &TunnelFrame::CloseUdp { association_id },
                            )
                            .await;
                        }
                    }
                }
                TunnelFrame::UdpDatagram {
                    association_id,
                    destination: _,
                    bytes,
                } => {
                    eprintln!(
                        "relay: UdpDatagram assoc={} len={}",
                        association_id,
                        bytes.len()
                    );
                    if let Some(socket) = udp_sockets.get(&association_id) {
                        let echo_addr =
                            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, udp_echo_port));
                        let _ = socket.send_to(&bytes, echo_addr).await;
                    }
                }
                TunnelFrame::CloseUdp { association_id } => {
                    udp_sockets.remove(&association_id);
                }
                TunnelFrame::Ping { nonce } => {
                    let mut t = transport.lock().await;
                    let mut w = writer.lock().await;
                    let _ =
                        server::write_frame(&mut *t, &mut **w, &TunnelFrame::Pong { nonce }).await;
                }
                _ => {}
            }
        }
        eprintln!("relay: exiting");
    }
}
