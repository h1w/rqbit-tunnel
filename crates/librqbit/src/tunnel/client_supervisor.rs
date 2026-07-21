// ── Reconnecting tunnel client supervisor ───────────────────────────────────
//
// The SOCKS ingress binds immediately and stays up for the whole session; the
// actual tunnel connection is established (and re-established) in the
// background by this supervisor. That means:
//
//   * `Session::new` no longer fails if the tunnel server is unreachable at
//     startup — the client just keeps retrying with exponential backoff.
//   * A dropped tunnel connection is transparently reconnected; existing SOCKS
//     streams on the dead connection are reset, new ones use the fresh mux.
//
// The server is located by a static `server_addr` (fast path) and/or via the
// DHT: the server announces the carrier hash (derived from its key), and the
// client looks it up. DHT results are UNTRUSTED — the Noise IK handshake pins
// the server's static key, so a wrong/poisoned address simply fails to
// authenticate and the next candidate is tried.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwapOption;
use dht::Dht;
use futures::StreamExt;
use tokio_util::sync::CancellationToken;

use super::carrier::TunnelCarrierStore;
use super::client::TunnelClient;
use super::client_mux::ClientMux;
use super::config::{CLIENT_CONNECT_TIMEOUT, DHT_PEER_CACHE, INITIAL_BACKOFF, MAX_BACKOFF};
use super::options::TunnelClientOptions;

/// Owns the "current" [`ClientMux`] and keeps it connected.
pub(crate) struct TunnelClientSupervisor {
    current: ArcSwapOption<ClientMux>,
    session_shutdown: CancellationToken,
    /// Deterministic synthetic carrier torrent shared with the server via the
    /// DHT rendezvous key (`descriptor().handshake_info_hash`). Built once by
    /// the pool and shared across supervisors. Not yet consumed by
    /// `TunnelClient::connect` / `ClientMux::new` — that lands in a later
    /// task; today it is only used to derive the DHT discovery key below.
    carrier_store: Arc<TunnelCarrierStore>,
}

impl TunnelClientSupervisor {
    /// Start the supervisor. Returns immediately; connection happens in a
    /// background task tied to `session_shutdown`. `dht`, when present, is the
    /// session's DHT — used to discover the server via the carrier store's
    /// `handshake_info_hash`. `carrier_store` is built once by the pool and
    /// shared (as an `Arc`) across all carriers.
    pub(crate) fn start(
        opts: TunnelClientOptions,
        dht: Option<Dht>,
        session_shutdown: CancellationToken,
        carrier_store: Arc<TunnelCarrierStore>,
    ) -> Arc<Self> {
        let sup = Arc::new(Self {
            current: ArcSwapOption::empty(),
            session_shutdown: session_shutdown.clone(),
            carrier_store,
        });
        tokio::spawn(sup.clone().run(opts, dht));
        sup
    }

    /// The mux for the currently-established connection, if any.
    pub(crate) fn current(&self) -> Option<Arc<ClientMux>> {
        self.current.load_full()
    }

    async fn run(self: Arc<Self>, opts: TunnelClientOptions, dht: Option<Dht>) {
        // Stable per-server "torrent" identity, derived from the pinned server
        // key (matches what the server derives from its own key). This keys
        // the MSE/PE carrier ONLY — it must NOT be used for DHT rendezvous
        // (that would announce one info_hash while presenting another in the
        // BT handshake, a fingerprint).
        let carrier_hash = super::crypto::derive_carrier_hash(&opts.expected_server_key);

        // DHT rendezvous key: the deterministic carrier torrent's
        // `handshake_info_hash`, matching what the server announces.
        let discover_hash = self.carrier_store.descriptor().handshake_info_hash;

        // Continuously drain the DHT lookup into a small, deduped, bounded cache
        // of recent candidate addresses. The lookup itself is what generates the
        // (observable) DHT peer-discovery traffic; announce port is `None` — the
        // client discovers, it does not announce itself.
        let dht_cache: Arc<Mutex<Vec<SocketAddr>>> = Arc::new(Mutex::new(Vec::new()));
        if let Some(dht) = dht.as_ref() {
            self.clone()
                .spawn_dht_drainer(dht.get_peers(discover_hash, None), dht_cache.clone());
            tracing::info!(
                ?discover_hash,
                "tunnel client discovering the server via DHT"
            );
        } else if opts.server_addr.is_none() {
            tracing::error!(
                "tunnel client has no --tunnel-server-addr and DHT is disabled; \
                 nothing to connect to (enable DHT or set a server address)"
            );
            return;
        }

        let mut backoff = INITIAL_BACKOFF;
        let mut last_good: Option<SocketAddr> = None;

        loop {
            if self.session_shutdown.is_cancelled() {
                break;
            }

            // Ordered candidates, all instant (no blocking on the DHT): the
            // last-known-good address, the static address, then recent
            // DHT-discovered peers (most recent first).
            let mut candidates: Vec<SocketAddr> = Vec::new();
            let push = |a: SocketAddr, v: &mut Vec<SocketAddr>| {
                if !v.contains(&a) {
                    v.push(a);
                }
            };
            if let Some(a) = last_good {
                push(a, &mut candidates);
            }
            if let Some(a) = opts.server_addr {
                push(a, &mut candidates);
            }
            for a in dht_cache.lock().unwrap().iter().rev() {
                push(*a, &mut candidates);
            }

            if candidates.is_empty() {
                // Nothing to try yet (no static address, DHT not populated).
                if self.sleep_backoff(&mut backoff).await {
                    break;
                }
                continue;
            }

            // Try candidates in order until one authenticates.
            let mut connected: Option<(SocketAddr, TunnelClient)> = None;
            for addr in candidates {
                if self.session_shutdown.is_cancelled() {
                    break;
                }
                if let Some(client) = self.attempt(addr, &opts, carrier_hash).await {
                    connected = Some((addr, client));
                    break;
                }
            }

            match connected {
                Some((addr, client)) => {
                    backoff = INITIAL_BACKOFF;
                    last_good = Some(addr);
                    // Each mux gets its own child token: when its reader detects
                    // a disconnect it cancels this token, which wakes us to
                    // reconnect — WITHOUT tearing down the session or ingress.
                    let mux_token = self.session_shutdown.child_token();
                    let mux = ClientMux::new(client, mux_token.clone());
                    self.current.store(Some(mux));
                    tracing::info!(server = %addr, "tunnel client connected");

                    tokio::select! {
                        _ = mux_token.cancelled() => {
                            tracing::warn!(server = %addr, "tunnel connection lost; reconnecting");
                        }
                        _ = self.session_shutdown.cancelled() => {
                            self.current.store(None);
                            break;
                        }
                    }
                    self.current.store(None);
                }
                None => {
                    self.current.store(None);
                    tracing::warn!(
                        backoff_ms = backoff.as_millis() as u64,
                        "no tunnel candidate connected; will retry"
                    );
                    if self.sleep_backoff(&mut backoff).await {
                        break;
                    }
                }
            }
        }

        self.current.store(None);
        tracing::debug!("tunnel client supervisor stopped");
    }

    /// One connection attempt to `addr`, bounded by a timeout and the session
    /// shutdown. Returns the authenticated client on success.
    async fn attempt(
        &self,
        addr: SocketAddr,
        opts: &TunnelClientOptions,
        carrier_hash: librqbit_core::Id20,
    ) -> Option<TunnelClient> {
        let result = tokio::select! {
            _ = self.session_shutdown.cancelled() => return None,
            r = tokio::time::timeout(
                CLIENT_CONNECT_TIMEOUT,
                TunnelClient::connect(
                    addr,
                    &opts.identity_key,
                    &opts.expected_server_key,
                    carrier_hash,
                ),
            ) => r,
        };
        match result {
            Ok(Ok(client)) => Some(client),
            Ok(Err(e)) => {
                tracing::debug!(server = %addr, error = %e, "tunnel candidate failed");
                None
            }
            Err(_) => {
                tracing::debug!(server = %addr, "tunnel candidate connect timed out");
                None
            }
        }
    }

    /// Drain the DHT `get_peers` stream into a bounded, deduped recent-peers
    /// cache until the session is cancelled or the stream ends.
    fn spawn_dht_drainer(
        self: Arc<Self>,
        mut stream: dht::RequestPeersStream,
        cache: Arc<Mutex<Vec<SocketAddr>>>,
    ) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = self.session_shutdown.cancelled() => break,
                    item = stream.next() => match item {
                        Some(addr) => {
                            let mut c = cache.lock().unwrap();
                            if !c.contains(&addr) {
                                if c.len() >= DHT_PEER_CACHE {
                                    c.remove(0);
                                }
                                c.push(addr);
                            }
                        }
                        None => break,
                    }
                }
            }
        });
    }

    /// Sleep for the current backoff (respecting shutdown) and grow it. Returns
    /// `true` if the session was cancelled during the sleep.
    async fn sleep_backoff(&self, backoff: &mut std::time::Duration) -> bool {
        let cancelled = tokio::select! {
            _ = tokio::time::sleep(*backoff) => false,
            _ = self.session_shutdown.cancelled() => true,
        };
        *backoff = (*backoff * 2).min(MAX_BACKOFF);
        cancelled
    }
}
