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

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use librqbit_core::Id20;
use tokio_util::sync::CancellationToken;

use super::client::TunnelClient;
use super::client_mux::ClientMux;
use super::config::{INITIAL_BACKOFF, MAX_BACKOFF};
use super::options::TunnelClientOptions;

/// Owns the "current" [`ClientMux`] and keeps it connected.
pub(crate) struct TunnelClientSupervisor {
    current: ArcSwapOption<ClientMux>,
    session_shutdown: CancellationToken,
}

impl TunnelClientSupervisor {
    /// Start the supervisor. Returns immediately; connection happens in a
    /// background task tied to `session_shutdown`.
    pub(crate) fn start(
        opts: TunnelClientOptions,
        session_shutdown: CancellationToken,
    ) -> Arc<Self> {
        let sup = Arc::new(Self {
            current: ArcSwapOption::empty(),
            session_shutdown: session_shutdown.clone(),
        });
        tokio::spawn(sup.clone().run(opts));
        sup
    }

    /// The mux for the currently-established connection, if any.
    pub(crate) fn current(&self) -> Option<Arc<ClientMux>> {
        self.current.load_full()
    }

    async fn run(self: Arc<Self>, opts: TunnelClientOptions) {
        let carrier_hash = opts
            .pairing
            .as_ref()
            .map(|p| p.carrier.handshake_info_hash)
            .unwrap_or_else(|| Id20::new([0u8; 20]));

        let mut backoff = INITIAL_BACKOFF;

        loop {
            if self.session_shutdown.is_cancelled() {
                break;
            }

            let connect = TunnelClient::connect(
                opts.server_addr,
                &opts.identity_key,
                &opts.expected_server_key,
                carrier_hash,
            );

            let client = tokio::select! {
                _ = self.session_shutdown.cancelled() => break,
                r = connect => r,
            };

            match client {
                Ok(client) => {
                    backoff = INITIAL_BACKOFF;
                    // Each mux gets its own child token: when its reader detects
                    // a disconnect it cancels this token, which wakes us to
                    // reconnect — WITHOUT tearing down the session or ingress.
                    let mux_token = self.session_shutdown.child_token();
                    let mux = ClientMux::new(client, mux_token.clone());
                    self.current.store(Some(mux));
                    tracing::info!(server = %opts.server_addr, "tunnel client connected");

                    tokio::select! {
                        _ = mux_token.cancelled() => {
                            tracing::warn!(server = %opts.server_addr, "tunnel connection lost; reconnecting");
                        }
                        _ = self.session_shutdown.cancelled() => {
                            self.current.store(None);
                            break;
                        }
                    }
                    self.current.store(None);
                }
                Err(e) => {
                    self.current.store(None);
                    tracing::warn!(
                        server = %opts.server_addr,
                        error = %e,
                        backoff_ms = backoff.as_millis() as u64,
                        "tunnel client connect failed; will retry"
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = self.session_shutdown.cancelled() => break,
                    }
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }

        self.current.store(None);
        tracing::debug!("tunnel client supervisor stopped");
    }
}
