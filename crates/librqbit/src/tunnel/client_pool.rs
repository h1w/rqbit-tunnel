/// Pick the index of the least-loaded available carrier.
///
/// `loads[i] == None` means carrier `i` is currently unavailable (not
/// connected). Returns `None` if no carrier is available. Ties break toward the
/// lowest index for determinism.
pub(crate) fn select_carrier(loads: &[Option<usize>]) -> Option<usize> {
    loads
        .iter()
        .enumerate()
        .filter_map(|(i, load)| load.map(|l| (i, l)))
        .min_by_key(|&(i, load)| (load, i))
        .map(|(i, _)| i)
}

use std::sync::Arc;

use dht::Dht;
use tokio_util::sync::CancellationToken;

use super::client_mux::ClientMux;
use super::client_supervisor::TunnelClientSupervisor;
use super::options::TunnelClientOptions;

/// A fixed pool of independent carrier connections. Each carrier is a
/// `TunnelClientSupervisor` that connects and reconnects on its own; the pool
/// only load-balances new streams across whichever carriers are live.
pub(crate) struct CarrierPool {
    carriers: Vec<Arc<TunnelClientSupervisor>>,
}

impl CarrierPool {
    /// Spawn `opts.carriers` supervisors, all targeting the same server. The
    /// `opts` are cloned per carrier (each moves its own copy into its task).
    pub(crate) fn start(
        opts: TunnelClientOptions,
        dht: Option<Dht>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let n = opts.carriers.max(1);
        let carriers = (0..n)
            .map(|_| TunnelClientSupervisor::start(opts.clone(), dht.clone(), shutdown.clone()))
            .collect();
        Arc::new(Self { carriers })
    }

    /// Total configured carriers (live or not).
    pub(crate) fn carrier_count(&self) -> usize {
        self.carriers.len()
    }

    /// Snapshot the current live muxes (connected, not shut down).
    fn live_muxes(&self) -> Vec<Option<Arc<ClientMux>>> {
        self.carriers
            .iter()
            .map(|sup| sup.current().filter(|m| !m.is_shutdown()))
            .collect()
    }

    /// Number of carriers currently connected.
    pub(crate) fn live_count(&self) -> usize {
        self.live_muxes().iter().filter(|m| m.is_some()).count()
    }

    /// The least-loaded live mux, or `None` if no carrier is connected.
    pub(crate) fn pick(&self) -> Option<Arc<ClientMux>> {
        let muxes = self.live_muxes();
        let loads: Vec<Option<usize>> = muxes
            .iter()
            .map(|m| m.as_ref().map(|mux| mux.load()))
            .collect();
        let idx = select_carrier(&loads)?;
        muxes.into_iter().nth(idx).flatten()
    }

    /// Test-only accessor exposing the current live-mux snapshot (indexed by
    /// carrier slot, `None` for a disconnected carrier), so integration tests
    /// can inspect per-carrier `load()` directly.
    #[cfg(test)]
    pub(crate) fn live_muxes_for_test(&self) -> Vec<Option<Arc<ClientMux>>> {
        self.live_muxes()
    }
}

#[cfg(test)]
mod tests {
    use super::select_carrier;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn pool_spawns_requested_carrier_count() {
        // No server needed: with no reachable address the supervisors stay
        // disconnected, but the pool must still hold N of them and report
        // zero live carriers / None from pick().
        let mut opts = crate::tunnel::options::TunnelClientOptions {
            expected_server_key: crate::tunnel::frame::TunnelPublicKey([9u8; 32]),
            server_addr: Some(([127, 0, 0, 1], 1).into()), // unreachable
            ..Default::default()
        };
        opts.carriers = 3;
        let pool = super::CarrierPool::start(opts, None, CancellationToken::new());
        assert_eq!(pool.carrier_count(), 3);
        assert_eq!(pool.live_count(), 0);
        assert!(pool.pick().is_none());
    }

    #[test]
    fn none_when_empty() {
        assert_eq!(select_carrier(&[]), None);
    }

    #[test]
    fn none_when_all_unavailable() {
        assert_eq!(select_carrier(&[None, None]), None);
    }

    #[test]
    fn picks_minimum_load() {
        assert_eq!(select_carrier(&[Some(3), Some(1), Some(2)]), Some(1));
    }

    #[test]
    fn ties_break_to_lowest_index() {
        assert_eq!(select_carrier(&[Some(2), Some(2)]), Some(0));
    }

    #[test]
    fn skips_unavailable_carriers() {
        assert_eq!(select_carrier(&[None, Some(5), None, Some(4)]), Some(3));
    }
}
