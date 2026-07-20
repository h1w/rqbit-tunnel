// ── Per-stream flow control + idle supervision ──────────────────────────────
//
// Two small primitives shared by the server relay and the client mux:
//
//   * `SendCredit` — credit-based flow control. A sender must `reserve(n)`
//     before transmitting `n` payload bytes; the peer replenishes credit via
//     `Credit` frames as it drains received data. This bounds the amount of
//     unacknowledged in-flight data per stream to `INITIAL_WINDOW`, which in
//     turn bounds the receiver's per-stream buffer — so a single slow stream
//     can never fill a buffer deep enough to block the shared frame reader
//     (no head-of-line blocking across streams).
//
//   * `IdleGuard` — a bidirectional idle watchdog. Activity in EITHER
//     direction pokes it; if nothing happens for the idle timeout the stream
//     token is cancelled. (The previous implementation only timed the
//     destination-read direction, so a busy upload with a quiet download
//     direction was wrongly reset.)

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

/// Initial per-stream receive window (bytes). Both peers assume this much
/// credit at stream open, so no window-advertisement handshake is needed.
pub(crate) const INITIAL_WINDOW: usize = 256 * 1024;

// ── Credit-based flow control ───────────────────────────────────────────────

/// Send-side flow-control credit for one stream direction.
#[derive(Clone)]
pub(crate) struct SendCredit {
    sem: Arc<Semaphore>,
}

impl SendCredit {
    /// A fresh credit pool seeded with the initial window.
    pub(crate) fn new() -> Self {
        Self {
            sem: Arc::new(Semaphore::new(INITIAL_WINDOW)),
        }
    }

    /// Wait until `n` bytes of credit are available and consume them.
    ///
    /// Returns `false` if the pool was [`close`](Self::close)d (stream torn
    /// down) — callers should stop sending. `acquire_many` is cancel-safe, so
    /// this may be raced in a `select!`.
    pub(crate) async fn reserve(&self, n: usize) -> bool {
        if n == 0 {
            return true;
        }
        // Chunks are always <= INITIAL_WINDOW, so this fits the pool.
        match self.sem.acquire_many(n as u32).await {
            Ok(permit) => {
                permit.forget();
                true
            }
            Err(_) => false,
        }
    }

    /// Replenish `n` bytes of credit (the peer drained `n` bytes downstream).
    pub(crate) fn grant(&self, n: usize) {
        if n == 0 {
            return;
        }
        // Cap defensively so we never exceed the semaphore's permit ceiling.
        let n = n.min(Semaphore::MAX_PERMITS);
        self.sem.add_permits(n);
    }

    /// Permanently close the pool, waking any pending `reserve` with `false`.
    pub(crate) fn close(&self) {
        self.sem.close();
    }
}

impl Default for SendCredit {
    fn default() -> Self {
        Self::new()
    }
}

// ── Bidirectional idle watchdog ─────────────────────────────────────────────

/// Cancels `token` if no activity is reported for `idle`. Any direction of a
/// stream reports activity via [`poke`](Self::poke).
#[derive(Clone)]
pub(crate) struct IdleGuard {
    notify: Arc<Notify>,
}

impl IdleGuard {
    /// Spawn the watchdog task. It stops when `token` is cancelled (by us on
    /// timeout, or by the owner on normal teardown).
    pub(crate) fn spawn(idle: Duration, token: CancellationToken) -> Self {
        let notify = Arc::new(Notify::new());
        let watch = notify.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(idle) => {
                        token.cancel();
                        break;
                    }
                    // Activity: loop, which re-arms the sleep from now.
                    _ = watch.notified() => {}
                }
            }
        });
        Self { notify }
    }

    /// Report activity, resetting the idle countdown.
    pub(crate) fn poke(&self) {
        self.notify.notify_one();
    }
}
