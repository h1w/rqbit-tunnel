// ── Per-stream flow control + idle supervision ──────────────────────────────
//
// Two small primitives shared by the server relay and the client mux:
//
//   * `SendCredit` — credit-based flow control. A sender must `reserve(n)`
//     before transmitting `n` payload bytes; the peer replenishes credit via
//     `Credit` frames as it drains received data. This bounds the amount of
//     unacknowledged in-flight data per stream to the configured window
//     (`DEFAULT_WINDOW` by default), which in turn bounds the receiver's
//     per-stream buffer — so a single slow stream can never fill a buffer
//     deep enough to block the shared frame reader (no head-of-line blocking
//     across streams).
//
//   * `IdleGuard` — a bidirectional idle watchdog. Activity in EITHER
//     direction pokes it; if nothing happens for the idle timeout the stream
//     token is cancelled. (The previous implementation only timed the
//     destination-read direction, so a busy upload with a quiet download
//     direction was wrongly reset.)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

use super::config::{DEFAULT_WINDOW, RTT_EWMA_DEN, RTT_EWMA_NUM};

// ── Credit-based flow control ───────────────────────────────────────────────

/// Send-side flow-control credit for one stream direction.
#[derive(Clone)]
pub(crate) struct SendCredit {
    sem: Arc<Semaphore>,
}

impl SendCredit {
    /// A fresh credit pool seeded with the default window.
    pub(crate) fn new() -> Self {
        Self::with_window(DEFAULT_WINDOW)
    }

    /// A fresh credit pool seeded with `window` bytes of credit. This is the
    /// seam a later task uses to pass a per-stream adaptive value; `new()`
    /// just fixes it to `DEFAULT_WINDOW`.
    pub(crate) fn with_window(window: usize) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(window)),
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
        // Chunks are always <= the configured window, so this fits the pool.
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

// ── RTT estimation via Ping/Pong ─────────────────────────────────────────────
//
// Pure, no I/O: fed by whoever owns the wire (the client mux's ping task /
// reader, and the server relay's mirrored ping task / reader). Share via
// `Arc<Mutex<RttEstimator>>` at the call site.

/// Tracks per-carrier round-trip time from `Ping`/`Pong` round trips: a
/// running minimum (the baseline, no-queuing RTT) and an EWMA-smoothed value
/// (the current estimate, which rises under queuing). `queuing_delay()` —
/// smooth minus min — is the core signal the later adaptive-window
/// controller uses to detect self-inflicted bufferbloat.
pub(crate) struct RttEstimator {
    min: Option<Duration>,
    smooth: Option<Duration>,
}

impl RttEstimator {
    pub(crate) fn new() -> Self {
        Self {
            min: None,
            smooth: None,
        }
    }

    /// Record one round-trip sample. The first sample seeds both the running
    /// minimum and the smoothed estimate; later samples update the minimum
    /// and nudge the smoothed estimate toward the sample by `NUM/DEN`
    /// (integer-nanosecond EWMA — deterministic, no floats, so tests aren't
    /// flaky).
    pub(crate) fn record(&mut self, sample: Duration) {
        self.min = Some(match self.min {
            Some(min) => min.min(sample),
            None => sample,
        });
        self.smooth = Some(match self.smooth {
            Some(smooth) => ewma_step(smooth, sample),
            None => sample,
        });
    }

    /// Lowest RTT sample observed so far (baseline, no-queuing RTT). Zero
    /// until the first sample is recorded.
    pub(crate) fn rtt_min(&self) -> Duration {
        self.min.unwrap_or(Duration::ZERO)
    }

    /// EWMA-smoothed RTT (current estimate, includes queuing). Zero until the
    /// first sample is recorded.
    pub(crate) fn rtt_smooth(&self) -> Duration {
        self.smooth.unwrap_or(Duration::ZERO)
    }

    /// Estimated self-inflicted queuing delay: `rtt_smooth - rtt_min`.
    pub(crate) fn queuing_delay(&self) -> Duration {
        self.rtt_smooth().saturating_sub(self.rtt_min())
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

/// One step of integer-nanosecond EWMA: `smooth += (sample - smooth) *
/// NUM/DEN`, computed on unsigned nanos in both directions so it never
/// depends on floats or signed overflow.
fn ewma_step(smooth: Duration, sample: Duration) -> Duration {
    let smooth_nanos = smooth.as_nanos() as u64;
    let sample_nanos = sample.as_nanos() as u64;
    let new_nanos = if sample_nanos >= smooth_nanos {
        let delta = sample_nanos - smooth_nanos;
        smooth_nanos + delta * u64::from(RTT_EWMA_NUM) / u64::from(RTT_EWMA_DEN)
    } else {
        let delta = smooth_nanos - sample_nanos;
        smooth_nanos - delta * u64::from(RTT_EWMA_NUM) / u64::from(RTT_EWMA_DEN)
    };
    Duration::from_nanos(new_nanos)
}

// ── Inflight-ping bookkeeping (shared by the client mux + server relay) ─────

/// Record that `nonce` was just sent at `now`, evicting the oldest in-flight
/// entry first if `map` is already at `cap`. Nonces are assigned
/// monotonically per side, so the smallest key is always the oldest — this
/// bounds memory even if `Pong`s are lost or arrive very late.
pub(crate) fn record_ping_sent(
    map: &mut HashMap<u64, Instant>,
    nonce: u64,
    now: Instant,
    cap: usize,
) {
    if map.len() >= cap {
        if let Some(&oldest) = map.keys().min() {
            map.remove(&oldest);
        }
    }
    map.insert(nonce, now);
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn with_window_allows_exactly_window_bytes_then_blocks() {
        let credit = SendCredit::with_window(1024);

        // Reserving the whole window (and a zero-sized reserve) succeeds
        // immediately.
        assert!(credit.reserve(0).await);
        assert!(credit.reserve(1024).await);

        // The pool is now exhausted: a further reserve must stay pending
        // until credit is granted back.
        let pending = credit.reserve(1);
        tokio::pin!(pending);
        let timed_out = tokio::time::timeout(Duration::from_millis(50), &mut pending).await;
        assert!(
            timed_out.is_err(),
            "reserve(1) should still be pending once the window is exhausted"
        );

        // Granting credit unblocks it.
        credit.grant(1);
        assert!(pending.await);
    }

    #[test]
    fn rtt_estimator_tracks_min_and_smooths_toward_samples() {
        let mut est = RttEstimator::new();

        // Before any sample, everything reads zero.
        assert_eq!(est.rtt_min(), Duration::ZERO);
        assert_eq!(est.rtt_smooth(), Duration::ZERO);

        est.record(Duration::from_millis(100));
        est.record(Duration::from_millis(120));
        est.record(Duration::from_millis(110));

        assert_eq!(
            est.rtt_min(),
            Duration::from_millis(100),
            "rtt_min should track the lowest sample seen"
        );

        let smooth = est.rtt_smooth();
        assert!(
            smooth > Duration::from_millis(100) && smooth < Duration::from_millis(120),
            "expected smoothed RTT to have moved toward recent samples while staying \
             between min and max, got {smooth:?}"
        );

        let queuing = est.queuing_delay();
        assert_eq!(
            queuing,
            smooth.saturating_sub(est.rtt_min()),
            "queuing_delay must equal smooth - min"
        );
        assert!(
            queuing <= Duration::from_millis(20),
            "queuing delay should stay within the sample spread, got {queuing:?}"
        );

        // A later, lower sample must drop the running minimum.
        est.record(Duration::from_millis(80));
        assert_eq!(
            est.rtt_min(),
            Duration::from_millis(80),
            "rtt_min should drop to a new lower sample"
        );
    }

    #[test]
    fn record_ping_sent_evicts_oldest_when_at_capacity() {
        let mut map = HashMap::new();
        let now = Instant::now();
        for n in 0..4u64 {
            record_ping_sent(&mut map, n, now, 3);
        }
        assert_eq!(map.len(), 3, "map should stay capped at 3 entries");
        assert!(
            !map.contains_key(&0),
            "oldest nonce (0) should have been evicted"
        );
        assert!(map.contains_key(&3), "newest nonce (3) should be present");
    }
}
