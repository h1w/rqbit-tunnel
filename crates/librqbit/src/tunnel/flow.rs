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
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

use super::config;
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

// ── Delay-adaptive window controller (Vegas/LEDBAT-style AIMD) ──────────────
//
// Pure, no I/O: driven once per RTT sample by whoever owns the carrier's
// `RttEstimator` (the ping task). Watches `queuing_delay` (smoothed RTT minus
// the running-minimum, no-queuing RTT) as the congestion signal instead of
// loss, so it backs off before a bottleneck buffer actually overflows —
// standard TCP Vegas / LEDBAT low-latency-first stance, appropriate for an
// interactive tunnel that would rather cap latency than max out throughput.

/// Per-carrier controller over an in-flight target (bytes), driven by
/// self-inflicted queuing delay. Slow-start (multiplicative ×2 growth) while
/// the link is utilized and queuing delay stays low and no congestion has been
/// seen yet; additive-increase after the first congestion event; and
/// multiplicative-decrease as soon as queuing delay rises, before a real
/// loss-based signal would ever fire.
///
/// The `target` bounds *aggregate* per-carrier in-flight data via the writer's
/// pacing rate (`target / rtt`); it is NOT a per-stream window (streams open
/// with a fixed generous `config::OPEN_WINDOW` so pacing, not the window, is the
/// sole in-flight control).
pub(crate) struct WindowController {
    target: usize,
    /// True until the first congestion event (queuing delay above
    /// `QUEUING_DELAY_HIGH`). While set, low-delay utilized growth is
    /// multiplicative (×2, TCP slow-start) so the target ramps to the path's
    /// capacity in a few RTTs instead of crawling up additively.
    in_slow_start: bool,
}

impl WindowController {
    /// A fresh controller, starting at the conservative floor
    /// (`config::MIN_TARGET`) in slow-start rather than assuming the link can
    /// already take the max.
    pub(crate) fn new() -> Self {
        Self {
            target: config::MIN_TARGET,
            in_slow_start: true,
        }
    }

    /// One control step, called once per RTT sample.
    ///
    /// `queuing_delay` is `rtt_smooth - rtt_min` from the carrier's
    /// `RttEstimator`. `utilized` is whether the writer actually had to
    /// pace-throttle (sleep for pacing) since the last step — i.e. pacing at
    /// `target / rtt` was the real bottleneck. Growth is gated on this so an
    /// idle or under-driven low-delay link doesn't get its target inflated for
    /// no reason (there's no evidence the link can sustain more until pacing is
    /// actually the constraint).
    ///
    /// Backoff, by contrast, isn't gated on utilization: a high queuing delay
    /// means something (even a long-past burst) is still draining through a
    /// buffer, so it always takes precedence over growth/hold — and it also
    /// exits slow-start, so subsequent growth is cautious (additive) rather
    /// than doubling straight back into congestion.
    pub(crate) fn step(&mut self, queuing_delay: Duration, utilized: bool) {
        if queuing_delay > config::QUEUING_DELAY_HIGH {
            self.target = self.target * config::TARGET_BACKOFF_NUM / config::TARGET_BACKOFF_DEN;
            self.in_slow_start = false;
        } else if utilized && queuing_delay < config::QUEUING_DELAY_LOW {
            self.target = if self.in_slow_start {
                // Slow-start: double toward capacity. A ×2 that would overshoot
                // MAX_TARGET just clamps below.
                self.target.saturating_mul(2)
            } else {
                self.target.saturating_add(config::TARGET_GROW_STEP)
            };
        }
        // else: delay is in [LOW, HIGH], or low-but-idle — hold.

        self.target = self.target.clamp(config::MIN_TARGET, config::MAX_TARGET);
    }

    /// The current per-carrier in-flight target (bytes).
    pub(crate) fn target(&self) -> usize {
        self.target
    }
}

impl Default for WindowController {
    fn default() -> Self {
        Self::new()
    }
}

// ── Per-carrier control loop (the actuator wiring) ──────────────────────────
//
// One control-loop iteration, shared verbatim by the client mux's ping task and
// the server relay's ping task so both carriers adapt identically. Called once
// per RTT probe, AFTER the reader has had a chance to record the prior probe's
// `Pong` sample into `rtt`. It reads the freshest queuing-delay estimate, steps
// the `WindowController`, and drives the writer's pacing rate to `target / rtt`
// (bytes/s) — the actuator that bounds in-flight data at ≈`target`, keeping
// self-inflicted queuing delay low while letting throughput rise as the
// controller grows `target` on a clear path.

/// Step `controller` from the carrier's freshest queuing delay and whether the
/// writer actually had to pace-throttle since the last tick (`paced` flag —
/// read-and-reset here), then store `target / rtt_smooth` (bytes/s) into
/// `pacing_rate` for the writer to pick up on its next frame.
///
/// `utilized` means "pacing at `target / rtt` was the real bottleneck" (the
/// writer slept for pacing), NOT merely "some bytes moved". Gating growth on
/// this means the target only ramps up when there's genuine evidence the link
/// could carry more than the current pace allows — a trickle of traffic that
/// never hits the pacing limit no longer ratchets the target to the max.
///
/// Guards `rtt_smooth == 0` (no sample yet — leaves `pacing_rate` at its
/// effectively-unlimited default so the writer never throttles before it can
/// measure the path) and floors the computed rate at `config::MIN_PACING_RATE`.
pub(crate) fn drive_flow_control(
    rtt: &StdMutex<RttEstimator>,
    controller: &StdMutex<WindowController>,
    paced: &AtomicBool,
    pacing_rate: &AtomicU64,
) {
    let (queuing_delay, rtt_smooth) = {
        let est = rtt.lock().unwrap();
        (est.queuing_delay(), est.rtt_smooth())
    };
    // Utilized = the writer actually throttled on the pacing rate since the last
    // tick (pacing was the bottleneck). Gating growth on this stops a low-rate
    // trickle — or an idle low-delay link — from inflating `target`.
    let utilized = paced.swap(false, Ordering::Relaxed);

    let target = {
        let mut ctl = controller.lock().unwrap();
        ctl.step(queuing_delay, utilized);
        ctl.target()
    };

    // bytes/s = target_bytes / rtt_seconds = target * 1e9 / rtt_nanos. Compute
    // in u128 (unconditionally overflow-safe), and let `checked_div` also handle
    // the "no RTT sample yet" guard: rtt_nanos == 0 yields `None`, so we leave
    // `pacing_rate` at its effectively-unlimited default until the path is
    // measured (the writer must not throttle before it can measure).
    if let Some(rate) = (target as u128 * 1_000_000_000u128).checked_div(rtt_smooth.as_nanos()) {
        let rate = rate.clamp(config::MIN_PACING_RATE as u128, u64::MAX as u128) as u64;
        pacing_rate.store(rate, Ordering::Relaxed);
    }
}

// ── Writer-side pacing (token bucket) ───────────────────────────────────────
//
// Pure mechanism: no `Instant::now()` inside — the caller (the frame writer in
// `relay.rs`) supplies `now_nanos` from its own clock so this stays
// deterministically testable. Phase A wires this into the writer at a very
// high default rate (`config::PACING_DEFAULT_RATE`), so it never meaningfully
// delays a frame; a later controller task drives `rate_bytes_per_s` down via
// `set_rate` from congestion signals (`RttEstimator::queuing_delay`).

/// A token bucket rate limiter: bytes accrue at `rate_bytes_per_s`, capped at
/// `burst`, and `take` reports how long the caller should wait before sending
/// `n` more bytes.
pub(crate) struct TokenBucket {
    rate_bytes_per_s: u64,
    burst: u64,
    /// Bucket fill level in bytes. Never negative — a deficit is reported via
    /// the returned delay instead of being carried forward as debt, so a
    /// caller that honors the delay (sleeps before its next `take`) sees the
    /// bucket refill exactly as if it had been draining in real time.
    tokens: f64,
    last_nanos: u64,
}

impl TokenBucket {
    /// A fresh bucket, starting full (the initial burst is available
    /// immediately — there's no reason to pace the very first frame).
    pub(crate) fn new(rate_bytes_per_s: u64, burst: u64) -> Self {
        Self {
            rate_bytes_per_s,
            burst,
            tokens: burst as f64,
            last_nanos: 0,
        }
    }

    /// Update the rate in place (the seam a later controller uses to drive
    /// pacing from congestion signals). Leaves the current fill level and
    /// clock untouched.
    pub(crate) fn set_rate(&mut self, rate_bytes_per_s: u64) {
        self.rate_bytes_per_s = rate_bytes_per_s;
    }

    /// Refill based on elapsed time since the last call, consume `n` bytes,
    /// and return the delay (nanoseconds) the caller should sleep before
    /// sending `n`. `now_nanos` must be monotonically non-decreasing across
    /// calls (e.g. nanos since some fixed base `Instant`).
    pub(crate) fn take(&mut self, now_nanos: u64, n: u64) -> u64 {
        let elapsed_nanos = now_nanos.saturating_sub(self.last_nanos);
        self.last_nanos = now_nanos;

        if self.rate_bytes_per_s > 0 && elapsed_nanos > 0 {
            let refill = elapsed_nanos as f64 * self.rate_bytes_per_s as f64 / 1e9;
            self.tokens = (self.tokens + refill).min(self.burst as f64);
        }

        let n = n as f64;
        if self.tokens >= n {
            self.tokens -= n;
            return 0;
        }

        let deficit = n - self.tokens;
        self.tokens = 0.0;
        if self.rate_bytes_per_s == 0 {
            // Fully paused: no finite delay pays off the deficit. Callers
            // shouldn't configure rate=0 today (the default is a high cap),
            // but avoid a div-by-zero -> NaN if they ever do.
            return u64::MAX;
        }
        (deficit * 1e9 / self.rate_bytes_per_s as f64) as u64
    }
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
    fn token_bucket_burst_then_paces_then_refills() {
        let mut bucket = TokenBucket::new(1000, 1000);

        // The initial burst allowance covers the first 1000 bytes for free.
        assert_eq!(
            bucket.take(0, 1000),
            0,
            "burst should cover the first take in full"
        );

        // Immediately (no elapsed time) asking for another 100 bytes exceeds
        // the now-exhausted bucket: the delay should be ~100/1000s = 1e8ns.
        let delay = bucket.take(0, 100);
        assert!(
            (delay as i64 - 100_000_000i64).abs() < 1_000_000,
            "expected ~1e8ns delay for a 100-byte deficit at rate 1000, got {delay}"
        );

        // After the 0.1s the previous delay demanded has actually elapsed,
        // the bucket has refilled enough to cover another 100 bytes for free.
        let delay2 = bucket.take(100_000_000, 100);
        assert!(
            delay2 < 1_000_000,
            "expected ~0ns delay once refilled after waiting out the prior debt, got {delay2}"
        );
    }

    #[test]
    fn window_controller_starts_at_min_target() {
        let ctl = WindowController::new();
        assert_eq!(ctl.target(), config::MIN_TARGET);
    }

    #[test]
    fn window_controller_slow_start_doubles_while_low_delay_and_utilized() {
        let mut ctl = WindowController::new();
        let low_delay = Duration::from_millis(1);

        // A fresh controller is in slow-start: each utilized low-delay step
        // DOUBLES the target (256K → 512K → 1M → 2M → 4M) until it clamps at
        // MAX_TARGET (== 4 MiB).
        let mut expected = config::MIN_TARGET;
        while expected < config::MAX_TARGET {
            ctl.step(low_delay, true);
            expected = (expected * 2).min(config::MAX_TARGET);
            assert_eq!(
                ctl.target(),
                expected,
                "slow-start should double the target each utilized low-delay step"
            );
        }
        // Once at MAX_TARGET a further ×2 just clamps back to MAX_TARGET.
        ctl.step(low_delay, true);
        assert_eq!(
            ctl.target(),
            config::MAX_TARGET,
            "a ×2 that would exceed MAX_TARGET must clamp, not overshoot"
        );
    }

    #[test]
    fn window_controller_post_congestion_growth_is_additive() {
        let mut ctl = WindowController::new();
        let low_delay = Duration::from_millis(1);
        let high_delay = Duration::from_millis(50);

        // Grow in slow-start, then a congestion event backs off AND exits
        // slow-start.
        ctl.step(low_delay, true); // 256K → 512K (slow-start double)
        assert_eq!(ctl.target(), 2 * config::MIN_TARGET);
        ctl.step(high_delay, true); // back off ×0.85, in_slow_start = false
        let after_backoff = ctl.target();
        assert_eq!(
            after_backoff,
            (2 * config::MIN_TARGET * config::TARGET_BACKOFF_NUM / config::TARGET_BACKOFF_DEN)
                .clamp(config::MIN_TARGET, config::MAX_TARGET)
        );

        // Now that slow-start is over, low-delay utilized growth is ADDITIVE
        // (+TARGET_GROW_STEP), not another double.
        ctl.step(low_delay, true);
        assert_eq!(
            ctl.target(),
            (after_backoff + config::TARGET_GROW_STEP).min(config::MAX_TARGET),
            "after a congestion event, growth must be additive (+grow-step), not ×2"
        );
    }

    #[test]
    fn window_controller_growth_clamps_at_max_target_without_overflow() {
        let mut ctl = WindowController::new();
        let low_delay = Duration::from_millis(1);

        // Many more steps than needed to reach MAX_TARGET from MIN_TARGET.
        let steps = (config::MAX_TARGET / config::TARGET_GROW_STEP) + 100;
        for _ in 0..steps {
            ctl.step(low_delay, true);
        }

        assert_eq!(
            ctl.target(),
            config::MAX_TARGET,
            "target must clamp at MAX_TARGET and never overflow past it"
        );
    }

    #[test]
    fn window_controller_idle_low_delay_does_not_grow() {
        let mut ctl = WindowController::new();
        let low_delay = Duration::from_millis(1);

        ctl.step(low_delay, false);
        assert_eq!(
            ctl.target(),
            config::MIN_TARGET,
            "an idle (non-utilized) low-delay step must hold, not grow"
        );

        ctl.step(low_delay, false);
        assert_eq!(
            ctl.target(),
            config::MIN_TARGET,
            "repeated idle low-delay steps must still hold"
        );
    }

    #[test]
    fn window_controller_high_delay_backs_off_multiplicatively() {
        let mut ctl = WindowController::new();
        let low_delay = Duration::from_millis(1);
        let high_delay = Duration::from_millis(50);

        // Grow a bit first so the backoff has room to show a real decrease.
        for _ in 0..10 {
            ctl.step(low_delay, true);
        }
        let grown = ctl.target();
        assert!(grown > config::MIN_TARGET);

        ctl.step(high_delay, true);
        let expected = (grown * config::TARGET_BACKOFF_NUM / config::TARGET_BACKOFF_DEN)
            .max(config::MIN_TARGET);
        assert_eq!(
            ctl.target(),
            expected,
            "a high-delay step should multiply target by TARGET_BACKOFF_NUM/DEN"
        );

        // utilized=false during high delay must still back off (backoff isn't
        // gated on utilization the way growth is).
        let before = ctl.target();
        ctl.step(high_delay, false);
        let expected2 = (before * config::TARGET_BACKOFF_NUM / config::TARGET_BACKOFF_DEN)
            .max(config::MIN_TARGET);
        assert_eq!(ctl.target(), expected2);
    }

    #[test]
    fn window_controller_high_delay_backoff_floors_at_min_target() {
        let mut ctl = WindowController::new();
        let high_delay = Duration::from_millis(50);

        // Already at MIN_TARGET: repeated backoff must never go below it.
        for _ in 0..20 {
            ctl.step(high_delay, true);
            assert!(
                ctl.target() >= config::MIN_TARGET,
                "target must never drop below MIN_TARGET"
            );
        }
        assert_eq!(ctl.target(), config::MIN_TARGET);
    }

    #[test]
    fn window_controller_mid_range_delay_holds() {
        let mut ctl = WindowController::new();
        let low_delay = Duration::from_millis(1);
        let mid_delay = Duration::from_millis(10); // between LOW (5ms) and HIGH (25ms)

        // Grow a bit so we're off MIN_TARGET, to distinguish "hold" from
        // "floored at MIN anyway".
        for _ in 0..5 {
            ctl.step(low_delay, true);
        }
        let before = ctl.target();

        ctl.step(mid_delay, true);
        assert_eq!(
            ctl.target(),
            before,
            "delay strictly between LOW and HIGH must hold, neither grow nor back off"
        );

        ctl.step(mid_delay, false);
        assert_eq!(
            ctl.target(),
            before,
            "mid-range delay holds regardless of utilization"
        );
    }

    #[test]
    fn drive_flow_control_grows_target_and_sets_pacing_from_target_over_rtt() {
        use super::super::config::{MIN_TARGET, PACING_DEFAULT_RATE};

        let rtt = StdMutex::new(RttEstimator::new());
        let controller = StdMutex::new(WindowController::new());
        let paced = AtomicBool::new(false);
        let pacing_rate = AtomicU64::new(PACING_DEFAULT_RATE);

        // No RTT sample yet: pacing stays at the untouched default (the writer
        // must not throttle before it can measure the path), and with the writer
        // never having paced (`paced == false`) the target holds at MIN_TARGET.
        drive_flow_control(&rtt, &controller, &paced, &pacing_rate);
        assert_eq!(pacing_rate.load(Ordering::Relaxed), PACING_DEFAULT_RATE);
        assert_eq!(controller.lock().unwrap().target(), MIN_TARGET);

        // Feed a low-delay 10ms RTT sample and signal the writer pace-throttled
        // since the last tick (`paced == true`): a fresh controller is in
        // slow-start, so the target DOUBLES, and pacing must drop to the finite
        // `target / rtt` value (well under the default cap).
        rtt.lock().unwrap().record(Duration::from_millis(10));
        paced.store(true, Ordering::Relaxed);
        drive_flow_control(&rtt, &controller, &paced, &pacing_rate);

        assert_eq!(
            controller.lock().unwrap().target(),
            2 * MIN_TARGET,
            "one utilized low-delay tick in slow-start should double the target"
        );
        // The paced flag must have been read-and-reset.
        assert!(!paced.load(Ordering::Relaxed));

        let rate = pacing_rate.load(Ordering::Relaxed);
        assert_ne!(
            rate, PACING_DEFAULT_RATE,
            "pacing rate must have been driven off the default cap"
        );
        // target = 2 * MIN_TARGET, rtt = 10ms → rate = target * 100.
        let target = (2 * MIN_TARGET) as u64;
        assert_eq!(
            rate,
            target * 100,
            "rate must equal target_bytes / rtt_seconds (10ms → ×100)"
        );
    }

    #[test]
    fn drive_flow_control_unpaced_tick_does_not_grow() {
        use super::super::config::{MIN_TARGET, PACING_DEFAULT_RATE};

        let rtt = StdMutex::new(RttEstimator::new());
        let controller = StdMutex::new(WindowController::new());
        let paced = AtomicBool::new(false);
        let pacing_rate = AtomicU64::new(PACING_DEFAULT_RATE);

        // A low-delay RTT sample but the writer never pace-throttled: even
        // though pacing is now driven off the default, the target must HOLD —
        // a trickle that never hits the pacing limit is not evidence the link
        // can carry more.
        rtt.lock().unwrap().record(Duration::from_millis(10));
        drive_flow_control(&rtt, &controller, &paced, &pacing_rate);

        assert_eq!(
            controller.lock().unwrap().target(),
            MIN_TARGET,
            "an unpaced (non-utilized) low-delay tick must hold the target"
        );
        assert_ne!(
            pacing_rate.load(Ordering::Relaxed),
            PACING_DEFAULT_RATE,
            "pacing rate is still driven from target/rtt once an RTT sample exists"
        );
    }

    #[test]
    fn drive_flow_control_floors_pacing_rate() {
        use super::super::config::MIN_PACING_RATE;

        let rtt = StdMutex::new(RttEstimator::new());
        let controller = StdMutex::new(WindowController::new());
        let paced = AtomicBool::new(false);
        let pacing_rate = AtomicU64::new(0);

        // A huge RTT over the floor-level (MIN_TARGET) target would compute a
        // sub-floor rate; the clamp must hold it at MIN_PACING_RATE so the
        // writer never stalls to ~0.
        rtt.lock().unwrap().record(Duration::from_secs(100));
        drive_flow_control(&rtt, &controller, &paced, &pacing_rate);

        assert_eq!(
            pacing_rate.load(Ordering::Relaxed),
            MIN_PACING_RATE,
            "a tiny target over a huge RTT must floor at MIN_PACING_RATE, not stall"
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
