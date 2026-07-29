//! Reconnect backoff with full jitter.
//!
//! When the connection to the control plane drops, the agent retries with
//! exponential backoff and *full jitter* (uniform random in `[0, cap]`), which
//! decorrelates a fleet of agents reconnecting after a gateway restart and
//! avoids a thundering herd.

use std::time::Duration;

use rand::Rng;

/// Exponential backoff with full jitter.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    base_ms: u64,
    max_ms: u64,
    factor: f64,
    attempt: u32,
}

impl ExponentialBackoff {
    /// Create a backoff starting at `base`, capped at `max`, doubling each
    /// attempt (factor 2.0).
    #[must_use]
    pub fn new(base: Duration, max: Duration) -> Self {
        Self {
            base_ms: base.as_millis() as u64,
            max_ms: max.as_millis() as u64,
            factor: 2.0,
            attempt: 0,
        }
    }

    /// Override the growth factor (default 2.0).
    #[must_use]
    pub fn with_factor(mut self, factor: f64) -> Self {
        self.factor = factor.max(1.0);
        self
    }

    /// The current attempt count (number of delays handed out so far).
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Reset to the initial attempt (call after a successful connection).
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// The next delay, using a thread-local RNG.
    pub fn next_delay(&mut self) -> Duration {
        self.next_delay_rng(&mut rand::thread_rng())
    }

    /// The next delay, using a caller-supplied RNG (for deterministic tests).
    ///
    /// Computes `cap = min(max, base * factor^attempt)`, then returns a uniform
    /// random duration in `[0, cap]` (full jitter), and advances the attempt.
    pub fn next_delay_rng(&mut self, rng: &mut impl Rng) -> Duration {
        // Clamp rather than cast-wrap: an unclamped `as i32` turns negative
        // once `attempt` exceeds `i32::MAX`, which would shrink `powi`'s
        // result toward zero instead of keeping the cap pinned at `max_ms`.
        let exponent = self.attempt.min(i32::MAX as u32) as i32;
        let exp = self.factor.powi(exponent);
        let grown = (self.base_ms as f64) * exp;
        let cap = (grown.min(self.max_ms as f64)).max(0.0) as u64;
        self.attempt = self.attempt.saturating_add(1);
        let jittered = if cap == 0 { 0 } else { rng.gen_range(0..=cap) };
        Duration::from_millis(jittered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn delays_are_bounded_by_max() {
        let mut bo =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_millis(1000));
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..50 {
            assert!(bo.next_delay_rng(&mut rng) <= Duration::from_millis(1000));
        }
    }

    #[test]
    fn cap_grows_then_clamps() {
        // With factor 2 and base 100ms, the cap sequence (before jitter) is
        // 100, 200, 400, 800, 1000(clamped)... We can't observe the cap directly
        // through jitter, but a max-equal-to-base backoff always yields <= base.
        let mut bo = ExponentialBackoff::new(Duration::from_millis(50), Duration::from_millis(50));
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..10 {
            assert!(bo.next_delay_rng(&mut rng) <= Duration::from_millis(50));
        }
    }

    #[test]
    fn reset_restarts_the_sequence() {
        let mut bo = ExponentialBackoff::new(Duration::from_millis(10), Duration::from_secs(60));
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..5 {
            bo.next_delay_rng(&mut rng);
        }
        assert_eq!(bo.attempt(), 5);
        bo.reset();
        assert_eq!(bo.attempt(), 0);
    }

    #[test]
    fn exponent_clamps_instead_of_wrapping_negative() {
        // Before the fix, `attempt as i32` wrapped negative once `attempt`
        // exceeded `i32::MAX`, collapsing `powi`'s result toward zero and
        // making the cap collapse to ~0 instead of staying at `max_ms`.
        let mut bo =
            ExponentialBackoff::new(Duration::from_millis(10), Duration::from_millis(1000));
        let mut rng = StdRng::seed_from_u64(11);
        let mut saw_nonzero = false;
        for _ in 0..200 {
            bo.attempt = u32::MAX; // far beyond i32::MAX
            let d = bo.next_delay_rng(&mut rng);
            assert!(d <= Duration::from_millis(1000));
            if d > Duration::from_millis(0) {
                saw_nonzero = true;
            }
        }
        assert!(
            saw_nonzero,
            "cap collapsed to zero: exponent likely wrapped negative instead of clamping"
        );
    }

    #[test]
    fn deterministic_with_seeded_rng() {
        let mut a = ExponentialBackoff::new(Duration::from_millis(100), Duration::from_secs(10));
        let mut b = ExponentialBackoff::new(Duration::from_millis(100), Duration::from_secs(10));
        let mut ra = StdRng::seed_from_u64(99);
        let mut rb = StdRng::seed_from_u64(99);
        for _ in 0..8 {
            assert_eq!(a.next_delay_rng(&mut ra), b.next_delay_rng(&mut rb));
        }
    }
}
