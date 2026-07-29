//! Retry backoff with jitter, shared by both ProofKeel agents.
//!
//! # Why jitter is not optional
//!
//! Without it, every agent that failed during an outage retries on the same
//! schedule, so the moment the control plane recovers the entire fleet arrives
//! at once and knocks it over again. Jitter spreads that load across the whole
//! window and is what keeps recovery monotonic.
//!
//! # Two floors, deliberately
//!
//! This crate merges `proofkeel-agent`'s `pk_transport::ExponentialBackoff`
//! with `proofkeel-sensor`'s `pk_ship::Backoff`. They computed the same
//! ceiling and drew the jitter from different intervals:
//!
//! - [`JitterFloor::Zero`] — uniform over `[0, ceiling]`. *Full jitter* in the
//!   AWS sense, and the strongest possible decorrelation of a reconnecting
//!   fleet. A retry may fire immediately.
//! - [`JitterFloor::Base`] — uniform over `[base, ceiling]`. Retains the
//!   decorrelation but guarantees a minimum spacing, which matters when the
//!   retry costs the *remote* side work it is already struggling to do.
//!
//! Neither dominates, so both are constructible and neither is a default that
//! silently changes the other agent's behaviour.
//!
//! # Server-directed delays win
//!
//! A `Retry-After` header is the server telling the client what it can handle.
//! Ignoring it in favour of a local schedule is how a struggling service gets
//! kept down by its own clients. It is honoured, but capped
//! ([`MAX_SERVER_DELAY`]) and still jittered.

#![forbid(unsafe_code)]

use std::time::Duration;

use rand::Rng;

/// First retry delay used by [`Backoff::default`].
pub const MIN_DELAY: Duration = Duration::from_millis(500);
/// Longest retry delay used by [`Backoff::default`].
pub const MAX_DELAY: Duration = Duration::from_secs(300);
/// Ceiling applied to a server-supplied `Retry-After`.
///
/// A misconfigured or hostile server sending `Retry-After: 86400` must not be
/// able to silence a host for a day; the spool would overflow and evidence
/// would be lost while the agent sat idle believing it was being polite.
pub const MAX_SERVER_DELAY: Duration = Duration::from_secs(900);

/// The lower bound of the interval the jittered delay is drawn from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterFloor {
    /// Draw uniformly from `[0, ceiling]` — full jitter; a retry may fire
    /// immediately.
    Zero,
    /// Draw uniformly from `[base, ceiling]` — guarantees minimum spacing.
    Base,
}

/// Exponential backoff with jitter.
#[derive(Debug, Clone)]
pub struct Backoff {
    base_ms: u64,
    max_ms: u64,
    factor: f64,
    floor: JitterFloor,
    attempt: u32,
}

impl Default for Backoff {
    /// [`Backoff::floored_jitter`] over [`MIN_DELAY`]..=[`MAX_DELAY`].
    fn default() -> Self {
        Self::floored_jitter(MIN_DELAY, MAX_DELAY)
    }
}

impl Backoff {
    /// Backoff drawing from `[0, ceiling]` (full jitter), starting at `base`
    /// and capped at `max`, doubling each attempt.
    #[must_use]
    pub fn full_jitter(base: Duration, max: Duration) -> Self {
        Self::build(base, max, JitterFloor::Zero)
    }

    /// Backoff drawing from `[min, ceiling]`, starting at `min` and capped at
    /// `max`, doubling each attempt.
    #[must_use]
    pub fn floored_jitter(min: Duration, max: Duration) -> Self {
        Self::build(min, max, JitterFloor::Base)
    }

    fn build(base: Duration, max: Duration, floor: JitterFloor) -> Self {
        Self {
            base_ms: u64::try_from(base.as_millis()).unwrap_or(u64::MAX),
            max_ms: u64::try_from(max.as_millis()).unwrap_or(u64::MAX),
            factor: 2.0,
            floor,
            attempt: 0,
        }
    }

    /// Override the growth factor (default 2.0). Values below 1.0 are clamped
    /// to 1.0, which would otherwise shrink the ceiling on every attempt.
    #[must_use]
    pub fn with_factor(mut self, factor: f64) -> Self {
        self.factor = factor.max(1.0);
        self
    }

    /// Which interval jittered delays are drawn from.
    #[must_use]
    pub const fn jitter_floor(&self) -> JitterFloor {
        self.floor
    }

    /// Consecutive failures so far (delays handed out).
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Forget the failure history after a success.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// The deterministic ceiling for the next delay, before jitter.
    ///
    /// `min(max, base * factor^attempt)`, additionally floored at `base` when
    /// the floor is [`JitterFloor::Base`].
    #[must_use]
    pub fn ceiling(&self) -> Duration {
        // Clamp rather than cast-wrap: an unclamped `as i32` turns negative
        // once `attempt` exceeds `i32::MAX`, which would shrink `powi`'s
        // result toward zero instead of keeping the cap pinned at `max_ms`.
        let exponent = i32::try_from(self.attempt).unwrap_or(i32::MAX);
        let grown = (self.base_ms as f64) * self.factor.powi(exponent);
        let capped = grown.min(self.max_ms as f64).max(0.0) as u64;
        let ms = match self.floor {
            JitterFloor::Zero => capped,
            JitterFloor::Base => capped.max(self.base_ms),
        };
        Duration::from_millis(ms)
    }

    /// The floor of the jitter interval.
    const fn floor_ms(&self) -> u64 {
        match self.floor {
            JitterFloor::Zero => 0,
            JitterFloor::Base => self.base_ms,
        }
    }

    /// Record a failure and return how long to wait, using a thread-local RNG.
    pub fn next_delay(&mut self) -> Duration {
        self.next_delay_rng(&mut rand::thread_rng())
    }

    /// Record a failure and return how long to wait, using a caller-supplied
    /// RNG (for deterministic tests).
    pub fn next_delay_rng(&mut self, rng: &mut impl Rng) -> Duration {
        let ceiling = self.ceiling();
        self.attempt = self.attempt.saturating_add(1);
        jitter(ceiling, Duration::from_millis(self.floor_ms()), rng)
    }

    /// Record a failure where the server named its own delay.
    ///
    /// The server's value is honoured but capped at [`MAX_SERVER_DELAY`], and
    /// jitter is still applied: a fleet told "come back in 60s" would otherwise
    /// return in lockstep.
    pub fn next_delay_after(&mut self, server: Option<Duration>) -> Duration {
        self.next_delay_after_rng(server, &mut rand::thread_rng())
    }

    /// [`Backoff::next_delay_after`] with a caller-supplied RNG.
    pub fn next_delay_after_rng(
        &mut self,
        server: Option<Duration>,
        rng: &mut impl Rng,
    ) -> Duration {
        match server {
            Some(delay) => {
                self.attempt = self.attempt.saturating_add(1);
                let floor = Duration::from_millis(self.floor_ms());
                jitter(delay.min(MAX_SERVER_DELAY).max(floor), floor, rng)
            }
            None => self.next_delay_rng(rng),
        }
    }
}

/// Draw uniformly from `[floor, ceiling]`.
fn jitter(ceiling: Duration, floor: Duration, rng: &mut impl Rng) -> Duration {
    let ceiling_ms = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
    let floor_ms = u64::try_from(floor.as_millis())
        .unwrap_or(u64::MAX)
        .min(ceiling_ms);
    if ceiling_ms <= floor_ms {
        return Duration::from_millis(ceiling_ms);
    }
    Duration::from_millis(rng.gen_range(floor_ms..=ceiling_ms))
}

/// Parse a `Retry-After` header value.
///
/// Only the delta-seconds form is honoured. The HTTP-date form would require
/// trusting the local clock to agree with the server's, and a host with a
/// skewed clock — exactly the host most likely to be having problems — would
/// compute a delay of hours or of zero.
#[must_use]
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    let secs: u64 = value.trim().parse().ok()?;
    Some(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // ---- inherited from proofkeel-agent's pk_transport::backoff ----------

    #[test]
    fn delays_are_bounded_by_max() {
        let mut bo = Backoff::full_jitter(Duration::from_millis(100), Duration::from_millis(1000));
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
        let mut bo = Backoff::full_jitter(Duration::from_millis(50), Duration::from_millis(50));
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..10 {
            assert!(bo.next_delay_rng(&mut rng) <= Duration::from_millis(50));
        }
    }

    #[test]
    fn reset_restarts_the_sequence() {
        let mut bo = Backoff::full_jitter(Duration::from_millis(10), Duration::from_secs(60));
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
        let mut bo = Backoff::full_jitter(Duration::from_millis(10), Duration::from_millis(1000));
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
        let mut a = Backoff::full_jitter(Duration::from_millis(100), Duration::from_secs(10));
        let mut b = Backoff::full_jitter(Duration::from_millis(100), Duration::from_secs(10));
        let mut ra = StdRng::seed_from_u64(99);
        let mut rb = StdRng::seed_from_u64(99);
        for _ in 0..8 {
            assert_eq!(a.next_delay_rng(&mut ra), b.next_delay_rng(&mut rb));
        }
    }

    // ---- inherited from proofkeel-sensor's pk_ship::backoff --------------

    #[test]
    fn the_ceiling_doubles_and_then_stops() {
        let mut b = Backoff::floored_jitter(Duration::from_secs(1), Duration::from_secs(16));
        let mut ceilings = Vec::new();
        for _ in 0..7 {
            ceilings.push(b.ceiling().as_secs());
            b.next_delay();
        }
        assert_eq!(ceilings, vec![1, 2, 4, 8, 16, 16, 16]);
    }

    #[test]
    fn delays_are_jittered_within_the_ceiling() {
        // The property that stops a recovering server being knocked over by its
        // own fleet arriving in lockstep.
        let mut b = Backoff::floored_jitter(Duration::from_millis(10), Duration::from_secs(10));
        for _ in 0..5 {
            b.next_delay();
        }
        let ceiling = b.ceiling();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..50 {
            let mut probe = b.clone();
            let delay = probe.next_delay();
            assert!(delay <= ceiling, "{delay:?} exceeds {ceiling:?}");
            seen.insert(delay.as_millis());
        }
        assert!(seen.len() > 5, "delays should vary, saw {}", seen.len());
    }

    #[test]
    fn a_success_resets_the_schedule() {
        let mut b = Backoff::default();
        for _ in 0..8 {
            b.next_delay();
        }
        assert!(b.attempt() > 0);
        b.reset();
        assert_eq!(b.attempt(), 0);
        assert_eq!(b.ceiling(), MIN_DELAY);
    }

    #[test]
    fn a_server_directed_delay_is_honoured() {
        let mut b = Backoff::default();
        let delay = b.next_delay_after(Some(Duration::from_secs(30)));
        assert!(delay <= Duration::from_secs(30));
        assert!(delay >= MIN_DELAY);
    }

    #[test]
    fn an_absurd_server_delay_is_capped() {
        // A hostile or misconfigured server must not be able to silence a host
        // for a day while its spool overflows.
        let mut b = Backoff::default();
        let delay = b.next_delay_after(Some(Duration::from_secs(86_400)));
        assert!(delay <= MAX_SERVER_DELAY);
    }

    #[test]
    fn retry_after_parses_only_delta_seconds() {
        assert_eq!(parse_retry_after("120"), Some(Duration::from_secs(120)));
        assert_eq!(parse_retry_after("  5 "), Some(Duration::from_secs(5)));
        // The HTTP-date form is deliberately ignored: honouring it would mean
        // trusting a possibly-skewed local clock.
        assert_eq!(parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
        assert_eq!(parse_retry_after(""), None);
        assert_eq!(parse_retry_after("-5"), None);
    }

    #[test]
    fn the_attempt_counter_cannot_overflow() {
        let mut b = Backoff {
            attempt: u32::MAX,
            ..Backoff::default()
        };
        b.next_delay();
        assert_eq!(b.attempt(), u32::MAX);
    }

    // ---- properties of the merge itself ---------------------------------

    #[test]
    fn the_two_floors_differ_only_in_the_lower_bound() {
        // Same ceiling schedule; only the interval the draw comes from differs.
        let zero = Backoff::full_jitter(Duration::from_secs(1), Duration::from_secs(16));
        let base = Backoff::floored_jitter(Duration::from_secs(1), Duration::from_secs(16));
        assert_eq!(zero.ceiling(), base.ceiling());
        assert_eq!(zero.jitter_floor(), JitterFloor::Zero);
        assert_eq!(base.jitter_floor(), JitterFloor::Base);

        // Full jitter must be able to produce a delay below the base; a floored
        // backoff must never do so.
        let mut rng = StdRng::seed_from_u64(5);
        let mut saw_below_base = false;
        for _ in 0..200 {
            let mut z = zero.clone();
            if z.next_delay_rng(&mut rng) < Duration::from_secs(1) {
                saw_below_base = true;
            }
            let mut b = base.clone();
            assert!(b.next_delay_rng(&mut rng) >= Duration::from_secs(1));
        }
        assert!(saw_below_base, "full jitter never dipped below base");
    }

    #[test]
    fn a_sub_unit_factor_is_clamped_so_the_ceiling_cannot_shrink() {
        let b =
            Backoff::full_jitter(Duration::from_secs(1), Duration::from_secs(60)).with_factor(0.5);
        let mut b2 = b.clone();
        let first = b2.ceiling();
        b2.next_delay();
        assert!(b2.ceiling() >= first);
    }
}
