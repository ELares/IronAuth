// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic environment seam for IronAuth.
//!
//! Every read of wall-clock time, monotonic time, or entropy anywhere in the
//! workspace flows through this crate. No other crate may call
//! `SystemTime::now`, `Instant::now`, or an OS random source directly; the
//! rule is enforced by `scripts/invariant-lints.sh` in CI. The seam exists so
//! that protocol logic (token lifetimes, code expiry, rotation schedules,
//! nonce generation) is testable with a manually advanced clock and a
//! deterministic entropy source, and so that environment-dependent behavior
//! stays swappable configuration rather than a baked-in choice.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

/// A source of wall-clock and monotonic time.
///
/// Implementations must be cheap to call and safe to share across threads.
pub trait Clock: Send + Sync {
    /// The current wall-clock time.
    ///
    /// Wall-clock time is for token timestamps and audit records. It may jump
    /// backwards (NTP steps); never use it to measure elapsed time.
    fn now_utc(&self) -> SystemTime;

    /// A monotonic instant for measuring elapsed time.
    ///
    /// Monotonic time never goes backwards. It is for timeouts, rate windows,
    /// and latency measurement, never for timestamps that leave the process.
    fn monotonic(&self) -> Instant;
}

/// A source of cryptographically secure entropy.
pub trait Entropy: Send + Sync {
    /// Fill `buf` with random bytes.
    ///
    /// # Panics
    ///
    /// Implementations backed by the operating system panic if the OS entropy
    /// source fails: in an identity provider, silently degraded randomness is
    /// strictly worse than a crash.
    fn fill_bytes(&self, buf: &mut [u8]);
}

/// The production clock, backed by the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_utc(&self) -> SystemTime {
        SystemTime::now()
    }

    fn monotonic(&self) -> Instant {
        Instant::now()
    }
}

/// The production entropy source, backed by the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill_bytes(&self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("OS entropy source failed; refusing to continue");
    }
}

/// A manually advanced clock for tests.
///
/// Starts at a fixed epoch and only moves when [`ManualClock::advance`] is
/// called, so time-dependent logic can be driven deterministically.
#[derive(Debug)]
pub struct ManualClock {
    /// Monotonic base captured once at construction; offsets are added to it.
    base_instant: Instant,
    /// Wall-clock base for the fabricated timeline.
    base_wall: SystemTime,
    /// Total advancement applied so far.
    offset: Mutex<Duration>,
}

impl ManualClock {
    /// A clock frozen at `start` until advanced.
    #[must_use]
    pub fn new(start: SystemTime) -> Self {
        Self {
            base_instant: Instant::now(),
            base_wall: start,
            offset: Mutex::new(Duration::ZERO),
        }
    }

    /// Move both wall-clock and monotonic time forward by `by`.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned, which only happens after a
    /// panic on another test thread.
    pub fn advance(&self, by: Duration) {
        let mut offset = self.offset.lock().expect("clock lock poisoned");
        *offset += by;
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new(SystemTime::UNIX_EPOCH)
    }
}

impl Clock for ManualClock {
    fn now_utc(&self) -> SystemTime {
        let offset = *self.offset.lock().expect("clock lock poisoned");
        self.base_wall + offset
    }

    fn monotonic(&self) -> Instant {
        let offset = *self.offset.lock().expect("clock lock poisoned");
        self.base_instant + offset
    }
}

/// A deterministic entropy source for tests.
///
/// Produces bytes from a simple counter stream seeded by `seed`. This is not
/// random and must never leave test code; it exists so that identifier and
/// nonce generation can be asserted byte for byte.
#[derive(Debug)]
pub struct FixedEntropy {
    counter: Mutex<u64>,
}

impl FixedEntropy {
    /// A deterministic stream starting from `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            counter: Mutex::new(seed),
        }
    }

    /// The next byte in the stream.
    fn next_byte(counter: &mut u64) -> u8 {
        // SplitMix64 step, truncated to one byte. Deterministic and well
        // distributed, which keeps fabricated identifiers distinct in tests.
        *counter = counter.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *counter;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        u8::try_from((z ^ (z >> 31)) & 0xFF).expect("masked to one byte")
    }
}

impl Entropy for FixedEntropy {
    fn fill_bytes(&self, buf: &mut [u8]) {
        let mut counter = self.counter.lock().expect("entropy lock poisoned");
        for byte in buf {
            *byte = Self::next_byte(&mut counter);
        }
    }
}

/// The bundle of environment capabilities handed to every component.
#[derive(Clone)]
pub struct Env {
    clock: Arc<dyn Clock>,
    entropy: Arc<dyn Entropy>,
}

impl Env {
    /// The production environment: OS clock and OS entropy.
    #[must_use]
    pub fn system() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            entropy: Arc::new(OsEntropy),
        }
    }

    /// A fully deterministic environment for tests.
    ///
    /// Returns the environment together with the [`ManualClock`] handle so the
    /// test can advance time.
    #[must_use]
    pub fn deterministic(start: SystemTime, seed: u64) -> (Self, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(start));
        let env = Self {
            clock: Arc::clone(&clock) as Arc<dyn Clock>,
            entropy: Arc::new(FixedEntropy::new(seed)),
        };
        (env, clock)
    }

    /// An environment from explicit parts, for composing custom test doubles.
    #[must_use]
    pub fn from_parts(clock: Arc<dyn Clock>, entropy: Arc<dyn Entropy>) -> Self {
        Self { clock, entropy }
    }

    /// The clock capability.
    #[must_use]
    pub fn clock(&self) -> &dyn Clock {
        self.clock.as_ref()
    }

    /// The entropy capability.
    #[must_use]
    pub fn entropy(&self) -> &dyn Entropy {
        self.entropy.as_ref()
    }
}

impl std::fmt::Debug for Env {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Env").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_is_frozen_until_advanced() {
        let clock = ManualClock::new(SystemTime::UNIX_EPOCH);
        let first = clock.now_utc();
        let second = clock.now_utc();
        assert_eq!(first, second);
    }

    #[test]
    fn manual_clock_advances_wall_and_monotonic_together() {
        let clock = ManualClock::new(SystemTime::UNIX_EPOCH);
        let wall_before = clock.now_utc();
        let mono_before = clock.monotonic();
        clock.advance(Duration::from_secs(3600));
        assert_eq!(
            clock
                .now_utc()
                .duration_since(wall_before)
                .expect("time moved forward"),
            Duration::from_secs(3600)
        );
        assert_eq!(clock.monotonic() - mono_before, Duration::from_secs(3600));
    }

    #[test]
    fn fixed_entropy_is_deterministic_for_equal_seeds() {
        let a = FixedEntropy::new(42);
        let b = FixedEntropy::new(42);
        let mut buf_a = [0_u8; 32];
        let mut buf_b = [0_u8; 32];
        a.fill_bytes(&mut buf_a);
        b.fill_bytes(&mut buf_b);
        assert_eq!(buf_a, buf_b);
    }

    #[test]
    fn fixed_entropy_streams_differ_across_seeds_and_calls() {
        let a = FixedEntropy::new(1);
        let b = FixedEntropy::new(2);
        let mut buf_a = [0_u8; 32];
        let mut buf_b = [0_u8; 32];
        a.fill_bytes(&mut buf_a);
        b.fill_bytes(&mut buf_b);
        assert_ne!(buf_a, buf_b);

        let mut buf_a2 = [0_u8; 32];
        a.fill_bytes(&mut buf_a2);
        assert_ne!(buf_a, buf_a2);
    }

    #[test]
    fn deterministic_env_wires_clock_and_entropy() {
        let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
        let before = env.clock().now_utc();
        clock.advance(Duration::from_secs(60));
        let after = env.clock().now_utc();
        assert_eq!(
            after.duration_since(before).expect("time moved forward"),
            Duration::from_secs(60)
        );

        let mut buf = [0_u8; 16];
        env.entropy().fill_bytes(&mut buf);
        assert_ne!(buf, [0_u8; 16]);
    }

    #[test]
    fn system_env_produces_entropy() {
        let env = Env::system();
        let mut buf = [0_u8; 16];
        env.entropy().fill_bytes(&mut buf);
        // 16 zero bytes from the OS source would indicate catastrophic failure.
        assert_ne!(buf, [0_u8; 16]);
    }
}
