// SPDX-License-Identifier: MIT OR Apache-2.0

//! A redacting wrapper for secret material.
//!
//! Signing keys and client secrets are the crown jewels of an identity
//! provider: a single leak into a log line, a `Debug` dump, or a serialized
//! config compromises every token the key ever signs. [`Redacted`] wraps such a
//! value so that its `Debug` and `Display` renderings are a fixed placeholder,
//! and it deliberately implements neither `Serialize` nor `Clone` of the inner
//! value through any formatting path. The value is reachable only through the
//! explicit [`Redacted::expose`], so every read of the secret is a visible,
//! greppable call site.
//!
//! IronAuth's configuration layer has its own `SecretString` for config-sourced
//! secrets (`crates/ironauth-config`); this type is the crypto core's local
//! equivalent, kept here so the security core does not take a dependency on the
//! configuration crate (the wrong dependency direction) just to redact bytes.
//!
//! [`Redacted`] itself still does not zero on drop, and cannot: it is generic
//! over `T`, so it has no way to wipe an arbitrary value. Its guarantee remains
//! "never printed". Scrubbing is the job of the concrete types that OWN secret
//! bytes, and each of them now does it on drop through [`wipe`] (issue #187):
//! `ClientSecret` here, `AeadKey` in [`crate::envelope`], the transient Ed25519
//! seed in [`crate::signing_key`], and outside this crate `SecretString` and the
//! day-one key material.
//!
//! `ring`'s internal key storage is NOT zeroizing and is outside our control, so
//! a signing key's live material still resides in memory `ring` owns. What is
//! covered is every secret buffer this workspace allocates itself.

use std::fmt;

/// Best-effort wipe of a buffer that held secret material, so it does not linger
/// in freed heap or on the stack.
///
/// A byte fill the optimizer is discouraged from eliding by a `black_box` read.
/// No `unsafe` and no extra crate, which is what makes it usable in the crypto
/// core: `zeroize` would give a stronger volatile write, and that tradeoff is
/// recorded in the module docs above rather than silently taken.
///
/// BEST EFFORT is meant literally. It cannot reach a copy the allocator already
/// moved (a `Vec` that reallocated as it grew, a value moved between stack
/// slots), so it shortens the window in which a secret sits in readable memory
/// rather than closing it.
pub fn wipe(buf: &mut [u8]) {
    buf.fill(0);
    std::hint::black_box(&*buf);
}

/// A value that must never be printed, logged, or serialized.
///
/// Wrap any secret (a key seed, a PKCS#8 blob, a client secret) so an accidental
/// `{:?}` or `{}` renders a placeholder instead of the bytes. Read the value
/// back only through [`Redacted::expose`].
pub struct Redacted<T>(T);

/// The text rendered wherever a redacted value would otherwise appear.
const PLACEHOLDER: &str = "[redacted]";

impl<T> Redacted<T> {
    /// Wrap a secret value.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Borrow the wrapped secret. Every call site is a deliberate exposure
    /// point; never pass the result to logging or error formatting.
    #[must_use]
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Borrow the wrapped secret mutably, so an owner can wipe it on drop.
    pub(crate) fn expose_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// Consume the wrapper and return the secret. As with [`Redacted::expose`],
    /// the caller owns the consequences of holding the bare value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Redacted({PLACEHOLDER})")
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PLACEHOLDER)
    }
}

impl<T> From<T> for Redacted<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{Redacted, wipe};

    #[test]
    fn debug_and_display_hide_the_value() {
        let secret = Redacted::new(vec![0x13_u8, 0x37, 0x42]);
        assert_eq!(format!("{secret:?}"), "Redacted([redacted])");
        assert_eq!(format!("{secret}"), "[redacted]");
        // The bytes never appear in any rendering.
        assert!(!format!("{secret:?}").contains("13"));
    }

    #[test]
    fn expose_returns_the_value() {
        let secret = Redacted::new(String::from("hunter2"));
        assert_eq!(secret.expose(), "hunter2");
        assert_eq!(secret.into_inner(), "hunter2");
    }

    #[test]
    fn wipe_zeroes_every_byte_and_keeps_the_buffer_length() {
        // Issue #187. Length is asserted alongside the zeroing so the helper cannot
        // satisfy this by truncating: the point is that the bytes the secret
        // OCCUPIED are overwritten, not that the buffer is made to look empty.
        let mut buf = [0xAB_u8; 32];
        wipe(&mut buf);
        assert_eq!(buf.len(), 32);
        assert!(buf.iter().all(|&b| b == 0), "got {buf:?}");
    }
}
