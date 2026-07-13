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
//! This wrapper does not zero the value on drop: `ring`'s key types already own
//! and protect the live key material, and adding a zeroizing dependency to the
//! crypto core is out of scope for M1. The guarantee here is "never printed",
//! not "scrubbed from memory".

use std::fmt;

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
    use super::Redacted;

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
}
