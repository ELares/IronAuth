// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed redaction for values that must never reach a log line.
//!
//! This extends the philosophy of `ironauth_config`'s `Secret` and
//! `SecretString` from config-time values to runtime values: wrap anything
//! sensitive (a bearer token, an authorization code, a subject identifier) in
//! [`Redacted`] and its `Debug` and `Display` render the shared `[redacted]`
//! placeholder instead of the value. The rule this enforces is structural:
//! logging is `{value:?}` or `{value}` at the call site, so a wrapped value
//! cannot leak by being interpolated, only by an explicit [`Redacted::expose`]
//! that reads as a deliberate exposure in review.

use std::fmt;

use ironauth_config::REDACTED;

/// A value whose contents must never appear in logs, errors, or serialized
/// output. `Debug` and `Display` emit the `[redacted]` placeholder; the value
/// is reachable only through [`Redacted::expose`].
#[derive(Clone, PartialEq, Eq)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Wrap a sensitive value.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// The wrapped value. Every call site is a deliberate exposure point;
    /// never hand the result to logging or error formatting.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Consume the wrapper, yielding the value. A deliberate exposure point.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> From<T> for Redacted<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_never_reveal_the_value() {
        let secret = Redacted::new("bearer-abc123");
        assert_eq!(format!("{secret:?}"), REDACTED);
        assert_eq!(format!("{secret}"), REDACTED);
        assert!(!format!("{secret:?}").contains("abc123"));
        assert_eq!(*secret.expose(), "bearer-abc123");
    }

    #[test]
    fn wraps_arbitrary_types() {
        let secret: Redacted<Vec<u8>> = Redacted::from(vec![1_u8, 2, 3]);
        assert_eq!(format!("{secret:?}"), REDACTED);
        assert_eq!(secret.into_inner(), vec![1, 2, 3]);
    }
}
