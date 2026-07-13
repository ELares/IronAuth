// SPDX-License-Identifier: MIT OR Apache-2.0

//! The caller-facing error type.
//!
//! The [`FetchError::Blocked`] variant is deliberately uniform: a rejected
//! scheme choice for the destination, a denied resolved address, a DNS failure,
//! and a rebinding block all collapse into it so the error cannot be used as an
//! oracle for internal network topology (it never reveals whether a host
//! resolved, or to what). The structured reason for a block travels to logs and
//! metrics (see [`crate::observe`]), never into this value. The remaining
//! variants describe conditions that only arise AFTER a connection to an
//! already-validated public destination (a redirect, a size cap, a deadline, a
//! transport failure) or a purely caller-side malformed request, none of which
//! leaks anything about the internal network.

use std::fmt;

/// Why an outbound fetch did not return a response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FetchError {
    /// The destination was refused by the outbound policy. Uniform by design:
    /// it covers a denied resolved address (loopback, private, link-local,
    /// metadata, and every other special-use range), a DNS resolution failure,
    /// and a rebinding block, with no detail that would distinguish them.
    Blocked,
    /// The URL used a scheme the caller is not permitted to reach (plaintext
    /// `http` without the explicit opt-in). Distinct from [`FetchError::Blocked`]
    /// because it is a property of the caller's own URL, not of the network.
    SchemeNotAllowed,
    /// The response was a redirect (a 3xx status carrying a `Location`). It is
    /// surfaced, never followed; the status is echoed because it came from an
    /// already-validated public origin and reveals nothing internal.
    RedirectNotFollowed {
        /// The 3xx status the origin returned.
        status: u16,
    },
    /// The response body exceeded the configured size cap and was aborted
    /// mid-stream.
    ResponseTooLarge {
        /// The byte cap that was exceeded.
        limit: u64,
    },
    /// The request exceeded the configured total deadline and was aborted.
    Timeout,
    /// The connection to the validated destination, or the HTTP exchange over
    /// it, failed at the transport or protocol layer.
    Upstream,
    /// The request could not be formed: a malformed URL, an invalid header, or
    /// an unsupported scheme. A caller-side bug, safe to describe.
    InvalidRequest(String),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::Blocked => f.write_str("outbound request blocked by destination policy"),
            FetchError::SchemeNotAllowed => {
                f.write_str("plaintext http is not permitted for this request")
            }
            FetchError::RedirectNotFollowed { status } => {
                write!(f, "redirect response ({status}) not followed")
            }
            FetchError::ResponseTooLarge { limit } => {
                write!(f, "response exceeded the {limit}-byte size cap")
            }
            FetchError::Timeout => f.write_str("outbound request exceeded its deadline"),
            FetchError::Upstream => f.write_str("outbound connection or exchange failed"),
            FetchError::InvalidRequest(why) => write!(f, "invalid outbound request: {why}"),
        }
    }
}

impl std::error::Error for FetchError {}
