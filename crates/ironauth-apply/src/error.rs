// SPDX-License-Identifier: MIT OR Apache-2.0

//! CLI error types and the process exit-code contract.
//!
//! Every failure path maps to a stable, documented exit code so the CLI is
//! usable as a CI gate: `0` means success or in-sync, and the nonzero codes below
//! distinguish a configuration drift (the code a gate keys on) from a usage
//! mistake or a transport fault.

use std::fmt;

/// The process exit codes the CLI returns. The values are a stable contract:
/// a CI pipeline keys on [`ExitCode::Drift`] to fail a gate, and on
/// [`ExitCode::Success`] to proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// The command succeeded: a document validated, a plan rendered, an apply
    /// applied or was a no-op, or a drift check found the target in sync.
    Success,
    /// The command ran but the outcome is a failure a CI gate should stop on:
    /// an invalid document, an unresolved reference, a server-reported error, or
    /// a transport/authentication fault.
    Failure,
    /// The target has DRIFTED: for `drift`, the live target differs from the
    /// document; for `apply`, the target changed since the expected revision
    /// (the server's optimistic-concurrency drift). A distinct code so a gate can
    /// tell drift apart from an operational error.
    Drift,
    /// The command line itself was malformed (a missing or unknown argument).
    Usage,
}

impl ExitCode {
    /// The numeric process exit status. `64` for a usage error follows the
    /// `sysexits.h` `EX_USAGE` convention; the rest are small, stable codes.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            ExitCode::Success => 0,
            ExitCode::Failure => 1,
            ExitCode::Drift => 2,
            ExitCode::Usage => 64,
        }
    }

    /// Whether this is the success code (`0`).
    #[must_use]
    pub fn is_success(self) -> bool {
        matches!(self, ExitCode::Success)
    }
}

/// A failure building or driving the management client (the transport half of a
/// `plan`, `apply`, or `drift`). It never carries a secret value: a bad token
/// surfaces as an unauthenticated status from the server, never as the token
/// text.
#[derive(Debug)]
pub enum ClientError {
    /// The configured API base URL could not be parsed into a scheme, host, and
    /// port.
    InvalidUrl(String),
    /// The OS trust store yielded no usable roots, so an https control plane
    /// could not be dialed.
    NoTrustRoots,
    /// The TLS crypto provider rejected the default protocol versions.
    TlsProvider,
    /// The host did not resolve to any address.
    Unresolved(String),
    /// A connection, TLS handshake, or HTTP exchange failed before a complete
    /// response was read.
    Transport(String),
    /// The server's response body exceeded the client's size cap.
    ResponseTooLarge,
    /// The exchange did not complete within the client's total deadline.
    Timeout,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::InvalidUrl(url) => write!(f, "invalid API base URL: {url}"),
            ClientError::NoTrustRoots => {
                f.write_str("no usable root certificates in the OS trust store")
            }
            ClientError::TlsProvider => {
                f.write_str("the TLS crypto provider rejected the default protocol versions")
            }
            ClientError::Unresolved(host) => write!(f, "could not resolve host {host}"),
            ClientError::Transport(detail) => write!(f, "transport error: {detail}"),
            ClientError::ResponseTooLarge => {
                f.write_str("the server response exceeded the size cap")
            }
            ClientError::Timeout => f.write_str("the request timed out"),
        }
    }
}

impl std::error::Error for ClientError {}
