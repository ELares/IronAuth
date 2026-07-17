// SPDX-License-Identifier: MIT OR Apache-2.0

//! The federation error taxonomy (issue #75).
//!
//! A federated login can fail for three fundamentally different reasons, and a
//! consumer (the failure-isolation layer, issue #76) must be able to tell them
//! apart to decide whether to retry, circuit-break, or surface a configuration
//! fault. This is the stable, `#[non_exhaustive]` contract issue #76 classifies on.
//!
//! The variants are deliberately COARSE and carry only a non-sensitive, operator
//! facing description (never an upstream token, a secret, or a private address):
//!
//! - [`ConnectorError::Config`]: the connector DEFINITION or claim mapping is wrong
//!   (a malformed URL, a missing required mapping). NOT retryable: the same
//!   definition will fail again until an operator fixes it.
//! - [`ConnectorError::UpstreamProtocol`]: the upstream spoke, but WRONGLY (a bad
//!   ID token, a discovery document whose issuer does not match, a missing
//!   claim). NOT retryable: replaying the exchange yields the same malformed
//!   answer. A verified-token rejection (`alg`/`iss`/`aud`/`exp` failure) maps
//!   here (the JOSE `verify` error, in the federation slice).
//! - [`ConnectorError::UpstreamUnavailable`]: the exchange could not COMPLETE (a
//!   blocked SSRF target, a timeout, a non-2xx, an empty JWKS). Transient: issue
//!   #76 may retry or trip a breaker. Every `ironauth_fetch` `FetchError` maps
//!   here (in the federation slice, which owns the fetch dependency).

use std::fmt;

/// Why a federation operation (discovery, JWKS resolution, the code exchange, or
/// upstream ID-token validation) failed (issue #75).
///
/// `#[non_exhaustive]` so issue #76 can match on it and new variants can be added
/// without a breaking change. Every variant carries a short, non-sensitive
/// description safe to log and surface to an operator.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectorError {
    /// The connector definition or claim mapping is wrong (not retryable).
    Config(String),
    /// The upstream responded, but incorrectly: a malformed or forged ID token, a
    /// discovery document whose issuer does not match the configured one, or a
    /// missing required claim (not retryable).
    UpstreamProtocol(String),
    /// The exchange could not complete: a blocked SSRF target, a timeout, a
    /// non-2xx response, or an empty key set (transient).
    UpstreamUnavailable(String),
}

impl ConnectorError {
    /// The stable, bounded label for metrics and structured logs (never the
    /// message, which may name an operator-supplied value).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            ConnectorError::Config(_) => "config",
            ConnectorError::UpstreamProtocol(_) => "upstream_protocol",
            ConnectorError::UpstreamUnavailable(_) => "upstream_unavailable",
        }
    }

    /// Whether a caller (issue #76) may reasonably RETRY the operation: only an
    /// [`ConnectorError::UpstreamUnavailable`] is transient; a config or protocol
    /// fault reproduces deterministically.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, ConnectorError::UpstreamUnavailable(_))
    }
}

impl fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectorError::Config(message) => {
                write!(f, "connector configuration error: {message}")
            }
            ConnectorError::UpstreamProtocol(message) => {
                write!(f, "upstream protocol error: {message}")
            }
            ConnectorError::UpstreamUnavailable(message) => {
                write!(f, "upstream unavailable: {message}")
            }
        }
    }
}

impl std::error::Error for ConnectorError {}

#[cfg(test)]
mod tests {
    use super::ConnectorError;

    #[test]
    fn only_unavailable_is_retryable() {
        assert!(ConnectorError::UpstreamUnavailable("timeout".to_owned()).is_retryable());
        assert!(!ConnectorError::UpstreamProtocol("bad token".to_owned()).is_retryable());
        assert!(!ConnectorError::Config("bad url".to_owned()).is_retryable());
    }

    #[test]
    fn kind_labels_are_stable_and_bounded() {
        assert_eq!(ConnectorError::Config(String::new()).kind(), "config");
        assert_eq!(
            ConnectorError::UpstreamProtocol(String::new()).kind(),
            "upstream_protocol"
        );
        assert_eq!(
            ConnectorError::UpstreamUnavailable(String::new()).kind(),
            "upstream_unavailable"
        );
    }
}
