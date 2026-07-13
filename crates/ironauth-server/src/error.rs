// SPDX-License-Identifier: MIT OR Apache-2.0

//! The server's fatal error type.
//!
//! Every variant is a startup or lifecycle failure the caller reports before
//! exiting. Errors never carry a secret value; a bind failure names the
//! address (operators need it), never a credential.

use std::fmt;
use std::io;

/// Why the server failed to build or run. Always fatal.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServerError {
    /// The configured `server.public_url` is not a usable base URL.
    InvalidPublicUrl {
        /// A short reason; never echoes credentials.
        reason: String,
    },
    /// A listener could not bind its socket (bad address or address in use).
    Bind {
        /// Which plane's address failed (`server.bind` or
        /// `server.management_bind`).
        field: &'static str,
        /// The address string that could not be bound.
        addr: String,
        /// The underlying I/O error.
        source: io::Error,
    },
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::InvalidPublicUrl { reason } => {
                write!(f, "invalid server.public_url: {reason}")
            }
            ServerError::Bind {
                field,
                addr,
                source,
            } => {
                write!(f, "cannot bind {field} '{addr}': {source}")
            }
        }
    }
}

impl std::error::Error for ServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ServerError::Bind { source, .. } => Some(source),
            ServerError::InvalidPublicUrl { .. } => None,
        }
    }
}
