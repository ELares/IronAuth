// SPDX-License-Identifier: MIT OR Apache-2.0

//! The store's error type.
//!
//! The isolation-critical property here is uniformity: a resource that belongs
//! to another tenant, a resource in another environment, and a resource that
//! never existed all surface as [`StoreError::NotFound`]. Nothing a caller can
//! observe distinguishes them, so the persistence layer never becomes an
//! existence oracle.

use std::fmt;

use crate::id::NotInScope;

/// Why a store operation failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// The requested resource is not visible in the current scope. Returned
    /// identically whether the resource is absent, belongs to another tenant,
    /// belongs to another environment, or was presented with a malformed
    /// identifier. This uniformity is the anti-IDOR contract.
    NotFound,
    /// A database or connection error. Never carries tenant data.
    Database(sqlx::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::NotFound => f.write_str("resource not found"),
            StoreError::Database(_) => f.write_str("database error"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::NotFound => None,
            StoreError::Database(source) => Some(source),
        }
    }
}

impl From<sqlx::Error> for StoreError {
    fn from(source: sqlx::Error) -> Self {
        // `RowNotFound` from a scoped query is an in-scope miss: report it as
        // the uniform not-found, not as a database fault.
        match source {
            sqlx::Error::RowNotFound => StoreError::NotFound,
            other => StoreError::Database(other),
        }
    }
}

impl From<NotInScope> for StoreError {
    fn from(_: NotInScope) -> Self {
        StoreError::NotFound
    }
}
