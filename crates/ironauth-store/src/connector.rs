// SPDX-License-Identifier: MIT OR Apache-2.0

//! Federation connector store value types (issue #75, PR A).
//!
//! The connector DEFINITION shape, its strict validation, and the capability
//! matrix live in the pure, I/O-free `ironauth-connector` crate (which the store
//! deliberately does NOT depend on, to keep the store's coupling minimal and the
//! federation data model in one place). This module carries only the
//! persistence-layer inputs and views the [`crate::repository`] `ConnectorRepo` /
//! `ActingConnectorRepo` read and write. The upstream client SECRET is passed in as
//! plaintext to be SEALED by the repository and is NEVER returned by a read (a read
//! record is secret-free); the capability matrix is stored as stable wire values so
//! the store never depends on the connector crate's enums.

use crate::id::ConnectorId;

/// The capability-matrix values to persist, written FROM the connector definition
/// at write time (single source of truth = the definition). `email_verified_trust`
/// is a stable wire string (`untrusted` / `trusted`) the CHECK constraint pins.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorCapabilities<'a> {
    /// Whether the upstream supports refresh tokens.
    pub refresh: bool,
    /// Whether the upstream delivers group memberships.
    pub groups: bool,
    /// Whether the upstream supports logout propagation.
    pub logout_propagation: bool,
    /// How much the upstream's `email_verified` claim is trusted (`untrusted` /
    /// `trusted`); defaults conservatively to `untrusted`.
    pub email_verified_trust: &'a str,
}

/// A connector definition to create or replace (issue #75). The `definition_json`
/// is the SECRET-FREE projection (the upstream client secret is stripped before it
/// reaches the store); `client_secret` is the plaintext the repository seals INLINE
/// under the scope's envelope DEK, never a plaintext column.
#[derive(Debug, Clone, Copy)]
pub struct NewConnector<'a> {
    /// The stable, human-readable per-environment connector slug.
    pub slug: &'a str,
    /// The secret-free connector definition, as a serialized JSON document.
    pub definition_json: &'a str,
    /// The upstream client secret plaintext, sealed by the repository. Never stored
    /// in the clear and never returned by a read.
    pub client_secret: &'a [u8],
    /// The capability matrix, written from the definition.
    pub capabilities: ConnectorCapabilities<'a>,
    /// Whether the connector is active.
    pub enabled: bool,
}

/// A stored connector, read back (issue #75). SECRET-FREE by construction: the
/// sealed client secret is never projected here, so a management read or a config
/// snapshot can never carry it.
#[derive(Debug, Clone)]
pub struct ConnectorRecord {
    /// The `cnr_` connector id.
    pub id: ConnectorId,
    /// The connector slug (the per-environment natural key).
    pub slug: String,
    /// The secret-free connector definition, as a serialized JSON document.
    pub definition_json: String,
    /// The capability matrix as stored.
    pub capabilities: StoredCapabilities,
    /// Whether the connector is active.
    pub enabled: bool,
    /// When the connector was created, in microseconds since the epoch.
    pub created_at_unix_micros: i64,
    /// When the connector was last updated, in microseconds since the epoch.
    pub updated_at_unix_micros: i64,
}

/// The capability matrix as stored, read back for the management capability
/// endpoint. `email_verified_trust` is the stable wire string.
#[derive(Debug, Clone)]
pub struct StoredCapabilities {
    /// Whether the upstream supports refresh tokens.
    pub refresh: bool,
    /// Whether the upstream delivers group memberships.
    pub groups: bool,
    /// Whether the upstream supports logout propagation.
    pub logout_propagation: bool,
    /// How much the upstream's `email_verified` claim is trusted (`untrusted` /
    /// `trusted`).
    pub email_verified_trust: String,
}
