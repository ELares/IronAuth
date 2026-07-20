// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment locale bundle store value types (issue #86, PR 2).
//!
//! The pure localization engine (the RFC 4647 lookup resolver and the per-id fallback
//! `localize()` over the compiled message registry) lives in the OIDC crate; the store
//! deliberately does NOT depend on it, keeping the store's coupling minimal exactly as it
//! does for brands and federation connectors. This module carries only the persistence-layer
//! inputs and views the repository reads and writes: the bundle entries travel as an
//! ALREADY-VALIDATED serialized JSON object string (a map of numeric message id string to the
//! plain text render, validated by the admin locales path at ingest so every key is a
//! registered message id and every interpolation placeholder is one the id declares), stored
//! verbatim as `jsonb`. A bundle string is PLAIN TEXT, escaped on render exactly like the
//! default message text; it is never markup at the store boundary.

/// A locale bundle to create or overwrite (issue #86, PR 2). The entries are passed in as an
/// already-validated serialized JSON object string; the store never interprets it. The
/// `is_env_default` flag marks the one per-environment default locale a scope resolves when an
/// end user requests no `ui_locales` the environment can render.
#[derive(Debug, Clone, Copy)]
pub struct NewLocaleBundle<'a> {
    /// The BCP47 language tag (the per-environment natural key, for example `fr` or `fr-CA`).
    pub locale: &'a str,
    /// Whether this is the environment's DEFAULT locale. At most one default per scope (a
    /// partial unique index enforces it).
    pub is_env_default: bool,
    /// The serialized bundle entries (a JSON object of numeric message id string to the plain
    /// text render), stored verbatim as `jsonb`.
    pub entries_json: &'a str,
}

/// A stored locale bundle, read back (issue #86, PR 2). The renderer resolves the plain text
/// per id from these entries and escapes it on render, so the read record is always safe to
/// render regardless of what the row holds.
#[derive(Debug, Clone)]
pub struct LocaleBundleRecord {
    /// The `lcb_` locale bundle id.
    pub id: String,
    /// The BCP47 language tag (the per-environment natural key).
    pub locale: String,
    /// Whether this is the environment's default locale.
    pub is_env_default: bool,
    /// The serialized bundle entries (a JSON object of numeric message id string to plain
    /// text).
    pub entries_json: String,
}
