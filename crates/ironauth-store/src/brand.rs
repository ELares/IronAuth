// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment brand store value types (issue #86).
//!
//! The TYPED branding model (the design-token grammar, the allowlist sanitizer, and the
//! rich-text slot types) lives in the pure branding module of the OIDC crate; the store
//! deliberately does NOT depend on it, keeping the store's coupling minimal exactly as it
//! does for federation connectors (whose definition shape lives in `ironauth-connector`).
//! This module carries only the persistence-layer inputs and views the repository reads
//! and writes: the design tokens and the sanitized slots travel as ALREADY-VALIDATED,
//! ALREADY-SANITIZED serialized JSON strings (validated by the branding module at ingest
//! and re-validated on render), stored verbatim as `jsonb`. No field is ever raw HTML or
//! CSS at the store boundary; a slot string is sanitizer output and a token blob is typed
//! scalars.

/// A brand to create or overwrite (issue #86). Every rich-text and token field is passed
/// in as an already-validated / already-sanitized serialized JSON string; the store never
/// interprets it. The `is_default` flag marks the one per-environment default brand a
/// scope resolves when nothing more specific is selected (per-domain / per-client selection
/// is deferred to PR3).
#[derive(Debug, Clone, Copy)]
pub struct NewBrand<'a> {
    /// The stable, human-readable per-environment brand slug (the promotion / diff key).
    pub slug: &'a str,
    /// Whether this is the environment's DEFAULT brand. At most one default per scope
    /// (a partial unique index enforces it).
    pub is_default: bool,
    /// The plain-text product name / wordmark (escaped on render, never markup).
    pub product_name: &'a str,
    /// Whether to show the wordmark header.
    pub show_wordmark: bool,
    /// An optional plain-text brand-token badge (escaped on render), or [`None`].
    pub brand_token: Option<&'a str>,
    /// The serialized TYPED design tokens (a JSON object of validated scalars), stored
    /// verbatim as `jsonb`.
    pub tokens_json: &'a str,
    /// The serialized dark-mode token variants, or [`None`] when dark mode reuses the
    /// neutral built-in block.
    pub tokens_dark_json: Option<&'a str>,
    /// The serialized sanitized rich-text slots (a JSON object of slot key to sanitized
    /// markup string), stored verbatim as `jsonb`.
    pub slots_json: &'a str,
}

/// A stored brand, read back (issue #86). The renderer resolves the typed tokens and
/// re-sanitizes the slots from these strings, so the read record is always safe to render
/// regardless of what the row holds.
#[derive(Debug, Clone)]
pub struct BrandRecord {
    /// The `brd_` brand id.
    pub id: String,
    /// The brand slug (the per-environment natural key).
    pub slug: String,
    /// Whether this is the environment's default brand.
    pub is_default: bool,
    /// The plain-text product name / wordmark.
    pub product_name: String,
    /// Whether to show the wordmark header.
    pub show_wordmark: bool,
    /// The optional plain-text brand-token badge.
    pub brand_token: Option<String>,
    /// The serialized typed design tokens (a JSON object of validated scalars).
    pub tokens_json: String,
    /// The serialized dark-mode token variants, or [`None`].
    pub tokens_dark_json: Option<String>,
    /// The serialized sanitized rich-text slots (a JSON object).
    pub slots_json: String,
}
