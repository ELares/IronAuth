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

/// Canonicalize a `host_pattern` (or a request Host) to the single form the per-domain brand
/// selection keys on (issue #86, PR 3): trim, drop any `:port` suffix (an IPv6 literal keeps its
/// bracketed form, whose port sits after the closing bracket), and lowercase. An empty result
/// yields [`None`] (there is no host to key on).
///
/// This is the SINGLE source of truth for the canonical host key. The store canonicalizes a
/// brand's `host_pattern` through it AT INGEST, so the per-scope unique index on `host_pattern`
/// rejects two brands that would resolve for the same host, and the OIDC selection matcher
/// normalizes the request Host through the SAME function so ingest and match never diverge.
#[must_use]
pub fn canonicalize_host(raw: &str) -> Option<String> {
    let host = raw.trim();
    // For a bracketed IPv6 literal (`[::1]:443`) the port follows the closing bracket; for a
    // regular host the port follows the single colon. Split off the port accordingly.
    let without_port = if let Some(end) = host.strip_prefix('[').and_then(|_| host.find(']')) {
        &host[..=end]
    } else {
        host.split(':').next().unwrap_or(host)
    };
    let normalized = without_port.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

/// A brand to create or overwrite (issue #86). Every rich-text and token field is passed
/// in as an already-validated / already-sanitized serialized JSON string; the store never
/// interprets it. The `is_default` flag marks the one per-environment default brand a
/// scope resolves when nothing more specific is selected. A non-empty `host_pattern` is
/// canonicalized through [`canonicalize_host`] at ingest so the per-scope unique index enforces
/// one brand per host.
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
    /// The per-environment per-DOMAIN selection key (issue #86, PR 3): the normalized Host
    /// this brand is selected for, or [`None`]. Within a scope, no two brands may claim the
    /// same host (a partial unique index enforces it).
    pub host_pattern: Option<&'a str>,
    /// The per-environment per-CLIENT selection key (issue #86, PR 3): the authorize request
    /// `client_id` this brand is selected for, or [`None`]. Within a scope, no two brands may
    /// claim the same client id (a partial unique index enforces it).
    pub client_id: Option<&'a str>,
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
    /// The per-DOMAIN selection key (issue #86, PR 3): the normalized Host this brand is
    /// selected for, or [`None`].
    pub host_pattern: Option<String>,
    /// The per-CLIENT selection key (issue #86, PR 3): the authorize `client_id` this brand
    /// is selected for, or [`None`].
    pub client_id: Option<String>,
}

/// A brand asset kind (issue #86, PR 3): the closed set of per-brand raster chrome. A logo
/// renders as an `<img>` on the flow page; a favicon rides the `<link rel="icon">`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BrandAssetKind {
    /// The brand logo (`<img>`). Accepts PNG, WebP, or JPEG.
    Logo,
    /// The brand favicon (`<link rel="icon">`). Accepts PNG, WebP, JPEG, or ICO.
    Favicon,
}

impl BrandAssetKind {
    /// Every asset kind, in a stable order.
    pub const ALL: [BrandAssetKind; 2] = [BrandAssetKind::Logo, BrandAssetKind::Favicon];

    /// The stable wire key this kind stores under (the `kind` column and the serve path).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            BrandAssetKind::Logo => "logo",
            BrandAssetKind::Favicon => "favicon",
        }
    }

    /// Parse a stored / path kind key back to a kind, or [`None`] for an unknown key.
    #[must_use]
    pub fn parse(key: &str) -> Option<Self> {
        BrandAssetKind::ALL.into_iter().find(|k| k.as_str() == key)
    }
}

/// A brand asset to upload or overwrite (issue #86, PR 3). The `content_type` is the SNIFFED
/// media type (the magic-byte sniff of `bytes`, never the client's declared header), the
/// `sha256` is the lowercase hex digest, and `size_bytes` is the payload length. The bytes are
/// bounded by the store's size CHECK and by the per-kind cap enforced at ingest.
#[derive(Debug, Clone, Copy)]
pub struct NewBrandAsset<'a> {
    /// The brand's per-environment natural key within scope (the brand this asset belongs to).
    pub brand_slug: &'a str,
    /// The asset kind (logo or favicon).
    pub kind: BrandAssetKind,
    /// The SNIFFED media type of the bytes (never the client's declared header).
    pub content_type: &'a str,
    /// The raster payload bytes.
    pub bytes: &'a [u8],
    /// The lowercase hex sha256 digest of the bytes.
    pub sha256: &'a str,
    /// The payload length in bytes.
    pub size_bytes: i32,
}

/// A stored brand asset read back for the serve path (issue #86, PR 3): the sniffed content
/// type, the raster bytes, and the sha256 the serve path turns into a strong `ETag` validator.
#[derive(Debug, Clone)]
pub struct BrandAssetRecord {
    /// The sniffed media type (the server-fixed `Content-Type` the serve path sets).
    pub content_type: String,
    /// The raster payload bytes streamed to the browser.
    pub bytes: Vec<u8>,
    /// The lowercase hex sha256 digest (the strong `ETag` validator).
    pub sha256: String,
}

/// The METADATA of a stored brand asset, WITHOUT the bytes (issue #86, PR 3): the by-reference
/// projection the brand snapshot carries and the render path uses to decide which asset hrefs
/// to thread. The bytes stay in the store and travel on the deferred promotion apply.
#[derive(Debug, Clone)]
pub struct BrandAssetMeta {
    /// The brand this asset belongs to.
    pub brand_slug: String,
    /// The asset kind (logo or favicon).
    pub kind: BrandAssetKind,
    /// The sniffed media type.
    pub content_type: String,
    /// The lowercase hex sha256 digest.
    pub sha256: String,
    /// The payload length in bytes.
    pub size_bytes: i32,
}
