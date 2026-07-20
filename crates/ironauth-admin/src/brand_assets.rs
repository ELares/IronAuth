// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment brand asset management (issue #86, PR 3).
//!
//! The management surface for a brand's raster chrome: upload (create or overwrite) and delete a
//! logo or a favicon. A brand asset is a DATA-plane scoped resource (`brand_assets`), reachable by
//! the operator OR by a management key scoped to exactly this environment, exactly like the locale
//! bundles and organizations.
//!
//! Every upload is validated on the ACTUAL BYTES, never the client's declared header (FORK B,
//! raster only):
//!
//! - the media type is decided by a MAGIC-BYTE sniff of the bytes: PNG, WebP, or JPEG for a logo
//!   (a favicon additionally accepts ICO). SVG and everything else are REJECTED with a loud 400,
//!   so a stored asset can never be active markup. The SNIFFED type is stored, never the client's;
//! - the payload is size capped (a logo at 256 KiB, a favicon at 64 KiB); an oversize body is a
//!   loud 400 and nothing is stored;
//! - the owning brand must exist (a clean 404 otherwise).
//!
//! The write is SUDO-GATED (`crate::sudo::require_fresh_privilege`) right after scope resolution,
//! exactly like the locale writes and organizations / connectors: a brand asset is the visible
//! chrome of the auth pages (a social-engineering surface), so it demands fresh privilege. The
//! gate is inert when sudo mode is off. Every write is audited against the owning brand's id.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{BrandAssetKind, BrandId, CorrelationId, NewBrandAsset, Scope};
use sha2::{Digest as _, Sha256};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::BrandAssetView;

/// The per-kind upload size caps (issue #86, PR 3). A logo is the larger page chrome; a favicon
/// is a small icon. Both sit well under the store's hard 262144-byte size CHECK.
const LOGO_MAX_BYTES: usize = 256 * 1024;
const FAVICON_MAX_BYTES: usize = 64 * 1024;

/// Resolve and authorize the `(tenant, environment)` scope from the path (issue #86). The operator
/// passes; a management key must be scoped to exactly this environment (otherwise the LOUD
/// wrong-scope error). A malformed tenant or environment id is the uniform not-found.
fn resolve_scope(
    state: &AdminState,
    principal: &Principal,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(Scope, ironauth_store::ActorRef), ApiError> {
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(tenant_id)?;
    let environment = state
        .store()
        .management()
        .environments(tenant)
        .parse_id(environment_id)?;
    let actor = principal.require_environment(tenant, environment)?;
    Ok((Scope::new(tenant, environment), actor))
}

/// The per-kind size cap.
fn size_cap(kind: BrandAssetKind) -> usize {
    match kind {
        BrandAssetKind::Logo => LOGO_MAX_BYTES,
        BrandAssetKind::Favicon => FAVICON_MAX_BYTES,
    }
}

/// Sniff the media type from the ACTUAL leading bytes (issue #86, PR 3), never the client's
/// declared header. Returns the SNIFFED `Content-Type` for a raster this kind accepts, or [`None`]
/// for SVG / anything else (which is rejected). Raster only (FORK B): PNG, WebP, and JPEG for both
/// kinds; ICO additionally for a favicon. A handful of byte-prefix checks owns zero supply chain.
fn sniff(bytes: &[u8], kind: BrandAssetKind) -> Option<&'static str> {
    // PNG: the 8-byte signature.
    if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png");
    }
    // JPEG: the SOI marker plus the start of an application segment.
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    // WebP: a RIFF container tagged WEBP (bytes 0..4 = "RIFF", 8..12 = "WEBP").
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    // ICO: the icon-directory header, accepted for a favicon ONLY.
    if kind == BrandAssetKind::Favicon && bytes.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        return Some("image/x-icon");
    }
    // SVG and everything else is refused: a stored asset is never active markup.
    None
}

/// The lowercase hex sha256 of `bytes` (the content reference the serve path turns into an `ETag`
/// and the snapshot carries by reference).
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The shared upload path for a logo or favicon (issue #86, PR 3): resolve + sudo-gate + size-cap
/// + magic-byte sniff + brand-existence, then store the sniffed type and the bytes, audited.
async fn upload_asset(
    state: &AdminState,
    principal: &Principal,
    tenant_id: &str,
    environment_id: &str,
    slug: &str,
    kind: BrandAssetKind,
    body: &Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(state, principal, tenant_id, environment_id)?;
    // A brand asset is the visible chrome of the auth pages (a social-engineering surface), so it
    // demands fresh privilege exactly like the locale writes and organizations / connectors.
    crate::sudo::require_fresh_privilege(state, scope, actor).await?;

    if body.is_empty() {
        return Err(ApiError::BadRequest("the asset body is empty".to_owned()));
    }
    let cap = size_cap(kind);
    if body.len() > cap {
        return Err(ApiError::BadRequest(format!(
            "the {} is {} bytes, over the {cap} byte limit",
            kind.as_str(),
            body.len()
        )));
    }
    // The media type is decided by a MAGIC-BYTE sniff of the actual bytes, never the client's
    // declared header. SVG and everything else are rejected.
    let content_type = sniff(body, kind).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "the {} is not an accepted raster image (png, webp, jpeg{}); svg and other formats \
             are refused",
            kind.as_str(),
            if kind == BrandAssetKind::Favicon {
                ", ico"
            } else {
                ""
            }
        ))
    })?;

    // The brand must exist (a clean 404 rather than a foreign-key error). The write is audited
    // against the owning brand's id.
    let brand = state
        .store()
        .scoped(scope)
        .brands()
        .get(slug)
        .await?
        .ok_or(ApiError::NotFound)?;
    let brand_id = BrandId::parse_in_scope(&brand.id, &scope).map_err(|_| ApiError::NotFound)?;

    let sha256 = sha256_hex(body);
    // The size is within the cap (checked above), so it fits an i32.
    let size_bytes = i32::try_from(body.len()).map_err(|_| ApiError::Internal)?;
    let created_at_micros = state.now_unix_micros();
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .brand_assets()
        .set(
            state.env(),
            &brand_id,
            created_at_micros,
            NewBrandAsset {
                brand_slug: slug,
                kind,
                content_type,
                bytes: body,
                sha256: &sha256,
                size_bytes,
            },
        )
        .await?;

    let view = BrandAssetView {
        slug: slug.to_owned(),
        kind: kind.as_str().to_owned(),
        content_type: content_type.to_owned(),
        sha256,
        size_bytes: i64::try_from(body.len()).unwrap_or(i64::MAX),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// The shared delete path for a logo or favicon (issue #86, PR 3): resolve + sudo-gate + brand
/// existence, then delete the asset, audited. An absent asset is a uniform 404.
async fn delete_asset(
    state: &AdminState,
    principal: &Principal,
    tenant_id: &str,
    environment_id: &str,
    slug: &str,
    kind: BrandAssetKind,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(state, principal, tenant_id, environment_id)?;
    crate::sudo::require_fresh_privilege(state, scope, actor).await?;
    let brand = state
        .store()
        .scoped(scope)
        .brands()
        .get(slug)
        .await?
        .ok_or(ApiError::NotFound)?;
    let brand_id = BrandId::parse_in_scope(&brand.id, &scope).map_err(|_| ApiError::NotFound)?;
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .brand_assets()
        .delete(state.env(), &brand_id, slug, kind)
        .await?;
    Ok(no_content())
}

/// Upload (create or overwrite) a brand's logo.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}/logo",
    operation_id = "setBrandLogo",
    tag = "brand-assets",
    request_body(content = Vec<u8>, description = "The raw raster bytes (png, webp, or jpeg)", content_type = "application/octet-stream"),
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("slug" = String, Path, description = "The brand slug")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Stored", body = BrandAssetView),
        (status = 400, description = "Not an accepted raster, or over the size cap", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or sudo required", body = ErrorBody),
        (status = 404, description = "Brand not found", body = ErrorBody)
    )
)]
pub async fn set_brand_logo(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, slug)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    upload_asset(
        &state,
        &principal,
        &tenant_id,
        &environment_id,
        &slug,
        BrandAssetKind::Logo,
        &body,
    )
    .await
}

/// Delete a brand's logo.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}/logo",
    operation_id = "deleteBrandLogo",
    tag = "brand-assets",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("slug" = String, Path, description = "The brand slug")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or sudo required", body = ErrorBody),
        (status = 404, description = "Brand or asset not found", body = ErrorBody)
    )
)]
pub async fn delete_brand_logo(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, slug)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    delete_asset(
        &state,
        &principal,
        &tenant_id,
        &environment_id,
        &slug,
        BrandAssetKind::Logo,
    )
    .await
}

/// Upload (create or overwrite) a brand's favicon.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}/favicon",
    operation_id = "setBrandFavicon",
    tag = "brand-assets",
    request_body(content = Vec<u8>, description = "The raw raster bytes (png, webp, jpeg, or ico)", content_type = "application/octet-stream"),
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("slug" = String, Path, description = "The brand slug")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Stored", body = BrandAssetView),
        (status = 400, description = "Not an accepted raster, or over the size cap", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or sudo required", body = ErrorBody),
        (status = 404, description = "Brand not found", body = ErrorBody)
    )
)]
pub async fn set_brand_favicon(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, slug)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    upload_asset(
        &state,
        &principal,
        &tenant_id,
        &environment_id,
        &slug,
        BrandAssetKind::Favicon,
        &body,
    )
    .await
}

/// Delete a brand's favicon.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}/favicon",
    operation_id = "deleteBrandFavicon",
    tag = "brand-assets",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("slug" = String, Path, description = "The brand slug")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or sudo required", body = ErrorBody),
        (status = 404, description = "Brand or asset not found", body = ErrorBody)
    )
)]
pub async fn delete_brand_favicon(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, slug)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    delete_asset(
        &state,
        &principal,
        &tenant_id,
        &environment_id,
        &slug,
        BrandAssetKind::Favicon,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{sha256_hex, sniff};
    use ironauth_store::BrandAssetKind;

    #[test]
    fn sniff_accepts_the_raster_set_and_refuses_svg_and_others() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00];
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00];
        let mut webp = Vec::from(*b"RIFF");
        webp.extend_from_slice(&[0, 0, 0, 0]);
        webp.extend_from_slice(b"WEBP");
        let ico = [0x00, 0x00, 0x01, 0x00, 0x01];

        // A logo accepts png / webp / jpeg but NOT ico.
        assert_eq!(sniff(&png, BrandAssetKind::Logo), Some("image/png"));
        assert_eq!(sniff(&jpeg, BrandAssetKind::Logo), Some("image/jpeg"));
        assert_eq!(sniff(&webp, BrandAssetKind::Logo), Some("image/webp"));
        assert_eq!(sniff(&ico, BrandAssetKind::Logo), None);
        // A favicon additionally accepts ico.
        assert_eq!(sniff(&ico, BrandAssetKind::Favicon), Some("image/x-icon"));

        // SVG (markup) is refused, whatever it claims to be.
        let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>";
        assert_eq!(sniff(svg, BrandAssetKind::Logo), None);
        assert_eq!(sniff(svg, BrandAssetKind::Favicon), None);
        // A leading-whitespace SVG (a classic sniff bypass) is still refused.
        let svg_ws = b"   \n<svg></svg>";
        assert_eq!(sniff(svg_ws, BrandAssetKind::Favicon), None);
        // Plain text / HTML is refused.
        assert_eq!(sniff(b"<!doctype html>", BrandAssetKind::Logo), None);
        assert_eq!(sniff(b"", BrandAssetKind::Logo), None);
    }

    #[test]
    fn sha256_hex_is_lowercase_and_matches_a_known_vector() {
        // The sha256 of the empty string.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
