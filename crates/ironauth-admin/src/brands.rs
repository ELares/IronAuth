// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment brand management (issues #86, #475).
//!
//! The management surface for the per-environment branding DEFINITIONS: list, set (create or
//! overwrite), get, and delete a brand keyed on its slug. A brand is a DATA-plane scoped
//! resource (`brands`), reachable by the operator OR by a management key scoped to exactly this
//! environment, exactly like the locale bundles and the signup forms this module mirrors.
//!
//! Issue #475 records why this module exists at all: `brands` shipped with a store-level writer
//! and NO management endpoint, so the only non-store callers of `Brands::set` were tests and a
//! brand could not be created through the public API. The asset endpoints
//! (`.../brands/{slug}/logo`, `.../brands/{slug}/favicon`) both 404 when the brand row is
//! absent, so without this a brand's only birth path would have been a config promotion, which
//! is a strange asymmetry beside locales and signup forms (both of which have had full CRUD
//! since they landed) and which also blocks the promotion asset path: an operator must be able
//! to create the target brand before uploading the bytes a promotion resolves by digest.
//!
//! Every write is STRICTLY validated before it is stored, and the store keeps only the validated
//! result, because branding is expressible ONLY through data that cannot become script:
//!
//! - `tokens` and `tokens_dark` must deserialize into the CLOSED typed design-token grammar
//!   ([`DesignTokens`]): hex-only colors, an allowlist font enum, clamped numerics. A malformed
//!   or hostile token blob is a loud 400 naming the fault, and nothing is stored. Never CSS.
//! - `slots` keys must be KNOWN slot ids and each value passes the ONE allowlist sanitizer at
//!   ingest ([`BrandSlots::from_raw`]), so a stored slot is sanitizer output, never the submitted
//!   markup. An unknown slot key is a loud 400 rather than a silent drop, so an operator who
//!   misspells a slot learns it instead of wondering why nothing renders.
//! - `client_id`, the per-CLIENT selection key, must parse as a real authorize
//!   [`ironauth_store::ClientId`] IN THIS SCOPE. It is the one selection column an operator could
//!   otherwise fill with a foreign environment's id (dead config that no authorize request in
//!   this environment can ever match), so an unparseable or cross-scope id answers the uniform
//!   not-found, exactly as the signup-form key does.
//! - the plain wordmark fields are stored as plain text and escaped on render.
//!
//! # There are TWO doors into `brands`, and both carry this wall
//!
//! The endpoints below are one. The other is a CONFIG PROMOTION apply, which writes brand rows
//! straight from an operator-submitted snapshot document, and `validate_document` checks only
//! that a brand's `tokens` and `slots` are JSON OBJECTS. Left alone that would have made the
//! claims above false: a submitted document could store an unknown slot key, unsanitized markup,
//! and a CSS breakout in a color token, none of which this door accepts. Not a live XSS, because
//! the render path re-sanitizes slots and falls back to neutral tokens, but a promoted brand
//! would then render as the NEUTRAL DEFAULT instead of its source, silently, and the slot size
//! cap would not exist on that path at all.
//!
//! [`promoted_brand_faults`] is that same wall applied to a promotion source, called by
//! [`crate::promotion`] on BOTH the plan and the apply. It is here, not in the store, because
//! the store deliberately does not depend on the branding module (a store to OIDC edge would be
//! a cycle) and because ONE grammar checked in ONE place is the whole point: [`checked_slots`]
//! and [`validated_tokens`] serve both doors.
//!
//! The two doors differ in DISPOSITION, deliberately. This one SANITIZES a submitted slot and
//! stores the result; the promotion door REFUSES a slot that is not already sanitizer output.
//! A snapshot's contract is the canonical shape the export returns, and the export returns
//! sanitizer output, so a genuine document round-trips. That rests ENTIRELY on the sanitizer
//! returning a fixed point of itself: while it applied a single allowlist pass, a slot whose
//! markup the pass reshaped was stored in a form this door then refused, and a document
//! IronAuth exported could not be re-imported. It applies the allowlist to convergence now,
//! and `a_slot_that_needed_a_second_pass_still_round_trips_through_the_promotion_wall`
//! drives both doors in one test so the two can never disagree again. Rewriting
//! a submitted document instead would mean the plan an operator reviewed and the bytes the apply
//! stored were different documents.
//!
//! The write is SUDO-GATED right after scope resolution, exactly like the locale writes and the
//! brand asset uploads: a brand is the visible chrome of the auth pages, a social-engineering
//! surface, so it demands fresh privilege. `a_brand_write_is_sudo_gated` in `tests/sudo.rs`
//! measures the gate on both mutating verbs.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_oidc::branding::{BrandSlots, DesignTokens, SlotId};
use ironauth_store::{BrandId, CorrelationId, NewBrand, Scope};
use std::collections::BTreeMap;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{BrandPage, BrandView, SetBrandRequest};

/// The serde default for [`SetBrandRequest::show_wordmark`]: an omitted flag shows the wordmark,
/// matching the store column's `DEFAULT true`.
pub(crate) const fn default_true() -> bool {
    true
}

/// The largest a single rich-text slot's SUBMITTED markup may be. A footer or a help blurb is
/// short; this bound (generous for any real slot) keeps a management key holder from storing a
/// huge string that then inflates the cost of every subsequent flow render for the environment.
/// Mirrors the locale module's per-string cap for the same reason.
const MAX_SLOT_BYTES: usize = 8192;

/// The largest a brand slug may be, and the character grammar it must fit. A slug is the stable
/// per-environment natural key AND the config-promotion diff key, so it is deliberately narrow:
/// lowercase alphanumerics, hyphen and underscore. A slug outside the grammar can name no
/// installed brand, so it answers the uniform not-found exactly as a malformed locale tag does.
const MAX_SLUG_BYTES: usize = 64;

/// Resolve and authorize the `(tenant, environment)` scope from the path (issue #86). The
/// operator passes; a management key must be scoped to exactly this environment (otherwise the
/// LOUD wrong-scope error). A malformed tenant or environment id is the uniform not-found.
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

/// Normalize the `{slug}` path parameter, or the uniform not-found for a slug outside the
/// grammar (such a slug can name no installed brand, so it is indistinguishable from an absent
/// one, exactly as a malformed locale tag is).
fn parse_slug(raw: &str) -> Result<String, ApiError> {
    if raw.is_empty()
        || raw.len() > MAX_SLUG_BYTES
        || !raw
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(ApiError::NotFound);
    }
    Ok(raw.to_owned())
}

/// Validate a token blob against the CLOSED typed grammar and re-serialize it as the store's
/// verbatim JSON string. An absent blob yields the neutral defaults for `tokens` (so a brand
/// that overrides nothing renders exactly today's neutral pages) and [`None`] for `tokens_dark`.
fn validated_tokens(raw: Option<&serde_json::Value>, field: &str) -> Result<String, ApiError> {
    let tokens: DesignTokens = match raw {
        Some(value) => serde_json::from_value(value.clone()).map_err(|error| {
            ApiError::BadRequest(format!(
                "{field} is not a valid design-token object: {error}. Every token is a validated \
                 scalar (a #rrggbb color, an allowlisted font family, a clamped numeric), never \
                 free-form CSS"
            ))
        })?,
        None => DesignTokens::default(),
    };
    serde_json::to_string(&tokens).map_err(|_| ApiError::Internal)
}

/// The slot rules that hold on EVERY door into `brands`: a KNOWN slot key and a value within
/// the size cap. Returns the parsed pairs so the caller can dispose of them.
///
/// An UNKNOWN slot key is a loud 400 (a misspelled slot would otherwise render nothing and look
/// like a server fault), and an oversize submitted value is a loud 400. Shared by the management
/// write below and by [`promoted_brand_faults`], so neither door can grow a rule the other
/// lacks.
fn checked_slots(raw: &BTreeMap<String, String>) -> Result<Vec<(SlotId, String)>, ApiError> {
    let mut checked = Vec::new();
    for (key, value) in raw {
        let slot = SlotId::parse(key).ok_or_else(|| {
            ApiError::BadRequest(format!(
                "slot key {key:?} is not one of the known rich-text slots (footer_legal, \
                 login_help, consent_notice)"
            ))
        })?;
        if value.len() > MAX_SLOT_BYTES {
            return Err(ApiError::BadRequest(format!(
                "slot {key} is {} bytes, over the {MAX_SLOT_BYTES} byte limit",
                value.len()
            )));
        }
        checked.push((slot, value.clone()));
    }
    Ok(checked)
}

/// Sanitize the submitted slots at ingest and serialize them as the store's verbatim JSON
/// string: the MANAGEMENT door's disposition of [`checked_slots`].
fn validated_slots(raw: &BTreeMap<String, String>) -> Result<String, ApiError> {
    Ok(BrandSlots::from_raw(checked_slots(raw)?).to_stored_json())
}

/// The BRAND INGEST WALL applied to a config-promotion source document (issue #475): every
/// fault in every brand the document carries, as operator-facing messages, or an empty vector
/// when the document's branding is storable as authored.
///
/// The promotion apply is the SECOND writer of the `brands` table and binds a submitted
/// snapshot's `tokens` and `slots` VERBATIM, while `validate_document` checks only that the two
/// are JSON objects. Without this, the module-level claims that a stored token blob is typed
/// scalars and a stored slot is sanitizer output would be false on that path, `MAX_SLOT_BYTES`
/// would go unenforced there, and a promoted brand would silently render as the neutral default
/// (the render path re-sanitizes and falls back) rather than as its source.
///
/// It is called from BOTH promotion endpoints, so the PLAN refuses first: an operator learns the
/// document is unstorable before reviewing a plan built from it, and every faulty brand is
/// reported at once, exactly as snapshot validation reports every violation at once.
///
/// Four rules, and the last two are what the transactional apply's own pre-steps rest on:
///
/// 1. `tokens` and `tokens_dark` must deserialize into the closed [`DesignTokens`] grammar.
/// 2. every `slots` value must be a string with a known key, within the size cap, and ALREADY
///    sanitizer output. `ironauth_oidc::branding::sanitize` returns a FIXED POINT of the
///    allowlist, so an exported document round-trips through this rule rather than being
///    refused by it.
/// 3. no two brands may claim the same CANONICAL host. The apply releases every other claimant
///    of a promoted host before binding it, which is only faithful to the document if the
///    document names one claimant per host; two would make the last-applied slug win and the
///    promotion would never converge.
/// 4. no two brands may be the environment default, for the identical reason: the apply demotes
///    every other default first.
///
/// The store's own uniqueness indexes guarantee 3 and 4 for an EXPORTED document; a hand
/// authored one is refused here rather than applied to a state no re-plan would reproduce.
pub(crate) fn promoted_brand_faults(snapshot: &ironauth_store::Snapshot) -> Vec<String> {
    let mut faults = Vec::new();
    let mut hosts: BTreeMap<String, String> = BTreeMap::new();
    let mut default_slug: Option<&str> = None;
    for brand in &snapshot.resources.brand {
        let slug = brand.slug.as_str();
        let mut note = |message: String| faults.push(format!("brand {slug}: {message}"));

        if let Err(ApiError::BadRequest(message)) = validated_tokens(Some(&brand.tokens), "tokens")
        {
            note(message);
        }
        if let Some(dark) = brand.tokens_dark.as_ref() {
            if let Err(ApiError::BadRequest(message)) = validated_tokens(Some(dark), "tokens_dark")
            {
                note(message);
            }
        }

        match serde_json::from_value::<BTreeMap<String, String>>(brand.slots.clone()) {
            Ok(raw) => match checked_slots(&raw) {
                Ok(checked) => {
                    for (slot, value) in checked {
                        // The document must carry what the store would hold, so the wall is
                        // "is this already sanitizer output", not "sanitize it for me".
                        if ironauth_oidc::branding::sanitize(&value).as_str() != value {
                            note(format!(
                                "slot {} is not sanitizer output. A snapshot carries the \
                                 canonical stored form, which the allowlist sanitizer produced \
                                 (only b i strong em u p br and https anchors survive, with a \
                                 forced rel), so submit the exported value rather than raw markup",
                                slot.as_str()
                            ));
                        }
                    }
                }
                Err(ApiError::BadRequest(message)) => note(message),
                Err(_) => note("slots could not be validated".to_owned()),
            },
            Err(error) => note(format!(
                "slots must be a JSON object of slot key to sanitized markup string: {error}"
            )),
        }

        if let Some(host) = brand
            .host_pattern
            .as_deref()
            .and_then(ironauth_store::canonicalize_host)
        {
            if let Some(other) = hosts.insert(host.clone(), slug.to_owned()) {
                faults.push(format!(
                    "brands {other} and {slug} both claim the host {host}; within an environment \
                     a host selects at most one brand, so a promotion of this document could \
                     never converge"
                ));
            }
        }
        if brand.is_default {
            if let Some(other) = default_slug {
                faults.push(format!(
                    "brands {other} and {slug} are both the environment default; an environment \
                     has at most one default brand"
                ));
            }
            default_slug = Some(slug);
        }
    }
    faults
}

/// Build the API view of a stored brand. The slots are re-read through
/// [`BrandSlots::from_stored_json`], so what the API echoes back is the SANITIZED value the
/// render path will use, never the submitted markup.
fn view_of(record: &ironauth_store::BrandRecord) -> Result<BrandView, ApiError> {
    let tokens: serde_json::Value =
        serde_json::from_str(&record.tokens_json).map_err(|_| ApiError::Internal)?;
    let tokens_dark = match &record.tokens_dark_json {
        Some(json) => Some(serde_json::from_str(json).map_err(|_| ApiError::Internal)?),
        None => None,
    };
    let slots: BTreeMap<String, String> = SlotId::ALL
        .into_iter()
        .filter_map(|slot| {
            BrandSlots::from_stored_json(&record.slots_json)
                .get(slot)
                .map(|value| (slot.as_str().to_owned(), value.as_str().to_owned()))
        })
        .collect();
    Ok(BrandView {
        slug: record.slug.clone(),
        is_default: record.is_default,
        product_name: record.product_name.clone(),
        show_wordmark: record.show_wordmark,
        brand_token: record.brand_token.clone(),
        tokens,
        tokens_dark,
        slots,
        host_pattern: record.host_pattern.clone(),
        client_id: record.client_id.clone(),
    })
}

/// List a per-environment's brands.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/brands",
    operation_id = "listBrands",
    tag = "brands",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The environment's brands, ordered by slug", body = BrandPage),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn list_brands(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let records = state.store().scoped(scope).brands().list_all().await?;
    let items = records
        .iter()
        .map(view_of)
        .collect::<Result<Vec<_>, ApiError>>()?;
    let body_string =
        serde_json::to_string(&BrandPage { items }).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Set (create or overwrite) a per-environment brand.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}",
    operation_id = "setBrand",
    tag = "brands",
    request_body = SetBrandRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("slug" = String, Path, description = "The brand slug (the per-environment natural key)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Set", body = BrandView),
        (status = 400, description = "An invalid design token, an unknown slot key, or an oversize slot", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or sudo required", body = ErrorBody),
        (status = 404, description = "Environment not found, malformed slug, or a client_id \
         selection key that names no client of this environment", body = ErrorBody),
        (status = 409, description = "Another brand in this environment already claims the same host or client selection key", body = ErrorBody)
    )
)]
pub async fn set_brand(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, slug)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // A brand write rewrites the visible chrome of the auth pages (a social-engineering
    // surface), so it demands fresh privilege exactly like the brand asset uploads and the
    // locale writes.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let slug = parse_slug(&slug)?;

    // The environment must exist (a clean 404 rather than a foreign-key error), through the
    // ONE expression of that precondition (issues #443, #451).
    crate::org_context::require_live_environment(&state, &scope).await?;

    let request: SetBrandRequest = parse_json(&body)?;
    // Store ONLY the validated result: a hostile token blob or an unknown slot key is a loud
    // 400 and nothing is written.
    let tokens_json = validated_tokens(request.tokens.as_ref(), "tokens")?;
    let tokens_dark_json = match request.tokens_dark.as_ref() {
        Some(value) => Some(validated_tokens(Some(value), "tokens_dark")?),
        None => None,
    };
    let slots_json = validated_slots(&request.slots)?;
    // The per-CLIENT selection key must name a client of THIS scope. It was the one new ingest
    // field with no wall, and it is a selection column: a foreign environment's id stored here
    // matches no authorize request that could ever reach this environment, so it is dead config
    // an operator would have no way to notice. A malformed or cross-scope id is the uniform
    // not-found, exactly as the signup-form key (the same `ClientId`) already answers.
    let client_id = match request.client_id.as_deref() {
        Some(raw) => Some(
            ironauth_store::ClientId::parse_in_scope(raw, &scope)
                .map_err(|_| ApiError::NotFound)?
                .to_string(),
        ),
        None => None,
    };

    let created_at_micros = state.now_unix_micros();
    let id = BrandId::generate(state.env(), &scope);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .brands()
        .set(
            state.env(),
            &id,
            created_at_micros,
            NewBrand {
                slug: &slug,
                is_default: request.is_default,
                product_name: &request.product_name,
                show_wordmark: request.show_wordmark,
                brand_token: request.brand_token.as_deref(),
                tokens_json: &tokens_json,
                tokens_dark_json: tokens_dark_json.as_deref(),
                slots_json: &slots_json,
                host_pattern: request.host_pattern.as_deref(),
                client_id: client_id.as_deref(),
            },
        )
        .await?;

    // Read back what was STORED rather than echoing the request: the host key is canonicalized
    // at ingest and the slots are sanitizer output, so the request and the row differ.
    let record = state
        .store()
        .scoped(scope)
        .brands()
        .get(&slug)
        .await?
        .ok_or(ApiError::Internal)?;
    let body_string = serde_json::to_string(&view_of(&record)?).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Get a per-environment brand by slug.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}",
    operation_id = "getBrand",
    tag = "brands",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("slug" = String, Path, description = "The brand slug")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The brand", body = BrandView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_brand(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, slug)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let slug = parse_slug(&slug)?;
    let record = state
        .store()
        .scoped(scope)
        .brands()
        .get(&slug)
        .await?
        .ok_or(ApiError::NotFound)?;
    let body_string = serde_json::to_string(&view_of(&record)?).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Delete a per-environment brand by slug.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}",
    operation_id = "deleteBrand",
    tag = "brands",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("slug" = String, Path, description = "The brand slug")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deleted, along with every asset installed under the slug"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or sudo required", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn delete_brand(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, slug)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // The parent-existence precondition, through the ONE expression of it (issues #443, #451):
    // a `brands` row survives its environment's soft delete, so without this the delete would
    // land inside a decommissioned environment while the SET next door refused.
    crate::org_context::require_live_environment(&state, &scope).await?;
    let slug = parse_slug(&slug)?;
    // Resolve the stored id by slug (a uniform not-found when absent), then delete by id so the
    // audit row names the immutable brand id.
    let record = state
        .store()
        .scoped(scope)
        .brands()
        .get(&slug)
        .await?
        .ok_or(ApiError::NotFound)?;
    let id = BrandId::parse_in_scope(&record.id, &scope).map_err(|_| ApiError::NotFound)?;
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .brands()
        .delete(state.env(), &id, &slug)
        .await?;
    Ok(no_content())
}

#[cfg(test)]
mod tests {
    use super::{parse_slug, promoted_brand_faults, validated_slots, validated_tokens};
    use crate::error::ApiError;
    use ironauth_store::{BrandSnapshot, SNAPSHOT_SCHEMA_VERSION, Snapshot, SnapshotResources};
    use std::collections::BTreeMap;

    /// A brand snapshot in exactly the shape an EXPORT produces: valid typed tokens and a
    /// sanitizer-output slot.
    fn exported_brand(slug: &str) -> BrandSnapshot {
        BrandSnapshot {
            slug: slug.to_owned(),
            is_default: false,
            product_name: "Acme".to_owned(),
            show_wordmark: true,
            brand_token: None,
            tokens: serde_json::json!({
                "color_bg": "#f5f5f5",
                "color_fg": "#1a1a1a",
                "color_accent": "#2f5bde",
                "color_accent_fg": "#ffffff",
                "color_error": "#b00020",
                "color_surface": "#ffffff",
                "color_border": "#bbbbbb",
                "font_family": "system_ui",
                "radius": 6,
                "space": 16
            }),
            tokens_dark: None,
            slots: serde_json::json!({"footer_legal": "<strong>Legal</strong>"}),
            host_pattern: None,
            client_id: None,
            assets: Vec::new(),
        }
    }

    fn document(brands: Vec<BrandSnapshot>) -> Snapshot {
        Snapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION.to_owned(),
            resources: SnapshotResources {
                brand: brands,
                ..SnapshotResources::default()
            },
        }
    }

    fn slots(pairs: Vec<(&str, &str)>) -> BTreeMap<String, String> {
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    #[test]
    fn a_slug_outside_the_grammar_is_the_uniform_not_found() {
        assert_eq!(parse_slug("acme-corp_1").expect("valid"), "acme-corp_1");
        // Uppercase, path traversal, a percent escape, and an empty slug can each name no
        // installed brand, so they answer the same not-found an absent brand does.
        for bad in ["Acme", "../etc", "a b", "a%2f", "", "\"><script>"] {
            assert!(
                matches!(parse_slug(bad), Err(ApiError::NotFound)),
                "{bad:?} must be the uniform not-found"
            );
        }
        // The length cap.
        assert!(matches!(
            parse_slug(&"a".repeat(super::MAX_SLUG_BYTES + 1)),
            Err(ApiError::NotFound)
        ));
        assert!(parse_slug(&"a".repeat(super::MAX_SLUG_BYTES)).is_ok());
    }

    #[test]
    fn an_omitted_token_blob_stores_the_neutral_defaults() {
        // A brand that overrides nothing renders exactly today's neutral pages, so an absent
        // blob is the neutral default rather than an empty object the renderer must guess at.
        let json = validated_tokens(None, "tokens").expect("neutral defaults");
        assert!(json.contains("color_bg"), "{json}");
        assert!(json.contains("font_family"), "{json}");
    }

    #[test]
    fn a_hostile_token_blob_is_a_loud_400_and_never_reaches_the_store() {
        // The whole point of the typed grammar: a CSS breakout in a color slot cannot be
        // stored, so the served stylesheet can never carry it.
        let hostile = serde_json::json!({
            "color_bg": "#ffffff; } body { background: url(javascript:alert(1)) } .x {",
            "color_fg": "#1a1a1a",
            "color_accent": "#2f5bde",
            "color_accent_fg": "#ffffff",
            "color_error": "#b00020",
            "color_surface": "#ffffff",
            "color_border": "#bbbbbb",
            "font_family": "system_ui",
            "radius": 6,
            "space": 16
        });
        match validated_tokens(Some(&hostile), "tokens") {
            Err(ApiError::BadRequest(message)) => {
                assert!(message.contains("design-token"), "{message}");
            }
            other => panic!("expected a 400 for a hostile color, got {other:?}"),
        }
        // An unknown font family is refused by the same closed grammar.
        let bad_font = serde_json::json!({"font_family": "url(evil)"});
        assert!(matches!(
            validated_tokens(Some(&bad_font), "tokens"),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn a_slot_is_sanitized_at_ingest_and_an_unknown_slot_key_is_a_loud_400() {
        let json = validated_slots(&slots(vec![(
            "footer_legal",
            "<p>Terms<script>alert(1)</script></p>",
        )]))
        .expect("sanitized");
        let lower = json.to_ascii_lowercase();
        assert!(!lower.contains("<script"), "{json}");
        assert!(lower.contains("terms"), "{json}");

        // An unknown key is refused rather than dropped: a misspelled slot would otherwise
        // render nothing and look like a server fault.
        match validated_slots(&slots(vec![("footer_lega", "<b>x</b>")])) {
            Err(ApiError::BadRequest(message)) => {
                assert!(message.contains("footer_lega"), "{message}");
            }
            other => panic!("expected a 400 for an unknown slot key, got {other:?}"),
        }
    }

    /// THE SECOND DOOR. A promotion source is held to the SAME grammar this module's write
    /// path enforces, and every faulty brand is reported at once.
    ///
    /// Each hostile case here is one the brand ENDPOINT already refuses and the promotion apply
    /// used to store verbatim: `validate_document` checks only that `tokens` and `slots` are
    /// JSON objects. Measured before the wall existed, promoting this document stored
    /// `slots_json={"not_a_slot": "<b>x</b>", "footer_legal": "<p>Terms<script>alert(1)</script></p>"}`
    /// and a `color_bg` carrying a CSS breakout.
    #[test]
    fn a_promotion_source_is_held_to_the_brand_ingest_wall() {
        let mut hostile = exported_brand("acme");
        hostile.tokens = serde_json::json!({
            "color_bg": "#fff; } body { background: url(javascript:alert(1)) } .x {"
        });
        hostile.slots = serde_json::json!({
            "not_a_slot": "<b>x</b>",
            "footer_legal": "<p>Terms<script>alert(1)</script></p>"
        });
        let faults = promoted_brand_faults(&document(vec![hostile]));
        let joined = faults.join(" | ");
        assert!(joined.contains("design-token"), "{joined}");
        assert!(joined.contains("not_a_slot"), "{joined}");
        assert!(
            faults.iter().all(|fault| fault.starts_with("brand acme:")),
            "every fault names the brand it belongs to: {joined}"
        );

        // The unknown key is refused BEFORE the unsanitized value is reached, so drive the
        // sanitizer rule on its own too.
        let mut unsanitized = exported_brand("acme");
        unsanitized.slots =
            serde_json::json!({"footer_legal": "<p>Terms<script>alert(1)</script></p>"});
        let joined = promoted_brand_faults(&document(vec![unsanitized])).join(" | ");
        assert!(
            joined.contains("sanitizer output"),
            "submitted markup that is not the stored form is refused: {joined}"
        );

        // The size cap exists on this door too.
        let mut oversize = exported_brand("acme");
        oversize.slots = serde_json::json!({"login_help": "a".repeat(super::MAX_SLOT_BYTES + 1)});
        let joined = promoted_brand_faults(&document(vec![oversize])).join(" | ");
        assert!(joined.contains("limit"), "{joined}");

        // A dark token blob is walled exactly like the light one.
        let mut dark = exported_brand("acme");
        dark.tokens_dark = Some(serde_json::json!({"font_family": "url(evil)"}));
        let joined = promoted_brand_faults(&document(vec![dark])).join(" | ");
        assert!(joined.contains("tokens_dark"), "{joined}");
    }

    /// THE CONTROL, without which the test above would pass against a wall that refuses
    /// everything: a document in the shape the EXPORT actually produces passes clean. The
    /// sanitizer is idempotent, so an exported slot is its own sanitizer output and a genuine
    /// promotion round-trips rather than 400ing.
    #[test]
    fn an_exported_shaped_brand_document_passes_the_wall() {
        let mut host = exported_brand("acme");
        host.host_pattern = Some("login.acme.test".to_owned());
        host.is_default = true;
        let mut anchor = exported_brand("beta");
        anchor.slots = serde_json::json!({
            "login_help": "<p>See <a href=\"https://help.test\" rel=\"noopener noreferrer \
        nofollow\">help</a></p>"
        });
        let faults = promoted_brand_faults(&document(vec![host, anchor]));
        assert!(faults.is_empty(), "{faults:?}");
    }

    /// A document naming two claimants of one host, or two environment defaults, is refused:
    /// the apply RELEASES the other claimant and DEMOTES the other default, so a document with
    /// two would land whichever slug sorted last and no re-plan would reproduce it. The host
    /// rule compares CANONICAL forms, because two spellings are one claim.
    /// THE ROUND TRIP, end to end through both doors: what the MANAGEMENT door stores is
    /// exactly what an export carries, so the promotion wall must accept it. The slot here
    /// is raw operator markup whose first allowlist pass emits `<p>` nested inside `<p>`;
    /// while the sanitizer settled after one pass, the stored value was NOT its own
    /// sanitizer output, and this document, exported from IronAuth unaltered, was refused
    /// on re-import by the very wall that tells the operator to "submit the exported value".
    #[test]
    fn a_slot_that_needed_a_second_pass_still_round_trips_through_the_promotion_wall() {
        // Door one: the management ingest, which sanitizes and stores the result.
        let stored = validated_slots(&slots(vec![("login_help", "<p>Help<select><p>more")]))
            .expect("the management door sanitizes and stores");
        // The export embeds that stored JSON verbatim as parsed JSON.
        let mut exported = exported_brand("acme");
        exported.slots = serde_json::from_str(&stored).expect("the stored slots are JSON");
        assert!(
            exported.slots.get("login_help").is_some(),
            "the slot survived ingest: {stored}"
        );
        // Door two: the promotion wall, on the document the export just produced.
        let faults = promoted_brand_faults(&document(vec![exported]));
        assert!(
            faults.is_empty(),
            "a document IronAuth itself exported must re-import: {faults:?}"
        );
    }

    #[test]
    fn a_document_that_could_never_converge_is_refused() {
        let mut first = exported_brand("aaa");
        first.host_pattern = Some("login.acme.test".to_owned());
        let mut second = exported_brand("zzz");
        second.host_pattern = Some("LOGIN.Acme.Test:8443".to_owned());
        let joined = promoted_brand_faults(&document(vec![first, second])).join(" | ");
        assert!(
            joined.contains("both claim the host login.acme.test"),
            "{joined}"
        );

        let mut one = exported_brand("aaa");
        one.is_default = true;
        let mut two = exported_brand("zzz");
        two.is_default = true;
        let joined = promoted_brand_faults(&document(vec![one, two])).join(" | ");
        assert!(joined.contains("both the environment default"), "{joined}");
    }

    #[test]
    fn an_oversize_slot_is_rejected() {
        let big = "a".repeat(super::MAX_SLOT_BYTES + 1);
        match validated_slots(&slots(vec![("login_help", big.as_str())])) {
            Err(ApiError::BadRequest(message)) => assert!(message.contains("limit"), "{message}"),
            other => panic!("expected a 400 for an oversize slot, got {other:?}"),
        }
        let at_cap = "a".repeat(super::MAX_SLOT_BYTES);
        assert!(validated_slots(&slots(vec![("login_help", at_cap.as_str())])).is_ok());
    }
}
