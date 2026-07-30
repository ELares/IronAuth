// SPDX-License-Identifier: MIT OR Apache-2.0

//! The resource-server registry as a MANAGEMENT surface (issue #98).
//!
//! `resource_servers` has existed since issue #29 as the audience-to-format registry
//! the mint reads, and it has never had a management API: registration is a store
//! call with no route in front of it. This module adds the smallest surface issue
//! #98 needs and no more.
//!
//! # The PATCH touches exactly one column, and that is the design
//!
//! [`UpdateResourceServerRequest`] writes `permission_claims_enabled` and nothing
//! else. Full resource-server CRUD (registering an audience, changing a token
//! format, setting a lifetime) is not this issue's business, and shipping it here
//! would put three unrelated decisions behind one endpoint that exists to answer one
//! question. The store method it calls
//! ([`ironauth_store::ActingResourceServerRepo::set_permission_claims`]) has no
//! parameter for any other column, so this is enforced a layer below the handler as
//! well as at the edge.
//!
//! The three read-only columns are nonetheless DECLARED on the request body, purely
//! so naming one is a typed 400 that says which field and why rather than a 200 that
//! dropped it. That follows [`crate::permissions`], and it matters more here than
//! there: this endpoint exists to manage the interaction between `token_format` and
//! the opt-in, so a caller who thinks they set the format in the same request must
//! be told they did not.
//!
//! # Addressed by `rsv_` id, never by audience
//!
//! An audience is an absolute URI. It contains `:` and `/`, so it cannot be a path
//! segment without percent-encoding that every proxy in the chain is free to
//! normalize differently. The LIST endpoint exists precisely so a console can find
//! the id for an audience it knows.
//!
//! # These endpoints are ENVIRONMENT level
//!
//! `resource_servers` carries no `organization_id`: a registered protected API
//! belongs to the environment, not to a customer inside it. So the
//! row-level-security policy is the table's complete fence, there is no parent
//! organization to resolve, and there is no cross-parent guard here to forget. The
//! two layers that remain are [`crate::org_context::resolve_scope`] (the credential
//! must be authorized for the environment the path names) and the typed
//! [`ironauth_store::ResourceServerId`] (an id minted in another `(tenant,
//! environment)` fails to parse in scope and never reaches a statement).
//!
//! # THREE addressing failures, not four
//!
//! Every other management surface in this crate makes four states one answer:
//! malformed, foreign scope, absent, and soft-deleted. This table has NO soft
//! delete, so there are three. A row a config promotion hard-deleted is simply gone and
//! reads exactly like one that was never registered, which is the same uniform
//! [`ApiError::NotFound`] the other three produce. The distinction is stated rather
//! than left implicit because a reader arriving from `permissions.rs` will look for
//! the fourth state and needs to find the answer here.
//!
//! # The opaque refusal, and the path it does NOT close
//!
//! An opaque access token carries no claims at all, and
//! `ironauth_oidc`'s introspection response has no field to put them in, so issue
//! #98 declares permission claims an `at+jwt`-only feature. The PATCH therefore
//! REFUSES to ENABLE the opt-in on a resource server whose `token_format` is
//! `opaque`, with a typed 422 naming the reason. Refusing at configuration time is
//! much better than accepting a setting that is silently dropped at mint time.
//!
//! Three properties of that refusal matter and each is enforced rather than assumed:
//!
//!   * It is reachable ONLY after the resource server has resolved as a live row of
//!     THIS scope, matching the reparent-422 ordering in [`crate::org_groups`]. A
//!     422 visible for an id the caller cannot address would be a format oracle over
//!     a sibling environment's protected APIs.
//!   * It refuses ENABLING only. Setting the flag to `false` on an opaque resource
//!     server is allowed, because refusing it would trap a row in the opted-in state
//!     with no way out.
//!   * It is a MANAGEMENT-PLANE guard and NOT a schema invariant, and the difference
//!     is real. `resource_servers` is a promotable resource type, and a config
//!     promotion writes `token_format` and `permission_claims_enabled` from one
//!     source snapshot in one statement, with no handler in the path. A snapshot
//!     carrying `opaque` plus an enabled opt-in therefore LANDS that combination in
//!     the target environment. Migration 0094 deliberately ships no CHECK constraint
//!     against it, because a CHECK would turn a whole-environment promotion into an
//!     opaque 500 over a setting whose only consequence is that a claim is not
//!     emitted. The combination is inert: the mint reads the format first and an
//!     opaque token has nowhere to put a claim.
//!
//!     The honest summary: the 422 makes the combination unreachable through THIS
//!     API, and it stays reachable through promotion, where it does nothing. Nothing
//!     in this module or in the store re-checks the format after a promotion, and a
//!     later read of an opted-in opaque resource server reports exactly what is
//!     stored rather than a corrected value.
//!
//! # No idempotency arm
//!
//! Both mutating siblings addressed by an existing id ([`crate::permissions`]'s
//! PATCH and [`crate::org_roles`]'s) take no `Idempotency-Key`, and neither does
//! this one. The key exists so a retried CREATE cannot mint two rows; a PATCH
//! addressed by an id that already exists is naturally idempotent, because applying
//! the same boolean twice reaches the same state. `every_post_documents_the_idempotency_key_header`
//! in the OpenAPI contract test enumerates POSTs for exactly this reason, and this
//! module adds none.
//!
//! # No caps
//!
//! Nothing here limits how many resource servers an environment may register. The
//! list's page size is clamped like every management list, which bounds ONE RESPONSE
//! and never the number of stored rows.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{CorrelationId, ResourceServerRecord, TokenFormat};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::org_context::{require_live_resource_server, resolve_scope};
use crate::pagination::{ListQuery, Pagination};
use crate::response::json;
use crate::state::AdminState;

/// A registered resource server, as returned by the management API (issue #98).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ResourceServerView {
    /// The resource-server identifier (`rsv_...`, embeds its scope). This is the
    /// address every item endpoint takes, because the audience cannot be one.
    pub id: String,
    /// The resource identifier / resource URI a token targets. Unique per
    /// environment.
    #[schema(example = "https://api.example.test/billing")]
    pub audience: String,
    /// The access-token format this resource server receives: `at_jwt` or `opaque`.
    /// Read-only on this surface; issue #98 changes no token format.
    #[schema(example = "at_jwt")]
    pub token_format: String,
    /// The per-resource-server access-token lifetime in seconds, or null to fall back
    /// to the environment default. Read-only on this surface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_ttl_secs: Option<i64>,
    /// Whether tokens minted for this audience may carry the permission claim. The
    /// ONE field this surface can write.
    pub permission_claims_enabled: bool,
    /// Registration time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
}

impl ResourceServerView {
    /// Build a view from a stored record.
    fn from_record(record: ResourceServerRecord) -> Self {
        Self {
            id: record.id.to_string(),
            audience: record.audience,
            token_format: record.token_format.as_str().to_owned(),
            access_token_ttl_secs: record.access_token_ttl_secs,
            permission_claims_enabled: record.permission_claims_enabled,
            created_at_unix_ms: record.created_at_unix_micros / 1000,
        }
    }
}

/// A page of resource servers.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ResourceServerList {
    /// The resource servers on this page, oldest first. There is no cap on how many
    /// an environment may register; this page is size-clamped like every list.
    pub items: Vec<ResourceServerView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Deserialize a present field as `Some`, so key PRESENCE stays distinguishable
/// from key ABSENCE.
///
/// Byte for byte the seam [`crate::permissions`] uses, generalized over the field
/// type because this body names one integer field as well as two string ones. The
/// outer [`Option`] is presence and the inner one is the JSON value, so `null` stays
/// distinguishable from a value and a wrong-typed value still fails to parse exactly
/// as before. serde's own [`Option`] cannot report this: under `#[serde(default)]`
/// an ABSENT key yields `None` because the default runs, and a key carrying `null`
/// yields the same `None` because that is how [`Option`] deserializes a null, so the
/// two collapse. `#[serde(default, deserialize_with = "named_field")]` splits them
/// because the default runs ONLY for an absent key and this function runs only when
/// one was present.
///
/// # Errors
///
/// Whatever the inner deserialization reports: a present field of the wrong JSON
/// type is still a parse failure, unchanged by this wrapper.
#[allow(
    clippy::option_option,
    reason = "the nesting is the point: the outer Option is key PRESENCE and the \
              inner one is the JSON value, and pedantic's objection (that the two \
              levels usually mean the same thing) is exactly what does not hold here"
)]
fn named_field<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// The body to set a resource server's permission-claim opt-in.
///
/// One REQUIRED field, deliberately: a partial edit whose only editable field is
/// optional would make the empty object a legal request that does nothing, and a
/// caller who sent one would have no way to tell it apart from a request that was
/// applied. `permission_claims_enabled` is therefore mandatory, and omitting it is a
/// 400 that names it.
///
/// # The three read-only fields, and why they are declared here at all
///
/// `token_format`, `audience`, and `access_token_ttl_secs` are NOT editable on this
/// surface, and they appear in this struct for exactly one reason: naming one is a
/// typed 400 that says which field and why, instead of a 200 that quietly ignored
/// it. This follows `UpdatePermissionRequest` on the permission vocabulary rather than a
/// bare `deny_unknown_fields`, so the refusal names the field and states the rule.
///
/// The reason to spend that here rather than take the silent ignore is specific to
/// this endpoint: its whole subject is the INTERACTION between `token_format` and
/// the opt-in (the 422 below exists only because of it), so a caller who sends
/// `{"permission_claims_enabled": true, "token_format": "at_jwt"}` believing they
/// have changed the format to make the opt-in legal must not be told 200. A field
/// this surface cannot write is a field it must refuse rather than drop.
///
/// The test is PRESENCE and never value, so `"token_format": null` is refused
/// exactly like `"token_format": "at_jwt"`: a caller who writes the key believes
/// they said something about it.
///
/// Genuinely UNKNOWN keys (a typo, a field from a future version) are still
/// tolerated and ignored, exactly as on every other management body in this crate.
/// This struct refuses the three keys that name real, real-looking columns of THIS
/// resource, which are the ones a caller can plausibly believe they just wrote.
#[allow(
    clippy::option_option,
    reason = "see `named_field`: on the three read-only fields the outer Option is \
              key PRESENCE and the inner one is the value, and only the outer one \
              is ever read"
)]
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateResourceServerRequest {
    /// Whether tokens minted for this audience may carry the permission claim.
    ///
    /// Enabling this on a resource server whose `token_format` is `opaque` is refused
    /// with a 422: an opaque access token carries no claims, so the setting could
    /// only ever be silently dropped at mint time.
    pub permission_claims_enabled: bool,
    /// REFUSED if the key is present AT ALL, `null` included: issue #98 changes no
    /// token format. Accepting it silently would be worst here of all, because this
    /// endpoint's 422 is decided BY the stored format.
    #[serde(default, deserialize_with = "named_field")]
    #[schema(value_type = Option<String>)]
    pub token_format: Option<Option<String>>,
    /// REFUSED if the key is present AT ALL, `null` included: the audience is the
    /// registry's natural key and is immutable by GRANT, not merely by policy.
    #[serde(default, deserialize_with = "named_field")]
    #[schema(value_type = Option<String>)]
    pub audience: Option<Option<String>>,
    /// REFUSED if the key is present AT ALL, `null` included: the per-resource-server
    /// access-token lifetime is not editable on this surface.
    #[serde(default, deserialize_with = "named_field")]
    #[schema(value_type = Option<i64>)]
    pub access_token_ttl_secs: Option<Option<i64>>,
}

/// Refuse a body that NAMES a field this surface cannot write, saying which one and
/// why.
///
/// The test is PRESENCE and never value: all three arrive through [`named_field`],
/// so `Some(None)` is a key carrying `null` and is refused exactly like a key
/// carrying a value.
///
/// This runs AFTER the target has resolved, so a caller who cannot address the
/// resource server still gets the uniform not-found and learns nothing from the
/// shape of their body.
///
/// # Errors
///
/// [`ApiError::BadRequest`] if the body carries `token_format`, `audience`, or
/// `access_token_ttl_secs`.
fn refuse_read_only_fields(request: &UpdateResourceServerRequest) -> Result<(), ApiError> {
    if request.token_format.is_some() {
        return Err(ApiError::BadRequest(
            "token_format is read-only on this endpoint: issue #98 changes no token \
             format, and this surface writes permission_claims_enabled only"
                .to_owned(),
        ));
    }
    if request.audience.is_some() {
        return Err(ApiError::BadRequest(
            "audience is immutable: it is the registry's natural key, and the control \
             role holds no UPDATE grant on it"
                .to_owned(),
        ));
    }
    if request.access_token_ttl_secs.is_some() {
        return Err(ApiError::BadRequest(
            "access_token_ttl_secs is read-only on this endpoint: this surface writes \
             permission_claims_enabled only"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Refuse enabling the opt-in on an opaque resource server.
///
/// Split out of the handler so the rule is one named thing a reader can find and a
/// test can point at. It runs only against a record that has ALREADY resolved as a
/// live resource server of this scope.
///
/// # It is an ALLOWLIST, and that is deliberate
///
/// The condition is `!= TokenFormat::AtJwt` rather than `== TokenFormat::Opaque`,
/// which coincide only while exactly two formats exist. Issue #98 declares permission
/// claims an `at+jwt`-ONLY feature, so the rule the module docs and the CHANGELOG
/// state is "permit `at_jwt`", not "forbid `opaque`". A third format added later
/// would inherit the refusal by default rather than silently inherit the permission,
/// which is the direction a fence should fail in.
///
/// No test can tell the two spellings apart today, and that is stated rather than
/// implied: with exactly two formats they are the same predicate, measured (flipping
/// this line back to `== TokenFormat::Opaque` leaves the whole suite green). The
/// spelling is chosen for the format that does not exist yet.
///
/// # Errors
///
/// [`ApiError::Unprocessable`] when `enabled` is true and the record's format is
/// anything other than [`TokenFormat::AtJwt`].
fn refuse_opaque_opt_in(record: &ResourceServerRecord, enabled: bool) -> Result<(), ApiError> {
    // DISABLING is always allowed, whatever the format. A row that reached the
    // opted-in state through a config promotion (which this API cannot refuse, see
    // the module docs) must have a way back out.
    if enabled && record.token_format != TokenFormat::AtJwt {
        return Err(ApiError::Unprocessable(
            "permission claims require the at_jwt access-token format: an opaque access \
             token carries no claims, so this resource server cannot be opted in while \
             its token_format is opaque"
                .to_owned(),
        ));
    }
    Ok(())
}

/// List an environment's registered resource servers (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/resource-servers",
    operation_id = "listResourceServers",
    tag = "resource-servers",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of resource servers", body = ResourceServerList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Tenant or environment not found", body = ErrorBody)
    )
)]
pub async fn list_resource_servers(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .management()
        .resource_servers(scope)
        .list_page(page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = ResourceServerList {
        items: rows
            .into_iter()
            .map(ResourceServerView::from_record)
            .collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get one registered resource server of an environment.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/resource-servers/{resource_server_id}",
    operation_id = "getResourceServer",
    tag = "resource-servers",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("resource_server_id" = String, Path, description = "The resource-server identifier (rsv_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The resource server", body = ResourceServerView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, malformed, or another scope's)", body = ErrorBody)
    )
)]
pub async fn get_resource_server(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, resource_server_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let record = require_live_resource_server(&state, scope, &resource_server_id).await?;
    let body = serde_json::to_string(&ResourceServerView::from_record(record))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Set a resource server's permission-claim opt-in. Nothing else about the resource
/// server is editable here.
#[utoipa::path(
    patch,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/resource-servers/{resource_server_id}",
    operation_id = "updateResourceServerPermissionClaims",
    tag = "resource-servers",
    request_body = UpdateResourceServerRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("resource_server_id" = String, Path, description = "The resource-server identifier (rsv_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The updated resource server", body = ResourceServerView),
        (status = 400, description = "Malformed request, a body omitting permission_claims_enabled, or a body naming a read-only field (token_format, audience, access_token_ttl_secs)", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, malformed, or another scope's)", body = ErrorBody),
        (status = 422, description = "Cannot enable permission claims on an opaque resource server", body = ErrorBody)
    )
)]
pub async fn update_resource_server_permission_claims(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, resource_server_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // Address the target FIRST, exactly as `permissions.rs` does and for the same
    // reason, sharpened here by the 422: a caller who cannot address the row must not
    // be able to tell "that resource server is not yours" from "that resource server
    // does not exist" by the STATUS of a body-level refusal. Both the parse failure
    // and the malformed body would otherwise be distinguishing signals.
    let record = require_live_resource_server(&state, scope, &resource_server_id).await?;

    let request: UpdateResourceServerRequest = parse_json(&body)?;
    // The read-only fields BEFORE the format rule: a body that names `token_format`
    // must be told the field is read-only rather than told its combination is
    // unprocessable, or the answer describes the wrong problem.
    refuse_read_only_fields(&request)?;
    refuse_opaque_opt_in(&record, request.permission_claims_enabled)?;

    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .resource_servers(scope)
        .set_permission_claims(state.env(), &record.id, request.permission_claims_enabled)
        .await?;

    // Re-read through the SAME address, so the response can only ever describe a
    // resource server of this environment.
    let updated = require_live_resource_server(&state, scope, &resource_server_id).await?;
    let body = serde_json::to_string(&ResourceServerView::from_record(updated))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
