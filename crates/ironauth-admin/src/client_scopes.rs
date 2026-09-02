// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-client OAuth SCOPE allowlist as a management surface (issue #98).
//!
//! Two endpoints over one column, `clients.allowed_scopes` (migration 0096):
//!
//! - GET `.../clients/{client_id}/allowed-scopes` reads it.
//! - PUT `.../clients/{client_id}/allowed-scopes` sets it, or clears it with an
//!   explicit `null`.
//!
//! # What the allowlist IS
//!
//! A DELEGATION restriction on what a machine may ASK FOR. Both machine-grant paths
//! refuse a request naming a scope outside a configured allowlist. Three states,
//! exactly the twin of `clients.allowed_resources`:
//!
//! | stored | meaning |
//! |---|---|
//! | `null` | no allowlist configured. Every scope passes the denylist floor. |
//! | `[..]` | the client may request exactly these tokens. |
//! | `[]` | the client may request no scope at all. |
//!
//! A malformed stored value reads as the EMPTY allowlist, never as unrestricted.
//! That is the store's rule (`ClientScopePolicyRepo::get`) and this surface inherits
//! it: a GET of a corrupted row answers `[]`, which is what the mint will enforce, so
//! the console shows the operator the truth rather than a repaired value.
//!
//! # The two grants refuse with DIFFERENT wire errors, which an operator reading a log will notice
//!
//! `client_credentials` answers `invalid_scope`, the spec-exact code. The jwt-bearer
//! grant answers its uniform `invalid_grant` and records `scope_not_allowlisted` in
//! the client-authentication diagnostics sink instead. That is not an inconsistency to
//! be tidied up: the jwt-bearer grant deliberately permits a PUBLIC presenting client
//! and checks the scope before the assertion is touched, so `invalid_scope` there
//! would let an unauthenticated caller read back the allowlist WRITTEN THROUGH THIS
//! ENDPOINT one scope token at a time. `client_credentials` requires client
//! authentication (RFC 6749 4.4), so its only reader is the client itself. (The
//! identity-chaining prototype, issue #133, adds a SECOND allowlist check on the
//! jwt-bearer grant that runs after the assertion is verified; it records the same
//! reason and is reachable only by a confidential client, so it is not an
//! unauthenticated oracle either.) The
//! `DISALLOWED_M2M_SCOPES` floor keeps `invalid_scope` on both, because it is a public
//! compile-time constant rather than anything an operator configured here.
//!
//! # Four things this deliberately is NOT, stated because the natural reading of "the scope allowlist landed" is that they were done
//!
//! **1. It is not the RBAC permission set. Machine principal roles and permissions
//! are issue #99, not issue #98.** A client-credentials token has a machine `sub` and
//! no human organization context, so issue #98's permission union has nothing to
//! resolve against and is unreachable from that grant.
//! `ClientCredentialsMintRequest` carries no permission field and must keep carrying
//! none. Scopes and permissions are two vocabularies with two enforcement points, and
//! this endpoint governs one of them.
//!
//! **2. No scope REGISTRY is built.** Discovery still serves a hard-coded
//! `SCOPES_SUPPORTED` const whose own comment calls itself "the authoritative source
//! until a scope subsystem exposes its own registry". This allowlist is per-client
//! and validates a request against ITSELF, not against a registry: an operator may
//! allowlist a scope no resource server has ever heard of, and nothing here objects.
//! Building the registry is out of scope for issue #98.
//!
//! **3. No scope CHARSET validation, and the asymmetry that follows.**
//! `parse_scope_set` is `split_whitespace()` and nothing in IronAuth validates a
//! scope token's characters. This endpoint does not change that. The consequence is
//! worth saying out loud because it is a live source of confusion: `read:orders` is a
//! legal scope token in IronAuth today while being an ILLEGAL permission slug under
//! issue #98's permission grammar. The two vocabularies are deliberately different
//! and neither is being converged onto the other.
//!
//! The ONE well-formedness rule this endpoint does enforce
//! ([`refuse_unmatchable_entries`]) is not charset validation and does not narrow the
//! character set by one character: it refuses an entry that is empty or carries
//! whitespace, because the matcher splits a REQUEST on whitespace, so such an entry
//! could never match anything and would be silently dead configuration.
//!
//! **4. No per-(client, audience) cross product.** `allowed_scopes` is per-client,
//! matching `allowed_resources`. Auth0's model (per-API scope definitions plus a
//! per-client subset grant) is a larger thing and is not issue #98.
//!
//! # These endpoints are ENVIRONMENT level
//!
//! A `clients` row carries no `organization_id`, so the row-level-security policy is
//! the table's complete fence, there is no parent organization to resolve, and there
//! is no cross-parent guard here to forget. The two layers that remain are
//! [`crate::org_context::resolve_scope`] (the credential must be authorized for the
//! environment the path names) and the typed [`ironauth_store::ClientId`] (an id
//! minted in another `(tenant, environment)` fails to parse in scope and never
//! reaches a statement).
//!
//! # THREE addressing failures, not four
//!
//! Malformed, foreign scope, and absent. `clients` has NO soft delete
//! (`ActingClientRepo::delete` removes the row outright), so a deleted client is simply
//! gone and reads exactly like one that was never registered. All three are the uniform
//! [`ApiError::NotFound`].
//!
//! # The write is on the CONTROL plane, and that is the point
//!
//! Migration 0096 grants `UPDATE (allowed_scopes) ON clients` to `ironauth_control`
//! alone, deliberately unlike the twin (0019 granted `allowed_resources` to
//! `ironauth_app`). The plane that MINTS a machine token cannot widen the set of
//! scopes that token may carry. So this handler writes through
//! `state.store().management()`, not through the data-plane registry the way
//! [`crate::signing_algorithm`] must, and it therefore needs none of that module's
//! cross-role idempotency machinery.
//!
//! # No idempotency arm
//!
//! The PUT takes no `Idempotency-Key`, following [`crate::resource_servers`] and
//! [`crate::permissions`]. The key exists so a retried CREATE cannot mint two rows; a
//! PUT of an absolute value onto a client that already exists is naturally
//! idempotent, because applying the same allowlist twice reaches the same state.
//!
//! # No caps
//!
//! Nothing here limits how many entries an allowlist may hold, matching
//! `allowed_resources`, which has never had one either. The bound that does exist is
//! the management API's request body size limit.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{ClientScopePolicy, CorrelationId};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::org_context::{EnvironmentAccess, require_client_scope_policy, resolve_scope};
use crate::response::json;
use crate::state::AdminState;

/// One client's scope-allowlist state.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClientAllowedScopesView {
    /// The client identifier (`cli_...`).
    pub client_id: String,
    /// The scope tokens this client may request on a machine grant, or `null` when no
    /// allowlist is configured (every scope passes the machine-grant denylist floor).
    /// An empty array is a real value meaning the client may request no scope at all.
    ///
    /// A stored value the server cannot parse reads as the EMPTY array here, because
    /// that is what the mint will enforce. The read reports what is in force, never a
    /// repaired value.
    #[schema(example = json!(["read:orders", "write:orders"]))]
    pub allowed_scopes: Option<Vec<String>>,
}

impl ClientAllowedScopesView {
    /// Project a stored policy for the wire.
    fn new(client_id: String, policy: ClientScopePolicy) -> Self {
        Self {
            client_id,
            allowed_scopes: policy.allowed_scopes,
        }
    }
}

/// The body of a set-allowed-scopes request.
///
/// One REQUIRED field whose value MAY be `null`, and the distinction is the whole
/// shape of this body. An absent `allowed_scopes` is a 400 that names it, because an
/// empty object would otherwise be a legal request that does nothing and a caller who
/// sent one could not tell it apart from a request that was applied. A PRESENT
/// `allowed_scopes: null` is the explicit CLEAR.
#[allow(
    clippy::option_option,
    reason = "see `named_field`: the outer Option is key PRESENCE (absent is a 400) \
              and the inner one is the JSON value (`null` is the explicit clear), and \
              collapsing them would delete the distinction this body is built on"
)]
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SetClientAllowedScopesRequest {
    /// The scope tokens this client may request, or `null` to clear the allowlist
    /// (after which every scope passes the machine-grant denylist floor). An empty
    /// array is a real value: the client may then request no scope at all. REQUIRED:
    /// omitting the key is a 400, and it is NOT the same as sending `null`.
    // `required = true` is stated rather than inferred, and it is deliberately a plain
    // comment so this codegen note stays out of the PUBLISHED description. utoipa reads
    // the OUTER `Option` of the `named_field` seam as "optional field", exactly as it
    // does everywhere else, so without this the generated schema carries no `required`
    // array and the generated client would happily omit a key the server answers 400
    // for: the document would contradict its own server. The two other bodies in this
    // crate built on `named_field` (`permissions::UpdatePermissionRequest` and
    // `resource_servers::UpdateResourceServerRequest`) are GENUINELY optional there
    // (omitted means unchanged, or the field exists only so naming it is refused), so
    // the inferred shape is right for them. Same Rust type, opposite requirement; this
    // is the only one of the three that was wrong.
    #[serde(default, deserialize_with = "named_field")]
    #[schema(value_type = Option<Vec<String>>, required = true)]
    pub allowed_scopes: Option<Option<Vec<String>>>,
}

/// Deserialize a present field into `Some(..)` and leave an ABSENT one as `None`.
///
/// The outer [`Option`] is key PRESENCE and the inner one is the JSON value, so
/// `null` stays distinguishable from an array. serde's own [`Option`] cannot report
/// this: under `#[serde(default)]` an absent key yields `None` because the default
/// runs, and a key carrying `null` yields the same `None` because that is how
/// [`Option`] deserializes a null, so the two collapse. The same helper
/// [`crate::permissions`] and [`crate::resource_servers`] carry, for the same reason.
///
/// # Errors
///
/// Whatever the inner deserialization reports: a present field that is neither an
/// array of strings nor `null` is still a parse failure, unchanged by this wrapper.
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

/// Refuse an allowlist entry that could never match a requested scope.
///
/// This is NOT charset validation and it narrows the legal scope alphabet by nothing:
/// `read:orders`, `urn:x:y`, and any other punctuation-bearing token pass unchanged.
/// The one thing it refuses is an entry the MATCHER could never see, because
/// `validate_m2m_scope` splits the REQUEST on whitespace: an entry that is empty, or
/// that contains a space or a tab, cannot equal any token that split can produce. A
/// 200 that stored such an entry would leave the operator believing they had
/// allowlisted something while the client's request was refused, which is the worst
/// of the available answers.
///
/// It runs AFTER the client has resolved, so a caller who cannot address the client
/// still gets the uniform not-found and learns nothing from the shape of their body.
///
/// # Errors
///
/// [`ApiError::BadRequest`] naming the offending entry.
fn refuse_unmatchable_entries(entries: &[String]) -> Result<(), ApiError> {
    for entry in entries {
        if entry.is_empty() {
            return Err(ApiError::BadRequest(
                "an allowed_scopes entry must not be empty: a requested scope is split \
                 on whitespace, so an empty entry could never match"
                    .to_owned(),
            ));
        }
        if entry.chars().any(char::is_whitespace) {
            return Err(ApiError::BadRequest(format!(
                "the allowed_scopes entry `{entry}` contains whitespace: a requested \
                 scope is split on whitespace, so this entry could never match. List \
                 each scope token separately"
            )));
        }
    }
    Ok(())
}

/// Read one client's scope allowlist.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/allowed-scopes",
    operation_id = "getClientAllowedScopes",
    tag = "client-scopes",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The client identifier (cli_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The client's scope allowlist", body = ClientAllowedScopesView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, malformed, or another scope's)", body = ErrorBody)
    )
)]
pub async fn get_client_allowed_scopes(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let (id, policy) =
        require_client_scope_policy(&state, scope, &client_id, EnvironmentAccess::Read).await?;
    let body = serde_json::to_string(&ClientAllowedScopesView::new(id.to_string(), policy))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Set (or clear) one client's scope allowlist.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/allowed-scopes",
    operation_id = "setClientAllowedScopes",
    tag = "client-scopes",
    request_body = SetClientAllowedScopesRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The client identifier (cli_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The updated scope allowlist", body = ClientAllowedScopesView),
        (status = 400, description = "Malformed request, a body omitting allowed_scopes, or an entry that is empty or carries whitespace", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or a lapsed sudo elevation (the RFC 9470 insufficient_user_authentication challenge)", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, malformed, or another scope's). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn set_client_allowed_scopes(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // Address the target FIRST, exactly as `resource_servers.rs` does and for the same
    // reason: a caller who cannot address the client must not be able to tell "that
    // client is not yours" from "that client does not exist" by the STATUS of a
    // body-level refusal.
    let (id, _current) =
        require_client_scope_policy(&state, scope, &client_id, EnvironmentAccess::Write).await?;

    let request: SetClientAllowedScopesRequest = parse_json(&body)?;
    let Some(allowed_scopes) = request.allowed_scopes else {
        return Err(ApiError::BadRequest(
            "allowed_scopes is required: send an array to set the allowlist, or an \
             explicit null to clear it"
                .to_owned(),
        ));
    };
    if let Some(entries) = allowed_scopes.as_deref() {
        refuse_unmatchable_entries(entries)?;
    }

    let pending = allowed_scopes_event(&state, scope, &id, allowed_scopes.is_some());
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .client_scope_policies(scope)
        .set_with_event(
            state.env(),
            &id,
            allowed_scopes.as_deref(),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;

    // Re-read through the SAME address, so the response can only ever describe a
    // client of this environment and reports what was actually stored.
    let (_id, updated) =
        require_client_scope_policy(&state, scope, &client_id, EnvironmentAccess::Write).await?;
    let body = serde_json::to_string(&ClientAllowedScopesView::new(id.to_string(), updated))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// The event a per-client scope-allowlist write emits (issue #108).
///
/// Whether the client is RESTRICTED, not which scopes it may request. The allowlist itself is
/// config a consumer re-reads through the authorized surface; what it cannot re-derive is
/// that the restriction was turned on or off at all.
///
/// An EMPTY allowlist counts as restricted, and maximally so: it is a real stored value,
/// distinct from the NULL clear, and a consumer that conflated the two would read the most
/// restrictive client in the environment as the least.
fn allowed_scopes_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    client_id: &ironauth_store::ClientId,
    restricted: bool,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = client_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "client.allowed_scopes_set",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "client_id": subject, "restricted": restricted }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}
