// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SCIM connection management surface (issue #135).
//!
//! # Why this exists, and what shipped without it
//!
//! The SCIM 2.0 inbound surface authenticates every route against a per-connection bearer
//! token, and until this module there was NO WAY TO CREATE ONE. The store could
//! (`ActingScimConnectionRepo::create`) but nothing reachable called it: `ironauth-admin` had
//! no SCIM route and the published management API had no SCIM path. A deployment that turned
//! `scim.enabled` on got a surface that authenticated correctly and that nobody could obtain a
//! credential for through any shipped interface.
//!
//! That is the "enforcement without a granting path" shape: the control is real, the door to
//! it is missing, and nothing fails because a control that refuses everyone refuses correctly.
//!
//! # The token is returned ONCE
//!
//! `scim_connections` stores only a SHA-256 digest, so the plaintext exists in exactly one
//! response: the 201 of a create. It is not in a listing, not in a read, and not in the
//! idempotency replay body -- the stored replay carries the id and a flag saying the token was
//! already issued, because `idempotency_keys.response_body` is plaintext retained for a day
//! and putting a live credential there would recreate the recoverable copy migration 0183
//! exists to prevent. `api_keys.rs` solved this first and this follows it, with two knowing
//! differences: the provider is validated in the handler rather than by catching the column's
//! CHECK, and the writes emit domain events through the `*_with_event` methods.
//!
//! # Revoked connections are listed
//!
//! For the reason 0183 retains the rows: an operator investigating a provisioning incident has
//! to be able to tell "I revoked that at 14:02" from "no such connection ever existed".

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, NewScimConnection, ScimConnectionId, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::ApiError;
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::org_context::{EnvironmentAccess, resolve_live_org, resolve_scope};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// One connection, as the management surface renders it.
///
/// NO DIGEST FIELD, and that is the type doing the work rather than the handler remembering:
/// `ScimConnection` carries no plaintext and this view carries no digest, so a listing has
/// nothing to leak even by accident.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScimConnectionView {
    /// The non-secret `scim_` handle. Every other operation names the connection by this.
    pub id: String,
    /// The operator-facing label.
    pub display_name: String,
    /// Which vendor this connection is for: `okta`, `entra` or `generic`.
    pub provider: String,
    /// Expiry in milliseconds since the epoch, absent for a connection that does not expire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<i64>,
    /// Revocation time in milliseconds since the epoch, absent while the connection is live.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at_unix_ms: Option<i64>,
    /// When the SOONEST live token of this connection lapses, in milliseconds since the epoch.
    ///
    /// DIFFERENT FROM `expires_at_unix_ms`, which is the CONNECTION's horizon and bounds every
    /// token it has. After a rotation a connection holds two tokens: the superseded one lapsing
    /// at the end of the overlap and the fresh one usually with no horizon. This is the earliest
    /// moment a token a customer might still be presenting stops working, which is what an
    /// operator needs to see.
    ///
    /// Absent when no live token has a horizon at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soonest_token_expiry_unix_ms: Option<i64>,
    /// Whether that horizon falls inside the configured warning lead time.
    ///
    /// #140 asks for "expiry warnings at the configured lead time". This is that warning,
    /// computed here rather than left to the caller: a client that had to compare two timestamps
    /// against a lead time it also had to fetch would get it wrong in a different way per
    /// client, and the whole point is that the deployment decides when to warn.
    ///
    /// FALSE when the lead time is zero (the operator turned warnings off), when no live token
    /// has a horizon, when the horizon is beyond the lead, and whenever the connection counts NO
    /// live credential -- revoked, lapsed, or in an organization that was deleted or disabled. A
    /// countdown is about something that still works; those have already stopped, and
    /// `no_live_token` beside `revoked_at_unix_ms` is what says so.
    pub token_expiring_soon: bool,
    /// Whether this connection has NO live token at all, so provisioning has already stopped.
    ///
    /// A DIFFERENT FACT FROM THE WARNING, and it needs its own field because the two would
    /// otherwise be indistinguishable through an absent horizon: a connection whose tokens have
    /// all lapsed and a perfectly healthy one whose token never expires BOTH publish no
    /// `soonest_token_expiry_unix_ms`. One of those needs an operator today.
    ///
    /// TRUE for a connection whose tokens have all lapsed, one past its own expiry, and one whose
    /// organization was deleted or disabled: `authenticate` refuses each, so nothing a customer
    /// presents will work.
    ///
    /// FALSE for a revoked connection, which stopped working because somebody made it stop.
    pub no_live_token: bool,
}

/// A page of connections.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScimConnectionListView {
    /// This organization's connections, revoked ones included.
    pub items: Vec<ScimConnectionView>,
    /// The cursor for the next page, absent on the last one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// What a create names.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateScimConnectionRequest {
    /// The operator-facing label, for telling two identity providers apart in a listing.
    pub display_name: String,
    /// `okta`, `entra` or `generic`. Anything else is refused by this route with
    /// `400 invalid_provider`, before the write.
    pub provider: String,
    /// Optional expiry, in milliseconds since the epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<i64>,
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections/{connection_id}/rotate",
    operation_id = "rotateScimConnectionToken",
    tag = "scim",
    request_body = RotateScimTokenRequest,
    params(
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST under one key returns the stored answer, which omits the token"),
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("connection_id" = String, Path, description = "The scim_ handle"),
    ),
    responses(
        (status = 200, description = "Rotated; the new token appears here and nowhere else", body = ScimTokenRotated),
        (status = 400, description = "An out-of-range overlap, or a missing Idempotency-Key", body = crate::error::ErrorBody),
        (status = 401, description = "Missing or invalid management credential", body = crate::error::ErrorBody),
        (status = 403, description = "The credential may not write credentials for this organization", body = crate::error::ErrorBody),
        (status = 404, description = "No such live connection in this organization; a revoked or expired one answers the same", body = crate::error::ErrorBody),
        (status = 409, description = "The organization is disabled, so a credential minted for it could not authenticate", body = crate::error::ErrorBody),
        (status = 409, description = "A concurrent request is already rotating under this Idempotency-Key; retry", body = crate::error::ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = crate::error::ErrorBody),
    ),
    security(("bearer_auth" = []))
)]
/// `POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections/{connection_id}/rotate`
// THE DOC COMMENT IS THE PATH AND NOTHING ELSE, matching every neighbour on this surface, and
// the rest of this note is a PLAIN comment rather than a doc one on purpose. utoipa publishes
// whatever doc comment sits on this function as the operation's summary and description, so an
// earlier version's `# Errors` section reached the committed contract and the generated clients
// as a heading followed by internal Rust type names, and the explanation of why that was wrong
// would have followed it there. What a customer reads must not be the crate's own vocabulary.
//
// The refusals, for a reader of this file: `BadRequest` for an out-of-range overlap; `NotFound`
// when no live connection of this organization has that handle, which is also the answer for a
// handle from another tenant and for a revoked or expired connection; `Conflict` when the
// organization is disabled; `Internal` on a persistence fault. All of them are published in the
// `responses(..)` block above, which is where a caller should be reading them.
#[allow(clippy::missing_errors_doc)]
pub async fn rotate_scim_connection_token(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, connection_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_credentials`. A
    // rotation MINTS a provisioning credential, which is the same authority the create grants,
    // so it takes the same permission rather than a lesser one.
    principal.require_permission(ManagementPermission::WriteCredentials)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    // REQUIRED, like the create's. A retried rotation is not harmlessly idempotent: without the
    // key it mints a third token and re-supersedes the second, shortening the life of the one
    // the customer may have just pasted into their identity provider.
    let idem_key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &idem_key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // LIVE, unlike the revoke beside it, and the difference is the direction of the act. A
    // revoke DESTROYS a capability and must keep working in a soft-deleted environment; a
    // rotation MINTS one, and minting a working credential inside an environment an operator
    // believes is decommissioned is the thing a soft delete exists to stop.
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;

    require_active_organization(&state, scope, &org_id).await?;

    let request: RotateScimTokenRequest = crate::input::parse_json(&body)?;
    let overlap = request.overlap_seconds.unwrap_or(DEFAULT_OVERLAP_SECS);
    if !(0..=MAX_OVERLAP_SECS).contains(&overlap) {
        return Err(ApiError::BadRequest(format!(
            "overlap_seconds must be between 0 and {MAX_OVERLAP_SECS}"
        )));
    }

    // PARSED IN SCOPE, so a handle minted in another tenant is the uniform not-found.
    let id =
        ScimConnectionId::parse_in_scope(&connection_id, &scope).map_err(|_| ApiError::NotFound)?;
    // AND CHECKED AGAINST THIS ORGANIZATION, for the reason the revoke gives: the store's
    // rotation is scope-fenced but not organization-fenced, so without this an operator holding
    // write-credentials on one organization could rotate another organization's connection in
    // the same environment -- which is a denial of service against a sibling's identity
    // provider AND hands the caller a working credential for it.
    let belongs = state
        .store()
        .scoped(scope)
        .scim_connections()
        .exists_in_organization(&org_id, &id)
        .await
        .map_err(|_| ApiError::Internal)?;
    if !belongs {
        return Err(ApiError::NotFound);
    }

    // MINTED THROUGH THE SCIM CRATE, not reimplemented here, for the reason the create gives:
    // two copies of the credential format would agree until somebody changed one.
    let mut secret = [0_u8; 32];
    state.env().entropy().fill_bytes(&mut secret);
    let token = ironauth_scim::server::mint_token(
        &id,
        &base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, secret),
    );
    let digest = ironauth_scim::server::digest_of(&token);

    let stored = ScimTokenRotated {
        id: id.to_string(),
        token: None,
        previous_token_expires_at_unix_ms: None,
        token_already_issued: true,
    };
    let stored_body = serde_json::to_string(&stored).map_err(|_| ApiError::Internal)?;

    let now_micros = state.now_unix_micros();
    // THE EVENT CARRIES WHAT THE OPERATOR ASKED FOR, not the resulting expiry. The producer
    // builds its envelope before the write, and the write applies `LEAST(existing, now +
    // overlap)`, so a computed horizon is wrong whenever a token was already lapsing sooner. The
    // precise instant comes back FROM the write and goes in the 200 below.
    let pending = rotated_event(&state, scope, &id, &org_id, overlap);
    match state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        // ATTRIBUTED TO THE ORGANIZATION, as every organization-scoped write on this surface is.
        // `audit_log.organization_id` is what a per-organization log stream selects on, and this
        // is the row saying that organization's provisioning credential was replaced.
        .in_organization(org_id)
        .scim_connections()
        .rotate_token_with_event(
            state.env(),
            ironauth_store::RotateScimToken {
                id: &id,
                new_token_digest: &digest,
                overlap_secs: overlap,
                now_micros,
            },
            // The body STORED for replay carries NO token, and the flag says so rather than
            // returning a body that looks like a rotation with a field missing.
            // `idempotency_keys.response_body` is plaintext retained 24 hours; storing the real
            // body would put a live provisioning credential there, which is the recoverable copy
            // migration 0183 exists to prevent.
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &idem_key,
                request_fingerprint: &fingerprint,
                response_status: 200,
                response_body: &stored_body,
            }),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await
    {
        Ok(superseded_expires_micros) => {
            let rotated = ScimTokenRotated {
                id: id.to_string(),
                token: Some(token),
                // READ BACK FROM THE WRITE. `LEAST` means this is not always `now + overlap`,
                // and reporting the arithmetic instead of the result was a number that lied
                // exactly when the clause did its job.
                //
                // ABSENT WHEN THE ROTATION SUPERSEDED NOTHING and when every superseded token
                // has no horizon at all, which cannot happen here (the rotation writes one) but
                // is the honest shape for a value the store may not have.
                previous_token_expires_at_unix_ms: superseded_expires_micros.map(|us| us / 1000),
                token_already_issued: false,
            };
            let body = serde_json::to_string(&rotated).map_err(|_| ApiError::Internal)?;
            Ok(crate::response::json(StatusCode::OK, body))
        }
        Err(error) => Err(rotation_failure(&error)),
    }
}

/// Map a rotation's store failure to what the caller is told.
///
/// EXTRACTED so the handler fits the crate's function-length lint, and so each arm is a named
/// case rather than a fall-through. The first version had only the not-found arm and a catch-all,
/// which sent the idempotency race -- the very thing the key was added to make safe -- to a 500
/// that a retrying client would then retry.
fn rotation_failure(error: &ironauth_store::StoreError) -> ApiError {
    match error {
        // A REVOKED OR EXPIRED CONNECTION IS THE UNIFORM NOT-FOUND, same as an absent one: a
        // rotation must not be a way to tell which handles exist but are switched off.
        ironauth_store::StoreError::NotFound => ApiError::NotFound,
        // THE IDEMPOTENCY RACE THE KEY EXISTS TO CLOSE: two requests under one key arriving
        // together, which is precisely what an SDK's retry-on-timeout produces.
        ironauth_store::StoreError::IdempotencyConflict => ApiError::IdempotencyKeyConflict,
        // A UNIQUE VIOLATION ON THE NEW DIGEST. Unreachable while this handler mints it from the
        // entropy seam, and named rather than left to fall into an opaque 500.
        ironauth_store::StoreError::Conflict => {
            ApiError::Conflict("token_exists: a token with this digest already exists".to_owned())
        }
        // EVERYTHING ELSE IS THE SERVER'S, so the sweep that looks for a 500 can see it.
        _ => ApiError::Internal,
    }
}

/// Refuse an organization that is present but DISABLED.
///
/// THE SAME CHECK THE CREATE CARRIES, extracted so both doors share one definition rather than
/// two copies that can drift. `resolve_live_org` fences on `deleted_at` and says nothing about
/// `state`, while `ScimConnectionRepo::authenticate` requires `o.state = 'active'` -- so minting
/// into a disabled organization answers success with a credential that is dead on arrival.
///
/// THE ROTATION LACKED IT AND THE CREATE HAD IT, which is this project's recurring shape: a
/// control installed on one door and claimed for the surface. On the rotation it was worse than
/// on the create, because a rotation also SUPERSEDES the working token: re-enabling the
/// organization would find the old credential already lapsed.
///
/// # Errors
///
/// [`ApiError::Conflict`] when the organization is disabled.
async fn require_active_organization(
    state: &AdminState,
    scope: ironauth_store::Scope,
    org_id: &ironauth_store::OrganizationId,
) -> Result<(), ApiError> {
    let organization = state
        .store()
        .management()
        .organizations(scope)
        .get(org_id)
        .await?;
    if organization.state == ironauth_store::OrganizationState::Active {
        return Ok(());
    }
    Err(ApiError::Conflict(
        "organization_disabled: a disabled organization cannot mint a provisioning \
         credential, because the credential would not authenticate"
            .to_owned(),
    ))
}

/// The default overlap between a rotation and the old token's death, in seconds.
///
/// TWENTY-FOUR HOURS. The window has to cover a human noticing a ticket, opening their identity
/// provider's admin console, and pasting a value -- across a weekend, a holiday, or an on-call
/// handover. Minutes would make the default a trap for exactly the customers least able to
/// react, and the failure it produces is silent: provisioning stops, and nobody learns until
/// somebody who left still has access.
const DEFAULT_OVERLAP_SECS: i64 = 86_400;

/// The longest overlap a caller may ask for, in seconds.
///
/// SEVEN DAYS. An overlap is a period in which a credential the operator has decided to replace
/// still works, so it is a window of exposure as well as a grace period. A week is long enough
/// for any handover and short enough that a leaked token is not a standing key.
const MAX_OVERLAP_SECS: i64 = 604_800;

/// The default overlap must be one the handler would accept.
///
/// A COMPILE-TIME ASSERTION, so a default outside the range fails the build rather than every
/// request that omitted `overlap_seconds` -- which is the common case and the one an integration
/// test that always sends the field would never reach.
const _: () = assert!(
    DEFAULT_OVERLAP_SECS >= 0 && DEFAULT_OVERLAP_SECS <= MAX_OVERLAP_SECS,
    "the default SCIM rotation overlap is outside the range the handler accepts"
);

/// A rotation request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RotateScimTokenRequest {
    /// How long the superseded token keeps working, in seconds. Defaults to 24 hours; 7 days is
    /// the maximum.
    #[serde(default)]
    pub overlap_seconds: Option<i64>,
}

/// The 200 of a rotation: the ONLY response that carries the new token.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScimTokenRotated {
    /// The `scim_` handle, unchanged. A rotation is not a new connection: everything keyed on
    /// this id survives it.
    pub id: String,
    /// The new bearer token. RETURNED ONCE, like the create's: the store keeps only a digest.
    ///
    /// OPTIONAL AND OMITTED ON A REPLAY, rather than an empty string. The create's field is
    /// shaped this way and the first version of this one was not: a replay body carrying
    /// `"token": ""` publishes a field that LOOKS like a credential of length zero, and a client
    /// checking `if (body.token)` and one checking `if ("token" in body)` disagree about it.
    /// Absent means absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// When the superseded token stops working, in milliseconds since the epoch.
    ///
    /// READ BACK FROM THE WRITE, not computed here: the rotation applies
    /// `LEAST(existing, now + overlap)`, so a token that already lapsed sooner keeps its own
    /// horizon and the requested overlap is an upper bound rather than the answer.
    ///
    /// Absent if the rotation superseded no token that has a horizon at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_token_expires_at_unix_ms: Option<i64>,
    /// Whether the token was already issued on an earlier identical request.
    ///
    /// A replay cannot return the token -- nothing stores it -- so it says so rather than
    /// returning a body that looks like a rotation with a missing field. Same shape, and same
    /// reason, as the create's.
    pub token_already_issued: bool,
}

/// The 201 of a create: the ONLY response that carries the token.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScimConnectionCreated {
    /// The non-secret handle.
    pub id: String,
    /// The operator-facing label.
    pub display_name: String,
    /// The bearer token, present exactly once. Absent on an idempotent replay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Whether the token was already issued on an earlier identical request.
    ///
    /// A replay cannot return the token -- nothing stores it -- so it says so rather than
    /// returning a body that looks like a create with a missing field.
    pub token_already_issued: bool,
}

/// Microseconds to milliseconds, the unit every admin view publishes.
///
/// `pub(crate)` because the outbound SCIM module publishes the same timestamps and had a
/// byte-identical copy. One conversion, so a change to the published unit cannot reach one
/// surface and miss the other.
pub(crate) fn micros_to_millis(micros: i64) -> i64 {
    micros / 1_000
}

fn view(
    connection: &ironauth_store::ScimConnection,
    now_micros: i64,
    warning_lead_secs: u64,
) -> ScimConnectionView {
    let soonest = connection.soonest_token_expiry_unix_micros;
    // THE COUNTDOWN IS ABOUT A CREDENTIAL THAT STILL WORKS. Without this a connection that
    // cannot authenticate at all reported BOTH signals at once -- "provisioning has stopped"
    // beside "it is about to stop" -- because the horizon is read off the token rows and they
    // outlive whatever killed the connection. A lapsed connection, and one whose organization
    // was disabled, each showed a live countdown on a credential nothing would accept.
    //
    // It also subsumes revocation, which is why there is no `!revoked` here: a revoked
    // connection counts no live credential, so the warning is already off. Writing both would
    // be a guard that cannot fail, of which this file has had several.
    let live = connection.live_token_count > 0;
    // AND `no_live_token` STILL EXCEPTS REVOCATION, which the count cannot express: a revoked
    // connection genuinely has no usable credential, but announcing that is noise on the one row
    // whose state `revoked_at_unix_ms` already explains. The operator switched this one off.
    let revoked = connection.revoked;
    ScimConnectionView {
        id: connection.id.to_string(),
        display_name: connection.display_name.clone(),
        provider: connection.provider.clone(),
        expires_at_unix_ms: connection.expires_at_unix_micros.map(micros_to_millis),
        revoked_at_unix_ms: connection.revoked_at_unix_micros.map(micros_to_millis),
        soonest_token_expiry_unix_ms: soonest.map(micros_to_millis),
        token_expiring_soon: live && expiring_soon(soonest, now_micros, warning_lead_secs),
        no_live_token: !revoked && !live,
    }
}

/// Whether `soonest` falls inside the warning lead time from `now`.
///
/// # What it is given, which is what makes it simple
///
/// `soonest` is the earliest horizon among the connection's LIVE tokens -- the store excludes
/// both revoked and already-lapsed rows -- so this never sees a past timestamp and has no
/// already-lapsed case to reason about.
///
/// AN EARLIER VERSION DID, and answered `true` for a past expiry on the theory that a warning
/// must not go quiet at the moment provisioning breaks. The theory was right and the design was
/// wrong: because a rotation supersedes a token WITHOUT revoking it and nothing sweeps the row,
/// every rotated connection then warned forever and hid its real next horizon behind a dead
/// one. "Provisioning has already stopped" is a different fact, and it is reported by
/// `no_live_token` rather than smuggled into a countdown.
///
/// A ZERO LEAD is the operator turning warnings off, so nothing is ever expiring. No horizon at
/// all is the ordinary state of a connection whose token does not expire.
fn expiring_soon(soonest_micros: Option<i64>, now_micros: i64, lead_secs: u64) -> bool {
    if lead_secs == 0 {
        return false;
    }
    let Some(soonest) = soonest_micros else {
        return false;
    };
    // SATURATING, because a lead time of a year in microseconds is comfortably inside i64 but
    // the addition is still arithmetic on a caller-supplied clock, and a wrap would silently
    // invert the comparison.
    let lead_micros = i64::try_from(lead_secs)
        .unwrap_or(i64::MAX)
        .saturating_mul(1_000_000);
    soonest <= now_micros.saturating_add(lead_micros)
}

/// `GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections`
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections",
    operation_id = "listScimConnections",
    tag = "scim",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ListQuery
    ),
    responses(
        (status = 200, description = "A page of the organization's SCIM connections", body = ScimConnectionListView),
        (status = 400, description = "Malformed cursor or limit", body = crate::error::ErrorBody),
        (status = 401, description = "Missing or invalid management credential", body = crate::error::ErrorBody),
        (status = 403, description = "The credential may not read this organization", body = crate::error::ErrorBody),
        (status = 404, description = "No such live organization", body = crate::error::ErrorBody),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_scim_connections(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // READ, not write credentials: a listing carries no digest and no plaintext, so it is a
    // strictly smaller capability than minting one.
    principal.require_permission(ManagementPermission::Read)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;
    // CURSOR PAGINATED, like every sibling listing on this surface. It was not, and an
    // organization's whole inventory came back in one response however large it had grown;
    // `MANAGEMENT_LIST_HARD_CAP` is the bound nothing was applying.
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let connections = state
        .store()
        .scoped(scope)
        .scim_connections()
        .list_for_organization(
            &org_id,
            page.fetch_limit(),
            page.after(),
            state.now_unix_micros(),
        )
        .await
        .map_err(|_| ApiError::Internal)?;
    let (connections, next_cursor) = page.finish(connections, |connection| {
        (connection.created_at_unix_micros, connection.id.to_string())
    });
    let body = serde_json::to_string(&ScimConnectionListView {
        items: connections
            .iter()
            .map(|connection| {
                view(
                    connection,
                    state.now_unix_micros(),
                    state.scim_token_expiry_warning_secs(),
                )
            })
            .collect(),
        next_cursor,
    })
    .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Check what a create names, and return the expiry in micros.
///
/// VALIDATED HERE, not by catching the database's refusal. The provider column carries a closed
/// vocabulary, and an earlier version mapped every `StoreError::Database` onto a 400 naming that
/// field -- so a revoked INSERT grant, a full disk, or a failed idempotency write all told the
/// caller their provider was wrong. A reviewer drove it: revoking `INSERT ON scim_connections`
/// produced `400 invalid_provider`, where `api_keys.rs` under the same revocation produces a 500.
///
/// That mattered beyond the message. `no_management_operation_answers_a_server_error_...` sweeps
/// for exactly the missing-grant case, and a handler that answers 400 to it passes the sweep
/// while being broken.
///
/// THE EXPIRY MUST BE IN THE FUTURE. A past one was accepted and minted a credential that never
/// authenticated: `authenticate` filters on `expires_at > now`, so the operator got a 201, a
/// token, and a connection that answered 401 to their identity provider from the first request.
/// Refusing here is the only place that can tell them why, because by the time SCIM fails there
/// is nothing left to distinguish "expired" from "wrong token".
fn validated_create(
    request: &CreateScimConnectionRequest,
    now_micros: i64,
) -> Result<(String, Option<i64>), ApiError> {
    // THE DISPLAY NAME, through the helper 15 admin modules already call. Migration 0183
    // carries `CHECK (display_name <> '')`, and a review drove what happens without this:
    // `{"display_name":""}` reached the INSERT, Postgres refused with SQLSTATE 23514, and
    // `is_unique_violation` is false for a CHECK violation, so it fell through to
    // `ApiError::Internal` -- a 500 on a brand-new route from a one-character body.
    // `input.rs`'s own doc says the helper exists for exactly that reason.
    let display_name = require_non_empty(&request.display_name, "display_name")?;
    // AND BOUNDED ABOVE, which 0183 does not do. A 200 000 character name was accepted and
    // stored; the migration is shipped and checksummed, so the bound lives here. The figure is
    // the schema's own slug ceiling times four, which is far more than an operator label needs
    // and far less than a row worth storing.
    if display_name.len() > MAX_DISPLAY_NAME_BYTES {
        return Err(ApiError::BadRequest(format!(
            "display_name must be at most {MAX_DISPLAY_NAME_BYTES} bytes"
        )));
    }
    if !matches!(request.provider.as_str(), "okta" | "entra" | "generic") {
        return Err(ApiError::BadRequest(
            "invalid_provider: provider must be one of okta, entra, generic".to_owned(),
        ));
    }
    let expires_micros = request
        .expires_at_unix_ms
        .map(|millis| millis.saturating_mul(1_000));
    if let Some(expires) = expires_micros
        && expires <= now_micros
    {
        return Err(ApiError::BadRequest(
            "invalid_expiry: expires_at_unix_ms must be in the future".to_owned(),
        ));
    }
    // AND BOUNDED ABOVE TOO. `saturating_mul` clamps to `i64::MAX` micros, which is in the
    // future and so passed the check above, and then reached
    // `TIMESTAMPTZ 'epoch' + ($8::bigint * INTERVAL '1 microsecond')` -- outside Postgres'
    // timestamp range, which is a 500. A review drove it: `i64::MAX` answered 500 while
    // 900000000000000 answered 201. A bound with only one side is half a bound.
    if let Some(expires) = expires_micros
        && expires > MAX_EXPIRY_UNIX_MICROS
    {
        return Err(ApiError::BadRequest(
            "invalid_expiry: expires_at_unix_ms is further ahead than this server stores"
                .to_owned(),
        ));
    }
    Ok((display_name, expires_micros))
}

/// The longest operator-facing label this route accepts.
///
/// Migration 0183 bounds the column below (non-empty) and not above, and it is shipped and
/// checksummed, so this is where the ceiling lives.
const MAX_DISPLAY_NAME_BYTES: usize = 252;

/// The furthest future expiry this route accepts, in microseconds since the epoch.
///
/// The year 9999, which is inside Postgres' `timestamptz` range with room to spare. Anything
/// past it is a client that computed a date wrong, and answering 400 says so where a 500 does
/// not.
const MAX_EXPIRY_UNIX_MICROS: i64 = 253_402_300_799_000_000;

/// `POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections`
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections",
    operation_id = "createScimConnection",
    tag = "scim",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("Idempotency-Key" = String, Header, description = "Required idempotency key"),
    ),
    request_body = CreateScimConnectionRequest,
    responses(
        (status = 201, description = "The connection, with its token, returned once", body = ScimConnectionCreated),
        (status = 200, description = "An idempotent replay; the token is not returned again", body = ScimConnectionCreated),
        (status = 400, description = "Malformed request, unknown provider, or an expiry that is not in the future", body = crate::error::ErrorBody),
        (status = 401, description = "Missing or invalid management credential", body = crate::error::ErrorBody),
        (status = 403, description = "The credential may not mint credentials for this organization", body = crate::error::ErrorBody),
        (status = 404, description = "No such live organization", body = crate::error::ErrorBody),
        (status = 409, description = "The same Idempotency-Key was used for a different request", body = crate::error::ErrorBody),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_scim_connection(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // WRITE CREDENTIALS, not write organizations, for the reason `api_keys.rs` gives: this
    // mints a credential that provisions INTO the organization, which is strictly higher
    // authority than editing its configuration, and the permission vocabulary separates them.
    principal.require_permission(ManagementPermission::WriteCredentials)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let idem_key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &idem_key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
    let request: CreateScimConnectionRequest = parse_json(&body)?;
    let (display_name, expires_micros) = validated_create(&request, state.now_unix_micros())?;

    // AND THE ORGANIZATION MUST BE ACTIVE, not merely undeleted. `resolve_live_org` fences on
    // `deleted_at` and says nothing about `state`, while `ScimConnectionRepo::authenticate`
    // requires `o.state = 'active'`. Minting into a DISABLED organization therefore answered
    // 201 with a token that authenticated `false` from its very first request -- exactly the
    // shape `validated_create` refuses on the expiry axis, on the other axis. Measured by a
    // reviewer: disable, mint (201, token), present it (401), enable, present it (200).
    //
    // Refused rather than allowed-and-dormant because the alternative reads the same to the
    // operator as a broken credential, and there is nothing at the point of failure that could
    // tell them which it was.
    require_active_organization(&state, scope, &org_id).await?;

    // MINTED THROUGH THE SCIM CRATE, not reimplemented here. `mint_token` and `digest_of` are
    // the format the verifier uses, so a second copy of `{scim_id}.{secret}` in this crate
    // would be two definitions of a credential that must agree byte for byte -- and they would
    // agree until somebody changed one.
    let id = ScimConnectionId::generate(state.env(), &scope);
    let mut secret = [0_u8; 32];
    state.env().entropy().fill_bytes(&mut secret);
    let token = ironauth_scim::server::mint_token(
        &id,
        &base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, secret),
    );
    let digest = ironauth_scim::server::digest_of(&token);

    let created = ScimConnectionCreated {
        id: id.to_string(),
        display_name: display_name.clone(),
        token: Some(token.clone()),
        token_already_issued: false,
    };
    let created_body = serde_json::to_string(&created).map_err(|_| ApiError::Internal)?;

    // The body STORED for replay carries NO token, and replays as 200 rather than 201.
    // `idempotency_keys.response_body` is plaintext retained 24 hours; storing the created
    // body verbatim would put a live provisioning credential there, which is the recoverable
    // copy migration 0183 exists to prevent -- `scim_connections` has no column the plaintext
    // can come back from, and this would have created one in a different table.
    let stored = ScimConnectionCreated {
        id: id.to_string(),
        display_name: display_name.clone(),
        token: None,
        token_already_issued: true,
    };
    let stored_body = serde_json::to_string(&stored).map_err(|_| ApiError::Internal)?;

    let pending = created_event(&state, scope, &id, &org_id, &request.provider);
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization, as every organization-scoped write
        // on this surface does.
        .in_organization(org_id)
        .scim_connections()
        .create_with_event(
            state.env(),
            NewScimConnection {
                id: &id,
                organization_id: &org_id,
                display_name: &display_name,
                provider: &request.provider,
                token_digest: &digest,
                expires_at_unix_micros: expires_micros,
            },
            // IN THE SAME TRANSACTION as the row, which is why it is a parameter rather than a
            // second call: a record written afterwards leaves a window in which the connection
            // exists and the retry that created it can still mint a second one.
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &idem_key,
                request_fingerprint: &fingerprint,
                response_status: 200,
                response_body: &stored_body,
            }),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await;
    match result {
        Ok(()) => {}
        // A unique violation on either the id or the digest. Neither is reachable from this
        // handler, which mints both, but the arm names the case rather than letting it fall
        // into an opaque 500.
        Err(StoreError::Conflict) => {
            return Err(ApiError::Conflict(
                "connection_exists: a connection with this id or token digest already exists"
                    .to_owned(),
            ));
        }
        // The idempotency race the record exists to close: two requests with one key arriving
        // together. A 409 telling the caller to retry, not a 500.
        Err(StoreError::IdempotencyConflict) => return Err(ApiError::IdempotencyKeyConflict),
        // EVERYTHING ELSE IS THE SERVER'S. A database failure is a 500 so the sweep that
        // looks for one can see it, and so a client that retries 5xx does.
        Err(_) => return Err(ApiError::Internal),
    }

    Ok(json(StatusCode::CREATED, created_body))
}

/// `DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections/{connection_id}`
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections/{connection_id}",
    operation_id = "revokeScimConnection",
    tag = "scim",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("connection_id" = String, Path, description = "The scim_ handle"),
    ),
    responses(
        (status = 204, description = "Revoked, or already revoked"),
        (status = 401, description = "Missing or invalid management credential", body = crate::error::ErrorBody),
        (status = 403, description = "The credential may not revoke credentials for this organization", body = crate::error::ErrorBody),
        (status = 404, description = "No such connection in this organization", body = crate::error::ErrorBody),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_scim_connection(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, connection_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteCredentials)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // PRESENT, NOT LIVE, and this is the one route on this surface where the difference
    // matters. A revoke DESTROYS a capability, so it must keep working after the environment
    // is soft-deleted: the row survives the deletion, and an environment that is later
    // restored must not resurrect a credential the operator killed. Requiring liveness to
    // DISARM turns a soft delete into a one-way door, which is the rule `org_context.rs`
    // states and issue #250 measured on the outbound-verification credential.
    //
    // THE PRESENCE HALF IS `resolve_scope`, above, and nothing else. It asks
    // `exists_in_any_state` under the bootstrap operator, which is the addressability check
    // its own comment describes, so an environment that never existed is already the uniform
    // not-found by the time control reaches here. An earlier version of this called
    // `require_present_environment` as well and three comments claimed that call was what made
    // the relaxation "present rather than unchecked". It was not: it is the SAME query with
    // the same arguments two lines later, and a review measured that deleting it left all 80
    // admin test binaries green. A guard that cannot fail is not a guard, and a second
    // round trip per revoke was its only effect.
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;

    // PARSED IN SCOPE, so a handle minted in another tenant is the uniform not-found rather
    // than a distinguishable parse failure.
    let id =
        ScimConnectionId::parse_in_scope(&connection_id, &scope).map_err(|_| ApiError::NotFound)?;
    // AND CHECKED AGAINST THIS ORGANIZATION. The store's revoke is scope-fenced but not
    // organization-fenced, so without this an operator holding write-credentials on one
    // organization could revoke another organization's provisioning connection in the same
    // environment -- a denial of service against a sibling tenant's identity provider.
    //
    // A POINT LOOKUP rather than a scan of the listing. Scanning was correct only while the
    // listing was unbounded; once it took a page limit, a connection past the first page would
    // have become unrevokable, which is the failure that matters most on this route.
    let belongs = state
        .store()
        .scoped(scope)
        .scim_connections()
        .exists_in_organization(&org_id, &id)
        .await
        .map_err(|_| ApiError::Internal)?;
    if !belongs {
        return Err(ApiError::NotFound);
    }

    let now = state.now_unix_micros();
    let pending = revoked_event(&state, scope, &id, &org_id);
    match state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .in_organization(org_id)
        .scim_connections()
        .revoke_with_event(
            state.env(),
            &id,
            now,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await
    {
        // TRUE and FALSE are both 204: revoking a connection that is already revoked is the
        // state the caller asked for, and distinguishing them would make a retry look like a
        // failure. The store writes an audit row only for the first, which is where the
        // distinction belongs.
        Ok(_) => Ok(no_content()),
        Err(StoreError::NotFound) => Err(ApiError::NotFound),
        Err(_) => Err(ApiError::Internal),
    }
}

/// The `scim_connection.created` envelope.
fn created_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    id: &ScimConnectionId,
    organization_id: &ironauth_store::OrganizationId,
    provider: &str,
) -> Option<crate::events::PendingEvent> {
    let event_id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        "scim_connection.created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "scim_connection_id": subject,
            "organization_id": organization_id.to_string(),
            "provider": provider,
        }),
    )?;
    Some(crate::events::PendingEvent {
        id: event_id,
        subject,
        envelope,
    })
}

/// The `scim_connection.revoked` envelope.
fn revoked_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    id: &ScimConnectionId,
    organization_id: &ironauth_store::OrganizationId,
) -> Option<crate::events::PendingEvent> {
    let event_id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        "scim_connection.revoked",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "scim_connection_id": subject,
            "organization_id": organization_id.to_string(),
        }),
    )?;
    Some(crate::events::PendingEvent {
        id: event_id,
        subject,
        envelope,
    })
}

/// The `scim_connection.token_rotated` envelope.
///
/// Returns `None` when the type is unregistered, which is the only reason
/// `event_catalog::envelope` declines; the payload is not validated there, so
/// `the_rotation_envelope_satisfies_its_registered_schema` is where the two are compared.
fn rotated_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    id: &ScimConnectionId,
    organization_id: &ironauth_store::OrganizationId,
    overlap_seconds: i64,
) -> Option<crate::events::PendingEvent> {
    let event_id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        "scim_connection.token_rotated",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &rotated_payload(&subject, &organization_id.to_string(), overlap_seconds),
    )?;
    Some(crate::events::PendingEvent {
        id: event_id,
        subject,
        envelope,
    })
}

/// The `scim_connection.token_rotated` payload, separated so a test can reach it.
fn rotated_payload(
    scim_connection_id: &str,
    organization_id: &str,
    overlap_seconds: i64,
) -> serde_json::Value {
    serde_json::json!({
        "scim_connection_id": scim_connection_id,
        "organization_id": organization_id,
        "overlap_seconds": overlap_seconds,
    })
}

#[cfg(test)]
mod rotation_tests {
    use super::{expiring_soon, rotated_payload, view};
    use ironauth_env::Env;
    use ironauth_store::{
        EnvironmentId, OrganizationId, Scope, ScimConnection, ScimConnectionId, TenantId,
    };

    /// A connection carrying exactly the four fields the view reads, with everything else at a
    /// value that makes no difference to it.
    fn connection(revoked: bool, live_token_count: i64, soonest: Option<i64>) -> ScimConnection {
        let env = Env::system();
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        ScimConnection {
            id: ScimConnectionId::generate(&env, &scope),
            organization_id: OrganizationId::generate(&env, &scope),
            display_name: "acme".to_owned(),
            provider: "okta".to_owned(),
            expires_at_unix_micros: None,
            revoked_at_unix_micros: revoked.then_some(1_699_000_000_000_000),
            revoked,
            live_token_count,
            soonest_token_expiry_unix_micros: soonest,
            created_at_unix_micros: 1_698_000_000_000_000,
        }
    }

    const DAY: i64 = 24 * 60 * 60 * 1_000_000;

    /// The warning fires inside the lead time and not outside it.
    ///
    /// Both directions in one test because either alone is satisfied by a constant: a predicate
    /// that always answered `true` would pass an inside-the-window assertion, and one that
    /// always answered `false` would pass an outside-it assertion.
    #[test]
    fn the_warning_fires_inside_the_lead_time_and_not_outside_it() {
        let now = 1_700_000_000_000_000_i64;
        let lead = 14 * 24 * 60 * 60;
        assert!(
            expiring_soon(Some(now + 13 * DAY), now, lead),
            "a token lapsing inside the lead time is not reported as expiring"
        );
        assert!(
            !expiring_soon(Some(now + 15 * DAY), now, lead),
            "a token lapsing beyond the lead time is reported as expiring, so the warning is \
             always on and says nothing"
        );
    }

    /// The boundary belongs to the warning.
    ///
    /// A token lapsing EXACTLY at the lead time is inside it. The alternative leaves a
    /// one-microsecond window in which the operator is not told, and the cost of being early is
    /// nothing while the cost of being late is provisioning stopping unannounced.
    #[test]
    fn a_token_lapsing_exactly_at_the_lead_time_is_warned_about() {
        let now = 1_700_000_000_000_000_i64;
        let lead = 7 * 24 * 60 * 60;
        assert!(expiring_soon(Some(now + 7 * DAY), now, lead));
        assert!(!expiring_soon(Some(now + 7 * DAY + 1), now, lead));
    }

    /// An ALREADY-LAPSED token keeps warning.
    ///
    /// The obvious implementation is a range check requiring the expiry to be in the future,
    /// and it goes quiet at exactly the moment provisioning breaks -- the column would look
    /// healthy from the instant the thing it warns about happened.
    #[test]
    fn an_already_lapsed_token_still_warns() {
        let now = 1_700_000_000_000_000_i64;
        assert!(
            expiring_soon(Some(now - DAY), now, 14 * 24 * 60 * 60),
            "a token that lapsed yesterday stopped warning, so the listing looks healthy at \
             exactly the moment provisioning is broken"
        );
    }

    /// The two derived signals, each driven against the input that distinguishes it.
    ///
    /// # Why these are unit tests and not HTTP ones
    ///
    /// Because the distinguishing states are unreachable through the API. Revoking a connection
    /// does not touch its token rows, so a revoked connection reached over HTTP has whatever
    /// count the store computes for it, and a test there cannot hold the count fixed while
    /// flipping `revoked`. Here both are inputs.
    ///
    /// Every assertion below has its control: the same fields with one value changed, asserted
    /// to come out the other way. Without them a view that never reported either signal would
    /// satisfy the negative half of each pair.
    #[test]
    fn the_countdown_is_about_a_credential_that_still_works() {
        let now = 1_700_000_000_000_000_i64;
        let lead = 14 * 24 * 60 * 60;
        let imminent = Some(now + DAY);

        // THE CONTROL: a live credential with an imminent horizon warns.
        assert!(
            view(&connection(false, 1, imminent), now, lead).token_expiring_soon,
            "the control: a live connection with an imminent horizon must warn"
        );

        // AND NOTHING LIVE SILENCES IT, however near the horizon on the dead rows. The store
        // reads the horizon off token rows, which outlive whatever killed the connection: a
        // lapsed connection, and one whose organization was disabled, each arrive here with a
        // future horizon and a zero count. Reporting both signals told an operator that
        // provisioning had stopped AND was about to.
        let dead = view(&connection(false, 0, imminent), now, lead);
        assert!(
            !dead.token_expiring_soon,
            "a connection with no usable credential is counting down to the moment it breaks, \
             which has already happened"
        );
        assert!(
            dead.no_live_token,
            "and the signal that IS true of it must still fire, or the row goes quiet entirely"
        );
        // The timestamp itself survives: the suppression is of the derived flag, not of the
        // fact under it.
        assert_eq!(
            dead.soonest_token_expiry_unix_ms,
            imminent.map(super::micros_to_millis),
            "suppressing the countdown must not blank the horizon it was derived from"
        );
    }

    /// Revocation is the one broken state the listing does not announce.
    #[test]
    fn a_revoked_connection_does_not_report_a_lost_credential() {
        let now = 1_700_000_000_000_000_i64;
        let lead = 14 * 24 * 60 * 60;

        // THE CONTROL: the same zero count on an UNREVOKED connection does report it. Only
        // `revoked` differs between the two, so this is the guard and not the count.
        assert!(
            view(&connection(false, 0, None), now, lead).no_live_token,
            "the control: a connection that lost its credentials must say so"
        );
        assert!(
            !view(&connection(true, 0, None), now, lead).no_live_token,
            "a revoked connection is reported as having lost its credentials, which is noise on \
             the one row whose state revoked_at already explains"
        );
    }

    /// A zero lead time turns the warning off, and no horizon means nothing to warn about.
    ///
    /// THE ZERO CASE IS DRIVEN AT EXACTLY `now`, which is the only input that distinguishes the
    /// early return from the arithmetic. For any horizon strictly in the future, the comparison
    /// against a zero lead is already false, so deleting the branch would leave such an
    /// assertion green. A horizon of exactly `now` satisfies the comparison and is refused only
    /// by the branch itself.
    #[test]
    fn a_zero_lead_or_no_horizon_never_warns() {
        let now = 1_700_000_000_000_000_i64;
        assert!(
            !expiring_soon(Some(now), now, 0),
            "the operator disabled warnings and got one anyway: a horizon of exactly now \
             satisfies the comparison, so only the zero branch can refuse it"
        );
        assert!(
            !expiring_soon(Some(now + 1), now, 0),
            "the operator disabled warnings and got one anyway"
        );
        assert!(
            !expiring_soon(None, now, 14 * 24 * 60 * 60),
            "a connection whose tokens have no horizon was reported as expiring"
        );
    }

    /// An enormous lead time does not wrap into `false`.
    ///
    /// The lead arrives as a `u64` of seconds from configuration and is multiplied by a million.
    /// Config load caps it at a year, but this function is the one that must not invert its
    /// comparison if that cap ever moves or a caller passes something else.
    #[test]
    fn an_enormous_lead_saturates_rather_than_wrapping() {
        let now = 1_700_000_000_000_000_i64;
        assert!(
            expiring_soon(Some(now + 365 * DAY), now, u64::MAX),
            "a huge lead time wrapped and inverted the comparison"
        );
    }

    /// The envelope this producer mints satisfies the schema the fan-out enforces.
    ///
    /// THE ONLY PLACE THE TWO ARE COMPARED. `event_catalog::envelope` answers `None` for an
    /// unregistered TYPE and never reads the payload, so a mismatch is committed with the
    /// rotation and then refused by the fan-out forever: not a dropped event but a stuck one.
    #[test]
    fn the_rotation_envelope_satisfies_its_registered_schema() {
        let payload = rotated_payload("scim_x", "org_x", 86_400);
        let envelope = ironauth_store::event_catalog::envelope(
            "evt_x",
            "scim_connection.token_rotated",
            "ten_x",
            "env_x",
            1_700_000_000_000,
            &payload,
        )
        .expect("scim_connection.token_rotated is registered");
        ironauth_store::event_catalog::validate_event(&envelope).unwrap_or_else(|error| {
            panic!("the rotation envelope is refused by the fan-out's own validation: {error:?}")
        });
    }
}
