// SPDX-License-Identifier: MIT OR Apache-2.0

//! The EXPLORATORY time-boxed access-request surface (issue #145 criterion 4).
//!
//! Three routes: raise a request, list them, decide one. Behind the
//! `access-request-approval` experimental feature, so an unacknowledged deployment gets a
//! uniform 404 from all three and learns nothing about what this build can do.
//!
//! # What is enforced here, and what is not
//!
//! The refusal of a self-approval happens THREE times, and only the last of them makes the
//! criterion's word "impossible" true:
//!
//! 1. here, as a 422 naming the rule, so a person gets a sentence;
//! 2. in the repository, as `StoreError::SelfApproval`, so any other Rust caller does too;
//! 3. in Postgres, as `access_grant_requests_decider_is_not_requester`, on every INSERT
//!    and UPDATE from every connection including the owner's.
//!
//! Only the third holds for a path nobody has written yet. The first two exist because a
//! constraint violation surfacing as a 500 tells the person nothing.
//!
//! ALL THREE COMPARE PRINCIPALS, NOT PEOPLE. `credential_ref()` is a credential's actor id:
//! a management key has one per key and a console session has a subject-derived human id,
//! and nothing binds two credentials to one human. One person holding two management keys
//! raises under the first and decides under the second, and all three layers pass because
//! the strings genuinely differ. Closing that would need a credential-to-person binding
//! this deployment does not have, so the bound is stated wherever the rule is published
//! and measured by a test rather than left for somebody to discover.
//!
//! # Why the deadline is a DURATION on the decision
//!
//! The approver decides how long, not the requester, and they decide it as a duration
//! rather than an instant. An instant would let a clock disagreement between caller and
//! server turn "one hour" into a week, and the bound below could not tell the difference.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::org_context::{EnvironmentAccess, resolve_live_org, resolve_scope};
use crate::response::json;
use crate::state::AdminState;
use ironauth_store::CorrelationId;

/// What an access-request announcement is about.
///
/// A struct rather than four `&str` parameters, for the reason [`NewAccessRequest`] gives:
/// a transposition among same-typed arguments would announce the wrong subject under the
/// wrong role and nothing downstream could detect it.
struct EventSubject<'a> {
    request_id: &'a str,
    organization_id: &'a str,
    subject_id: &'a str,
    role_slug: &'a str,
}

/// Build the announcement for one access-request change.
///
/// [`None`] when the payload does not validate against the registered schema, which is how
/// every producer here behaves: the write still happens and the event is dropped rather
/// than shipping an envelope a consumer's validator would refuse.
fn access_request_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    what: &EventSubject<'_>,
    decision: Option<(bool, Option<i64>)>,
    event_type: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = what.request_id.to_owned();
    let mut payload = serde_json::json!({
        "access_request_id": subject,
        "organization_id": what.organization_id,
        "subject_id": what.subject_id,
        "role_slug": what.role_slug,
    });
    if let Some((approved, granted_until_unix_ms)) = decision {
        payload["approved"] = serde_json::json!(approved);
        // ABSENT ON A DENIAL, never zero. A consumer reading a deadline out of a refusal
        // would schedule a revocation for a grant that never existed.
        if let Some(until) = granted_until_unix_ms {
            payload["granted_until_unix_ms"] = serde_json::json!(until);
        }
    }
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &payload,
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}

/// The longest an approval may grant for.
///
/// Thirty days. A bound rather than no bound, because an approval measured in years is the
/// standing access this primitive exists to replace and nothing else here would refuse it.
/// Not configurable in the exploratory: an operator who can raise the ceiling has the same
/// standing access back, and the right conversation to have first is whether the ceiling is
/// wrong for everyone.
pub const MAX_GRANT_SECS: u64 = 30 * 24 * 60 * 60;

/// The longest reason a request may carry, in bytes.
const MAX_REASON_BYTES: usize = 1024;

/// The most requests one listing returns.
const LIST_LIMIT: i64 = 200;

/// What a member asks for.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RaiseAccessRequestBody {
    /// Who would receive the access. Not necessarily the caller: a manager may ask on
    /// behalf of somebody else.
    pub subject_id: String,
    /// Which organization role.
    pub role_slug: String,
    /// Why, in the requester's words.
    pub reason: String,
}

/// What an approver decides.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DecideAccessRequestBody {
    /// Whether to grant.
    pub approve: bool,
    /// How long the grant lasts, in seconds. Required for an approval and refused for a
    /// denial: an approval IS a grant with an end.
    pub grant_secs: Option<u64>,
}

/// One request, as the API reports it.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccessRequestView {
    /// The `agr_` identifier.
    pub id: String,
    /// Whose roles are at stake.
    pub organization_id: String,
    /// Who would receive the access.
    pub subject_id: String,
    /// Which role.
    pub role_slug: String,
    /// Who asked.
    pub requested_by: String,
    /// Why.
    pub reason: String,
    /// `pending`, `approved`, `denied` or `expired`.
    pub state: String,
    /// Whether the grant is live AT THE MOMENT OF THE READ.
    ///
    /// Not derivable from `state` by a reader: an approved grant past its deadline still
    /// reads `approved` until a sweep relabels it, and it grants nothing from the instant
    /// the deadline passes. This field is the answer to "may they act", and `state` is the
    /// answer to "what happened".
    pub granting_now: bool,
    /// Who decided, or absent while pending.
    pub decided_by: Option<String>,
    /// When the grant ended or will end, in epoch milliseconds.
    ///
    /// Present on an APPROVED row and on an EXPIRED one, absent on pending and denied.
    /// An expired row keeps it deliberately: it is the only record of how long the member
    /// actually held the role, which is the second question an auditor asks.
    pub granted_until_unix_ms: Option<i64>,
    /// When it was raised, in epoch milliseconds.
    pub created_at_unix_ms: i64,
}

/// A page of requests.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccessRequestList {
    /// The requests, newest first.
    pub items: Vec<AccessRequestView>,
    /// Whether the listing was cut at its bound.
    pub truncated: bool,
}

fn view(
    request: ironauth_store::access_request::AccessGrantRequest,
    now_micros: i64,
) -> AccessRequestView {
    AccessRequestView {
        granting_now: request.grants_now(now_micros),
        id: request.id,
        organization_id: request.organization_id,
        subject_id: request.subject_id,
        role_slug: request.role_slug,
        requested_by: request.requested_by,
        reason: request.reason,
        state: request.state.as_str().to_owned(),
        decided_by: request.decided_by,
        granted_until_unix_ms: request.granted_until_micros.map(|micros| micros / 1000),
        created_at_unix_ms: request.created_at_micros / 1000,
    }
}

/// The uniform not-found an unacknowledged deployment gets from every route here.
fn armed(state: &AdminState) -> Result<(), ApiError> {
    if state.access_requests_enabled() {
        return Ok(());
    }
    // NOT a 503 naming the feature. A deployment that has not acknowledged the shape
    // should not learn from us that this build has one: the answer is the same one an
    // unmounted route gives.
    Err(ApiError::NotFound)
}

/// Refuse a request whose subject or role would make the grant meaningless.
///
/// Split out for the crate's function-length bound, and the two checks belong together:
/// each is the same shape, a field that is well formed and names nothing.
async fn require_grantable(
    state: &AdminState,
    scope: ironauth_store::Scope,
    org_id: &ironauth_store::OrganizationId,
    body: &RaiseAccessRequestBody,
) -> Result<(), ApiError> {
    // THE SUBJECT MUST BE A LIVE MEMBER of this organization.
    //
    // A grant for a non-member confers nothing -- the resolution closure seeds only on a
    // live active membership, so the fourth arm yields no row for them -- and that is
    // exactly why refusing it here matters: without this an approver agrees to an
    // elevation, the request reads `approved` in every listing, and the subject's
    // authorization is unchanged. Nobody downstream can tell the difference between that
    // and a grant that worked.
    //
    // `for_user_in_org` checks the USER's tombstone as well as the membership's, so a
    // request for somebody who has been deleted is refused with the rest.
    let subject = ironauth_store::UserId::parse_in_scope(&body.subject_id, &scope)
        .map_err(|_| ApiError::Unprocessable("subject_id is not a user id".into()))?;
    if state
        .store()
        .management()
        .org_memberships(scope)
        .for_user_in_org(org_id, &subject)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_none()
    {
        return Err(ApiError::Unprocessable(
            "the subject is not a live member of this organization, so a grant would \
             confer nothing"
                .into(),
        ));
    }

    // PAGED THROUGH, not one page. An earlier version read `max_page_size` roles and
    // refused anything past the boundary, so an organization with more roles than a page
    // could not request its own later ones -- a refusal that reads exactly like a typo and
    // is not one.
    let mut cursor = None;
    let mut defined = false;
    loop {
        let page = state
            .store()
            .scoped(scope)
            .org_roles()
            .list_for_org(org_id, i64::from(state.max_page_size()), cursor.as_ref())
            .await
            .map_err(|_| ApiError::Internal)?;
        if page.is_empty() {
            break;
        }
        if page.iter().any(|role| role.slug == body.role_slug) {
            defined = true;
            break;
        }
        cursor = page.last().map(|role| ironauth_store::CursorPosition {
            created_at_unix_micros: role.created_at_unix_micros,
            id: role.id.to_string(),
        });
        if cursor.is_none() {
            break;
        }
    }
    if !defined {
        return Err(ApiError::Unprocessable(format!(
            "no role {} in this organization",
            body.role_slug
        )));
    }
    Ok(())
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/access-requests",
    operation_id = "raiseAccessRequest",
    tag = "organizations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier")
    ),
    request_body = RaiseAccessRequestBody,
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The request was raised and is awaiting a decision", body = AccessRequestView),
        (status = 400, description = "A field is empty or too long", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such live organization in this scope, or the exploratory feature is not acknowledged", body = ErrorBody)
    )
)]
pub async fn raise_access_request(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    raw: axum::body::Bytes,
) -> Result<Response, ApiError> {
    armed(&state)?;
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;

    // PARSED ONLY NOW. Taken as `Bytes` and decoded after the scope, the permission and
    // the organization are resolved, because an extractor parses before the handler runs:
    // with `axum::Json` in the signature, a malformed body at a soft-deleted environment
    // answers 400 instead of the uniform not-found, and "this write refuses a dead
    // environment" becomes true only of well-formed requests. `live_surface` measures
    // exactly that ordering.
    let body: RaiseAccessRequestBody = serde_json::from_slice(&raw)
        .map_err(|error| ApiError::BadRequest(format!("invalid request body: {error}")))?;

    // REFUSED HERE rather than left to the CHECK constraints, so the caller is told which
    // field is wrong instead of reading a constraint name out of a 500.
    if body.subject_id.trim().is_empty() {
        return Err(ApiError::BadRequest("subject_id must not be empty".into()));
    }
    if body.role_slug.trim().is_empty() {
        return Err(ApiError::BadRequest("role_slug must not be empty".into()));
    }
    if body.reason.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "reason must not be empty: an approval nobody wrote a reason for is one nobody \
             can review afterwards"
                .into(),
        ));
    }
    if body.reason.len() > MAX_REASON_BYTES {
        return Err(ApiError::BadRequest(format!(
            "reason must be at most {MAX_REASON_BYTES} bytes"
        )));
    }

    // THE ROLE MUST EXIST IN THIS ORGANIZATION, checked rather than assumed.
    //
    // The column's own comment says "a role that must exist in this organization" and
    // nothing established it: `role_slug` is a bare text column with no foreign key, and
    // there cannot be one, because a role is keyed by (organization, slug) and the slug
    // alone does not identify a row. Without this a request could be raised for
    // `billing-admni`, approved by a second principal who reads the same typo, and grant
    // nothing at all -- an elevation that looks granted in every listing and every audit
    // row and confers no access, which is the failure an approver cannot see.
    //
    // Checked at RAISE rather than at decide, so the typo is caught by the person who made
    // it rather than by the person asked to trust it.
    require_grantable(&state, scope, &org_id, &body).await?;

    let id = ironauth_store::AccessRequestId::generate(state.env(), &scope);
    let organization = org_id.to_string();
    let request_id = id.to_string();
    let pending = access_request_event(
        &state,
        scope,
        &EventSubject {
            request_id: &request_id,
            organization_id: &organization,
            subject_id: &body.subject_id,
            role_slug: &body.role_slug,
        },
        None,
        "access_request.raised",
    );
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .in_organization(org_id)
        .access_requests(scope)
        .raise(
            state.env(),
            &id,
            ironauth_store::NewAccessRequest {
                organization_id: &org_id.to_string(),
                subject_id: &body.subject_id,
                role_slug: &body.role_slug,
                requested_by: &principal.credential_ref(),
                reason: &body.reason,
            },
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    let raised = state
        .store()
        .scoped(scope)
        .access_requests()
        .get(&id.to_string())
        .await
        .map_err(|_| ApiError::Internal)?;
    let now = now_micros(&state);
    let body = serde_json::to_string(&view(raised, now)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::CREATED, body))
}

#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/access-requests",
    operation_id = "listAccessRequests",
    tag = "organizations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "This organization's access requests, newest first. `granting_now` is the live answer and `state` is the recorded one; they differ for an approved grant whose deadline has passed and which no sweep has yet relabelled", body = AccessRequestList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such live organization in this scope, or the exploratory feature is not acknowledged", body = ErrorBody)
    )
)]
pub async fn list_access_requests(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    armed(&state)?;
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::Read)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;

    let mut rows = state
        .store()
        .scoped(scope)
        .access_requests()
        .list_for_organization(&org_id.to_string(), LIST_LIMIT + 1)
        .await
        .map_err(|_| ApiError::Internal)?;
    let truncated = i64::try_from(rows.len()).unwrap_or(i64::MAX) > LIST_LIMIT;
    rows.truncate(usize::try_from(LIST_LIMIT).unwrap_or(usize::MAX));

    let now = now_micros(&state);
    let list = AccessRequestList {
        items: rows.into_iter().map(|row| view(row, now)).collect(),
        truncated,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/access-requests/{request_id}/decision",
    operation_id = "decideAccessRequest",
    tag = "organizations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("request_id" = String, Path, description = "The access request identifier")
    ),
    request_body = DecideAccessRequestBody,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The decision was recorded", body = AccessRequestView),
        (status = 400, description = "An approval carried no duration, a denial carried one, or the duration exceeds the ceiling", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 422, description = "This credential raised the request and may not decide it. Refused here in words and by a CHECK constraint on every other path into the table. The rule separates PRINCIPALS: one person holding two credentials can raise under one and decide under the other, and nothing here detects that", body = ErrorBody),
        (status = 404, description = "No such pending request in this organization, or the exploratory feature is not acknowledged", body = ErrorBody)
    )
)]
pub async fn decide_access_request(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, request_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    raw: axum::body::Bytes,
) -> Result<Response, ApiError> {
    armed(&state)?;
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;

    // PARSED ONLY NOW, for the ordering reason given on the raise above.
    let body: DecideAccessRequestBody = serde_json::from_slice(&raw)
        .map_err(|error| ApiError::BadRequest(format!("invalid request body: {error}")))?;

    let grant_secs = match (body.approve, body.grant_secs) {
        (true, Some(secs)) if secs > 0 && secs <= MAX_GRANT_SECS => secs,
        (true, Some(_)) => {
            return Err(ApiError::BadRequest(format!(
                "grant_secs must be between 1 and {MAX_GRANT_SECS}"
            )));
        }
        (true, None) => {
            return Err(ApiError::BadRequest(
                "an approval must say how long it grants for".into(),
            ));
        }
        (false, Some(_)) => {
            return Err(ApiError::BadRequest(
                "a denial grants nothing, so it takes no duration".into(),
            ));
        }
        (false, None) => 0,
    };

    let request_id = ironauth_store::AccessRequestId::parse_in_scope(&request_id, &scope)
        .map_err(|_| ApiError::NotFound)?;

    // ADDRESSED THROUGH ITS ORGANIZATION. The path names one, and a request belonging to a
    // sibling must not be decidable by naming the caller's own: without this the
    // organization segment would be decoration and the id alone would be the authority.
    let existing = state
        .store()
        .scoped(scope)
        .access_requests()
        .get(&request_id.to_string())
        .await
        .map_err(|_| ApiError::NotFound)?;
    if existing.organization_id != org_id.to_string() {
        return Err(ApiError::NotFound);
    }

    let now = now_micros(&state);
    let granted_until = body
        .approve
        .then(|| now.saturating_add(i64::try_from(grant_secs).unwrap_or(0) * 1_000_000));

    let request_id_string = request_id.to_string();
    let pending = access_request_event(
        &state,
        scope,
        &EventSubject {
            request_id: &request_id_string,
            organization_id: &existing.organization_id,
            subject_id: &existing.subject_id,
            role_slug: &existing.role_slug,
        },
        Some((body.approve, granted_until.map(|micros| micros / 1000))),
        "access_request.decided",
    );
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .in_organization(org_id)
        .access_requests(scope)
        .decide(
            state.env(),
            &request_id,
            ironauth_store::AccessDecision {
                approve: body.approve,
                decided_by: &principal.credential_ref(),
                decided_at_micros: now,
                granted_until_micros: granted_until,
            },
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await
        .map_err(|error| match error {
            // THE SENTENCE, rather than a constraint name in a 500. The database refuses
            // this too, on every path; here it is refused in words.
            ironauth_store::StoreError::SelfApproval => ApiError::Unprocessable(
                "the credential that raised an access request may not decide it".into(),
            ),
            ironauth_store::StoreError::NotFound => ApiError::NotFound,
            _ => ApiError::Internal,
        })?;

    let decided = state
        .store()
        .scoped(scope)
        .access_requests()
        .get(&request_id.to_string())
        .await
        .map_err(|_| ApiError::Internal)?;
    let body = serde_json::to_string(&view(decided, now)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// The clock seam, in epoch microseconds.
fn now_micros(state: &AdminState) -> i64 {
    i64::try_from(
        state
            .env()
            .clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
    )
    .unwrap_or(i64::MAX)
}
