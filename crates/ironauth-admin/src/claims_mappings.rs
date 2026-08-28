// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment, per-client declarative claim mapping management (issue #113).
//!
//! Set (create or overwrite), get, and delete the ordered rule list that shapes a client's
//! tokens. A mapping is a CONTROL-plane resource: the plane that mints tokens may read one and
//! must never write one, because a data plane that could write itself a mapping and then honour
//! it is a privilege escalation with no audit trail.
//!
//! # Every write is validated before it is stored, and every REFUSAL is audited
//!
//! `ironauth_oidc::claims_mapping::validate` is the one fence: a rule may not write any of the
//! twenty-five names the mint treats as issuer-set, which include `iss`, `sub`, `aud`, `exp` and
//! `iat`. (Twenty-five is the union, not five plus twenty-five.)
//!
//! It bounds the NAME and not the COUNT: a thirty-three-rule document passes `validate` and is
//! refused by the table's CHECK constraint, which surfaces as a 500 rather than an audited 400.
//! That is a real gap and it is #113's, not this module's -- closing it means teaching the write
//! path to read a check violation, which is a change to a shared helper's contract. A refusal
//! is a loud 400 naming the rule INDEX and the claim, never a value, and nothing is written.
//!
//! And the refusal is written to the audit log. Criterion 5 asks that attempts to override a
//! protected claim are "rejected AND AUDITED", and those are two requirements: a rejection
//! nobody can see afterwards is indistinguishable from an attempt that was never made. An
//! operator trying to make `sub` say something else is exactly the event an auditor is looking
//! for, and it is the one event a validate-then-write path naturally throws away.
//!
//! The audit row names the client and a short reason token. It does not carry the rules, because
//! a document refused for stating a protected claim is precisely the thing not to copy onto an
//! audit stream.
//!
//! # Why the request body is a raw JSON value
//!
//! `ironauth-admin` would otherwise need its own definition of a rule, which is a SECOND
//! definition of one wire format -- the drift criterion 5 exists to prevent. `claims_mapping`
//! owns the shape; this parses against it and reports what it could not read.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_oidc::claims_mapping::{self, MappingRefusal};
use ironauth_store::{ClientId, CorrelationId, Scope};

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{ClaimsMappingView, SetClaimsMappingRequest};

/// Resolve and authorize the `(tenant, environment)` scope from the path. The operator passes; a
/// management key must be scoped to exactly this environment. A malformed tenant or environment
/// id is the uniform not-found.
async fn resolve_scope(
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
        .environments(state.bootstrap_operator_id(), tenant)
        .parse_id(environment_id)?;
    // Issue #185: the caller's OPERATOR fences the pair. `tenants` and `environments` sit ABOVE
    // row-level security, so without this a caller naming another operator's tenant reaches that
    // tenant's environments and everything under them.
    if !state
        .store()
        .management()
        .environments(state.bootstrap_operator_id(), tenant)
        .exists_in_any_state(&environment)
        .await
        .map_err(|_| ApiError::Internal)?
    {
        return Err(ApiError::NotFound);
    }
    let actor = principal.require_environment(tenant, environment)?;
    Ok((Scope::new(tenant, environment), actor))
}

/// Normalize the `{client_id}` path parameter to a validated, in-scope client id.
///
/// A malformed or cross-scope id is the uniform not-found: a mapping can be keyed only on a
/// client of this scope, so anything else names no installable mapping.
fn parse_client_id(raw: &str, scope: Scope) -> Result<ClientId, ApiError> {
    ClientId::parse_in_scope(raw, &scope).map_err(|_| ApiError::NotFound)
}

/// The machine-stable reason token an audited refusal records.
///
/// A short token rather than the message, because an audit stream is queried: an auditor asking
/// "how often does someone try to override a protected claim" needs a value to group by, not a
/// sentence to substring-match. `unreadable` covers a document that is not a rule list at all.
fn refusal_reason(refusal: &MappingRefusal) -> &'static str {
    use ironauth_oidc::claims_mapping::RefusalReason;
    match refusal.reason {
        RefusalReason::Reserved => "reserved_claim",
        RefusalReason::EmptyName => "empty_claim_name",
        RefusalReason::Untrimmed => "untrimmed_claim_name",
        RefusalReason::NameTooLong => "claim_name_too_long",
        // UNREACHABLE from this surface: `validate` carries no count bound, so only
        // `filter_hook_claims` produces this. Kept because the match is exhaustive and the
        // alternative is a catch-all arm that would give a future reason the wrong token
        // silently -- which is the one thing the distinctness test exists to prevent.
        RefusalReason::TooManyClaims => "too_many_claims",
        // The `cel` rule's three (issue #113 criterion 2). The first two ARE reachable from
        // this surface and are the point of it: `validate` compiles every expression against
        // the cost budget, so an operator who writes one too expensive to run learns it here,
        // in a 400 they read, rather than from failed logins.
        //
        // Separate tokens for separate operator actions, which is what this function is for:
        // an auditor grouping by reason can tell "someone is writing expressions we refuse to
        // run" from "someone has a typo", and those want different responses.
        RefusalReason::ExpressionUncompilable => "expression_uncompilable",
        RefusalReason::ExpressionOverBudget => "expression_over_budget",
        // The two SIZE refusals, distinct from the cost one because the operator's next action
        // differs: over budget means "flatten it or declare the cardinality you have", too
        // long means "this is not a mapping rule any more".
        RefusalReason::ExpressionTooLong => "expression_too_long",
        RefusalReason::DeclaredCardinalityTooLarge => "declared_cardinality_too_large",
        // UNREACHABLE from this surface, like `too_many_claims` above and for the same kind of
        // reason: it is the one `cel` refusal that is a RUNTIME event. It needs a claim set,
        // and `validate` has none -- it decides what a rule would do, not what it did.
        RefusalReason::ExpressionFailed => "expression_failed",
    }
}

/// Set (create or overwrite) a per-environment, per-client declarative claim mapping.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/claims-mapping",
    operation_id = "setClaimsMapping",
    tag = "claims-mappings",
    request_body = SetClaimsMappingRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the rules shape")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Set", body = ClaimsMappingView),
        (status = 400, description = "A rule that is unreadable or that writes a protected claim", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found or malformed client id", body = ErrorBody)
    )
)]
pub async fn set_claims_mapping(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // A mapping write changes the SHAPE OF EVERY TOKEN this client is issued -- which claims it
    // carries, under what names, in which token -- so it demands fresh privilege exactly like
    // the other environment-scoped management writes.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let client = parse_client_id(&client_id, scope)?;
    crate::org_context::require_live_environment(&state, &scope).await?;

    let request: SetClaimsMappingRequest = parse_json(&body)?;
    let rules_json = serde_json::to_string(&request.rules).map_err(|_| ApiError::Internal)?;

    let acting = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()));

    // PARSE, then VALIDATE, and audit either refusal. Two separate failures with two separate
    // reasons: a document this version cannot read is a different operator problem from a rule
    // that names a protected claim, and an audit stream that collapsed them could not tell an
    // integration bug from an override attempt.
    //
    // The audit write is `?`-propagated, so a store fault turns what would be a 400 into a 500.
    // That is deliberate and it is the uncomfortable direction: criterion 5 asks for "rejected
    // AND audited", and answering 400 when the audit did not land would report both while
    // delivering one. An operator retries a 500; nobody retrieves an audit row that was never
    // written. Stated here because it is a surprising status code for a validation error, and
    // the surprise is the cost of the conjunction.
    let rules = match claims_mapping::parse(&rules_json) {
        Ok(rules) => rules,
        Err(error) => {
            acting
                .claims_mappings()
                .record_refusal(state.env(), &client, "unreadable")
                .await?;
            return Err(ApiError::BadRequest(format!(
                "the rules could not be read as a rule list: {error}"
            )));
        }
    };
    if let Err(refusal) = claims_mapping::validate(&rules) {
        acting
            .claims_mappings()
            .record_refusal(state.env(), &client, refusal_reason(&refusal))
            .await?;
        return Err(ApiError::BadRequest(refusal.to_string()));
    }

    let pending = claims_mapping_set_event(&state, scope, &client_id);
    acting
        .claims_mappings()
        .set_with_event(
            state.env(),
            &client,
            &rules_json,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;

    let view = ClaimsMappingView {
        client_id: client.to_string(),
        rules: request.rules,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Get a per-environment, per-client declarative claim mapping.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/claims-mapping",
    operation_id = "getClaimsMapping",
    tag = "claims-mappings",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the rules shape")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The claim mapping", body = ClaimsMappingView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found, malformed client id, or no mapping installed", body = ErrorBody)
    )
)]
pub async fn get_claims_mapping(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    principal.require_permission(ManagementPermission::Read)?;
    let client = parse_client_id(&client_id, scope)?;

    let record = state
        .store()
        .scoped(scope)
        .claims_mappings()
        .get(&client.to_string())
        .await?
        .ok_or(ApiError::NotFound)?;
    // A stored document is validated on write, so a parse fault here is a real persistence
    // corruption rather than a client fault.
    let rules: serde_json::Value =
        serde_json::from_str(&record.rules_json).map_err(|_| ApiError::Internal)?;
    let view = ClaimsMappingView {
        client_id: record.client_id,
        rules,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Delete a per-environment, per-client declarative claim mapping.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/claims-mapping",
    operation_id = "deleteClaimsMapping",
    tag = "claims-mappings",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the rules shape")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found, malformed client id, or no mapping installed", body = ErrorBody)
    )
)]
pub async fn delete_claims_mapping(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // Deleting a mapping RESTORES THE UNMAPPED TOKEN, and that changes what every token this
    // client is issued carries -- in BOTH directions. Claims the mapping filtered out come back
    // to the ID token, and a claim it had PLACED in the access token stops reaching one, so a
    // resource server authorizing on it starts refusing. Either direction is a change to the
    // shape of every token, which is why it demands fresh privilege exactly as the write does.
    //
    // (An earlier version of this comment said the claims "appear in both". That was true of a
    // default placement of `Both`, which review measured as a widening and which is gone.)
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let client = parse_client_id(&client_id, scope)?;
    crate::org_context::require_live_environment(&state, &scope).await?;

    let pending = claims_mapping_deleted_event(&state, scope, &client_id);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .claims_mappings()
        .delete(
            state.env(),
            &client,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(no_content())
}

/// The event a claim-mapping write emits (issue #108).
///
/// Carries the CLIENT and not the rules. The client is the stable address (this table has no id
/// of its own and the write is an upsert keyed on it), and the rules are configuration a consumer
/// refetches: an event embedding them would put the whole document on every subscribing stream.
fn claims_mapping_set_event(
    state: &AdminState,
    scope: Scope,
    client_id: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "claims_mapping.set",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "client_id": client_id }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        // The stable address is the subject, so two events about one record stay ordered.
        subject: client_id.to_owned(),
        envelope,
    })
}

/// The event a claim-mapping delete emits (issue #108).
fn claims_mapping_deleted_event(
    state: &AdminState,
    scope: Scope,
    client_id: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "claims_mapping.deleted",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "client_id": client_id }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject: client_id.to_owned(),
        envelope,
    })
}

#[cfg(test)]
mod tests {
    use super::refusal_reason;
    use ironauth_oidc::claims_mapping::{MappingRefusal, RefusalReason};

    /// Every refusal reason maps to a DISTINCT token.
    ///
    /// An audit stream is queried by grouping on this value, so two reasons sharing a token make
    /// an integration bug and a protected-claim override attempt indistinguishable to whoever is
    /// looking. Asserting distinctness rather than the individual strings, because the strings
    /// are arbitrary and the property is not.
    #[test]
    fn every_refusal_reason_has_its_own_token() {
        // EVERY variant, listed here rather than sampled: the point of the test is that no two
        // share a token, and a list that omits one cannot see the collision it introduces.
        //
        // NOTHING ENFORCES THAT THIS LIST IS COMPLETE, and saying so is the point of this
        // paragraph. An earlier version claimed the exhaustive match in `refusal_reason` did
        // it ("a new variant fails the build"): that forces a new ARM, in a different file,
        // and nothing brings the author back here. Measured -- five variants were added for
        // the `cel` rule and this list kept its original five, so a collision among the new
        // ones would have been invisible.
        //
        // The `assert_eq!` below compares `distinct` against `reasons.len()`, which is this
        // list against ITSELF: it catches two entries sharing a token and cannot catch an
        // entry that is missing. Rust has no way to iterate an enum's variants without a
        // derive this workspace does not carry, so the completeness of this list is a reading
        // discipline, and a reader who does not know that will trust it further than it goes.
        // ADD EVERY NEW VARIANT HERE when you add its arm to `refusal_reason`.
        let reasons = [
            RefusalReason::Reserved,
            RefusalReason::EmptyName,
            RefusalReason::Untrimmed,
            RefusalReason::NameTooLong,
            RefusalReason::TooManyClaims,
            RefusalReason::ExpressionUncompilable,
            RefusalReason::ExpressionOverBudget,
            RefusalReason::ExpressionTooLong,
            RefusalReason::DeclaredCardinalityTooLarge,
            RefusalReason::ExpressionFailed,
        ];
        let mut tokens: Vec<&'static str> = reasons
            .iter()
            .map(|&reason| {
                refusal_reason(&MappingRefusal {
                    rule_index: 0,
                    claim: "irrelevant".to_owned(),
                    reason,
                })
            })
            .collect();
        let distinct = {
            let mut sorted = tokens.clone();
            sorted.sort_unstable();
            sorted.dedup();
            sorted.len()
        };
        assert_eq!(
            distinct,
            reasons.len(),
            "two reasons share an audit token: {tokens:?}"
        );
        tokens.retain(|token| token.is_empty() || token.contains(' '));
        assert!(
            tokens.is_empty(),
            "a token is grouped on, so it must be a single machine-stable word: {tokens:?}"
        );
    }
}
