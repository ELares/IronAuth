// SPDX-License-Identifier: MIT OR Apache-2.0

//! SESSION TOKENIZER template management (issue #119).
//!
//! Set (create or replace), list, and delete the per-environment templates that convert an opaque
//! session into a short-lived JWT. A template is a CONTROL-plane resource for the reason a claim
//! mapping is one, only more so: it names an AUDIENCE, and the plane that mints tokens must never
//! be the plane that can choose who they are minted for.
//!
//! # Every write is validated BEFORE it is stored, and the refusal is the operator's
//!
//! `ironauth_oidc::session_tokenizer::validate_template` is the one fence, and it is the same
//! fence the mint applies to the document it reads back. A refusal is a 400 naming what was
//! wrong -- which rule, which bound -- and nothing is written.
//!
//! Every bound this surface refuses is ALSO a CHECK on the table, and the ordering is deliberate:
//! the code refuses first so an operator gets a 400 they can act on, and the constraint stands
//! behind it so a hand-edited row cannot reach the mint. `claims_mappings` shipped the other way
//! round on its rule count and its own header records the result: a 500 where a 400 belonged.
//!
//! # No domain event, and that is a decision rather than an omission
//!
//! `challenge_components` emits none either, and for the same reason: the event catalogue is a
//! product surface with its own compatibility rules, and adding an event is a commitment to a
//! payload shape forever. The AUDIT trail carries this write today
//! (`session_token_template.set` / `.delete`), which is what an operator investigating a change
//! reads. An event lands when something needs to react to a template changing.
//!
//! # Why the request body carries the rules as a raw JSON value
//!
//! `ironauth-admin` would otherwise need its own definition of a mapping rule, which is a SECOND
//! definition of one wire format. `claims_mapping` owns the shape, `session_tokenizer` owns which
//! subset of it this surface admits, and this parses against both.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_oidc::session_tokenizer::{self, TemplateError};
use ironauth_store::session_token_store::{
    NewSessionTokenKey, NewSessionTokenTemplate, SESSION_TOKEN_SEED_LEN,
};
use ironauth_store::{CorrelationId, Scope, SessionTokenKeyId};
use serde::Deserialize;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{
    SessionJwtModeView, SessionTokenTemplateView, SessionTokenTemplatesView,
    SetSessionJwtModeRequest, SetSessionTokenTemplateRequest,
};

/// Now, in epoch microseconds, from the environment clock seam.
///
/// The APPLICATION clock and never the database clock, matching how every other lifecycle
/// instant in `signing_keys` and in this table is written: a test that pins the clock has to be
/// able to pin these too.
fn epoch_micros(env: &ironauth_env::Env) -> i64 {
    env.clock()
        .now_utc()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(i64::MAX)
}

/// Resolve the scope and actor, refusing a cross-plane or cross-scope caller.
async fn resolve(
    state: &AdminState,
    principal: &Principal,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(Scope, ironauth_store::ActorRef), ApiError> {
    crate::token_hooks::resolve_scope(state, principal, tenant_id, environment_id).await
}

/// The `{name}` query parameter naming which template to act on.
#[derive(Deserialize)]
pub struct NameQuery {
    /// The template name. REQUIRED and never defaulted: a request that does not say which
    /// template it means is a request nobody can carry out safely, and a default would let a
    /// typo overwrite the wrong one.
    name: Option<String>,
}

/// Turn a template refusal into the 400 an operator reads.
///
/// The message names WHAT was refused and, where the refusal has a position, WHICH rule. An
/// operator with a list of thirty rules should not have to bisect it.
fn refusal_message(error: &TemplateError) -> String {
    match error {
        TemplateError::Name => format!(
            "the template name must be between 1 and {} characters",
            session_tokenizer::MAX_TEMPLATE_NAME_BYTES
        ),
        TemplateError::Audience => format!(
            "an audience is required, and must be at most {} characters",
            session_tokenizer::MAX_AUDIENCE_BYTES
        ),
        TemplateError::Ttl => format!(
            "ttl_seconds must be between {} and {}; it is also the exact window in which a \
             revoked session's already-minted token still verifies",
            session_tokenizer::MIN_TTL_SECONDS,
            session_tokenizer::MAX_TTL_SECONDS
        ),
        TemplateError::Unreadable(detail) => {
            format!("the rules could not be read as a rule list: {detail}")
        }
        TemplateError::TooManyRules { count } => format!(
            "a template may carry at most {} rules; this one carries {count}",
            session_tokenizer::MAX_TEMPLATE_RULES
        ),
        TemplateError::PlacementRule { rule_index } => format!(
            "rule {rule_index} is a `place` rule, which names a token this surface does not \
             mint: a template mints exactly one token, so the rule would never do anything"
        ),
        TemplateError::Mapping(refusal) => refusal.to_string(),
    }
}

/// Create or replace a session tokenizer template.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/session-token-templates",
    operation_id = "setSessionTokenTemplate",
    tag = "session-token-templates",
    request_body = SetSessionTokenTemplateRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("name" = String, Query, description = "The template name a tokenize request selects with `tokenize_as`, and the name in the template's own JWKS URL. REQUIRED: renaming a template breaks both")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Set", body = SessionTokenTemplateView),
        (status = 400, description = "An invalid name, audience, TTL, or rule list", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn set_session_token_template(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<NameQuery>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // FRESH PRIVILEGE. Writing a template decides which audience receives tokens for which
    // subjects, with a claim set an operator chooses, verifiable for the whole TTL with nothing
    // able to withdraw it early. That is at least as consequential as a claim mapping, which
    // demands the same.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    crate::org_context::require_live_environment(&state, &scope).await?;

    let Some(name) = query.name.as_deref() else {
        return Err(ApiError::BadRequest(
            "a template name is required".to_owned(),
        ));
    };
    let request: SetSessionTokenTemplateRequest = parse_json(&body)?;
    let rules_json = serde_json::to_string(&request.rules).map_err(|_| ApiError::Internal)?;
    // VALIDATED BEFORE ANYTHING IS WRITTEN, against the same function the mint runs.
    let template = session_tokenizer::validate_template(
        name,
        &request.audience,
        request.ttl_seconds,
        &rules_json,
    )
    .map_err(|error| ApiError::BadRequest(refusal_message(&error)))?;

    // The template's OWN key. Drawn from the entropy seam, stored as a raw Ed25519 seed, and
    // written in the same transaction as the template, so a template with no key is never
    // reachable. A REPLACE keeps the existing key: see the repository's own doc for why
    // rotation is an operator decision rather than a side effect of raising a TTL.
    let mut seed = [0_u8; SESSION_TOKEN_SEED_LEN];
    state.env().entropy().fill_bytes(&mut seed);
    let key_id = SessionTokenKeyId::generate(state.env(), &scope);
    let now_micros = epoch_micros(state.env());

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .session_token_templates()
        .set(
            state.env(),
            NewSessionTokenTemplate {
                name: template.name(),
                audience: template.audience(),
                ttl_seconds: template.ttl_seconds(),
                rules_json: &rules_json,
            },
            NewSessionTokenKey {
                id: &key_id,
                seed: &seed,
                // PUBLISHED AND ACTIVE AT THE SAME INSTANT, because there is nothing to
                // pre-publish TO: a template's JWKS has no reader until the template exists, so
                // the pre-publication window that protects an issuer rotation would only delay
                // the first mint. When a rotation surface lands, a successor gets a real
                // pre-publication window; a day-one key does not need one.
                publish_at_micros: now_micros,
                activate_at_micros: now_micros,
            },
            tokenizer_event(
                &state,
                scope,
                "session_token_template.set",
                // THE TTL RIDES ALONG because it is the exact width of the window in which a
                // revoked session's already-minted token still verifies. A consumer tracking
                // revocation latency reads this number; refetching to learn it would make the
                // event useless for that. NEVER the rules and never key material.
                &serde_json::json!({
                    "name": template.name(),
                    "audience": template.audience(),
                    "ttl_seconds": template.ttl_seconds(),
                }),
                template.name(),
            )
            .as_ref()
            .map(crate::events::PendingEvent::domain_event)
            .as_ref(),
        )
        .await?;

    let view = SessionTokenTemplateView {
        name: template.name().to_owned(),
        audience: template.audience().to_owned(),
        ttl_seconds: template.ttl_seconds(),
        rules: request.rules,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// List an environment's session tokenizer templates.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/session-token-templates",
    operation_id = "listSessionTokenTemplates",
    tag = "session-token-templates",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The templates", body = SessionTokenTemplatesView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn list_session_token_templates(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`. The listing returns
    // CONFIGURATION and never key material, so demanding `write_config` would make asking which
    // templates exist cost the authority to change them.
    principal.require_permission(ManagementPermission::Read)?;

    let listed = state
        .store()
        .scoped(scope)
        .session_token_templates()
        .list()
        .await?;
    let templates = listed
        .into_iter()
        .map(|record| {
            // A stored document was validated on write, so a parse fault here is persistence
            // corruption rather than a caller fault.
            let rules: serde_json::Value =
                serde_json::from_str(&record.rules_json).map_err(|_| ApiError::Internal)?;
            Ok(SessionTokenTemplateView {
                name: record.name,
                audience: record.audience,
                ttl_seconds: record.ttl_seconds,
                rules,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let body_string = serde_json::to_string(&SessionTokenTemplatesView { templates })
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Remove a session tokenizer template.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/session-token-templates",
    operation_id = "deleteSessionTokenTemplate",
    tag = "session-token-templates",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("name" = String, Query, description = "Which template to remove. ITS KEYS GO WITH IT: the template's JWKS URL stops answering and every consumer verifying against it starts failing")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Removed, along with its key set"),
        (status = 400, description = "An absent name", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found, or no template of that name", body = ErrorBody)
    )
)]
pub async fn delete_session_token_template(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<NameQuery>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // FRESH PRIVILEGE ON THE REMOVAL TOO, and a removal is not a de-escalation here: the
    // template's keys cascade away with it, so its JWKS URL stops answering and every consumer
    // still verifying against it starts refusing. That is an outage a stolen session could
    // otherwise cause.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    crate::org_context::require_live_environment(&state, &scope).await?;

    let Some(name) = query.name.as_deref() else {
        return Err(ApiError::BadRequest(
            "a template name is required".to_owned(),
        ));
    };
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .session_token_templates()
        .delete(
            state.env(),
            name,
            tokenizer_event(
                &state,
                scope,
                "session_token_template.deleted",
                &serde_json::json!({ "name": name }),
                name,
            )
            .as_ref()
            .map(crate::events::PendingEvent::domain_event)
            .as_ref(),
        )
        .await?;
    Ok(no_content())
}

/// Turn the OPT-IN short-lived JWT session mode ON, pointed at a template.
///
/// # This is the one write in this module that changes how EVERY session in the environment is
/// checked
///
/// A tokenizer template on its own does nothing until somebody calls `tokenize`. This switch
/// makes the SDKs do it in the background, which moves the whole environment from a
/// database-backed session check that honours revocation immediately to a token that keeps
/// verifying until it expires. The template's TTL is the width of that window.
///
/// So it is classified and gated exactly like the template write, and the response repeats the
/// TTL and says what it means, because an operator turning this on should not have to look the
/// number up somewhere else to learn what they just accepted.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/session-jwt-mode",
    operation_id = "setSessionJwtMode",
    tag = "session-token-templates",
    request_body = SetSessionJwtModeRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Enabled", body = SessionJwtModeView),
        (status = 400, description = "An absent template name", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found, or no template of that name", body = ErrorBody)
    )
)]
pub async fn set_session_jwt_mode(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // FRESH PRIVILEGE, for a stronger reason than the template write: this is the switch that
    // makes every SDK in the environment stop checking the database.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    crate::org_context::require_live_environment(&state, &scope).await?;

    let request: SetSessionJwtModeRequest = parse_json(&body)?;
    if request.template.is_empty() {
        return Err(ApiError::BadRequest(
            "a template name is required: enabling this mode means naming the template SDKs \
             mint from"
                .to_owned(),
        ));
    }
    // READ THE TEMPLATE FIRST, so naming one that does not exist is a 404 an operator can act on
    // rather than the foreign key surfacing as a 500. The constraint stays behind this as the
    // backstop that a concurrent delete cannot get past.
    let template = state
        .store()
        .scoped(scope)
        .session_token_templates()
        .get(&request.template)
        .await?
        .ok_or(ApiError::NotFound)?;

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .session_jwt_mode()
        .enable(
            state.env(),
            &template.name,
            tokenizer_event(
                &state,
                scope,
                "session_jwt_mode.enabled",
                &serde_json::json!({ "template": template.name }),
                &template.name,
            )
            .as_ref()
            .map(crate::events::PendingEvent::domain_event)
            .as_ref(),
        )
        .await?;

    let view = SessionJwtModeView {
        enabled: true,
        template: Some(template.name),
        ttl_seconds: Some(template.ttl_seconds),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Report whether the OPT-IN short-lived JWT session mode is on.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/session-jwt-mode",
    operation_id = "getSessionJwtMode",
    tag = "session-token-templates",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The mode. A fresh environment reports disabled", body = SessionJwtModeView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn get_session_jwt_mode(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    principal.require_permission(ManagementPermission::Read)?;

    let mode = state
        .store()
        .scoped(scope)
        .session_jwt_mode()
        .template()
        .await?;
    // A 200 REPORTING DISABLED, not a 404. "This environment does not run the mode" is an
    // answer, and the only answer a fresh environment has; a 404 would make the caller
    // distinguish "no such environment" from "the default", which are not the same thing.
    let view = match mode {
        None => SessionJwtModeView {
            enabled: false,
            template: None,
            ttl_seconds: None,
        },
        Some(name) => {
            let ttl = state
                .store()
                .scoped(scope)
                .session_token_templates()
                .get(&name)
                .await?
                .map(|record| record.ttl_seconds);
            SessionJwtModeView {
                enabled: true,
                template: Some(name),
                ttl_seconds: ttl,
            }
        }
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Turn the OPT-IN short-lived JWT session mode OFF.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/session-jwt-mode",
    operation_id = "deleteSessionJwtMode",
    tag = "session-token-templates",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Disabled. Every SDK goes back to the stateful session check"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found, or the mode was not on", body = ErrorBody)
    )
)]
pub async fn delete_session_jwt_mode(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // FRESH PRIVILEGE ON THE DISABLE TOO. This one is the SAFE direction -- every SDK goes back
    // to the database-backed check -- but it is still a change every request in the environment
    // feels, and a load characteristic somebody sized for. It is not a de-escalation.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    crate::org_context::require_live_environment(&state, &scope).await?;

    // The template the mode WAS pointed at, read before the delete so the audit row can name it.
    // A disable that names nothing would be a row an auditor cannot use.
    let template = state
        .store()
        .scoped(scope)
        .session_jwt_mode()
        .template()
        .await?
        .ok_or(ApiError::NotFound)?;
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .session_jwt_mode()
        .disable(
            state.env(),
            &template,
            tokenizer_event(
                &state,
                scope,
                "session_jwt_mode.disabled",
                &serde_json::json!({ "template": template }),
                &template,
            )
            .as_ref()
            .map(crate::events::PendingEvent::domain_event)
            .as_ref(),
        )
        .await?;
    Ok(no_content())
}

/// Build the event a tokenizer or session-mode write announces (issue #108's contract).
///
/// One builder for all four, for the reason `challenge_components::component_event` gives: the
/// differences are the type and the payload, and the SUBJECT is what keeps two events about one
/// object ordered on a consumer's stream.
///
/// The subject is the template NAME. For the mode's two events that is the template it was
/// pointed at, which is deliberate: the mode is per-environment and has no name of its own, and
/// ordering its events beside the template's is what a consumer tracking "what governs this
/// environment's sessions" needs.
fn tokenizer_event(
    state: &AdminState,
    scope: Scope,
    event_type: &str,
    payload: &serde_json::Value,
    subject: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        payload,
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject: subject.to_owned(),
        envelope,
    })
}
