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
    SessionTokenTemplateView, SessionTokenTemplatesView, SetSessionTokenTemplateRequest,
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
        .delete(state.env(), name)
        .await?;
    Ok(no_content())
}
