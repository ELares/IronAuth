// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment CUSTOM FACTOR component management (issue #114 criterion 6).
//!
//! Deploy, describe, remove and grant secrets to the components a journey's `custom_challenge`
//! steps run.
//!
//! # Why this exists, said plainly
//!
//! The same reason `token_hooks` gives for itself. Without it, `challenge_components` has no
//! production writer: every row the feature runs against would be written by a test fixture or a
//! database console, and a criterion measured against a table only tests can populate is measured
//! against nothing. This repository's own migration 0166 puts it as "a sample that cannot be
//! deployed through the API it is a sample for is not a sample".
//!
//! # A factor decides whether a login succeeds
//!
//! So a deploy is `management.write_config` AND demands fresh privilege, exactly as a token hook's
//! does. The reach is different rather than smaller: a token hook shapes claims on a token the
//! login has ALREADY earned, while a factor decides whether it is earned at all.
//!
//! The DELETE is the remediation, and it FAILS CLOSED rather than open: removing a component a
//! journey still names does not disable the factor, it makes every login that reaches the step
//! refuse. That is the safe direction and it is the opposite of a token hook's delete, which
//! restores the unshaped token. An operator removing a factor must also take the step out of the
//! journey, and the refusal is what tells them they have not.
//!
//! # What is validated here, and what is not
//!
//! Refused at the door: a payload version this build cannot honour, an empty or oversized
//! component, bytes that are not a WebAssembly COMPONENT, an invalid name, and an out-of-range
//! fetch budget.
//!
//! NOT validated here: whether the component exports the custom-challenge world. That is decided
//! by wasmtime when the component is LINKED, and this crate has no engine -- a deployment can be
//! built without the `wasm-hooks` feature entirely. Refusing to deploy a component this build
//! cannot inspect would make the admin surface's answer depend on a build flag, so the world
//! mismatch surfaces where every other link failure does: at the login, under the failure policy,
//! fail-closed.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{ChallengeDeployment, CorrelationId, Scope};
use serde::Deserialize;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{
    ChallengeComponentSecretsView, ChallengeComponentView, ChallengeComponentsView,
};

/// The most CHARACTERS a component name may carry, matching the CHECK on the column.
///
/// CHARACTERS AND NOT BYTES, for the reason `token_hooks::MAX_HOOK_NAME_CHARS` records: Postgres
/// `length()` counts characters, so a byte count would disagree with the column on every
/// non-ASCII name.
const MAX_NAME_CHARS: usize = 64;

/// The most CHARACTERS an environment secret name may carry, matching its column's CHECK.
const MAX_SECRET_NAME_CHARS: usize = 128;

/// The largest outbound request budget a component may be granted, matching the column's CHECK.
const MAX_FETCH_BUDGET: i32 = 16;

/// The annotation on `deployChallengeComponent` spells this bound as a LITERAL, so nothing but
/// this line stops a raised cap from leaving a spec that promises sixteen while the handler
/// accepts more. A generated client believes the spec.
const _: () = assert!(
    MAX_FETCH_BUDGET == 16,
    "update the deployChallengeComponent annotation too"
);

/// The query a deploy takes.
#[derive(Debug, Deserialize)]
pub struct DeployQuery {
    /// The component name a journey step references. REQUIRED.
    name: Option<String>,
    /// The payload version the guest was built against. REQUIRED.
    payload_version: Option<String>,
    /// The outbound request budget, absent meaning zero.
    fetch_budget: Option<String>,
}

/// The query the by-name routes take.
#[derive(Debug, Deserialize)]
pub struct NameQuery {
    /// Which component. REQUIRED: unlike a token hook there is no `default`, because a journey
    /// step always names one explicitly and a default would be a component nobody referenced.
    name: Option<String>,
}

/// The query the secret-grant routes take.
#[derive(Debug, Deserialize)]
pub struct SecretQuery {
    /// Which component. REQUIRED.
    name: Option<String>,
    /// The environment secret's name. REQUIRED.
    secret: Option<String>,
}

/// Validate the component NAME a journey will reference.
///
/// REQUIRED, with no default. A token hook may omit its name because a client had exactly one
/// hook before ordering existed and `default` is that hook; a component has no such history, and
/// a defaulted name would be a component no journey step names.
fn component_name(raw: Option<&str>) -> Result<&str, ApiError> {
    let name = raw.unwrap_or_default();
    if name.is_empty() {
        return Err(ApiError::BadRequest(
            "invalid_component_name: name is required and must not be empty".to_owned(),
        ));
    }
    if name.trim() != name {
        return Err(ApiError::BadRequest(
            "invalid_component_name: name must not have leading or trailing whitespace".to_owned(),
        ));
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(ApiError::BadRequest(format!(
            "invalid_component_name: name must be at most {MAX_NAME_CHARS} characters"
        )));
    }
    Ok(name)
}

/// Validate an environment secret name.
fn secret_name(raw: Option<&str>) -> Result<&str, ApiError> {
    let name = raw.unwrap_or_default();
    if name.is_empty() {
        return Err(ApiError::BadRequest(
            "invalid_secret_name: secret is required and must not be empty".to_owned(),
        ));
    }
    if name.chars().count() > MAX_SECRET_NAME_CHARS {
        return Err(ApiError::BadRequest(format!(
            "invalid_secret_name: secret must be at most {MAX_SECRET_NAME_CHARS} characters"
        )));
    }
    Ok(name)
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

/// Deploy (create or replace) a custom factor component.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/challenge-components",
    operation_id = "deployChallengeComponent",
    tag = "challenge-components",
    request_body(content = String, description = "The WebAssembly component bytes", content_type = "application/wasm"),
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("name" = String, Query, description = "The name a journey step references this component by. REQUIRED: there is no default, because a journey always names one explicitly"),
        ("payload_version" = u32, Query, description = "The custom-challenge payload version the guest was built against"),
        ("fetch_budget" = Option<u32>, Query, maximum = 16, description = "How many outbound requests ONE call of the triad may make, 0 to 16. Absent means ZERO, which is not granted. Applied on a redeploy: capabilities travel with the code")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Deployed", body = ChallengeComponentView),
        (status = 400, description = "An unknown or absent payload version, an invalid name, an out-of-range fetch budget, or bytes that are not a WebAssembly component", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn deploy_challenge_component(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<DeployQuery>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // FRESH PRIVILEGE, with more force than a token hook's: a hook shapes claims on a token the
    // login already earned, and this decides whether it is earned.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    crate::org_context::require_live_environment(&state, &scope).await?;

    let name = component_name(query.name.as_deref())?;
    let raw = query.payload_version.as_deref().ok_or_else(|| {
        ApiError::BadRequest("unknown_payload_version: payload_version is required".to_owned())
    })?;
    let payload_version: u32 = raw.parse().map_err(|_| {
        ApiError::BadRequest(
            "unknown_payload_version: payload_version must be a non-negative integer".to_owned(),
        )
    })?;
    if payload_version != CHALLENGE_PAYLOAD_VERSION {
        return Err(ApiError::BadRequest(
            "unknown_payload_version: this build cannot honour that custom-challenge payload \
             version"
                .to_owned(),
        ));
    }
    let fetch_budget = match query.fetch_budget.as_deref() {
        Some(raw) => raw
            .parse::<i32>()
            .ok()
            .filter(|budget| (0..=MAX_FETCH_BUDGET).contains(budget))
            .ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "invalid_fetch_budget: fetch_budget must be an integer between 0 and \
                     {MAX_FETCH_BUDGET}"
                ))
            })?,
        None => 0,
    };
    // THE SAME PREAMBLE CHECK a token hook gets, and for the same reason: a core module and a
    // component are both "a .wasm file", and neither the name nor the size tells them apart.
    crate::token_hooks::validate_component(&body)?;

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .challenge_components()
        .deploy(
            state.env(),
            ChallengeDeployment {
                name,
                component: &body,
                payload_version: i32::try_from(payload_version).map_err(|_| ApiError::Internal)?,
                fetch_budget,
            },
        )
        .await?;

    let view = ChallengeComponentView {
        name: name.to_owned(),
        component_bytes: body.len(),
        payload_version,
        fetch_budget: u32::try_from(fetch_budget).map_err(|_| ApiError::Internal)?,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// The custom-challenge payload version this build honours.
///
/// ITS OWN CONSTANT, not the token-customize one. The two worlds carry independent payload
/// versions that move on independent schedules, and sharing a number would make a bump to one
/// silently refuse every component of the other.
pub(crate) const CHALLENGE_PAYLOAD_VERSION: u32 = 1;

/// List the custom factor components deployed in this environment.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/challenge-components",
    operation_id = "listChallengeComponents",
    tag = "challenge-components",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The deployed components, as metadata", body = ChallengeComponentsView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn list_challenge_components(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    principal.require_permission(ManagementPermission::Read)?;

    // METADATA, never the components. A listing exists so an operator can see WHICH factors are
    // deployed, and a scope with eight sixteen-megabyte components would be a hundred and
    // twenty-eight megabytes of response to answer that.
    let listed = state
        .store()
        .scoped(scope)
        .challenge_components()
        .list()
        .await?;
    let view = ChallengeComponentsView {
        components: listed
            .into_iter()
            .map(|row| {
                Ok(ChallengeComponentView {
                    name: row.name,
                    component_bytes: usize::try_from(row.component_bytes)
                        .map_err(|_| ApiError::Internal)?,
                    payload_version: u32::try_from(row.payload_version)
                        .map_err(|_| ApiError::Internal)?,
                    fetch_budget: u32::try_from(row.fetch_budget)
                        .map_err(|_| ApiError::Internal)?,
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Remove a custom factor component.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/challenge-components",
    operation_id = "deleteChallengeComponent",
    tag = "challenge-components",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("name" = String, Query, description = "Which component to remove. REMOVING ONE A JOURNEY STILL NAMES MAKES EVERY LOGIN THAT REACHES THAT STEP REFUSE: a factor fails closed, so the step must come out of the journey too")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Removed, along with every secret grant it held"),
        (status = 400, description = "An invalid or absent name", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found, or no component of that name", body = ErrorBody)
    )
)]
pub async fn delete_challenge_component(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<NameQuery>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // FRESH PRIVILEGE ON THE REMOVAL TOO, because a removal is not a de-escalation here: a
    // journey that still names the component starts refusing every login that reaches it, so
    // this is as disruptive as the deploy and reachable by the same stolen session otherwise.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    crate::org_context::require_live_environment(&state, &scope).await?;
    let name = component_name(query.name.as_deref())?;

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .challenge_components()
        .delete(state.env(), name)
        .await?;
    Ok(no_content())
}

/// List the environment secrets a component may read.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/challenge-components/secrets",
    operation_id = "listChallengeComponentSecrets",
    tag = "challenge-components",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("name" = String, Query, description = "Which component")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The secret NAMES this component may read, never their values", body = ChallengeComponentSecretsView),
        (status = 400, description = "An invalid or absent name", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn list_challenge_component_secrets(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<NameQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::Read)?;
    let name = component_name(query.name.as_deref())?;
    read_back_secrets(&state, scope, name).await
}

/// Grant a component permission to read an environment secret.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/challenge-components/secrets",
    operation_id = "grantChallengeComponentSecret",
    tag = "challenge-components",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("name" = String, Query, description = "Which component"),
        ("secret" = String, Query, description = "The environment secret's name. REQUIRED: there is no meaningful default, and an omitted one would have to mean `all of them`")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The secret NAMES this component may now read", body = ChallengeComponentSecretsView),
        (status = 400, description = "An invalid or absent name or secret", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found, or that component is not deployed", body = ErrorBody)
    )
)]
pub async fn grant_challenge_component_secret(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<SecretQuery>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // FRESH PRIVILEGE: this hands a key to code that decides whether logins succeed.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    crate::org_context::require_live_environment(&state, &scope).await?;
    let name = component_name(query.name.as_deref())?;
    let secret = secret_name(query.secret.as_deref())?;

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .challenge_components()
        .grant_secret(state.env(), name, secret)
        .await?;
    read_back_secrets(&state, scope, name).await
}

/// Withdraw a component's permission to read an environment secret.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/challenge-components/secrets",
    operation_id = "revokeChallengeComponentSecret",
    tag = "challenge-components",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("name" = String, Query, description = "Which component"),
        ("secret" = String, Query, description = "The environment secret's name")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The secret NAMES this component may still read", body = ChallengeComponentSecretsView),
        (status = 400, description = "An invalid or absent name or secret", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn revoke_challenge_component_secret(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<SecretQuery>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    crate::org_context::require_live_environment(&state, &scope).await?;
    let name = component_name(query.name.as_deref())?;
    let secret = secret_name(query.secret.as_deref())?;

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .challenge_components()
        .revoke_secret(state.env(), name, secret)
        .await?;
    read_back_secrets(&state, scope, name).await
}

/// Read the grants back from the store and render them.
///
/// READ BACK, never echoed. The grant and revoke routes both end here so their response says what
/// the component MAY READ rather than what the caller just asked for -- an echo would report a
/// grant that a concurrent revoke had already removed.
async fn read_back_secrets(
    state: &AdminState,
    scope: Scope,
    name: &str,
) -> Result<Response, ApiError> {
    let secrets = state
        .store()
        .scoped(scope)
        .challenge_components()
        .granted_secrets(name)
        .await?;
    let view = ChallengeComponentSecretsView {
        name: name.to_owned(),
        secrets,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}
