// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment, per-client WASM token hook management (issue #114, criterion 5).
//!
//! Deploy, describe and remove the component that shapes a client's tokens.
//!
//! # Why this exists at all, said plainly
//!
//! `token_hooks` had NO production writer. `.token_hooks()` had exactly one non-test reference
//! in the whole tree and it was the READ on the issuance path; every row the feature has ever
//! run against was written by a test fixture. A criterion measured against a table only tests
//! can populate is measured against nothing, so this is the surface that makes the rest of #114
//! reachable by a deployment rather than by a harness.
//!
//! # A hook is the most privileged thing an operator installs here
//!
//! It is code that runs inside the token mint. So a deploy is `management.write_config` AND
//! demands fresh privilege, exactly like a claim mapping, and for a stronger reason: a mapping
//! rearranges claims the mint already produced, a hook computes new ones.
//!
//! The DELETE matters as much as the PUT and is the reason this is a lifecycle surface rather
//! than a deploy button. Removing the row restores the unshaped token on the next issuance --
//! the dispatch reads per request -- so it is the remediation for a hook that is refusing
//! logins, available without a restart or a database console.
//!
//! # What is validated here, and what is not
//!
//! Refused at the door: a payload version this build cannot honour, an empty or oversized
//! component, and bytes that are not a WebAssembly COMPONENT. That last one earns its place --
//! a core module and a component are both "a .wasm file" and neither the name nor the size
//! tells them apart, so a module built for the wrong target or against the wrong world is the
//! most likely first failure. The preamble distinguishes them exactly: a core module's version
//! word is `01 00 00 00` and a component's layer is `0d 00 01 00`.
//!
//! An earlier version of the refusal told operators to use `cargo component build` instead of
//! `cargo build`. That is WRONG in this repository: `crates/ironauth-hooks/build.rs` builds
//! every shipped guest with plain `cargo build --target wasm32-wasip2` and gets components,
//! because that target emits one for a crate with a WIT world. Advice contradicting the build
//! the project actually runs sends an operator to change the thing that was already right.
//!
//! NOT validated here: that the component LINKS -- that its imports resolve against the host
//! surface the sandbox offers. That needs a `wasmtime` engine, and this crate does not have one;
//! the dispatch discovers it at the first invocation and memoises the refusal, so the cost is
//! bounded but the report reaches an operator through a log rather than through this response.
//! Deploy-time link validation is the obvious next slice and is deliberately not claimed here.
//!
//! # The component is written, never read back
//!
//! `GET` returns metadata -- which client, how many bytes, which payload version -- and not the
//! component. An operator asking "what is deployed" wants to know whether the thing they pushed
//! is the thing running, which a length and a version answer; streaming megabytes of WASM back
//! through the management API answers a question nobody asked and makes every list response a
//! potential multi-megabyte body.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{ClientId, CorrelationId, Scope};

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{DeployTokenHookQuery, TokenHookView};

/// The largest component this surface accepts, matching `token_hooks`' own CHECK.
///
/// Duplicated deliberately rather than imported: the database bound is the one that must hold,
/// and this one exists so an oversized deploy is a 400 naming the limit instead of a constraint
/// violation surfacing as a 500.
///
/// NOTHING HERE PROVES THE TWO AGREE. An earlier version of this comment claimed the unit test
/// below pins it; that test reads this constant and never reads the migration, so it would pass
/// with both numbers wrong in the same direction. `a_component_at_the_documented_bound_is_stored`
/// is what actually crosses the two: it deploys exactly this many bytes through the real
/// handler into the real table, so a disagreement is a failed insert rather than a comment.
pub(crate) const MAX_COMPONENT_BYTES: usize = 8 * 1024 * 1024;

/// The eight-byte preamble every WebAssembly component starts with.
///
/// `\0asm` then the layer/version word. A core module carries `01 00 00 00` here; a component
/// carries `0d 00 01 00`.
const COMPONENT_PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];

/// The same preamble for a core MODULE, which is the near-miss worth naming in the error.
const MODULE_PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

/// Resolve and authorize the `(tenant, environment)` scope from the path.
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
    // Issue #185: the caller's OPERATOR fences the pair, exactly as every sibling surface does.
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
fn parse_client_id(raw: &str, scope: Scope) -> Result<ClientId, ApiError> {
    ClientId::parse_in_scope(raw, &scope).map_err(|_| ApiError::NotFound)
}

/// Refuse a component this build could not run, naming which check failed.
fn validate_component(component: &[u8]) -> Result<(), ApiError> {
    if component.is_empty() {
        return Err(ApiError::BadRequest("invalid_component: the request body is empty; deploy the component bytes as the body with \
             Content-Type: application/wasm".to_owned()));
    }
    if component.len() > MAX_COMPONENT_BYTES {
        return Err(ApiError::BadRequest(
            "component_too_large: the component exceeds the 8388608-byte limit".to_owned(),
        ));
    }
    if component.starts_with(&COMPONENT_PREAMBLE) {
        return Ok(());
    }
    if component.starts_with(&MODULE_PREAMBLE) {
        // NAMED SPECIFICALLY, because it is the mistake this check exists to catch and the two
        // artifacts are indistinguishable by filename. An operator who reads "not a component"
        // checks their bytes; one who reads "that is a core module" checks their build command.
        return Err(ApiError::BadRequest(
            "core_module_not_component: these bytes are a core WebAssembly module, not a \
             component. A guest built against the hook WIT world compiles to one with \
             `cargo build --target wasm32-wasip2`; a module means the target or the world is \
             not what this expects."
                .to_owned(),
        ));
    }
    Err(ApiError::BadRequest(
        "invalid_component: these bytes are not WebAssembly: the component preamble is missing"
            .to_owned(),
    ))
}

/// Deploy (create or replace) a client's WASM token hook.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/token-hook",
    operation_id = "deployTokenHook",
    tag = "token-hooks",
    request_body(content = String, description = "The WebAssembly component bytes", content_type = "application/wasm"),
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the hook shapes"),
        ("payload_version" = u32, Query, description = "The token-customize payload version the guest was built against"),
        ("failure_policy" = Option<String>, Query, description = "What the dispatch does when this hook does not complete: `fail_closed` (the default) or `fail_open`")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Deployed", body = TokenHookView),
        (status = 400, description = "An unknown or absent payload version, an unknown failure policy, or bytes that are not a WebAssembly component", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found or malformed client id", body = ErrorBody)
    )
)]
pub async fn deploy_token_hook(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    Query(query): Query<DeployTokenHookQuery>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // A hook is CODE INSIDE THE TOKEN MINT. Fresh privilege for the same reason a claim mapping
    // demands it, and with more force: a mapping rearranges claims the mint produced, a hook
    // computes them.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let client = parse_client_id(&client_id, scope)?;
    crate::org_context::require_live_environment(&state, &scope).await?;

    // THE VERSION FIRST, because it is the cheapest refusal and the one whose message is most
    // actionable: a guest built against another revision of the WIT interface cannot be run by
    // this build at all, and saying so beats letting it deploy and fail at the first login.
    // BOTH the absent and the malformed case, parsed here rather than by the extractor, so
    // each is this API's 400 with an `ErrorBody` instead of axum's plain-text one and each
    // happens AFTER the permission, privilege and environment gates. Typing the field
    // `Option<String>` is what makes the absent case reachable at all: as a bare `String` it
    // failed inside `Query<T>`, before any of them.
    let raw = query.payload_version.as_deref().ok_or_else(|| {
        ApiError::BadRequest("unknown_payload_version: payload_version is required".to_owned())
    })?;
    let payload_version: u32 = raw.parse().map_err(|_| {
        ApiError::BadRequest(
            "unknown_payload_version: payload_version must be a non-negative integer".to_owned(),
        )
    })?;
    if payload_version != ironauth_store::token_customize::TOKEN_CUSTOMIZE_VERSION {
        return Err(ApiError::BadRequest("unknown_payload_version: this build cannot honour that token-customize payload version".to_owned()));
    }
    // ABSENT MEANS FAIL-CLOSED. The dangerous setting is the one an operator has to type, and
    // an unrecognised spelling is refused rather than read as the default -- a typo that
    // silently selected the safe answer would be indistinguishable from asking for it, and the
    // operator would never learn their `fail-open` did nothing.
    let failure_policy = match query.failure_policy.as_deref() {
        None => ironauth_store::HookFailurePolicy::FailClosed,
        Some(raw) => ironauth_store::HookFailurePolicy::parse(raw).ok_or_else(|| {
            ApiError::BadRequest(
                "unknown_failure_policy: failure_policy must be `fail_closed` or `fail_open`"
                    .to_owned(),
            )
        })?,
    };
    validate_component(&body)?;

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .token_hooks()
        .set_with_event(
            state.env(),
            &client,
            &body,
            i32::try_from(payload_version).map_err(|_| ApiError::Internal)?,
            failure_policy,
            deployed_event(
                &state,
                scope,
                &client.to_string(),
                body.len(),
                payload_version,
                failure_policy,
            )
            .as_ref()
            .map(crate::events::PendingEvent::domain_event)
            .as_ref(),
        )
        .await?;

    let view = TokenHookView {
        client_id: client.to_string(),
        component_bytes: body.len(),
        payload_version,
        failure_policy: failure_policy.as_str().to_owned(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Describe a client's deployed token hook.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/token-hook",
    operation_id = "getTokenHook",
    tag = "token-hooks",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the hook shapes")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The deployed hook's metadata", body = TokenHookView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found, malformed client id, or no hook deployed", body = ErrorBody)
    )
)]
pub async fn get_token_hook(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    principal.require_permission(ManagementPermission::Read)?;
    let client = parse_client_id(&client_id, scope)?;

    // `metadata`, not `get`: the component is up to eight megabytes and this reports its
    // LENGTH, so the length is computed where the bytes already are rather than by hauling
    // them across the wire to call `.len()`.
    let record = state
        .store()
        .scoped(scope)
        .token_hooks()
        .metadata(&client.to_string())
        .await?
        .ok_or(ApiError::NotFound)?;
    let view = TokenHookView {
        client_id: record.client_id,
        component_bytes: usize::try_from(record.component_bytes).map_err(|_| ApiError::Internal)?,
        payload_version: u32::try_from(record.payload_version).map_err(|_| ApiError::Internal)?,
        failure_policy: record.failure_policy.as_str().to_owned(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Remove a client's WASM token hook.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/token-hook",
    operation_id = "deleteTokenHook",
    tag = "token-hooks",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the hook shapes")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found, malformed client id, or no hook deployed", body = ErrorBody)
    )
)]
pub async fn delete_token_hook(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // Removal changes the shape of every token this client is issued, in the same way a deploy
    // does, so it demands the same fresh privilege. It is ALSO the break-glass path for a hook
    // that is failing logins, which is an argument for keeping it fast rather than for making
    // it easier: an operator who can remove a hook without proving privilege is an attacker who
    // can strip a security-relevant claim from every token.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let client = parse_client_id(&client_id, scope)?;
    crate::org_context::require_live_environment(&state, &scope).await?;

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .token_hooks()
        .delete_with_event(
            state.env(),
            &client,
            deleted_event(&state, scope, &client.to_string())
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(no_content())
}

/// The event a hook deploy emits (issue #108).
///
/// The client, the byte count and the payload version -- never the component. An event is a
/// notification, not a binary store: the bytes are durable in the row this points at, and
/// putting megabytes of WASM on every subscriber's stream would be a denial of service dressed
/// as an announcement. The count and the version are what let a consumer tell one deploy from
/// another without refetching.
fn deployed_event(
    state: &AdminState,
    scope: Scope,
    client_id: &str,
    component_bytes: usize,
    payload_version: u32,
    failure_policy: ironauth_store::HookFailurePolicy,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "token_hook.deployed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "client_id": client_id,
            "component_bytes": component_bytes,
            "payload_version": payload_version,
            // THE POLICY RIDES ALONG, because a redeploy that changes only it would otherwise
            // emit an event byte-identical to the one before -- and flipping a client to
            // fail-open is the change on this surface a consumer most needs to see.
            "failure_policy": failure_policy.as_str(),
        }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        // The stable address is the subject, so two events about one hook stay ordered.
        subject: client_id.to_owned(),
        envelope,
    })
}

/// The event a hook removal emits (issue #108).
///
/// A removal restores the UNSHAPED token, so a claim the hook computed stops being minted and a
/// resource server authorizing on it starts refusing. A consumer cannot tell that from silence.
fn deleted_event(
    state: &AdminState,
    scope: Scope,
    client_id: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "token_hook.deleted",
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
    use super::{MAX_COMPONENT_BYTES, validate_component};

    /// A real component preamble is admitted.
    #[test]
    fn a_component_preamble_is_admitted() {
        let mut bytes = vec![0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
        bytes.extend_from_slice(b"the rest of a component");
        assert!(validate_component(&bytes).is_ok());
    }

    /// A CORE MODULE is refused, and the message says which mistake it is.
    ///
    /// This is the check's whole reason for existing: `cargo build` and `cargo component build`
    /// both emit a `.wasm`, and the two are indistinguishable by name.
    #[test]
    fn a_core_module_is_refused_as_a_core_module() {
        let mut bytes = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        bytes.extend_from_slice(b"the rest of a module");
        let error = validate_component(&bytes).expect_err("a core module is not a component");
        assert!(
            format!("{error:?}").contains("core_module_not_component"),
            "the refusal must name the core-module case rather than a generic one: {error:?}"
        );
    }

    /// Bytes that are not WebAssembly at all are refused, distinctly from a core module.
    #[test]
    fn arbitrary_bytes_are_refused_as_not_wasm() {
        let error = validate_component(b"#!/bin/sh\necho not wasm\n")
            .expect_err("a shell script is not a component");
        assert!(
            format!("{error:?}").contains("invalid_component"),
            "not-wasm must not be reported as a core module: {error:?}"
        );
    }

    /// Empty is refused before the database's own non-empty CHECK sees it, WITH the message
    /// that names the mistake.
    ///
    /// Asserting only `is_err()` was vacuous: `<[u8]>::starts_with` is false whenever the
    /// needle is longer than the slice, so deleting the empty-body branch entirely leaves an
    /// empty body falling through both preamble arms to the generic "not WebAssembly" error --
    /// still an `Err`, still green, and the operator is told their bytes are malformed rather
    /// than that they sent none. Naming the branch is what makes the test able to fail.
    #[test]
    fn an_empty_body_is_refused_as_an_empty_body() {
        let error = validate_component(b"").expect_err("an empty body is not a component");
        assert!(
            format!("{error:?}").contains("the request body is empty"),
            "the refusal must name the empty body, not report it as malformed wasm: {error:?}"
        );
    }

    /// The bound is INCLUSIVE at the boundary and exclusive one byte past it.
    ///
    /// That is all this test establishes. It reads `MAX_COMPONENT_BYTES` and never reads the
    /// migration, so it would pass with this constant and the table's CHECK both wrong in the
    /// same direction; the cross-check is `a_component_at_the_documented_bound_is_stored` in
    /// `tests/token_hooks.rs`, which puts exactly this many bytes through the real handler
    /// into the real table.
    #[test]
    fn the_size_bound_is_inclusive_at_the_boundary() {
        let mut at_bound = vec![0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
        at_bound.resize(MAX_COMPONENT_BYTES, 0);
        assert!(
            validate_component(&at_bound).is_ok(),
            "the bound is inclusive"
        );

        let mut over = at_bound;
        over.push(0);
        let error = validate_component(&over).expect_err("one byte over is refused");
        assert!(format!("{error:?}").contains("component_too_large"));
    }
}
