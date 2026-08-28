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
use crate::views::{
    DeployTokenHookQuery, RollbackTokenHookRequest, TokenHookVersionView, TokenHookView,
};

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
///
/// # Where the number comes from
///
/// NOT from judgement. It was 8 MiB, chosen from the observation that a claim-shaping hook is
/// "under a hundred kilobytes" -- which is true of Rust and false of every scripting language,
/// because a hook written in one carries its interpreter. Criterion 1 of issue #114 asks for a
/// TypeScript hook, and the shipped TypeScript sample is roughly 10.6 MiB of which about four
/// kilobytes is the author's code. The old bound did not squeeze TypeScript hooks, it made
/// them undeployable through this surface while the integration suite ran them happily, because
/// the suite reads a component from disk and never crosses this constant.
///
/// So the bound is pinned to the artifact rather than to a preference:
/// `the_shipped_typescript_sample_fits_this_bound` reads the COMMITTED component's real length
/// and fails if it no longer fits.
///
/// THAT TEST DOES NOT CATCH A componentize-js UPGRADE ON ITS OWN, and an earlier version of
/// this paragraph said it did. Bumping the pin in `guests-ts/package.json` does not change the
/// committed artifact, so the test goes on measuring the old bytes until someone regenerates
/// `dist/`. What catches the upgrade is `scripts/ts-hook-freshness.sh`, which is the only thing
/// that BUILDS from the current pin: it compares the rebuilt size against this constant and
/// fails. The test guards the artifact; the script guards the pin, and it takes both.
pub(crate) const MAX_COMPONENT_BYTES: usize = 16 * 1024 * 1024;

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
        // INTERPOLATED, never written out. This message named 8388608 as a literal while the
        // constant beside it moved to 16 MiB, so a refusal would have quoted a limit that was
        // not the limit -- and the test above only asserts the error CODE, so nothing would
        // have caught it. A number in prose next to the number it describes is a number that
        // will disagree with it.
        return Err(ApiError::BadRequest(format!(
            "component_too_large: the component is {} bytes and the limit is \
             {MAX_COMPONENT_BYTES} bytes",
            component.len()
        )));
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

    // `metadata`, not `get`: the component runs to tens of megabytes and this reports its
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

/// Take a client's WASM token hook out of service.
///
/// # It is no longer a deletion, and this PR is what changed that
///
/// Before the version history, removing the row destroyed the component: there was one copy
/// and this deleted it. Now the deploy that installed it also wrote a history row, and nothing
/// here touches that table -- the prune runs on a DEPLOY, so a client that never deploys again
/// keeps the withdrawn bytes indefinitely.
///
/// So the surface answers three things about the same client, and they are all true:
/// `getTokenHook` is 404, `listTokenHookVersions` lists the withdrawn hook, and
/// `rollbackTokenHook` re-installs its exact bytes. No endpoint erases the history.
///
/// That is the right default -- the break-glass case is "this hook is failing logins, take it
/// out", and an operator doing that at 3am should not also be discarding the ability to put it
/// back -- but it means this is a WITHDRAWAL rather than an erasure, and an operator removing a
/// hook because its bytes should not exist any more is not served by it. Said here and in the
/// 204's description because the old name promised something this no longer does.
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
        (status = 204, description = "Removed from service. The version HISTORY is kept, so the withdrawn component is still listed by listTokenHookVersions and can be re-installed by rollbackTokenHook; no endpoint erases it"),
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
            // NO POLICY HERE. A redeploy that changes only it therefore emits an event
            // identical to the one before, which is a real gap -- and the smaller one. See
            // `token_hook.deployed` in the event catalog: adding any property to a closed
            // schema dead-letters the event on a consumer running the older registry, in one
            // direction if it is required and the other if it is optional.
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

    /// THE BOUND IS PINNED TO A REAL ARTIFACT, which is the whole point of it being 16 MiB.
    ///
    /// A bound and the thing it bounds should not be editable in the same commit without one
    /// of them objecting, and until now they were: `MAX_COMPONENT_BYTES` was a number chosen
    /// from a sentence about Rust hooks, and nothing in the repository held it against a hook
    /// anyone would actually deploy. Under 8 MiB every TypeScript hook was refused by this
    /// surface, and no test noticed, because the hook tests read components from disk.
    ///
    /// This reads the COMMITTED TypeScript sample's real length, so it fails when the artifact
    /// in the tree no longer fits what an operator may upload.
    ///
    /// It does NOT see a componentize-js upgrade by itself: bumping the pin does not change the
    /// committed bytes, so this keeps measuring the old ones until `dist/` is regenerated.
    /// `scripts/ts-hook-freshness.sh` is what builds from the current pin and compares the
    /// rebuilt size against this constant. Two guards, two different things guarded.
    #[test]
    fn the_shipped_typescript_sample_fits_this_bound() {
        let sample = ironauth_hooks::fixtures::TS_TOKEN_CUSTOMIZE.len();
        assert!(
            sample <= MAX_COMPONENT_BYTES,
            "the shipped TypeScript hook is {sample} bytes and this surface refuses anything \
             over {MAX_COMPONENT_BYTES}, so the sample cannot be deployed through the product \
             it samples"
        );
        // And the margin, so shrinking headroom is visible before it is gone. Not a tight
        // bound: it exists to make "the committed artifact is close to the bound" a test
        // failure instead of a discovery.
        assert!(
            sample * 5 / 4 <= MAX_COMPONENT_BYTES,
            "the shipped TypeScript hook is {sample} bytes against a {MAX_COMPONENT_BYTES} \
             byte bound, under 25% of headroom; raise the bound in a migration before a \
             JavaScript engine upgrade makes every TypeScript hook undeployable"
        );
    }
}

/// List a client's most recent token-hook deploys, newest first.
///
/// NOT every deploy. The history is pruned to `TOKEN_HOOK_VERSION_RETENTION` on each write,
/// so this returns at most that many and an older version may have existed and been discarded.
/// Said here because "every deploy" is what this used to claim, and an operator who reads a
/// list of twenty as complete will conclude a version they remember was never deployed.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/token-hook/versions",
    operation_id = "listTokenHookVersions",
    tag = "token-hooks",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the hook shapes")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The most recent deploys, newest first. At most 20: the history is capped, so an older version may have existed and been pruned", body = Vec<TokenHookVersionView>),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found or malformed client id", body = ErrorBody)
    )
)]
pub async fn list_token_hook_versions(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    principal.require_permission(ManagementPermission::Read)?;
    let client = parse_client_id(&client_id, scope)?;

    // AN EMPTY LIST, not a 404, when the client has never had a hook. "No versions" is a
    // complete and common answer to "what have I deployed", unlike `getTokenHook`, where
    // "no hook" and "an empty hook" would be opposite tokens.
    //
    // The list is CAPPED by the store's retention, not paginated. A cursor would imply the
    // older pages exist; they do not, because the prune deleted them.
    let versions = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .token_hooks()
        .versions(state.env(), &client)
        .await?;
    let view: Vec<TokenHookVersionView> = versions
        .into_iter()
        .map(|version| TokenHookVersionView {
            version: version.version,
            component_bytes: version.component_bytes,
            payload_version: version.payload_version,
            failure_policy: version.failure_policy.as_str().to_owned(),
            created_at_unix_micros: version.created_at_unix_micros,
        })
        .collect();
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Roll a client's token hook back to an earlier version.
///
/// A rollback is a DEPLOY of an older component, not a rewind: it appends a new version whose
/// bytes are the named one's. So the number an operator asked for is not the number that ends
/// up active, and the response reports what is RUNNING rather than echoing the request.
///
/// # Why it takes no `Idempotency-Key`
///
/// Unlike the create-shaped POSTs on this surface, which mint an identity a replay must not
/// mint twice. This names an existing version, and the store makes a rollback to what is
/// already running write nothing -- so a retry after a lost response is inert rather than a
/// second deploy that spends a slot of the capped history. That inertness is the whole
/// justification, and it is asserted in `a_repeated_rollback_writes_no_second_version`.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/token-hook/rollback",
    operation_id = "rollbackTokenHook",
    tag = "token-hooks",
    request_body = RollbackTokenHookRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the hook shapes")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Rolled back. A NEW version carrying that component is now active, because a rollback is a deploy of an older component rather than a rewind; the response reports what is running. Rolling back to what is already running writes nothing and is safe to retry", body = TokenHookView),
        (status = 400, description = "An unreadable body", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found, malformed client id, or no such version. A version that existed can become no-such-version: the history is capped, so a number read from an older listing may since have been pruned", body = ErrorBody)
    )
)]
pub async fn rollback_token_hook(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // A ROLLBACK IS A DEPLOY of an older component, so it demands exactly what the deploy
    // does. It is also the break-glass path when a hook is failing logins, and that is an
    // argument for the operation existing rather than for making it cheaper to reach: an
    // attacker who can roll a client back to a hook that lacked a security-relevant claim has
    // stripped it from every token that client is issued.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let client = parse_client_id(&client_id, scope)?;
    crate::org_context::require_live_environment(&state, &scope).await?;

    let request: RollbackTokenHookRequest = crate::input::parse_json(&body)?;

    // THE TARGET'S METADATA FIRST, because the event describes what will be RUNNING and this
    // handler does not otherwise know: a rollback restores a component it never saw, so its
    // byte count and payload version belong to the version, not to the request.
    //
    // It also turns "no such version" into a 404 before anything is written. The store checks
    // again -- a concurrent delete between these two statements is real -- so this is the
    // better error rather than the only one.
    let target = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .token_hooks()
        .versions(state.env(), &client)
        .await?
        .into_iter()
        .find(|candidate| candidate.version == request.version)
        .ok_or(ApiError::NotFound)?;

    let announced = deployed_event(
        &state,
        scope,
        &client.to_string(),
        usize::try_from(target.component_bytes).map_err(|_| ApiError::Internal)?,
        u32::try_from(target.payload_version).map_err(|_| ApiError::Internal)?,
    );
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .token_hooks()
        .rollback_to(
            state.env(),
            &client,
            request.version,
            announced
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;

    // READ BACK rather than echoing the request. A rollback restores a component this handler
    // never saw, so its byte count and payload version come from the row, and reporting the
    // request's own numbers would report what was asked for rather than what is now running.
    let record = state
        .store()
        .scoped(scope)
        .token_hooks()
        .metadata(&client.to_string())
        .await?
        .ok_or(ApiError::Internal)?;
    let view = TokenHookView {
        client_id: record.client_id,
        component_bytes: usize::try_from(record.component_bytes).map_err(|_| ApiError::Internal)?,
        payload_version: u32::try_from(record.payload_version).map_err(|_| ApiError::Internal)?,
        failure_policy: record.failure_policy.as_str().to_owned(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}
