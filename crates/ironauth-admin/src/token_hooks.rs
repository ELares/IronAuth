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
    DeployTokenHookQuery, HookSecretQuery, NamedTokenHookQuery, ReorderTokenHooksRequest,
    RollbackTokenHookRequest, TestTokenHookRequest, TestTokenHookResponse, TokenHookChainEntryView,
    TokenHookChainView, TokenHookSecretsView, TokenHookVersionView, TokenHookView,
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

/// The most CHARACTERS a hook name may carry, matching the CHECK on the column.
///
/// Two copies of one number, and the reason is the one `MAX_COMPONENT_BYTES` gives for its own
/// pair: a database CHECK cannot produce this API's `ErrorBody`, so refusing here is what turns
/// a constraint violation into a message an operator can read.
///
/// CHARACTERS AND NOT BYTES, and an earlier version of this counted bytes while claiming to
/// match the column. Postgres `length()` counts characters, so the two bounds disagreed on
/// every non-ASCII name: a forty-character name of three-byte characters is a hundred and
/// twenty bytes, which the column admits and a byte count refuses. That direction is safe --
/// the API was strictly stricter, so no constraint violation could escape it -- but "matching
/// the CHECK" was false, and the next person to move one of the two numbers would have moved it
/// against a comment that lied about the other.
const MAX_HOOK_NAME_CHARS: usize = 64;

/// Which hook a request addresses, and where a NEW one goes.
///
/// Absent name means `default`, which is what every hook deployed before ordering existed was
/// backfilled to, so a caller that says nothing keeps addressing the hook it always did.
///
/// REFUSED AT THE DOOR rather than by the column's CHECK, for the reason above: an untrimmed or
/// over-long name is an operator mistake with an actionable message, and `23514` is not it.
fn hook_name(raw: Option<&str>) -> Result<&str, ApiError> {
    let name = raw.unwrap_or(ironauth_store::DEFAULT_HOOK_NAME);
    if name.is_empty() {
        return Err(ApiError::BadRequest(
            "invalid_hook_name: name must not be empty".to_owned(),
        ));
    }
    if name.trim() != name {
        return Err(ApiError::BadRequest(
            "invalid_hook_name: name must not begin or end with whitespace".to_owned(),
        ));
    }
    if name.chars().count() > MAX_HOOK_NAME_CHARS {
        return Err(ApiError::BadRequest(format!(
            "invalid_hook_name: name must be at most {MAX_HOOK_NAME_CHARS} characters"
        )));
    }
    Ok(name)
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
        ("failure_policy" = Option<String>, Query, description = "What the dispatch does when this hook does not complete: `fail_closed` (the default) or `fail_open`"),
        ("name" = Option<String>, Query, description = "Which of the client's hooks this deploys; absent means `default`"),
        ("ordinal" = Option<u32>, Query, description = "Where a NEW hook runs in the chain, ascending; absent means last. IGNORED when the hook already exists, so a redeploy replaces code without moving it")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Deployed", body = TokenHookView),
        (status = 400, description = "An unknown or absent payload version, an unknown failure policy, an invalid hook name, or bytes that are not a WebAssembly component", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found or malformed client id", body = ErrorBody),
        (status = 409, description = "This client already holds the maximum number of hooks", body = ErrorBody)
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
    let name = hook_name(query.name.as_deref())?;
    // ABSENT MEANS LAST, which is the only default that cannot surprise: appending changes
    // nothing about what the hooks already deployed are handed, while inserting at the front
    // silently changes the input of every one of them. An operator who wants a different
    // position says so, or reorders afterwards.
    //
    // IGNORED WHEN THE HOOK ALREADY EXISTS -- the upsert leaves `ordinal` alone on conflict --
    // and that is what a rollback depends on: restoring the code of the hook that runs third
    // must not make it run first.
    let ordinal = match query.ordinal.as_deref() {
        Some(raw) => raw
            .parse::<i32>()
            .ok()
            .filter(|at| *at >= 0)
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "invalid_ordinal: ordinal must be a non-negative integer".to_owned(),
                )
            })?,
        None => next_free_ordinal(&state, scope, &client).await?,
    };
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
            ironauth_store::HookDeployment {
                component: &body,
                payload_version: i32::try_from(payload_version).map_err(|_| ApiError::Internal)?,
                failure_policy,
                placement: ironauth_store::HookPlacement { name, ordinal },
            },
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
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the hook shapes"),
        ("name" = Option<String>, Query, description = "Which of the client's hooks to describe; absent means `default`")
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
    Query(query): Query<NamedTokenHookQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    principal.require_permission(ManagementPermission::Read)?;
    let client = parse_client_id(&client_id, scope)?;
    let hook = hook_name(query.name.as_deref())?;

    // `metadata`, not `get`: the component runs to tens of megabytes and this reports its
    // LENGTH, so the length is computed where the bytes already are rather than by hauling
    // them across the wire to call `.len()`.
    let record = state
        .store()
        .scoped(scope)
        .token_hooks()
        .metadata(&client.to_string(), hook)
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
    Query(query): Query<NamedTokenHookQuery>,
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
    let hook = hook_name(query.name.as_deref())?;
    crate::org_context::require_live_environment(&state, &scope).await?;

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .token_hooks()
        .delete_with_event(
            state.env(),
            &client,
            hook,
            deleted_event(&state, scope, &client.to_string())
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(no_content())
}

/// List a client's hook chain, in the order it runs.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/token-hook/chain",
    operation_id = "listTokenHookChain",
    tag = "token-hooks",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the hooks shape")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The chain, first to last. Empty when the client has no hooks", body = TokenHookChainView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found or malformed client id", body = ErrorBody)
    )
)]
pub async fn list_token_hook_chain(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`. It reports byte
    // LENGTHS and never components, so it discloses exactly what `getTokenHook` already does,
    // once per hook.
    principal.require_permission(ManagementPermission::Read)?;
    let client = parse_client_id(&client_id, scope)?;

    let chain = state
        .store()
        .scoped(scope)
        .token_hooks()
        .chain_metadata(&client.to_string())
        .await?;
    // AN EMPTY CHAIN IS A 200, not a 404. "This client has no hooks" is an answer to the
    // question asked, and the caller reordering a chain needs to tell it from "this client does
    // not exist" -- which is the 404 above, raised by `parse_client_id`.
    let view = TokenHookChainView {
        client_id: client.to_string(),
        hooks: chain
            .into_iter()
            .map(|hook| {
                Ok(TokenHookChainEntryView {
                    name: hook.name,
                    ordinal: hook.ordinal,
                    component_bytes: u32::try_from(hook.component_bytes)
                        .map_err(|_| ApiError::Internal)?,
                    payload_version: u32::try_from(hook.payload_version)
                        .map_err(|_| ApiError::Internal)?,
                    failure_policy: hook.failure_policy.as_str().to_owned(),
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Set the order a client's hooks run in.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/token-hook/order",
    operation_id = "reorderTokenHooks",
    tag = "token-hooks",
    request_body = ReorderTokenHooksRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the hooks shape")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The chain in its new order", body = TokenHookChainView),
        (status = 400, description = "A malformed body or a repeated name", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found, malformed client id, or the order is not exactly this client's hook names", body = ErrorBody)
    )
)]
pub async fn reorder_token_hooks(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    body: axum::extract::Json<ReorderTokenHooksRequest>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`, with the
    // DEPLOY rather than the reads, because a reorder changes what every later hook is handed
    // and so can change every claim in a token while every component stays byte-identical.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // FRESH PRIVILEGE, for the same reason a deploy demands it. Reordering is not a smaller
    // act than deploying: moving a hook that strips a claim to run before the one that adds it
    // puts the claim back in every token, without any code changing.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let client = parse_client_id(&client_id, scope)?;
    crate::org_context::require_live_environment(&state, &scope).await?;

    // NAMES VALIDATED AT THE DOOR, so an untrimmed or over-long entry is this API's 400 rather
    // than a 404 that reads as "no such hook" -- the caller needs to tell "I typed the name
    // wrong" from "that hook is not deployed".
    for name in &body.order {
        hook_name(Some(name.as_str()))?;
    }

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .token_hooks()
        .reorder(state.env(), &client, &body.order)
        .await?;

    // READ BACK, not echo. The request says what the caller asked for; the response says what
    // the chain IS, which is what they need to see to know the arrangement took.
    let chain = state
        .store()
        .scoped(scope)
        .token_hooks()
        .chain_metadata(&client.to_string())
        .await?;
    let view = TokenHookChainView {
        client_id: client.to_string(),
        hooks: chain
            .into_iter()
            .map(|hook| {
                Ok(TokenHookChainEntryView {
                    name: hook.name,
                    ordinal: hook.ordinal,
                    component_bytes: u32::try_from(hook.component_bytes)
                        .map_err(|_| ApiError::Internal)?,
                    payload_version: u32::try_from(hook.payload_version)
                        .map_err(|_| ApiError::Internal)?,
                    failure_policy: hook.failure_policy.as_str().to_owned(),
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// The secret name a grant or a revoke addresses.
///
/// REQUIRED, unlike the hook name, and the asymmetry is deliberate: `default` is a meaningful
/// answer for "which hook" and there is no meaningful default secret. A request that omitted it
/// would have to mean "all of them", which is not something an operator should be able to say
/// by leaving a parameter out.
fn secret_name(raw: Option<&str>) -> Result<&str, ApiError> {
    let name = raw.ok_or_else(|| {
        ApiError::BadRequest("invalid_secret_name: secret is required".to_owned())
    })?;
    if name.is_empty() || name.trim() != name {
        return Err(ApiError::BadRequest(
            "invalid_secret_name: secret must not be empty or padded with whitespace".to_owned(),
        ));
    }
    // 128, matching the CHECK on `token_hook_secrets.secret_name`, in the column's unit --
    // Postgres `length()` counts CHARACTERS. Refusing here is what turns a constraint violation
    // into a message an operator reads.
    if name.chars().count() > MAX_SECRET_NAME_CHARS {
        return Err(ApiError::BadRequest(format!(
            "invalid_secret_name: secret must be at most {MAX_SECRET_NAME_CHARS} characters"
        )));
    }
    Ok(name)
}

/// The most CHARACTERS an environment secret name may carry, matching its column's CHECK.
const MAX_SECRET_NAME_CHARS: usize = 128;

/// List the environment secrets a hook may read.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/token-hook/secrets",
    operation_id = "listTokenHookSecrets",
    tag = "token-hooks",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the hook shapes"),
        ("name" = Option<String>, Query, description = "Which of the client's hooks; absent means `default`")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The secret NAMES this hook may read, never their values", body = TokenHookSecretsView),
        (status = 400, description = "An invalid hook name", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found or malformed client id", body = ErrorBody)
    )
)]
pub async fn list_token_hook_secrets(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    Query(query): Query<HookSecretQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`. It reports NAMES and
    // never values -- the values live sealed behind a different repository and the platform
    // key -- so this discloses which secrets an operator wired to a hook and nothing they hold.
    principal.require_permission(ManagementPermission::Read)?;
    let client = parse_client_id(&client_id, scope)?;
    let hook = hook_name(query.name.as_deref())?;

    let secrets = state
        .store()
        .scoped(scope)
        .token_hooks()
        .granted_secrets(&client.to_string(), hook)
        .await?;
    let view = TokenHookSecretsView {
        client_id: client.to_string(),
        hook: hook.to_owned(),
        secrets,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Grant a hook permission to read an environment secret.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/token-hook/secrets",
    operation_id = "grantTokenHookSecret",
    tag = "token-hooks",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the hook shapes"),
        ("name" = Option<String>, Query, description = "Which of the client's hooks; absent means `default`"),
        ("secret" = String, Query, description = "The environment secret's name. REQUIRED: there is no meaningful default, and an omitted one would have to mean `all of them`")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The secret NAMES this hook may now read", body = TokenHookSecretsView),
        (status = 400, description = "An invalid or absent secret name, or an invalid hook name", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found, malformed client id, or that hook is not deployed", body = ErrorBody)
    )
)]
pub async fn grant_token_hook_secret(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    Query(query): Query<HookSecretQuery>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`, with the
    // DEPLOY. Granting a secret to a hook widens what the operator's own code inside the token
    // mint may read, which is a configuration change with the same reach as deploying the code.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // FRESH PRIVILEGE, for the same reason a deploy demands it and with more force: this hands
    // a key to code, and the code is already running on every token this client is issued.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let client = parse_client_id(&client_id, scope)?;
    crate::org_context::require_live_environment(&state, &scope).await?;
    let hook = hook_name(query.name.as_deref())?;
    let secret = secret_name(query.secret.as_deref())?;

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .token_hooks()
        .grant_secret(state.env(), &client, hook, secret)
        .await?;
    read_back_secrets(&state, scope, &client, hook).await
}

/// Withdraw a hook's permission to read an environment secret.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/token-hook/secrets",
    operation_id = "revokeTokenHookSecret",
    tag = "token-hooks",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the hook shapes"),
        ("name" = Option<String>, Query, description = "Which of the client's hooks; absent means `default`"),
        ("secret" = String, Query, description = "The environment secret's name")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The secret NAMES this hook may still read. Revoking a grant that does not exist succeeds: the caller's intent holds either way", body = TokenHookSecretsView),
        (status = 400, description = "An invalid or absent secret name, or an invalid hook name", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found or malformed client id", body = ErrorBody)
    )
)]
pub async fn revoke_token_hook_secret(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    Query(query): Query<HookSecretQuery>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    //
    // Like the grant, and NOT a lesser permission because it is the safe direction. A caller who can narrow what a hook reads can break a working hook, which is
    // a configuration change; and a permission that let someone revoke but not grant would be
    // a denial-of-service primitive handed out as a read.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let client = parse_client_id(&client_id, scope)?;
    crate::org_context::require_live_environment(&state, &scope).await?;
    let hook = hook_name(query.name.as_deref())?;
    let secret = secret_name(query.secret.as_deref())?;

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .token_hooks()
        .revoke_secret(state.env(), &client, hook, secret)
        .await?;
    read_back_secrets(&state, scope, &client, hook).await
}

/// The hook's grants as they now stand, as a response body.
///
/// READ BACK, not echoed. The request says what the caller asked for; this says what the hook
/// may read, which is what they need to see to know the change took -- and on a revoke of a
/// grant that never existed, the two differ in exactly the way the caller should be able to
/// notice.
async fn read_back_secrets(
    state: &AdminState,
    scope: ironauth_store::Scope,
    client: &ironauth_store::ClientId,
    hook: &str,
) -> Result<Response, ApiError> {
    let secrets = state
        .store()
        .scoped(scope)
        .token_hooks()
        .granted_secrets(&client.to_string(), hook)
        .await?;
    let view = TokenHookSecretsView {
        client_id: client.to_string(),
        hook: hook.to_owned(),
        secrets,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// One past the last position this client's chain occupies, or zero when it has none.
///
/// What "absent means last" resolves to. Reading it rather than counting the hooks matters
/// because positions may have GAPS: deleting the hook at position one leaves two at two, and a
/// count would return two and collide.
///
/// A RACE IS POSSIBLE and it is a 409 rather than a corruption: two concurrent deploys of two
/// NEW hooks can read the same free position, and the second one violates the unique constraint.
/// That is the right failure -- the alternative is picking a position for a caller who did not
/// choose one, silently, while another deploy did the same.
async fn next_free_ordinal(
    state: &AdminState,
    scope: ironauth_store::Scope,
    client: &ironauth_store::ClientId,
) -> Result<i32, ApiError> {
    let chain = state
        .store()
        .scoped(scope)
        .token_hooks()
        .chain_metadata(&client.to_string())
        .await?;
    Ok(chain
        .iter()
        .map(|hook| hook.ordinal)
        .max()
        .map_or(0, |last| last.saturating_add(1)))
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
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the hook shapes"),
        ("name" = Option<String>, Query, description = "Which of the client's hooks to list versions of; absent means `default`")
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
    Query(query): Query<NamedTokenHookQuery>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    principal.require_permission(ManagementPermission::Read)?;
    let client = parse_client_id(&client_id, scope)?;
    let hook = hook_name(query.name.as_deref())?;

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
        .versions(state.env(), &client, hook)
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
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the hook shapes"),
        ("name" = Option<String>, Query, description = "Which of the client's hooks to roll back; absent means `default`")
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
    Query(query): Query<NamedTokenHookQuery>,
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
    let hook = hook_name(query.name.as_deref())?;
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
        .versions(state.env(), &client, hook)
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
            hook,
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
        // THE DEFAULT HOOK, matching the rollback above: `rollback_to` restores the default
        // hook's code, so the row it wrote is the row read back. When rollback takes a name,
        // both halves take the same one.
        .metadata(&client.to_string(), hook)
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

/// Run a client's token hook against a recorded event, without deploying anything.
///
/// Issue #114 criterion 5's fixture-based draft testing, and the half of the Auth0 Actions loop
/// this surface was missing: deploy, ROLL BACK and list already worked, so an operator could
/// recover from a bad hook but could not avoid shipping one.
///
/// # It runs the SHIPPED dispatch, not a copy of it
///
/// `ironauth_oidc::token_hook::run_record` is the same function an issuance calls, with the
/// same limits, the same payload-version check, the same fence and the same fault
/// classification. A second implementation built for this endpoint would answer about itself,
/// which is the one thing a draft run must not do.
///
/// Two deliberate departures, both because a draft run has no login to protect:
///
/// * THE FAILURE POLICY IS NOT APPLIED. `run` swallows a fault under `fail_open` so a broken
///   hook does not fail a login. Here the operator IS the audience, and hiding the fault is
///   hiding the answer, so the outcome reports `aborted` with the reason.
///
/// # A deliberate DECLINE is reported as `aborted`, and that is a real limitation
///
/// The WIT contract distinguishes them -- its own doc says the error arm "is NOT the same thing
/// as a trap" -- and `HookFault` does not: `Aborted` is documented as "exhausted a bound,
/// trapped, OR DECLINED", because at issuance the difference changes nothing a client may see.
/// It changes plenty for an operator testing a hook, and carrying it out means giving
/// `HookFault` a payload it deliberately does not have. Not done here. Said rather than papered
/// over with an outcome value nothing can produce.
/// * THE FENCE'S REFUSALS ARE REPORTED, and so is the count of claims whose VALUE was not
///   JSON. At issuance both are logged and dropped, because nobody can act on them
///   mid-request. An operator asking what a hook would do can act on "it tried to set `sub`"
///   immediately -- and on "one of your values is not JSON", which is the one class that
///   otherwise leaves no trace at all: the claim is missing from the maps and missing from
///   `refused`, exactly as it is for a hook that dropped it on purpose.
///
/// # The GRANT decides whether there is an ID half
///
/// `client_credentials`, `jwt:bearer` and token exchange mint no ID token, and their shipped
/// dispatch is `apply_to_machine_token`, which hands the guest an EMPTY ID-token list and drops
/// the one it returns. A draft run on those grants does the same and reports
/// `id_token_claims_discarded` instead, so the answer is the one that door would give rather
/// than the one the fixture asked for. That is not a third departure: it is the shipped
/// behaviour of the grant the request names.
///
/// # Nothing is written, and one thing IS disclosed
///
/// No deploy, no version row, no audit `token_hook.set`. It is a READ plus a computation, which
/// is why it is `management.read` rather than `write_config` -- and why it does not take the
/// sudo freshness a deploy does.
///
/// It does disclose the hook's BEHAVIOUR, which the metadata read does not, and an earlier
/// version of this paragraph said the opposite: that running a hook the operator can already
/// read the bytes of discloses nothing new. No endpoint returns the component. `TokenHookView`
/// and `TokenHookVersionView` carry a byte LENGTH, and `get_token_hook` calls `metadata` rather
/// than `get` precisely so the bytes stay in the database. So a `management.read` credential
/// that could previously learn a length, a payload version and a failure policy can now learn
/// what the hook EMITS for an event it chose, for the deployed hook and for every retained
/// version. That is what the endpoint is for, and it is bounded by the guest world importing
/// NOTHING: a run is a pure function of the component and the supplied event, reaching no user,
/// no stored row and no network. It sits with the reads on the same ground as
/// `getClaimsMapping`, which hands this same reader the complete declarative rule list shaping
/// the same tokens.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/token-hook/test",
    operation_id = "testTokenHook",
    tag = "token-hooks",
    request_body = TestTokenHookRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier whose tokens the hook shapes"),
        ("name" = Option<String>, Query, description = "Which of the client's hooks to run; absent means `default`")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The hook ran. `outcome` is `completed` or `aborted`; an aborted run is still a 200, because the QUESTION was answered. `refused` is capped, so read `refusals_not_reported` before treating it as complete, and on a grant that mints no ID token `id_token_claims` is empty with `id_token_claims_discarded` saying how many the hook returned, and `values_not_json` for claims the hook mis-serialised, which are dropped and appear in neither list", body = TestTokenHookResponse),
        (status = 400, description = "An unreadable body", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found, malformed client id, no hook deployed, or no such version", body = ErrorBody),
        (status = 503, description = "This build or this process does not carry the WASM hook runtime", body = ErrorBody)
    )
)]
pub async fn test_token_hook(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    Query(query): Query<NamedTokenHookQuery>,
    body: Bytes,
) -> Result<Response, ApiError> {
    // NO ACTOR, and that is the tell: `resolve_scope` returns one for writing onto an audit
    // row, and this handler writes none.
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    //
    // READ and not `write_config`, unlike its three write-shaped neighbours on this surface:
    // this stores nothing, and what it DOES disclose -- the hook's behaviour on an event the
    // caller supplied -- is a read of a hook resource this credential may already read, bounded
    // by a guest world that imports nothing. See the note on the handler.
    principal.require_permission(ManagementPermission::Read)?;
    let client = parse_client_id(&client_id, scope)?;
    let hook = hook_name(query.name.as_deref())?;
    crate::org_context::require_live_environment(&state, &scope).await?;

    let request: TestTokenHookRequest = crate::input::parse_json(&body)?;

    // The RECORD to run: a named version, or the active hook. Both come back as the same type,
    // so the dispatch below cannot tell which one it was handed -- which is the point.
    // The plain repo, not the acting one: this READS. `acting` exists to carry an actor onto an
    // audit row, and a draft run writes none.
    let hooks = state.store().scoped(scope).token_hooks();
    // AND WHICH VERSION THAT IS, resolved rather than echoed.
    //
    // `version_run` said "which version ran, so a run with no `version` says which one it
    // picked" and was set to `request.version` at all three arms -- so in the case the sentence
    // names, the omitted one, it serialised as null. The record carries no version number
    // (`token_hooks` has no such column; the numbers live in the history), so the active
    // version is the newest row in the history, which is what a deploy appends and what a
    // rollback appends too.
    //
    // ONE READ, not two. The first version of this fix called `get` and then `newest_version`,
    // which is two transactions and therefore two snapshots: a deploy landing between them
    // returns the OLD component beside the NEW number, and the report then names a version
    // whose bytes did not run -- the version an operator would roll back to.
    // `active_with_version` resolves the pair in a single statement.
    let (record, version_run) = if let Some(version) = request.version {
        (
            hooks.version(&client.to_string(), hook, version).await?,
            Some(version),
        )
    } else {
        match hooks.active_with_version(&client.to_string(), hook).await? {
            Some((record, newest)) => (Some(record), newest),
            None => (None, None),
        }
    };
    let Some(record) = record else {
        // The uniform not-found covers both "no hook deployed" and "no such version". They are
        // different sentences to an operator, and the 404 body says both.
        //
        // NOT because distinguishing them would leak the version count -- it would not, to this
        // caller: `listTokenHookVersions` is on the same `management.read` permission and hands
        // them the whole list. Uniform because the two states are one answer to the question
        // asked ("there is nothing here to run"), and because a body that branched would be a
        // second place the version-existence rule is written down.
        return Err(ApiError::NotFound);
    };

    // NOT a 500 and not a plain refusal, for the reason `NotConfigured` already gives about a
    // missing DNS resolver: answering "the hook produced nothing" would be indistinguishable
    // from a hook that produced nothing, and would send an operator to debug their component
    // instead of their build.
    let Some(runtime) = state.hook_runtime() else {
        return Err(ApiError::NotConfigured(
            "the WASM hook runtime is not available in this build or process".to_owned(),
        ));
    };

    // NO `cfg` HERE, and that is deliberate. A `cfg` in this crate keys on THIS crate's flag
    // while `HookRuntime` comes from `ironauth-oidc`'s, and the two can be enabled
    // independently -- measured, that combination fails to compile. The stub module carries the
    // whole seam instead, so one signature serves both builds.
    let grant_type = request
        .grant_type
        .as_deref()
        .unwrap_or("authorization_code");
    // WHETHER THERE IS AN ID TOKEN AT ALL is decided by the GRANT, not by the fixture.
    //
    // `client_credentials`, `jwt:bearer` and token exchange mint no ID token, and their shipped
    // dispatch -- `apply_to_machine_token` -- hands the guest an EMPTY ID-token list and DROPS
    // the one it returns. Passing the request's list through would hand the guest an input no
    // login on that grant produces, so a hook branching on that list takes a different branch
    // here than in production, and the report would name an ID half nothing can carry.
    let mints_id_token =
        ironauth_oidc::claims_mapping_at_issuance::grant_mints_id_token(grant_type);
    let no_id_token = serde_json::Map::new();
    let invocation = ironauth_oidc::token_hook::Invocation {
        scope,
        client_id: &client.to_string(),
        grant_type,
        subject: request.subject.as_deref(),
        id_token_claims: if mints_id_token {
            &request.id_token_claims
        } else {
            &no_id_token
        },
        access_token_claims: &request.access_token_claims,
    };
    let outcome = ironauth_oidc::token_hook::run_record(runtime, &invocation, &record).await;
    let view = match outcome {
        Ok(Some(claims)) => {
            // THE DISCARDED ID HALF IS COUNTED, for the same reason the fence's refusals are
            // reported: at issuance it is a log line the operator has to go and find, and here
            // they are the audience. An empty `id_token_claims` with a non-zero count says
            // "your hook filled the ID list and this grant threw it away"; without the count
            // it is indistinguishable from a hook that filled nothing.
            let (id_token_claims, id_token_claims_discarded) = if mints_id_token {
                (claims.id_token.into_iter().collect(), 0)
            } else {
                (serde_json::Map::new(), claims.id_token.len())
            };
            TestTokenHookResponse {
                outcome: "completed".to_owned(),
                reason: None,
                id_token_claims,
                access_token_claims: claims.access_token.into_iter().collect(),
                refused: claims.refused,
                refusals_not_reported: claims.refusals_not_reported,
                values_not_json: claims.values_not_json,
                id_token_claims_discarded,
                version_run,
            }
        }
        // UNREACHABLE, and named rather than described as a behaviour. `run_record` delegates
        // to `run_deployed_hook`, whose only non-error exit is `Ok(Some(..))`. The `None` in
        // the seam's type belongs to `run`, which uses it for "no hook deployed" and for a
        // fail-open swallow -- neither of which a draft run reaches, because it resolves the
        // record itself (404 above) and applies no failure policy. The arm is here because the
        // match is exhaustive, not because anything produces it.
        //
        // What it must NOT be read as is "the hook contributed nothing". Under the REPLACE
        // contract a hook that changes nothing ECHOES what it was handed, and `fence` keeps
        // echoes rather than putting them through the fence -- so that hook reports the FULL
        // maps, not empty ones.
        Ok(None) => TestTokenHookResponse {
            outcome: "completed".to_owned(),
            reason: None,
            id_token_claims: serde_json::Map::new(),
            access_token_claims: serde_json::Map::new(),
            refused: Vec::new(),
            refusals_not_reported: 0,
            values_not_json: 0,
            id_token_claims_discarded: 0,
            version_run,
        },
        Err(fault) => TestTokenHookResponse {
            outcome: "aborted".to_owned(),
            // A STABLE TOKEN, not `{fault:?}`. `HookFault`'s own doc says it deliberately
            // carries no underlying error because "a client learning which resource bound
            // a hook exhausted learns about the hook" -- and the four variants are exactly
            // the distinction an operator needs: their artifact is wrong, their code
            // misbehaved, their payload version is stale, or the store was unreachable.
            reason: Some(
                match fault {
                    ironauth_oidc::token_hook::HookFault::Unavailable => "store_unavailable",
                    ironauth_oidc::token_hook::HookFault::Unloadable => "component_unloadable",
                    ironauth_oidc::token_hook::HookFault::Aborted => "aborted_or_declined",
                    ironauth_oidc::token_hook::HookFault::PayloadVersion => "payload_version",
                }
                .to_owned(),
            ),
            id_token_claims: serde_json::Map::new(),
            access_token_claims: serde_json::Map::new(),
            refused: Vec::new(),
            refusals_not_reported: 0,
            values_not_json: 0,
            id_token_claims_discarded: 0,
            version_run,
        },
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}
