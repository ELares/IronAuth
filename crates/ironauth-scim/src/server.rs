// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SCIM 2.0 inbound HTTP surface: authentication and discovery (issue #135).
//!
//! # Where this is mounted, and why
//!
//! The PUBLIC plane, beside the OIDC provider, not the management plane. The callers are
//! Okta, Entra and their peers, which are hosted services on the open internet, so a surface they cannot reach
//! is a surface that does not work. It carries its own authentication and shares none with the
//! management API: an operator token opens nothing here, and a connection token opens nothing
//! there.
//!
//! # The path carries no organization, deliberately
//!
//! RFC 7644 puts resources under a base URL, and the obvious shape would be
//! `/organizations/{id}/scim/v2/Users`. This surface does not do that. The organization comes
//! off the CREDENTIAL (see migration 0183), so the path is
//! `/scim/v2/...` with nothing in it a caller could vary.
//!
//! That is the whole answer to the CVE class this issue names. Zitadel's CVE-2026-32130 was a
//! SCIM auth bypass through URL ENCODING and Casdoor's CVE-2025-4210 an authorization gap:
//! both are attacks on the step where a server decodes a caller-supplied identifier and then
//! decides whether the caller may have it. A path with no organization in it has no such step.
//! "Decode then authorize" is the standard advice; having nothing to decode is stronger.
//!
//! # Mounted behind a config flag
//!
//! `crates/ironauth/src/main.rs` mounts this router on the public plane when `scim.enabled`
//! is set. While it is off nothing under `/scim/v2` is mounted and every such path is a
//! uniform 404, which is the same shape the admin console takes: a surface an operator has
//! not asked for is not one reachable from the internet.

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::map_response;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use ironauth_store::identifier::UniquenessMode;
use ironauth_store::{ActorRef, ScimConnection, ServiceId, Store};
use serde_json::json;

use crate::service_provider_config::{ScimLimits, ServiceProviderConfig};

// WHERE THE PRE-AUTHENTICATION BOUND ACTUALLY LIVES, and why there is no semaphore here.
//
// Every request reaches `scim_connections().authenticate` before anything is authenticated:
// a well-formed but invented bearer token costs one store round trip. That is by design --
// the digest lookup IS the authentication -- and it means an unauthenticated caller
// influences how much database work this surface does.
//
// A previous revision of this file bounded that with a 32-permit semaphore and `try_acquire`.
// It was wrong twice over, and a reviewer measured both. The pool `Store::connect` builds
// caps connections at 16, so database work in flight was ALREADY bounded at half the
// semaphore's size and the semaphore could never be the binding constraint -- the number was
// chosen without reading the one beside it. And because `try_acquire` refuses rather than
// queues, 64 concurrent requests carrying the SAME VALID TOKEN got 32 answers and 32 refusals
// in 0.34 seconds against an idle database: a provisioning surface refusing provisioning. The
// refusal was a 503, which `AuthRefusal::Unavailable` documents as the answer clients back off
// on, so the mitigation would have converted a burst into cross-tenant identity-provider
// backoff that any caller could trigger on demand with 32 open connections.
//
// So the bound is the connection pool, which is a real bound on the real resource, and the
// gap that remains is honest: the public plane applies no rate limit of its own (verified --
// `ironauth-server` installs a panic catcher, a header backstop and observation, and nothing
// else). Closing that needs a dimension, and the only one available before authentication is
// the scope the caller's own token declares. That is a decision to make alongside the
// credential-minting route, not a number to guess at here.

/// The largest request body this surface accepts.
///
/// One mebibyte, the same figure as `BulkLimits::max_payload_bytes`. They are TWO literals,
/// not one: a reviewer pointed out that an earlier version of this sentence claimed they were
/// "one number rather than two that drift" while nothing pinned them together. The agreement
/// is asserted by `the_two_payload_bounds_agree` below rather than described here. A SCIM create or PATCH is a small JSON document;
/// the only shape that approaches this is a bulk payload, and that surface advertises the same
/// figure.
///
/// EXPLICIT rather than inherited. Axum's implicit default is 2 MiB and its refusal is a bare
/// `text/plain` 413 emitted before any handler runs, which is the one response shape on this
/// surface that would not be SCIM.
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;

/// Rewrite the framework's oversized-body refusal into a SCIM error document.
///
/// # Exactly the 413, and nothing else
///
/// The first version keyed on the ABSENCE of a content type, reasoning that only a framework
/// response would lack one. It does not: axum's body-limit rejection answers
/// `text/plain; charset=utf-8` with "Failed to buffer the request body", so the guard passed
/// it straight through and the test caught it.
///
/// Keying on the status is also what keeps this narrow. A path this router does not mount
/// falls through to axum's own 404, and that 404 must STAY un-SCIM: `surface.rs` uses the
/// content type to tell a mounted route from an unmounted one, which is the only signal that
/// separates them once a mounted route can legitimately answer 404 for an absent resource.
/// Rewriting every framework response would destroy that discriminator.
///
/// No handler here produces a 413, so a 413 is always the body-limit layer's.
///
/// # Why a response map and not a fallback
///
/// A reviewer falsified the reason an earlier version of this comment gave. It said
/// `DefaultBodyLimit` "rejects before routing", and it does not: the layer only inserts a
/// limit into the request extensions, and the 413 is produced by the BODY EXTRACTOR inside
/// the matched route. A router `fallback` therefore never sees it, which is why this is a
/// response map.
///
/// The correction matters beyond the wording. Because the bound is enforced by the extractor,
/// it reaches only handlers that extract a body -- a route taking no body extractor would
/// answer 200 to an oversized request, which the reviewer demonstrated directly. Every route
/// on this surface that accepts a body takes `body: String`, so the bound is complete today;
/// a future route that reads the body some other way would not inherit it.
async fn scim_shaped_refusal(response: Response) -> Response {
    if response.status() != StatusCode::PAYLOAD_TOO_LARGE {
        return response;
    }
    scim_error(
        StatusCode::PAYLOAD_TOO_LARGE,
        Some("tooLarge"),
        "the request body exceeds the size this server accepts",
    )
}

/// The SCIM content type (RFC 7644 section 3.1). Answered on every response, including errors.
pub const SCIM_CONTENT_TYPE: &str = "application/scim+json";

/// Everything the SCIM surface needs to serve a request.
#[derive(Clone)]
pub struct ScimState {
    inner: Arc<ScimStateInner>,
}

struct ScimStateInner {
    store: Store,
    env: ironauth_env::Env,
    limits: ScimLimits,
    uniqueness: UniquenessMode,
}

impl ScimState {
    /// Build the state for a mounted SCIM surface.
    ///
    /// `uniqueness` is the DEPLOYMENT's configured identifier-uniqueness mode, passed in
    /// rather than chosen here. SCIM is one door onto the same identity model the admin API
    /// writes through, and a surface that picked its own mode would make "the same person"
    /// mean one thing through this door and another through that one.
    #[must_use]
    pub fn new(
        store: Store,
        env: ironauth_env::Env,
        limits: ScimLimits,
        uniqueness: UniquenessMode,
    ) -> Self {
        Self {
            inner: Arc::new(ScimStateInner {
                store,
                env,
                limits,
                uniqueness,
            }),
        }
    }

    /// The advertised limits, which are also the ones enforced.
    #[must_use]
    pub fn limits(&self) -> &ScimLimits {
        &self.inner.limits
    }

    /// The store the resource handlers read and write through.
    pub(crate) fn store(&self) -> &Store {
        &self.inner.store
    }

    /// The application environment, which owns the clock and the id generator.
    pub(crate) fn env(&self) -> &ironauth_env::Env {
        &self.inner.env
    }

    /// The deployment's configured identifier-uniqueness mode.
    ///
    /// Public so the boot-wiring harness can assert this surface and the management plane hold
    /// the SAME mode. Two doors onto one identity model that disagreed about what "the same
    /// person" means is the corruption the single-carrier boot exists to prevent, and it is
    /// only observable if the value can be read back off an assembled state.
    #[must_use]
    pub fn uniqueness_mode(&self) -> UniquenessMode {
        self.inner.uniqueness
    }

    /// Resolve the connection a request authenticates as, for a resource handler.
    ///
    /// # Errors
    ///
    /// [`AuthRefusal`] when the request carries no usable credential. Both variants render
    /// the same response; see [`AuthRefusal::response`].
    pub(crate) async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<Authenticated, AuthRefusal> {
        let (scope, connection) = authenticate(self, headers).await?;
        // The audit actor is DERIVED from the connection id rather than generated, so every
        // row a given credential writes carries one stable machine principal and an operator
        // reading the audit log can group a provisioning run. This is the same derivation a
        // management API key's actor uses.
        let actor = ActorRef::service(ServiceId::from_seed_bytes(connection.id.unique_bytes()));
        Ok(Authenticated {
            scope,
            connection,
            actor,
        })
    }
}

/// A request that has proved which connection it is.
///
/// Carried by value into every resource handler, so a handler cannot read the credential's
/// organization from anywhere else: there is no other place in the module that has one.
pub(crate) struct Authenticated {
    /// The (tenant, environment) the credential declared and was found in.
    pub(crate) scope: ironauth_store::Scope,
    /// The connection itself, whose `organization_id` is the authorization boundary.
    pub(crate) connection: ScimConnection,
    /// The audit principal every write by this request is attributed to.
    pub(crate) actor: ActorRef,
}

/// The SCIM router (issue #135).
///
/// Every route is under `/scim/v2` and every one authenticates the same way. There is no
/// unauthenticated route, including the discovery documents: RFC 7644 section 4 permits them
/// to be open, and this surface does not take that permission, because an open endpoint that
/// echoes a deployment's configured limits is a free fingerprint of the deployment.
pub fn scim_router(state: ScimState) -> Router {
    Router::new()
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(service_provider_config),
        )
        .route("/scim/v2/ResourceTypes", get(resource_types))
        .route("/scim/v2/Schemas", get(schemas))
        .route(
            "/scim/v2/Users",
            get(crate::users::list_users).post(crate::users::create_user),
        )
        .route(
            "/scim/v2/Users/{id}",
            get(crate::users::get_user)
                .put(crate::users::replace_user)
                .patch(crate::users::patch_user)
                .delete(crate::users::delete_user),
        )
        .route(
            "/scim/v2/Groups",
            get(crate::groups::list_groups).post(crate::groups::create_group),
        )
        .route(
            "/scim/v2/Groups/{id}",
            get(crate::groups::get_group)
                .put(crate::groups::replace_group)
                .patch(crate::groups::patch_group)
                .delete(crate::groups::delete_group),
        )
        .with_state(state)
        // EVERY RESPONSE ON THIS SURFACE IS A SCIM DOCUMENT, including the ones the framework
        // produces. Six handlers take `body: String`, so without an explicit bound they
        // inherit axum's implicit 2 MiB default and a body over it becomes a bare
        // `text/plain` 413 emitted before any handler runs -- which falsifies
        // `SCIM_CONTENT_TYPE`'s own promise two hundred lines up, and hands Okta and Entra a
        // response shape their connectors do not parse.
        //
        // The bound is `MAX_REQUEST_BYTES` and the refusal is rewritten below, so the answer
        // to an oversized body is a SCIM error like every other refusal here.
        .layer(map_response(scim_shaped_refusal))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
}

/// Why a SCIM request was refused before any handler ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthRefusal {
    /// No `Authorization: Bearer` header, or one that does not parse.
    Missing,
    /// A well-formed bearer token that matches no live connection.
    Unknown,
    /// The credential could not be CHECKED, which is not the same as being invalid.
    ///
    /// A database outage answering 401 tells every identity provider that its credential has
    /// stopped working. A well-behaved one then stops retrying and alerts an operator about a
    /// revocation that did not happen, so an IronAuth outage becomes a customer-visible
    /// credential incident. 503 says the true thing, and is what a client backs off on.
    Unavailable,
}

impl AuthRefusal {
    /// The wire answer.
    ///
    /// Both REFUSALS answer 401 with the same body. A caller that could tell "no such token"
    /// from "malformed header" learns nothing useful, but a caller that could tell "no such
    /// token" from "revoked token" learns that a token it holds was once valid -- which is
    /// exactly what an attacker testing a leaked credential wants to know.
    pub(crate) fn response(self) -> Response {
        if self == AuthRefusal::Unavailable {
            return scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                None,
                "the credential could not be verified; retry later",
            );
        }
        scim_error(
            StatusCode::UNAUTHORIZED,
            None,
            "the request carried no usable SCIM credential",
        )
    }
}

/// A SCIM error document (RFC 7644 section 3.12), with the SCIM content type.
///
/// `scim_type` is omitted for statuses that do not define one, which is most of them; RFC 7644
/// lists `scimType` only for 400 and 409.
pub(crate) fn scim_error(status: StatusCode, scim_type: Option<&str>, detail: &str) -> Response {
    let mut body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "detail": detail,
        "status": status.as_u16().to_string(),
    });
    if let Some(scim_type) = scim_type {
        body["scimType"] = json!(scim_type);
    }
    (
        status,
        [(header::CONTENT_TYPE, SCIM_CONTENT_TYPE)],
        body.to_string(),
    )
        .into_response()
}

/// A SCIM success document, with the SCIM content type.
fn scim_ok<T: serde::Serialize>(body: &T) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, SCIM_CONTENT_TYPE)],
        Json(body).into_response().into_body(),
    )
        .into_response()
}

/// A SCIM success document at an explicit status, with the SCIM content type.
///
/// Separate from [`scim_ok`] because a create answers 201 and a list answers 200 with the
/// same body shape: one renderer, two statuses, rather than two renderers that can drift on
/// the content type.
pub(crate) fn scim_json(status: StatusCode, body: &serde_json::Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, SCIM_CONTENT_TYPE)],
        body.to_string(),
    )
        .into_response()
}

/// The bearer token a request presents, or [`None`].
///
/// Case-insensitive on the scheme per RFC 7235. The token is taken as sent EXCEPT for the
/// whitespace RFC 7235 allows between the scheme and the credential, which `split_once(' ')`
/// leaves on the front when a caller sent more than one space. Nothing else is trimmed or
/// decoded: the digest covers the whole remaining string, so any further normalization here
/// would make it depend on this parser rather than on what the caller sent.
fn presented_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim_start();
    (!token.is_empty()).then_some(token)
}

/// The SHA-256 hex digest a presented token is looked up by.
fn token_digest(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Resolve the connection a request authenticates as.
///
/// # The token DECLARES its own scope, and that is not a convenience
///
/// A SCIM caller names no tenant, no environment and no organization anywhere in the request.
/// Something still has to say which scope to look in, and there are only two candidates: search
/// every scope, or have the credential carry it.
///
/// Searching every scope would mean a reader that crosses a tenant boundary -- the one thing
/// this store's row-level security exists to make impossible -- justified by "the digest is
/// unguessable". That is a real argument and it is the wrong trade: it puts an unscoped query
/// into the codebase, and the next person to need one has a precedent.
///
/// So the token is `{scim_id}.{secret}`, and the `scim_` half is a SCOPED identifier that
/// decodes to its own (tenant, environment) exactly as an authorization code does
/// (`parse_declared_scope`). The lookup then runs INSIDE that scope under the ordinary policy.
/// A caller who edits the id half to name another tenant simply looks up a digest that is not
/// there: the digest covers the WHOLE token, so changing any part of it changes what is being
/// searched for.
async fn authenticate(
    state: &ScimState,
    headers: &HeaderMap,
) -> Result<(ironauth_store::Scope, ScimConnection), AuthRefusal> {
    let token = presented_token(headers).ok_or(AuthRefusal::Missing)?;
    // The scope comes from the id half. A token with no separator, or an id half that does not
    // decode, is refused before any query runs.
    let (handle, _secret) = token.split_once('.').ok_or(AuthRefusal::Unknown)?;
    let scope = ironauth_store::ScimConnectionId::parse_declared_scope(handle)
        .map_err(|_| AuthRefusal::Unknown)?
        .scope();
    // The digest covers the WHOLE presented token, id half included, so a caller cannot keep a
    // valid secret and repoint the scope.
    let digest = token_digest(token);
    let now = i64::try_from(
        state
            .inner
            .env
            .clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| AuthRefusal::Unknown)?
            .as_micros(),
    )
    .map_err(|_| AuthRefusal::Unknown)?;
    let found = state
        .inner
        .store
        .scoped(scope)
        .scim_connections()
        .authenticate(&digest, now)
        .await
        // A STORE failure is not a bad credential; see `AuthRefusal::Unavailable`. Only the
        // absent row below is.
        .map_err(|_| AuthRefusal::Unavailable)?
        .ok_or(AuthRefusal::Unknown)?;
    Ok((scope, found))
}

/// Mint a SCIM bearer token for a connection: `{scim_id}.{secret}`.
///
/// The id half makes the token self-scoping (see [`authenticate`]); the secret half is what
/// makes it a credential. Returned once by whatever creates the connection, and stored
/// nowhere: only the SHA-256 of the whole string is written.
///
/// CALLED BY THE MANAGEMENT PLANE, which is why this is `pub`: `ironauth-admin`'s
/// `create_scim_connection` mints here and stores only the digest, and `authenticate` above
/// hashes the presented token with `digest_of`. ONE definition of the format, used by both,
/// rather than two that would agree until somebody changed one.
///
/// An earlier version of this said no shipped caller existed, which was true when the surface
/// was mounted and the minting route had not landed.
#[must_use]
pub fn mint_token(id: &ironauth_store::ScimConnectionId, secret: &str) -> String {
    format!("{id}.{secret}")
}

/// The digest to store for a minted token.
#[must_use]
pub fn digest_of(token: &str) -> String {
    token_digest(token)
}

/// `GET /scim/v2/ServiceProviderConfig` (RFC 7644 section 4).
async fn service_provider_config(State(state): State<ScimState>, headers: HeaderMap) -> Response {
    if let Err(refusal) = authenticate(&state, &headers).await {
        return refusal.response();
    }
    // The limits reported are the SAME value the enforcement reads, not a second copy. A
    // document that advertised a bulk maximum the server did not enforce would be worse than
    // no document at all.
    scim_ok(&ServiceProviderConfig::new(*state.limits()))
}

/// `GET /scim/v2/ResourceTypes` (RFC 7644 section 4).
async fn resource_types(State(state): State<ScimState>, headers: HeaderMap) -> Response {
    if let Err(refusal) = authenticate(&state, &headers).await {
        return refusal.response();
    }
    let types = json!([
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "User Account",
            "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
            "schemaExtensions": [{
                "schema": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
                "required": false,
            }],
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "Group",
            "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
        },
    ]);
    scim_ok(&list_response(
        types.as_array().map_or(&[][..], Vec::as_slice),
    ))
}

/// `GET /scim/v2/Schemas` (RFC 7644 section 4).
async fn schemas(State(state): State<ScimState>, headers: HeaderMap) -> Response {
    if let Err(refusal) = authenticate(&state, &headers).await {
        return refusal.response();
    }
    scim_ok(&list_response(&crate::schema::core_schemas()))
}

/// Wrap resources in the SCIM `ListResponse` envelope (RFC 7644 section 3.4.2).
fn list_response(resources: &[serde_json::Value]) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": resources.len(),
        "itemsPerPage": resources.len(),
        "startIndex": 1,
        "Resources": resources,
    })
}
