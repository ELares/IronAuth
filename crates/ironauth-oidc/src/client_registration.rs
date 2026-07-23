// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dynamic Client Registration and configuration management (issue #30).
//!
//! This module serves RFC 7591 (dynamic client registration) and RFC 7592 (client
//! configuration management), with OpenID Connect Dynamic Client Registration 1.0
//! errata set 2 and RP Metadata Choices 1.0 layered on top. It is CLIENT
//! registration (an OAuth client registering itself), a distinct concept from the
//! human account registration in [`crate::register`]; the two never share a module
//! or a route (this one is mounted at `/connect/register`).
//!
//! # Where the abuse controls live (the issue #31 seam)
//!
//! Open self-service client registration is an abuse surface. This issue ships
//! ONLY the endpoint plus a plain default-off enable flag
//! (`oidc.registration_enabled`, surfaced as
//! [`OidcState::registration_enabled`](crate::OidcState::registration_enabled));
//! the real gating (initial access token policy chains, per-tenant quotas, and
//! quarantine) is owned by the abuse-controls work (issue #31). The clean seam #31
//! layers onto is the single `registration_enabled` gate here and the fact that
//! every request funnels through [`register`]: #31 can wrap the handler or add a
//! policy check ahead of the create without reshaping this module. Because the
//! safe posture is off, the default is UNMOUNTED and undiscoverable.
//!
//! # What is validated (RFC 7591 section 2)
//!
//! The metadata property set is validated with per-spec defaults applied when a
//! property is omitted, and UNRECOGNIZED properties are ignored (RFC 7591 section
//! 2, never an error). The spec defaults:
//!
//! - `token_endpoint_auth_method` defaults to `client_secret_basic`;
//! - `response_types` defaults to `["code"]`, `grant_types` to
//!   `["authorization_code"]` (the only flow this provider serves);
//! - `id_token_signed_response_alg`, when omitted, records the ENVIRONMENT's actual
//!   default signing algorithm (the algorithm the mint will sign this client's ID
//!   tokens with), not the abstract RS256 spec default the environment may be unable
//!   to honor.
//!
//! `token_endpoint_auth_method` and every algorithm value are validated against
//! the ACTUALLY IMPLEMENTED client-authentication suite (issue #25,
//! [`ClientAuthMethod::ALL`]): a method the suite does not honor (the inert
//! `client_secret_jwt`, or an unknown value) is rejected with
//! `invalid_client_metadata`, never stored as a client that could never
//! authenticate.
//!
//! `redirect_uris` are validated as RFC 8252 targets: for a `web` client, https
//! only; for a `native` client, https OR an http loopback IP literal OR a
//! reverse-domain private-use scheme. Dangerous schemes are rejected. `jwks` and
//! `jwks_uri` are mutually exclusive, and a `jwks_uri` is fetched THROUGH the
//! SSRF-hardened fetcher (issue #25's [`ClientKeyResolver`](crate::ClientKeyResolver)),
//! so a private-address destination is rejected structurally.
//!
//! # RP Metadata Choices negotiation
//!
//! `id_token_signed_response_alg` may be supplied as an ARRAY of acceptable values
//! (RP Metadata Choices 1.0), either under that name or under the plural
//! `id_token_signed_response_alg_values`. The OP negotiates against the algorithms
//! the ENVIRONMENT can ACTUALLY sign with (each permitted by the environment policy
//! AND backed by a loaded, active signing key), NOT the advertised
//! `id_token_signing_alg_values` (which carries the RS256 discovery floor even where
//! no RS256 key exists). Of the offered algorithms the environment can sign with, it
//! PREFERS `EdDSA`, falls back to `RS256`, and otherwise takes the first mutual
//! value. An offered set with NOTHING the environment can sign is REJECTED with
//! `invalid_client_metadata` (never silently downgraded). The negotiated value is
//! recorded on the client and echoed in the registration response, and the token
//! endpoint signs THAT client's ID token under exactly that algorithm, so the
//! recorded value equals the algorithm the OP actually uses.
//!
//! # Credentials at rest (never plaintext)
//!
//! The generated `client_secret` and `registration_access_token` are stored ONLY
//! as their SHA-256 hashes; each plaintext is returned exactly once (the secret at
//! registration, the token at registration and again, freshly rotated, on every
//! successful update) and never persisted. Every value the OP mints (the client
//! id, the secret, the registration access token) is drawn from the environment
//! entropy seam.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_config::RegistrationMode;
use ironauth_env::Env;
use ironauth_jose::JwsAlgorithm;
use ironauth_store::{
    Action, ActorRef, CorrelationId, DynamicClientRecord, DynamicClientUpdate, GuardrailSet,
    InitialAccessTokenId, NewDynamicClient, Scope, ServiceId, StoreError,
    redirect_uri_is_registrable,
};
use serde_json::{Value, json};

use crate::client_auth::{ClientAuthMethod, generate_secret, hash_secret};
use crate::dcr_policy::{PolicyPrimitive, PolicyRejection, apply_chain, parse_chain};
use crate::issuer::IssuerEntry;
use crate::state::OidcState;
use crate::util::{client_service_actor, epoch_micros};
use crate::wellknown::{not_found, parse_scope};

/// Bytes of entropy in a registration access token: 32 bytes is 256 bits, drawn
/// from the entropy seam and base64url-encoded (URL-safe, no padding) so the token
/// is safe in an `Authorization: Bearer` header and in the response body.
const REGISTRATION_TOKEN_BYTES: usize = 32;

/// The spec-default `token_endpoint_auth_method` when omitted (RFC 7591 section 2).
const DEFAULT_AUTH_METHOD: &str = "client_secret_basic";

/// The TRANSPORT PEER IP of the request, for the endpoint's best-effort rate-limit
/// source key (issue #31, FIX 3).
///
/// This is the address the server's `ConnectInfo<SocketAddr>` reports (installed by
/// `into_make_service_with_connect_info`), NOT a request header: a raw
/// `X-Forwarded-For` hop is fully caller-controlled, so keying the rate limit on it
/// let a direct caller mint a fresh bucket per request (bypassing the limit) or poison
/// a victim's bucket. The peer address cannot be forged at the application layer, so
/// it closes that bypass.
///
/// Behind a trusted proxy the peer is the proxy, so the source bucket collapses to one
/// per proxy: the endpoint rate limit is therefore BEST-EFFORT / advisory, and the
/// real hard cap is the per-environment QUOTA (proven un-raceable) plus the per-token
/// (`iat:`) counter. The robust, topology-aware limiter is deferred to the M15 layered
/// rate limiter, which resolves the true client IP under the configured trusted-proxy
/// policy. `None` when the server installed no `ConnectInfo` (for example an in-process
/// test router), in which case the source collapses to a single shared bucket.
///
/// The extractor never fails: an absent `ConnectInfo` is `None`, not a rejection.
pub(crate) struct PeerIp(Option<IpAddr>);

impl<S> FromRequestParts<S> for PeerIp
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Infallible> {
        Ok(PeerIp(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip()),
        ))
    }
}

/// `POST {issuer}/connect/register`: register a client from an RFC 7591 metadata
/// document, returning the created client and its credentials (201 Created).
///
/// The issue #31 abuse controls WRAP the issue #30 create: the exposure switch
/// decides whether an anonymous / initial-access-token / closed request is allowed;
/// a `token_gated` environment requires a valid initial access token (checked and
/// consumed first); that token's policy chain is applied to the submitted metadata
/// (force / restrict / reject / default) BEFORE the client is created; the created
/// client starts QUARANTINED unless a token vouched for it; and the endpoint's rate
/// limit and per-environment quota are enforced.
// The abuse-control orchestration (rate limit, exposure resolve, policy apply,
// signing negotiation, validate, mint, create) is a linear pipeline; splitting it
// would only scatter the request's single control flow across helpers.
#[allow(clippy::too_many_lines)]
pub async fn register(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    peer: PeerIp,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(scope) = enabled_scope(&state, &tenant_id, &environment_id).await else {
        return not_found();
    };

    // One acting identity for the whole request, so the registration audit and every
    // abuse event (rate limit, quota, policy rejection) attribute to the same
    // service actor and correlation id.
    let actor = ActorRef::service(ServiceId::generate(state.env()));
    let correlation = CorrelationId::generate(state.env());
    let presented = bearer_token(&headers);

    // Endpoint-local rate limiting (issue #31), keyed by the transport peer (a
    // non-forgeable source, FIX 3) and by presented token, using the clock seam for
    // the window. Checked before any store write, so a flood never reaches the create
    // path.
    if let Some(refusal) = enforce_rate_limits(
        &state,
        scope,
        actor,
        correlation,
        peer.0,
        presented.as_deref(),
    )
    .await
    {
        return refusal;
    }

    // The exposure switch + initial access token (issue #31): decide whether this
    // request is authorized, resolve the policy chain it must satisfy, and whether
    // the resulting client starts quarantined. A `token_gated` environment CONSUMES
    // the presented token here (atomically), so an exhausted or expired token is
    // refused before the client is created.
    //
    // This runs BEFORE the body is parsed (FIX 6), so an UNauthorized request is the
    // uniform 403 `access_denied` regardless of whether the body is valid JSON: a
    // malformed body must never turn the authorization refusal into a 400 that leaks
    // whether the environment is closed / token-gated.
    let authz = match resolve_registration(&state, scope, presented.as_deref()).await {
        Ok(authz) => authz,
        Err(refusal) => return refusal,
    };

    let Ok(metadata) = serde_json::from_slice::<Value>(&body) else {
        return metadata_error("the request body must be a JSON object");
    };
    let Some(metadata) = metadata.as_object() else {
        return metadata_error("the request body must be a JSON object");
    };
    let mut metadata = metadata.clone();

    // Apply the policy chain to the submitted metadata BEFORE validation (force /
    // default / restrict / reject). A rejection stays a GENERIC
    // `invalid_client_metadata` on the wire, but the actionable diagnostic is
    // recorded OUT OF BAND (a `dcr.policy_rejected` audit event plus a structured
    // log line), so the endpoint is never an oracle for the operator's policy (AC5).
    if let Err(rejection) = apply_chain(&authz.chain, &mut metadata) {
        record_policy_rejection(
            &state,
            scope,
            actor,
            correlation,
            authz.iat_id.as_ref(),
            &rejection,
        )
        .await;
        return metadata_error("the request metadata is not acceptable");
    }

    // The environment's real ID-token signing capability drives the algorithm
    // negotiation, so a recorded `id_token_signed_response_alg` is always one the OP
    // can and will sign this client's ID tokens with (issue #30).
    let Some((signable, default_alg)) = env_signing_capability(&state, &scope).await else {
        return server_error();
    };

    // The environment's TYPED guardrails (issue #42): a PROD environment rejects an
    // http loopback redirect that a dev/staging environment accepts. Resolved from
    // the shared registry (the same cached entry env_signing_capability just loaded),
    // so the redirect guardrail is enforced on the real DCR path BEFORE the client
    // is stored.
    let Some(guardrails) = state.environment_guardrails(&scope).await else {
        return server_error();
    };

    let validated = match validate_metadata(
        &state,
        &metadata,
        None,
        &signable,
        default_alg,
        guardrails,
    )
    .await
    {
        Ok(validated) => validated,
        Err(error) => return error.into_response(),
    };

    // Mint the credentials from the entropy seam. A confidential client gets a
    // secret; every DCR client gets a registration access token. Only the hashes
    // are stored; the plaintext is returned once here.
    let secret = validated
        .auth_method
        .needs_secret()
        .then(|| generate_secret(state.env()));
    let secret_hash = secret.as_deref().map(hash_secret);
    let registration_token = generate_registration_token(state.env());
    let registration_token_hash = hash_secret(&registration_token);

    let issuer = state.issuer_for(&scope);
    let registration_uri_base = format!("{issuer}/connect/register");

    let params = NewDynamicClient {
        display_name: &validated.display_name,
        auth_method: validated.auth_method.as_str(),
        secret_hash: secret_hash.as_deref(),
        redirect_uris: &validated.redirect_uris,
        application_type: &validated.application_type,
        id_token_signed_response_alg: &validated.id_token_signed_response_alg,
        jwks: validated.jwks.as_deref(),
        jwks_uri: validated.jwks_uri.as_deref(),
        token_endpoint_auth_signing_alg: validated.token_endpoint_auth_signing_alg.as_deref(),
        registration_access_token_hash: &registration_token_hash,
        registration_uri_base: &registration_uri_base,
        quarantined: authz.quarantined,
        dcr_policy_chain: authz.chain_text.as_deref(),
    };

    // The per-environment quota is enforced ATOMICALLY inside register_dynamic (under
    // a per-scope advisory lock), so two concurrent registrations cannot both slip
    // past the cap.
    let max_clients = i64::from(state.registration_max_clients());
    let registration = match state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .clients()
        .register_dynamic(state.env(), params, Some(max_clients))
        .await
    {
        Ok(registration) => registration,
        Err(StoreError::QuotaExceeded) => {
            record_quota_hit(&state, scope, actor, correlation).await;
            return quota_refused();
        }
        Err(StoreError::InvalidRedirectUri) => {
            return redirect_error("a redirect_uri is not a registrable target");
        }
        Err(StoreError::Conflict) => {
            return metadata_error("the client key configuration is invalid");
        }
        Err(_) => return server_error(),
    };

    let issued_at = epoch_micros(state.now()) / 1_000_000;
    let mut body = base_metadata(
        &registration.id.to_string(),
        issued_at,
        &validated,
        &registration.registration_client_uri,
    );
    if let Some(secret) = &secret {
        body.insert("client_secret".to_owned(), json!(secret));
        // 0 means the secret does not expire (RFC 7591 section 3.2.1).
        body.insert("client_secret_expires_at".to_owned(), json!(0));
    }
    body.insert(
        "registration_access_token".to_owned(),
        json!(registration_token),
    );

    credential_response(StatusCode::CREATED, &Value::Object(body))
}

/// `GET {registration_client_uri}`: read a dynamically registered client's current
/// configuration (RFC 7592 section 2.1). Authenticated by the registration access
/// token.
pub async fn read(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some((_scope, record)) =
        authenticate(&state, &tenant_id, &environment_id, &client_id, &headers).await
    else {
        return unauthorized();
    };

    let issued_at = record.created_at_unix_micros / 1_000_000;
    let uri = record.registration_client_uri.clone().unwrap_or_default();
    let body = read_metadata(&record, issued_at, &uri);
    credential_response(StatusCode::OK, &Value::Object(body))
}

/// `PUT {registration_client_uri}`: replace a dynamically registered client's
/// configuration (RFC 7592 section 2.2), ROTATING the registration access token.
/// The old token is rejected on the next call. Authenticated by the current token.
pub async fn update(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some((scope, record)) =
        authenticate(&state, &tenant_id, &environment_id, &client_id, &headers).await
    else {
        return unauthorized();
    };

    let Ok(metadata) = serde_json::from_slice::<Value>(&body) else {
        return metadata_error("the request body must be a JSON object");
    };
    let Some(metadata) = metadata.as_object() else {
        return metadata_error("the request body must be a JSON object");
    };
    let mut metadata = metadata.clone();

    // AC1: the SAME policy chain that bound the original registration binds this RFC
    // 7592 update. The chain snapshot rides on the client (and thus on the
    // registration access token that authenticated this call) for the client's
    // lifetime, so a later edit or deletion of the source policy object never
    // loosens the constraint. A rejection is opaque on the wire but recorded out of
    // band, exactly as at registration (AC5).
    if let Some(chain_text) = &record.dcr_policy_chain {
        // Fail CLOSED on a corrupt stored snapshot (FIX 5): a policy-chain snapshot
        // that will not parse is a broken security control, so refuse the update
        // rather than proceed with an empty (unconstrained) chain that would silently
        // drop every constraint. Unreachable today (snapshots are server-serialized
        // canonical JSON), but the failure mode must be closed, not open.
        let Ok(chain) = parse_chain(chain_text) else {
            tracing::error!(
                "stored dcr policy-chain snapshot failed to parse; refusing the 7592 update"
            );
            return server_error();
        };
        if let Err(rejection) = apply_chain(&chain, &mut metadata) {
            record_policy_rejection_for_client(&state, scope, &record.id, &rejection).await;
            return metadata_error("the request metadata is not acceptable");
        }
    }

    let Some((signable, default_alg)) = env_signing_capability(&state, &scope).await else {
        return server_error();
    };

    // The environment's TYPED guardrails also bind an RFC 7592 UPDATE (issue #42):
    // a prod client can never be edited to carry an http loopback redirect.
    let Some(guardrails) = state.environment_guardrails(&scope).await else {
        return server_error();
    };

    let validated = match validate_metadata(
        &state,
        &metadata,
        Some(&record),
        &signable,
        default_alg,
        guardrails,
    )
    .await
    {
        Ok(validated) => validated,
        Err(error) => return error.into_response(),
    };

    // Rotate the registration access token on every successful update: mint a fresh
    // one, store only its new hash, and hand back the plaintext. The superseded
    // token's hash no longer matches, so it stops working immediately.
    let new_token = generate_registration_token(state.env());
    let new_token_hash = hash_secret(&new_token);
    let actor = client_service_actor(&record.id);

    let store_update = DynamicClientUpdate {
        display_name: &validated.display_name,
        auth_method: validated.auth_method.as_str(),
        redirect_uris: &validated.redirect_uris,
        application_type: &validated.application_type,
        id_token_signed_response_alg: &validated.id_token_signed_response_alg,
        jwks: validated.jwks.as_deref(),
        jwks_uri: validated.jwks_uri.as_deref(),
        token_endpoint_auth_signing_alg: validated.token_endpoint_auth_signing_alg.as_deref(),
        registration_access_token_hash: &new_token_hash,
    };

    match state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .clients()
        .update_dynamic(state.env(), &record.id, store_update)
        .await
    {
        Ok(()) => {}
        Err(StoreError::InvalidRedirectUri) => {
            return redirect_error("a redirect_uri is not a registrable target");
        }
        Err(StoreError::NotFound) => return unauthorized(),
        Err(StoreError::Conflict) => {
            return metadata_error("the client key configuration is invalid");
        }
        Err(_) => return server_error(),
    }

    let issued_at = record.created_at_unix_micros / 1_000_000;
    let uri = record.registration_client_uri.clone().unwrap_or_default();
    let mut body = base_metadata(&record.id.to_string(), issued_at, &validated, &uri);
    body.insert("registration_access_token".to_owned(), json!(new_token));
    credential_response(StatusCode::OK, &Value::Object(body))
}

/// `DELETE {registration_client_uri}`: delete a dynamically registered client (RFC
/// 7592 section 2.3), returning 204 No Content. Authenticated by the token.
pub async fn delete(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some((scope, record)) =
        authenticate(&state, &tenant_id, &environment_id, &client_id, &headers).await
    else {
        return unauthorized();
    };

    let actor = client_service_actor(&record.id);
    match state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .clients()
        .delete(state.env(), &record.id)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        // The client authenticated a moment ago; a not-found here is a concurrent
        // delete, reported as the uniform unauthorized (no existence oracle).
        Err(StoreError::NotFound) => unauthorized(),
        Err(_) => server_error(),
    }
}

/// Resolve the `(tenant, environment)` scope for a registration request, returning
/// `None` (a uniform 404) when the endpoint is disabled, the scope is malformed, or
/// the environment is unprovisioned or cross-tenant.
async fn enabled_scope(state: &OidcState, tenant_id: &str, environment_id: &str) -> Option<Scope> {
    if !state.registration_enabled() {
        return None;
    }
    let scope = parse_scope(tenant_id, environment_id)?;
    // Require a provisioned environment, exactly as discovery and the JWKS surface
    // do: a cross-tenant scope loads zero rows under row-level security and yields
    // no entry, so registration cannot be aimed at another tenant's environment.
    state.issuer_entry(&scope).await?;
    Some(scope)
}

/// The resolved authorization for a registration request (issue #31): the policy
/// chain the submitted metadata must satisfy, the snapshot text to persist on the
/// client (so RFC 7592 updates re-apply the SAME chain), whether the resulting
/// client starts quarantined, and the initial access token that authorized it (if
/// any, for the audit target).
struct RegistrationAuthz {
    chain: Vec<PolicyPrimitive>,
    chain_text: Option<String>,
    quarantined: bool,
    iat_id: Option<InitialAccessTokenId>,
}

/// Resolve the exposure switch and initial access token for a registration request
/// (issue #31), returning the authorization on success or a typed refusal
/// [`Response`] otherwise.
///
/// - `closed`: every public registration is refused (clients are created only
///   through the management API).
/// - `token_gated`: a valid initial access token is REQUIRED; it is consumed here,
///   its policy chain applies, and the resulting client is trusted (not quarantined).
/// - `open`: a request WITHOUT a token registers anonymously and the client starts
///   quarantined; a request WITH a token must present a valid one (a bad token is a
///   refusal, never a silent fallback to anonymous), which vouches for the client.
async fn resolve_registration(
    state: &OidcState,
    scope: Scope,
    presented: Option<&str>,
) -> Result<RegistrationAuthz, Response> {
    match state.registration_mode() {
        RegistrationMode::Closed => Err(exposure_refused(
            "dynamic client registration is closed for this environment",
        )),
        RegistrationMode::TokenGated => match presented {
            Some(token) => consume_iat_authz(state, scope, token).await,
            None => Err(exposure_refused(
                "an initial access token is required to register a client here",
            )),
        },
        RegistrationMode::Open => match presented {
            Some(token) => consume_iat_authz(state, scope, token).await,
            // Anonymous open registration: no policy chain, and the client starts
            // quarantined until an admin verifies it.
            None => Ok(RegistrationAuthz {
                chain: Vec::new(),
                chain_text: None,
                quarantined: true,
                iat_id: None,
            }),
        },
    }
}

/// Consume a presented initial access token (issue #31), returning the
/// authorization it grants, or a typed refusal when it is invalid, expired, or
/// exhausted (all indistinguishable, so the endpoint is never an oracle). Consuming
/// increments the token's use count ATOMICALLY, so a usage limit cannot be raced
/// past.
async fn consume_iat_authz(
    state: &OidcState,
    scope: Scope,
    token: &str,
) -> Result<RegistrationAuthz, Response> {
    let hash = hash_secret(token);
    let now = epoch_micros(state.now());
    match state
        .store()
        .scoped(scope)
        .initial_access_tokens()
        .consume(&hash, now)
        .await
    {
        Ok(consumed) => {
            // Fail CLOSED on a corrupt stored snapshot (FIX 5): a policy-chain snapshot
            // that will not parse is a broken security control, so refuse the
            // registration rather than proceed with an empty (unconstrained) chain that
            // would silently drop every constraint the operator's policy imposed.
            // Unreachable today (snapshots are server-serialized canonical JSON).
            let Ok(chain) = parse_chain(&consumed.policy_chain) else {
                tracing::error!(
                    "stored dcr policy-chain snapshot failed to parse; refusing the registration"
                );
                return Err(server_error());
            };
            // Persist the token's snapshot verbatim (so a 7592 update re-applies the
            // exact chain); a token that carried no constraints leaves the column NULL.
            let chain_text = (!chain.is_empty()).then(|| consumed.policy_chain.clone());
            Ok(RegistrationAuthz {
                chain,
                chain_text,
                quarantined: false,
                iat_id: Some(consumed.id),
            })
        }
        Err(StoreError::NotFound) => Err(exposure_refused(
            "the initial access token is invalid, expired, or exhausted",
        )),
        Err(_) => Err(server_error()),
    }
}

/// Enforce the endpoint-local registration rate limit (issue #31), keyed by source
/// AND by presented token, using the clock seam for the fixed window. Returns a
/// typed refusal [`Response`] when either key is over its limit (and records a
/// `dcr.rate_limited` audit event), or `None` to proceed. A configured limit of 0
/// disables it.
async fn enforce_rate_limits(
    state: &OidcState,
    scope: Scope,
    actor: ActorRef,
    correlation: CorrelationId,
    peer: Option<IpAddr>,
    presented: Option<&str>,
) -> Option<Response> {
    let limit = i64::from(state.registration_rate_limit());
    if limit <= 0 {
        return None;
    }
    let window = i64::try_from(state.registration_rate_window().as_secs()).unwrap_or(i64::MAX);
    let now = epoch_micros(state.now());
    let limiter = state.store().scoped(scope).dcr_rate_limiter();

    // The source key is best-effort (the non-forgeable transport peer, FIX 3) and the
    // token key is the robust one; a request is refused if EITHER is over its limit.
    let source_key = format!("src:{}", request_source(peer));
    match limiter
        .check_and_increment(&source_key, limit, window, now)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            record_rate_limited(state, scope, actor, correlation).await;
            return Some(rate_limited_refused());
        }
        Err(_) => return Some(server_error()),
    }
    if let Some(token) = presented {
        let iat_key = format!("iat:{}", hash_secret(token));
        match limiter
            .check_and_increment(&iat_key, limit, window, now)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                record_rate_limited(state, scope, actor, correlation).await;
                return Some(rate_limited_refused());
            }
            Err(_) => return Some(server_error()),
        }
    }
    None
}

/// A best-effort source identifier for rate limiting (issue #31, FIX 3): the request's
/// TRANSPORT PEER address, or a fixed `unknown` bucket when none was resolved.
///
/// This deliberately does NOT consult `X-Forwarded-For` (or any forwarding header): a
/// raw forwarded hop is fully caller-controlled, so keying on it let a direct caller
/// rotate the header to mint a fresh bucket per request (bypassing the limit entirely)
/// or forge a victim's address to poison their bucket. The transport peer cannot be
/// forged at the application layer, which closes both.
///
/// The peer is best-effort by design: behind a trusted proxy every request shares the
/// proxy's address, so this counter is ADVISORY. The real, un-raceable hard cap is the
/// per-environment quota (proven in `register_dynamic`), backed by the per-token
/// (`iat:`) counter; the robust, trusted-proxy-aware limiter is deferred to the M15
/// layered rate limiter (which resolves the true client IP under the configured proxy
/// policy). `None` (no `ConnectInfo` installed) collapses to one shared bucket.
fn request_source(peer: Option<IpAddr>) -> String {
    peer.map_or_else(|| "unknown".to_owned(), |ip| ip.to_string())
}

/// Record a `dcr.policy_rejected` event out of band (issue #31, AC5): a structured
/// diagnostic log line plus the typed audit event, targeting the initial access
/// token that carried the offending policy.
async fn record_policy_rejection(
    state: &OidcState,
    scope: Scope,
    actor: ActorRef,
    correlation: CorrelationId,
    iat_id: Option<&InitialAccessTokenId>,
    rejection: &PolicyRejection,
) {
    tracing::warn!(diagnostic = %rejection.diagnostic(), "dcr registration policy rejection");
    // The offending property is OPERATOR-authored (it names a property the operator's
    // policy constrains, never attacker-supplied text), so it is safe to record as the
    // audit event's detail dimension (FIX 11): an operator reading the audit table
    // alone gets the actionable property, while the wire response stays opaque.
    let detail = Some(rejection.property.as_str());
    let acting = state.store().scoped(scope).acting(actor, correlation);
    let result = match iat_id {
        Some(iat) => {
            acting
                .clients()
                .record_dcr_event(state.env(), Action::DcrPolicyRejected, iat, detail)
                .await
        }
        // A policy chain only exists when a token was consumed, so this branch is
        // defensive; target the environment when no token id is available.
        None => {
            acting
                .clients()
                .record_dcr_event(
                    state.env(),
                    Action::DcrPolicyRejected,
                    &scope.environment(),
                    detail,
                )
                .await
        }
    };
    if let Err(error) = result {
        tracing::error!(%error, "failed to record dcr.policy_rejected");
    }
}

/// Record a `dcr.policy_rejected` event for an RFC 7592 update rejection (issue #31,
/// AC5): the target is the client whose stored chain refused the update.
async fn record_policy_rejection_for_client(
    state: &OidcState,
    scope: Scope,
    client_id: &ironauth_store::ClientId,
    rejection: &PolicyRejection,
) {
    tracing::warn!(diagnostic = %rejection.diagnostic(), "dcr update policy rejection");
    // Operator-safe detail dimension (FIX 11): the offending property, so the update
    // rejection is diagnosable from the audit table alone. The wire stays opaque.
    let detail = Some(rejection.property.as_str());
    let actor = client_service_actor(client_id);
    let correlation = CorrelationId::generate(state.env());
    if let Err(error) = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .clients()
        .record_dcr_event(state.env(), Action::DcrPolicyRejected, client_id, detail)
        .await
    {
        tracing::error!(%error, "failed to record dcr.policy_rejected (update)");
    }
}

/// Record a `dcr.quota_hit` event (issue #31), targeting the environment.
async fn record_quota_hit(
    state: &OidcState,
    scope: Scope,
    actor: ActorRef,
    correlation: CorrelationId,
) {
    if let Err(error) = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .clients()
        .record_dcr_event(state.env(), Action::DcrQuotaHit, &scope.environment(), None)
        .await
    {
        tracing::error!(%error, "failed to record dcr.quota_hit");
    }
}

/// Record a `dcr.rate_limited` event (issue #31), targeting the environment.
async fn record_rate_limited(
    state: &OidcState,
    scope: Scope,
    actor: ActorRef,
    correlation: CorrelationId,
) {
    if let Err(error) = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .clients()
        .record_dcr_event(
            state.env(),
            Action::DcrRateLimited,
            &scope.environment(),
            None,
        )
        .await
    {
        tracing::error!(%error, "failed to record dcr.rate_limited");
    }
}

/// A 403 `access_denied` refusal for an exposure-switch or quota block (issue #31).
/// The description is safe (it names the policy posture, never a secret).
fn exposure_refused(description: &str) -> Response {
    refused(StatusCode::FORBIDDEN, "access_denied", description)
}

/// The 403 `access_denied` refusal when the environment is at its registered-client
/// quota (issue #31). The count itself is not disclosed.
fn quota_refused() -> Response {
    refused(
        StatusCode::FORBIDDEN,
        "access_denied",
        "the registered-client quota for this environment has been reached",
    )
}

/// The 429 refusal when the endpoint's rate limit is exceeded (issue #31).
fn rate_limited_refused() -> Response {
    refused(
        StatusCode::TOO_MANY_REQUESTS,
        "temporarily_unavailable",
        "the registration endpoint is rate limited; retry later",
    )
}

/// Build a typed refusal response with a `no-store` cache directive.
fn refused(status: StatusCode, code: &str, description: &str) -> Response {
    let body = json!({ "error": code, "error_description": description }).to_string();
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        body,
    )
        .into_response()
}

/// Authenticate an RFC 7592 request: resolve the scope and DCR client, then compare
/// the presented registration access token's hash against the stored hash in
/// constant time. Returns the scope and the record on success, or `None` for ANY
/// failure (disabled, malformed, absent, not a DCR client, missing or wrong token)
/// so the surface is never an oracle. The caller maps `None` to a uniform 401.
async fn authenticate(
    state: &OidcState,
    tenant_id: &str,
    environment_id: &str,
    client_id: &str,
    headers: &HeaderMap,
) -> Option<(Scope, DynamicClientRecord)> {
    let scope = enabled_scope(state, tenant_id, environment_id).await?;
    let presented = bearer_token(headers)?;
    let id = state
        .store()
        .scoped(scope)
        .clients()
        .parse_id(client_id)
        .ok()?;
    let record = state
        .store()
        .scoped(scope)
        .clients()
        .dynamic_registration(&id)
        .await
        .ok()?;
    let stored = record.registration_access_token_hash.as_deref()?;
    if constant_time_eq(hash_secret(&presented).as_bytes(), stored.as_bytes()) {
        Some((scope, record))
    } else {
        None
    }
}

/// A client's validated registration metadata, ready to persist.
struct ValidatedMetadata {
    display_name: String,
    auth_method: ClientAuthMethod,
    redirect_uris: Vec<String>,
    application_type: String,
    id_token_signed_response_alg: String,
    jwks: Option<String>,
    jwks_uri: Option<String>,
    token_endpoint_auth_signing_alg: Option<String>,
}

/// Validate an RFC 7591 metadata document, applying per-spec defaults, ignoring
/// unrecognized properties, negotiating the ID token algorithm, and (for a
/// `jwks_uri`) fetching through the SSRF-hardened fetcher. `existing` is the record
/// being updated (RFC 7592), so the auth-method transition rules apply; `None` for
/// a fresh registration. `signable` is the set of algorithms the environment can
/// actually sign an ID token with (the negotiation constrains to it), and
/// `default_alg` is the environment's default signing algorithm (recorded when the
/// client expresses no `id_token_signed_response_alg` preference).
async fn validate_metadata(
    state: &OidcState,
    metadata: &serde_json::Map<String, Value>,
    existing: Option<&DynamicClientRecord>,
    signable: &[JwsAlgorithm],
    default_alg: JwsAlgorithm,
    guardrails: GuardrailSet,
) -> Result<ValidatedMetadata, RegistrationError> {
    let application_type = match metadata.get("application_type") {
        None => "web".to_owned(),
        Some(Value::String(value)) if value == "web" || value == "native" => value.clone(),
        Some(_) => {
            return Err(RegistrationError::metadata(
                "application_type must be \"web\" or \"native\"",
            ));
        }
    };

    // response_types / grant_types: this provider serves only the authorization
    // code flow, so a request that pins any other value is rejected (RFC 7591
    // consistency), while omission takes the spec defaults.
    check_only(metadata, "response_types", "code")?;
    check_only(metadata, "grant_types", "authorization_code")?;

    let auth_method = validate_auth_method(metadata)?;

    let redirect_uris = validate_redirect_uris(metadata, &application_type, guardrails)?;

    // On an RFC 7592 update, switching to a secret-based method requires a secret
    // the client does not have (an update never mints one), so refuse the
    // transition and let the RP re-register instead of silently creating a client
    // that can never authenticate.
    if let Some(existing) = existing {
        let had_secret = matches!(
            ClientAuthMethod::parse(&existing.auth_method),
            Some(ClientAuthMethod::Basic | ClientAuthMethod::Post)
        );
        if auth_method.needs_secret() && !had_secret {
            return Err(RegistrationError::metadata(
                "cannot switch to a secret-based token_endpoint_auth_method on update",
            ));
        }
    }

    let id_token_signed_response_alg = negotiate_id_token_alg(metadata, signable, default_alg)?;
    let token_endpoint_auth_signing_alg = validate_signing_alg(metadata)?;
    let (jwks, jwks_uri) = validate_client_keys(state, metadata, auth_method).await?;

    let display_name = metadata
        .get("client_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("Dynamically Registered Client")
        .to_owned();

    Ok(ValidatedMetadata {
        display_name,
        auth_method,
        redirect_uris,
        application_type,
        id_token_signed_response_alg,
        jwks,
        jwks_uri,
        token_endpoint_auth_signing_alg,
    })
}

/// Validate `token_endpoint_auth_method` against the ACTUALLY IMPLEMENTED suite
/// (issue #25). The default is `client_secret_basic`. A method the suite does not
/// advertise (the inert `client_secret_jwt`, or an unknown string) is rejected: the
/// provider never stores a client registered for a method it cannot honor.
fn validate_auth_method(
    metadata: &serde_json::Map<String, Value>,
) -> Result<ClientAuthMethod, RegistrationError> {
    let raw = match metadata.get("token_endpoint_auth_method") {
        None => DEFAULT_AUTH_METHOD,
        Some(Value::String(value)) => value.as_str(),
        Some(_) => {
            return Err(RegistrationError::metadata(
                "token_endpoint_auth_method must be a string",
            ));
        }
    };
    match ClientAuthMethod::parse(raw) {
        // Only a method the suite ADVERTISES is registrable: client_secret_jwt is
        // recognized but inert (issue #25), so it is not in ALL and is refused here.
        Some(method) if ClientAuthMethod::ALL.contains(&method) => Ok(method),
        _ => Err(RegistrationError::metadata(
            "token_endpoint_auth_method is not supported by this provider",
        )),
    }
}

/// Validate `redirect_uris` as RFC 8252 targets under the client's application
/// type AND the environment's typed guardrails (issue #42). `redirect_uris` is
/// required (the only supported flow is redirect based), every entry must be
/// registrable, and for a `web` client every entry must be https (loopback and
/// private-use schemes are native-only). Layered ON TOP of the application-type
/// rule, the environment guardrail additionally rejects an http loopback (which a
/// `native` client would otherwise register) in a PRODUCTION environment: a prod
/// environment hard-requires https redirect URIs, so it cannot silently carry the
/// dev laxity a native-app loopback represents.
fn validate_redirect_uris(
    metadata: &serde_json::Map<String, Value>,
    application_type: &str,
    guardrails: GuardrailSet,
) -> Result<Vec<String>, RegistrationError> {
    let Some(value) = metadata.get("redirect_uris") else {
        return Err(RegistrationError::redirect(
            "redirect_uris is required and must be a non-empty array",
        ));
    };
    let Some(array) = value.as_array() else {
        return Err(RegistrationError::redirect(
            "redirect_uris must be an array",
        ));
    };
    if array.is_empty() {
        return Err(RegistrationError::redirect(
            "redirect_uris must not be empty",
        ));
    }
    let mut uris = Vec::with_capacity(array.len());
    for entry in array {
        let Some(uri) = entry.as_str() else {
            return Err(RegistrationError::redirect(
                "every redirect_uri must be a string",
            ));
        };
        if !redirect_allowed(uri, application_type) {
            return Err(RegistrationError::redirect(
                "a redirect_uri is not a valid target for this application_type",
            ));
        }
        // The environment-kind guardrail (issue #42): registrability is established
        // above, so the only remaining failure is the production https-only rule,
        // which rejects an http loopback in a prod environment with the named
        // guardrail. A dev/staging environment relaxes it and accepts the loopback.
        if let Err(violation) = guardrails.check_redirect_uri(uri) {
            return Err(RegistrationError::guardrail(&violation));
        }
        uris.push(uri.to_owned());
    }
    Ok(uris)
}

/// Whether `uri` is an allowed redirect target for `application_type`. Both types
/// require an RFC 8252 registrable target (which rejects dangerous schemes,
/// fragments, and non-ASCII authorities); a `web` client additionally requires the
/// https scheme, so an http loopback or a private-use scheme is native-only.
fn redirect_allowed(uri: &str, application_type: &str) -> bool {
    if !redirect_uri_is_registrable(uri) {
        return false;
    }
    if application_type == "web" {
        return uri
            .split_once(':')
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"));
    }
    // Native: any registrable target (https, http loopback IP literal, or a
    // reverse-domain private-use scheme).
    true
}

/// The environment's ID-token signing capability for `scope`: the algorithms it can
/// ACTUALLY sign an ID token with (each permitted by the environment policy AND
/// backed by an active loaded key), in preference order, plus its DEFAULT signing
/// algorithm (what the mint uses when a client expresses no per-client preference).
///
/// `None` when the environment has no active signing key, which the caller maps to a
/// `server_error`: a client whose ID tokens could never be signed is never stored,
/// so registration cannot record an algorithm the OP would not honor.
async fn env_signing_capability(
    state: &OidcState,
    scope: &Scope,
) -> Option<(Vec<JwsAlgorithm>, JwsAlgorithm)> {
    let entry = state.issuer_entry(scope).await?;
    let now = state.now();
    let default_alg = entry.signer(now)?.algorithm();
    Some((signable_id_token_algs(&entry, now), default_alg))
}

/// The algorithms this environment can ACTUALLY sign an ID token with at `now`, in
/// the policy's preference order: each is permitted by the environment policy AND
/// has an active signing key in the key set.
///
/// This is deliberately NOT the discovery `id_token_signing_alg_values`, which
/// carries the RS256 "floor" (Discovery section 3) even in an environment that has
/// NO RS256 key loaded. Negotiating against the floor would record an algorithm the
/// mint could never sign with (no key), so the negotiation constrains to exactly the
/// algorithms a signing key exists for.
fn signable_id_token_algs(entry: &IssuerEntry, now: SystemTime) -> Vec<JwsAlgorithm> {
    // One source of truth: the computation lives on `IssuerEntry` so the DCR
    // negotiation here and the management compatibility wizard (issue #93) can never
    // disagree on what an environment can sign with.
    entry.signable_id_token_algs(now)
}

/// Negotiate `id_token_signed_response_alg` (RP Metadata Choices 1.0) against the
/// algorithms the environment can ACTUALLY sign with (`signable`). The RP may offer a
/// single value or an array of acceptable values (under the singular name or the
/// plural `id_token_signed_response_alg_values`).
///
/// Of the offered algorithms the environment can sign with, the OP prefers `EdDSA`,
/// then `RS256`, then the first mutual value. An offered set with NOTHING the
/// environment can sign is REJECTED with `invalid_client_metadata`, never silently
/// downgraded to an algorithm the RP never offered or the OP cannot sign with.
/// Omission records `default_alg` (the environment's actual default signing
/// algorithm). Every outcome equals the algorithm the mint will sign this client's
/// ID token with, so the recorded and echoed value can never diverge from the
/// signed algorithm.
fn negotiate_id_token_alg(
    metadata: &serde_json::Map<String, Value>,
    signable: &[JwsAlgorithm],
    default_alg: JwsAlgorithm,
) -> Result<String, RegistrationError> {
    let Some(candidates) = id_token_alg_candidates(metadata)? else {
        // No preference: record the environment's actual default signing algorithm.
        return Ok(default_alg.as_jose_name().to_owned());
    };
    // The offered, representable algorithms the environment can actually sign with,
    // in the RP's offered order.
    let mutual: Vec<JwsAlgorithm> = candidates
        .iter()
        .filter_map(|name| JwsAlgorithm::from_jose_name(name))
        .filter(|alg| signable.contains(alg))
        .collect();
    let Some(&first) = mutual.first() else {
        return Err(RegistrationError::metadata(
            "no offered id_token_signed_response_alg is one this issuer can sign with",
        ));
    };
    // Prefer EdDSA when signable and offered, else RS256, else the first mutual value.
    let chosen = if mutual.contains(&JwsAlgorithm::EdDsa) {
        JwsAlgorithm::EdDsa
    } else if mutual.contains(&JwsAlgorithm::Rs256) {
        JwsAlgorithm::Rs256
    } else {
        first
    };
    Ok(chosen.as_jose_name().to_owned())
}

/// The candidate `id_token_signed_response_alg` values from the metadata: the
/// plural `_values` array (RP Metadata Choices) if present, otherwise the singular
/// value (a string, or an array some deployments use). `None` when the client
/// expressed no preference.
fn id_token_alg_candidates(
    metadata: &serde_json::Map<String, Value>,
) -> Result<Option<Vec<String>>, RegistrationError> {
    if let Some(value) = metadata.get("id_token_signed_response_alg_values") {
        return string_array(value).map(Some).ok_or_else(|| {
            RegistrationError::metadata(
                "id_token_signed_response_alg_values must be an array of strings",
            )
        });
    }
    match metadata.get("id_token_signed_response_alg") {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(vec![value.clone()])),
        Some(value @ Value::Array(_)) => string_array(value).map(Some).ok_or_else(|| {
            RegistrationError::metadata(
                "id_token_signed_response_alg must be a string or array of strings",
            )
        }),
        Some(_) => Err(RegistrationError::metadata(
            "id_token_signed_response_alg must be a string or array of strings",
        )),
    }
}

/// Validate `token_endpoint_auth_signing_alg` (the pinned `private_key_jwt`
/// assertion algorithm, issue #25). It must be a representable JWS algorithm; an
/// unrepresentable one (for example ES512) is rejected. `None` when omitted.
fn validate_signing_alg(
    metadata: &serde_json::Map<String, Value>,
) -> Result<Option<String>, RegistrationError> {
    match metadata.get("token_endpoint_auth_signing_alg") {
        None => Ok(None),
        Some(Value::String(value)) if JwsAlgorithm::from_jose_name(value).is_some() => {
            Ok(Some(value.clone()))
        }
        Some(_) => Err(RegistrationError::metadata(
            "token_endpoint_auth_signing_alg is not a supported algorithm",
        )),
    }
}

/// Validate the `jwks` / `jwks_uri` pair. They are MUTUALLY EXCLUSIVE. A
/// `private_key_jwt` client MUST supply exactly one usable source; other methods
/// ignore any key material (it has no effect on their authentication). An inline
/// `jwks` must name at least one representable key; a `jwks_uri` is fetched THROUGH
/// the SSRF-hardened fetcher and must yield at least one key, so a private-address
/// destination is rejected structurally (issue #25 path reuse).
async fn validate_client_keys(
    state: &OidcState,
    metadata: &serde_json::Map<String, Value>,
    auth_method: ClientAuthMethod,
) -> Result<(Option<String>, Option<String>), RegistrationError> {
    let jwks_value = metadata.get("jwks").filter(|value| !value.is_null());
    let jwks_uri = metadata
        .get("jwks_uri")
        .and_then(Value::as_str)
        .map(str::to_owned);

    if jwks_value.is_some() && jwks_uri.is_some() {
        return Err(RegistrationError::metadata(
            "jwks and jwks_uri are mutually exclusive",
        ));
    }

    // Only private_key_jwt consumes registered keys; for any other method they are
    // an unrecognized-for-this-method property, so they are ignored (RFC 7591).
    if auth_method != ClientAuthMethod::PrivateKeyJwt {
        return Ok((None, None));
    }

    if let Some(jwks_value) = jwks_value {
        let Some(object) = jwks_value.as_object() else {
            return Err(RegistrationError::metadata("jwks must be a JWK Set object"));
        };
        let serialized = Value::Object(object.clone()).to_string();
        if ironauth_jose::trusted_keys_from_jwks(serialized.as_bytes()).is_empty() {
            return Err(RegistrationError::metadata("jwks names no usable key"));
        }
        return Ok((Some(serialized), None));
    }

    if let Some(jwks_uri) = jwks_uri {
        // Fetch through the SSRF-hardened resolver (issue #25). An internal or
        // private-address destination is blocked and yields an empty key set; a
        // non-https or unreachable URL likewise yields none. Any of these is a
        // uniform rejection, so the endpoint reveals nothing about internal hosts.
        let Some(resolver) = state.client_key_resolver() else {
            return Err(RegistrationError::metadata(
                "jwks_uri registration is not available on this deployment",
            ));
        };
        let keys = resolver.resolve(state.now(), &jwks_uri).await;
        if keys.is_empty() {
            return Err(RegistrationError::metadata(
                "jwks_uri did not yield a usable key set",
            ));
        }
        return Ok((None, Some(jwks_uri)));
    }

    // private_key_jwt with neither source: a keyless client would authenticate
    // nothing. Reject at registration rather than store an inert client.
    Err(RegistrationError::metadata(
        "private_key_jwt requires jwks or jwks_uri",
    ))
}

/// Reject a metadata property that pins any value other than `only` (used for the
/// single-value `response_types`/`grant_types` this provider supports). An omitted
/// property is fine (the default applies); a present one must contain `only` and
/// nothing else.
fn check_only(
    metadata: &serde_json::Map<String, Value>,
    key: &str,
    only: &str,
) -> Result<(), RegistrationError> {
    let Some(value) = metadata.get(key) else {
        return Ok(());
    };
    let Some(values) = string_array(value) else {
        return Err(RegistrationError::metadata_owned(format!(
            "{key} must be an array of strings"
        )));
    };
    if values.is_empty() || values.iter().any(|entry| entry != only) {
        return Err(RegistrationError::metadata_owned(format!(
            "{key} supports only [\"{only}\"]"
        )));
    }
    Ok(())
}

/// A JSON value as a `Vec<String>` if it is an array whose every element is a
/// string, else `None`.
fn string_array(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|entry| entry.as_str().map(str::to_owned))
        .collect()
}

/// Whether the method mints and stores a client secret (`client_secret_basic` /
/// `client_secret_post`).
impl ClientAuthMethod {
    fn needs_secret(self) -> bool {
        matches!(self, ClientAuthMethod::Basic | ClientAuthMethod::Post)
    }
}

/// Generate a registration access token: 256 bits from the entropy seam, URL-safe
/// base64 (no padding). Only its hash is stored; this plaintext is returned once.
fn generate_registration_token(env: &Env) -> String {
    let mut bytes = [0_u8; REGISTRATION_TOKEN_BYTES];
    env.entropy().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Extract a `Bearer` token from the `Authorization` header (case-insensitive
/// scheme), or `None`.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_owned())
}

/// Build the shared client-metadata portion of a registration response from the
/// validated metadata (used by the register and update responses).
fn base_metadata(
    client_id: &str,
    issued_at: i64,
    validated: &ValidatedMetadata,
    registration_client_uri: &str,
) -> serde_json::Map<String, Value> {
    metadata_object(
        client_id,
        issued_at,
        &validated.display_name,
        validated.auth_method.as_str(),
        &validated.redirect_uris,
        Some(&validated.application_type),
        Some(&validated.id_token_signed_response_alg),
        validated.jwks.as_deref(),
        validated.jwks_uri.as_deref(),
        validated.token_endpoint_auth_signing_alg.as_deref(),
        registration_client_uri,
    )
}

/// Build the client-metadata portion of an RFC 7592 read response from the stored
/// record.
///
/// The `application_type` and `id_token_signed_response_alg` are surfaced FAITHFULLY
/// from the stored columns (never substituted with a default): a DCR client always
/// has both persisted, so a persistence regression that dropped a column would show
/// as an absent field rather than a masked default, and the round-trip test genuinely
/// proves persistence.
fn read_metadata(
    record: &DynamicClientRecord,
    issued_at: i64,
    registration_client_uri: &str,
) -> serde_json::Map<String, Value> {
    metadata_object(
        &record.id.to_string(),
        issued_at,
        &record.display_name,
        &record.auth_method,
        &record.redirect_uris,
        record.application_type.as_deref(),
        record.id_token_signed_response_alg.as_deref(),
        record.jwks.as_deref(),
        record.jwks_uri.as_deref(),
        record.token_endpoint_auth_signing_alg.as_deref(),
        registration_client_uri,
    )
}

/// The shared response object builder for the register, update, and read
/// responses. Never includes a credential (the caller adds the secret and/or the
/// registration access token where applicable).
#[allow(clippy::too_many_arguments)]
fn metadata_object(
    client_id: &str,
    issued_at: i64,
    display_name: &str,
    auth_method: &str,
    redirect_uris: &[String],
    application_type: Option<&str>,
    id_token_signed_response_alg: Option<&str>,
    jwks: Option<&str>,
    jwks_uri: Option<&str>,
    token_endpoint_auth_signing_alg: Option<&str>,
    registration_client_uri: &str,
) -> serde_json::Map<String, Value> {
    let mut object = serde_json::Map::new();
    object.insert("client_id".to_owned(), json!(client_id));
    object.insert("client_id_issued_at".to_owned(), json!(issued_at));
    object.insert("client_name".to_owned(), json!(display_name));
    object.insert("redirect_uris".to_owned(), json!(redirect_uris));
    object.insert("token_endpoint_auth_method".to_owned(), json!(auth_method));
    object.insert("grant_types".to_owned(), json!(["authorization_code"]));
    object.insert("response_types".to_owned(), json!(["code"]));
    // Surfaced faithfully: a DCR client always has both persisted, so these are
    // present with the stored value; a dropped column shows as absent, never a
    // masked default (issue #30).
    if let Some(application_type) = application_type {
        object.insert("application_type".to_owned(), json!(application_type));
    }
    if let Some(id_token_signed_response_alg) = id_token_signed_response_alg {
        object.insert(
            "id_token_signed_response_alg".to_owned(),
            json!(id_token_signed_response_alg),
        );
    }
    if let Some(jwks_uri) = jwks_uri {
        object.insert("jwks_uri".to_owned(), json!(jwks_uri));
    }
    if let Some(jwks) = jwks {
        if let Ok(value) = serde_json::from_str::<Value>(jwks) {
            object.insert("jwks".to_owned(), value);
        }
    }
    if let Some(signing_alg) = token_endpoint_auth_signing_alg {
        object.insert(
            "token_endpoint_auth_signing_alg".to_owned(),
            json!(signing_alg),
        );
    }
    object.insert(
        "registration_client_uri".to_owned(),
        json!(registration_client_uri),
    );
    object
}

/// A validation failure, mapped to the RFC 7591 error object.
#[derive(Debug)]
enum RegistrationError {
    /// A metadata property is missing, malformed, or unsupported.
    InvalidClientMetadata(String),
    /// A `redirect_uri` is not a valid registrable target.
    InvalidRedirectUri(String),
    /// A `redirect_uri` is well formed but the environment's KIND rejects it under
    /// a typed guardrail (issue #42): for example an http loopback in a PROD
    /// environment. Carries the stable guardrail code and an operator-safe message,
    /// so the error names the exact failed guardrail.
    Guardrail(String),
}

impl RegistrationError {
    fn metadata(message: &'static str) -> Self {
        RegistrationError::InvalidClientMetadata(message.to_owned())
    }

    fn metadata_owned(message: String) -> Self {
        RegistrationError::InvalidClientMetadata(message)
    }

    fn redirect(message: &'static str) -> Self {
        RegistrationError::InvalidRedirectUri(message.to_owned())
    }

    /// Build a guardrail error naming the failed guardrail (issue #42).
    fn guardrail(violation: &ironauth_store::GuardrailViolation) -> Self {
        RegistrationError::Guardrail(format!(
            "guardrail {}: {}",
            violation.code(),
            violation.message
        ))
    }
}

impl IntoResponse for RegistrationError {
    fn into_response(self) -> Response {
        match self {
            RegistrationError::InvalidClientMetadata(description) => {
                error_body("invalid_client_metadata", &description)
            }
            RegistrationError::InvalidRedirectUri(description)
            | RegistrationError::Guardrail(description) => {
                error_body("invalid_redirect_uri", &description)
            }
        }
    }
}

/// A 400 `invalid_client_metadata` error response.
fn metadata_error(description: &str) -> Response {
    error_body("invalid_client_metadata", description)
}

/// A 400 `invalid_redirect_uri` error response.
fn redirect_error(description: &str) -> Response {
    error_body("invalid_redirect_uri", description)
}

/// Build a 400 RFC 7591 error object with a `no-store` cache directive.
fn error_body(code: &str, description: &str) -> Response {
    let body = json!({ "error": code, "error_description": description }).to_string();
    (
        StatusCode::BAD_REQUEST,
        [
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        body,
    )
        .into_response()
}

/// A uniform 401 for an unauthenticated RFC 7592 request, with the RFC 6750
/// `WWW-Authenticate: Bearer` challenge and no oracle for which check failed.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (
                header::WWW_AUTHENTICATE,
                "Bearer error=\"invalid_token\"".to_owned(),
            ),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        "",
    )
        .into_response()
}

/// A 500 for an unexpected persistence fault, with no detail.
fn server_error() -> Response {
    let body = json!({ "error": "server_error" }).to_string();
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(header::CONTENT_TYPE, "application/json".to_owned())],
        body,
    )
        .into_response()
}

/// A success response carrying credentials: the JSON body, `Cache-Control:
/// no-store`, and `Pragma: no-cache`, so a response containing a secret or token is
/// never cached.
fn credential_response(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (header::CACHE_CONTROL, "no-store".to_owned()),
            (header::PRAGMA, "no-cache".to_owned()),
        ],
        body.to_string(),
    )
        .into_response()
}

/// Compare two byte strings in time independent of where they first differ. Both
/// operands here are fixed-length SHA-256 hex, so equal length is the normal path.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(json: &str) -> serde_json::Map<String, Value> {
        serde_json::from_str(json).expect("json object")
    }

    #[test]
    fn omitted_metadata_takes_the_spec_defaults() {
        let m = meta(r#"{"redirect_uris":["https://rp.example/cb"]}"#);
        assert_eq!(
            validate_auth_method(&m).expect("method"),
            ClientAuthMethod::Basic
        );
        // An omitted id_token_signed_response_alg records the environment's ACTUAL
        // default signing algorithm (what the mint will sign this client's ID token
        // with), not the abstract RS256 spec default the environment might be unable
        // to honor (FIX 1). In an EdDSA-only environment that is EdDSA.
        let signable = [JwsAlgorithm::EdDsa];
        assert_eq!(
            negotiate_id_token_alg(&m, &signable, JwsAlgorithm::EdDsa).expect("alg"),
            "EdDSA"
        );
        // response_types / grant_types omitted is accepted (defaults apply).
        check_only(&m, "response_types", "code").expect("default response_types");
        check_only(&m, "grant_types", "authorization_code").expect("default grant_types");
    }

    #[test]
    fn client_secret_jwt_and_unknown_methods_are_rejected() {
        for method in ["client_secret_jwt", "tls_client_auth", "made_up"] {
            let m = meta(&format!(r#"{{"token_endpoint_auth_method":"{method}"}}"#));
            assert!(
                validate_auth_method(&m).is_err(),
                "{method} must be rejected"
            );
        }
        // The four advertised methods are accepted.
        for method in [
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "none",
        ] {
            let m = meta(&format!(r#"{{"token_endpoint_auth_method":"{method}"}}"#));
            assert!(validate_auth_method(&m).is_ok(), "{method} is supported");
        }
    }

    #[test]
    fn metadata_choices_negotiate_against_the_environments_signable_set() {
        // FIX 1: the negotiation is constrained to the algorithms the environment
        // can ACTUALLY sign with, so a recorded id_token_signed_response_alg is never
        // one the OP would refuse to sign this client's ID tokens with.

        // An EdDSA-only environment: EdDSA is the only signable algorithm.
        let eddsa_only = [JwsAlgorithm::EdDsa];
        // EdDSA offered alongside RS256: EdDSA wins (offered and signable).
        let m = meta(r#"{"id_token_signed_response_alg":["RS256","EdDSA"]}"#);
        assert_eq!(
            negotiate_id_token_alg(&m, &eddsa_only, JwsAlgorithm::EdDsa).expect("alg"),
            "EdDSA"
        );
        // ES256/ES384 offered, but the environment has no ES key: REJECTED, never
        // recorded (this is the defect the fix closes: it used to record ES256).
        let m = meta(r#"{"id_token_signed_response_alg":["ES256","ES384"]}"#);
        assert!(negotiate_id_token_alg(&m, &eddsa_only, JwsAlgorithm::EdDsa).is_err());
        // Only RS256 offered in an EdDSA-only env (the RS256 discovery FLOOR has no
        // key here): REJECTED rather than recording an unsignable RS256.
        let m = meta(r#"{"id_token_signed_response_alg":["RS256"]}"#);
        assert!(negotiate_id_token_alg(&m, &eddsa_only, JwsAlgorithm::EdDsa).is_err());

        // A dual EdDSA + RS256 environment: BOTH are signable.
        let dual = [JwsAlgorithm::EdDsa, JwsAlgorithm::Rs256];
        // EdDSA preferred when offered (plural RP Metadata Choices name too).
        let m = meta(r#"{"id_token_signed_response_alg_values":["ES256","EdDSA"]}"#);
        assert_eq!(
            negotiate_id_token_alg(&m, &dual, JwsAlgorithm::EdDsa).expect("alg"),
            "EdDSA"
        );
        // No EdDSA offered, RS256 offered AND signable: RS256 recorded, because the
        // mint can and will honor it for this client.
        let m = meta(r#"{"id_token_signed_response_alg":["RS256"]}"#);
        assert_eq!(
            negotiate_id_token_alg(&m, &dual, JwsAlgorithm::EdDsa).expect("alg"),
            "RS256"
        );
        // ES256 (no key) alongside RS256 (a key exists): the ES256 is filtered out,
        // RS256 chosen.
        let m = meta(r#"{"id_token_signed_response_alg":["ES256","RS256"]}"#);
        assert_eq!(
            negotiate_id_token_alg(&m, &dual, JwsAlgorithm::EdDsa).expect("alg"),
            "RS256"
        );
        // An offered set with nothing signable (ES512 is neither representable nor
        // backed by a key) is rejected.
        let m = meta(r#"{"id_token_signed_response_alg":["ES512"]}"#);
        assert!(negotiate_id_token_alg(&m, &dual, JwsAlgorithm::EdDsa).is_err());
    }

    #[test]
    fn web_requires_https_native_allows_loopback_and_private_use() {
        // Web: https only.
        assert!(redirect_allowed("https://rp.example/cb", "web"));
        assert!(!redirect_allowed("http://127.0.0.1/cb", "web"));
        assert!(!redirect_allowed("com.example.app:/cb", "web"));
        // Native: https, http loopback IP literal, and reverse-domain private-use.
        assert!(redirect_allowed("https://rp.example/cb", "native"));
        assert!(redirect_allowed("http://127.0.0.1:52000/cb", "native"));
        assert!(redirect_allowed("http://[::1]/cb", "native"));
        assert!(redirect_allowed(
            "com.example.app:/oauth2redirect",
            "native"
        ));
        // Dangerous schemes are rejected for both types.
        for uri in [
            "javascript:alert(1)",
            "data:text/html,x",
            "http://evil.example/cb",
        ] {
            assert!(!redirect_allowed(uri, "native"), "{uri} rejected (native)");
            assert!(!redirect_allowed(uri, "web"), "{uri} rejected (web)");
        }
    }

    #[test]
    fn response_and_grant_types_must_match_the_supported_flow() {
        let ok = meta(r#"{"response_types":["code"],"grant_types":["authorization_code"]}"#);
        check_only(&ok, "response_types", "code").expect("code ok");
        check_only(&ok, "grant_types", "authorization_code").expect("authorization_code ok");

        let bad = meta(r#"{"response_types":["token"]}"#);
        assert!(check_only(&bad, "response_types", "code").is_err());
        let bad = meta(r#"{"grant_types":["client_credentials"]}"#);
        assert!(check_only(&bad, "grant_types", "authorization_code").is_err());
    }

    #[test]
    fn a_registration_token_is_url_safe_and_from_the_seam() {
        let (env, _) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 7);
        let token = generate_registration_token(&env);
        let decoded = URL_SAFE_NO_PAD.decode(&token).expect("url-safe base64");
        assert_eq!(decoded.len(), REGISTRATION_TOKEN_BYTES);
        assert!(
            token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "url-safe alphabet: {token}"
        );
    }

    #[test]
    fn constant_time_eq_matches_only_identical_equal_length_inputs() {
        assert!(constant_time_eq(b"abcd", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abce"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn bearer_token_parses_case_insensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer tok-123".parse().unwrap());
        assert_eq!(bearer_token(&headers).as_deref(), Some("tok-123"));
        headers.insert(header::AUTHORIZATION, "bEaReR  spaced ".parse().unwrap());
        assert_eq!(bearer_token(&headers).as_deref(), Some("spaced"));
        headers.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
    }
}
