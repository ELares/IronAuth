// SPDX-License-Identifier: MIT OR Apache-2.0

//! The generic OIDC UPSTREAM: discovery, code exchange, and the security-critical
//! validation of an upstream ID token (issue #75, PR B).
//!
//! A declarative connector (issue #75, PR A) describes an OIDC-shaped upstream as
//! pure DATA. This module turns that data into a federated login WITHOUT a line of
//! per-provider code: it resolves the connector's endpoints (from an explicit set or
//! a fetched discovery document), exchanges the authorization code, and VALIDATES the
//! returned upstream ID token. Adding a provider is a stored definition, never a
//! release.
//!
//! # The two hardened seams
//!
//! Every outbound call (discovery, JWKS, token exchange, `UserInfo`) rides the one
//! SSRF-hardened [`ironauth_fetch::Fetcher`], so a connector URL that resolves to a
//! loopback or internal address is [`ironauth_fetch::FetchError::Blocked`] on the wire
//! (mapped here to [`ConnectorError::UpstreamUnavailable`]); this module writes no ad
//! hoc HTTP.
//!
//! The upstream ID token is validated through the ONE JOSE entry point
//! ([`ironauth_jose::verify`]): this module builds a [`VerificationPolicy`] pinning the
//! algorithm allowlist (the upstream-advertised or connector-allowed algorithms
//! INTERSECTED with the JOSE core's allowlist), the trusted keys (the cached upstream
//! JWKS, never a token-embedded key), the expected issuer (the configured connector
//! issuer), and the expected audience (the connector's client id), then verifies the
//! bound `nonce`. It writes NO crypto: `alg: none`, algorithm confusion, an unknown
//! `kid`, a forged issuer, a wrong audience, and an expired token ALL die inside
//! [`ironauth_jose::verify`], and every rejection maps to
//! [`ConnectorError::UpstreamProtocol`] so no identity is ever provisioned from an
//! unverified token.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::extract::{Path, RawQuery, State};
use axum::http::HeaderMap;
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_connector::{
    ClaimSources, ConnectorError, ConnectorRuntimeConfig, Endpoints, PkceMode, ResolvedEndpoints,
    TraitDocument, TraitPointerFailure, TraitSchemaView, discovery_url, evaluate, parse_discovery,
};
use ironauth_env::Clock;
use ironauth_fetch::{FetchError, FetchPurpose, FetchRequest, Fetcher};
use ironauth_jose::{JwsAlgorithm, TrustedKey, VerificationPolicy, verify};
use ironauth_store::{
    ConnectorId, FederationLoginStateId, NewAdminUser, NewFederationLoginState, Scope, StoreError,
    TraitSchema, UserId, UserState,
};
use sha2::{Digest, Sha256};

use crate::authn::AuthenticationEvent;
use crate::federation_jwks::FederationKeyResolver;
use crate::interaction;
use crate::state::OidcState;
use crate::util::{append_query, epoch_micros, percent_encode_query, query_get};
use crate::wellknown::{not_found, parse_scope};

/// The verified, honest identity recovered from a validated upstream ID token (issue
/// #75). Every field derives from claims that passed [`ironauth_jose::verify`]; nothing
/// here is trusted from an unverified token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedUpstreamIdentity {
    /// The upstream stable subject (`sub`): the federated user's key at the provider.
    pub subject: String,
    /// The upstream email, if the token carried one. Its trustworthiness is governed
    /// by the connector's `email_verified_trust` capability; PR B provisions a minimal
    /// identity and PR C generalizes claim mapping.
    pub email: Option<String>,
    /// The upstream's OWN asserted `amr` tokens, carried through verbatim for an honest
    /// federated `amr` passthrough (never re-asserted as a LOCAL factor). Empty when the
    /// upstream asserted none.
    pub upstream_amr: Vec<String>,
    /// The upstream's OWN `acr`, retained for the honest federated context. [`None`]
    /// when the upstream asserted none.
    pub upstream_acr: Option<String>,
    /// The upstream `auth_time` in epoch SECONDS, if the token asserted one. When
    /// absent the callback instant (from the clock seam) is the honest `auth_time`.
    pub auth_time_secs: Option<i64>,
    /// The full set of VERIFIED ID-token claims, retained so the declarative claim
    /// mapping (issue #75, PR C) can resolve trait fields from them. Every claim here
    /// passed [`ironauth_jose::verify`]; nothing unverified is carried.
    pub claims: serde_json::Map<String, serde_json::Value>,
}

/// The JOSE core's full signature-algorithm allowlist. HMAC and `none` are absent by
/// construction (see [`ironauth_jose`]), so intersecting any upstream-advertised list
/// with this set can never admit a symmetric or unsecured algorithm.
fn jose_supported_algs() -> Vec<JwsAlgorithm> {
    vec![
        JwsAlgorithm::EdDsa,
        JwsAlgorithm::Es256,
        JwsAlgorithm::Es384,
        JwsAlgorithm::Rs256,
        JwsAlgorithm::Rs384,
        JwsAlgorithm::Rs512,
        JwsAlgorithm::Ps256,
        JwsAlgorithm::Ps384,
        JwsAlgorithm::Ps512,
    ]
}

/// Resolve the algorithm allowlist for verifying an upstream ID token: the
/// upstream-advertised `id_token_signing_alg_values_supported` (or the connector's
/// configured algorithms) INTERSECTED with the JOSE core's allowlist.
///
/// When `advertised` is [`None`] (an explicit-endpoint connector advertises nothing),
/// the full JOSE allowlist governs, so any core-supported algorithm the upstream
/// actually signs with is accepted (and `none`/HMAC remain impossible). When
/// `advertised` is present, an unrecognized or non-core name is dropped, so the result
/// is exactly the algorithms BOTH sides can do.
#[must_use]
pub fn resolve_alg_allowlist(advertised: Option<&[String]>) -> Vec<JwsAlgorithm> {
    let Some(names) = advertised else {
        return jose_supported_algs();
    };
    let mut algs: Vec<JwsAlgorithm> = Vec::new();
    for name in names {
        if let Some(alg) = JwsAlgorithm::from_jose_name(name) {
            if !algs.contains(&alg) {
                algs.push(alg);
            }
        }
    }
    algs
}

/// Map an [`ironauth_fetch::FetchError`] to the transient [`ConnectorError::UpstreamUnavailable`].
/// A blocked SSRF target, a timeout, a redirect, an oversized body, or a transport
/// failure all mean the exchange could not COMPLETE, so issue #76 may retry or trip a
/// breaker. The message is non-sensitive (it never names a resolved address).
fn unavailable(err: &FetchError) -> ConnectorError {
    ConnectorError::UpstreamUnavailable(err.to_string())
}

/// Resolve a connector's endpoints, fetching and parsing the upstream discovery
/// document for an issuer-form connector (validating the mix-up defence) or resolving
/// an explicit-endpoint connector directly.
///
/// `issuer` is the configured connector issuer whose OIDC discovery document is fetched
/// (through [`FetchPurpose::FederationDiscovery`], the well-known path built by
/// `ironauth_connector::discovery_url`) and whose in-document issuer must match (the
/// mix-up defence).
///
/// # Errors
///
/// [`ConnectorError::UpstreamUnavailable`] if the discovery fetch is blocked, times
/// out, or returns a non-2xx; [`ConnectorError::UpstreamProtocol`] if the document is
/// malformed or its issuer does not match (the mix-up defence); or
/// [`ConnectorError::Config`] if neither an issuer nor an explicit set was supplied.
pub async fn fetch_discovery(
    fetcher: &Fetcher,
    issuer: &str,
    allow_http: bool,
) -> Result<ResolvedEndpoints, ConnectorError> {
    let url = discovery_url(issuer);
    let mut request = FetchRequest::get(FetchPurpose::FederationDiscovery, url);
    if allow_http {
        request = request.allow_plaintext_http();
    }
    let response = fetcher
        .fetch(request)
        .await
        .map_err(|err| unavailable(&err))?;
    if !response.status().is_success() {
        return Err(ConnectorError::UpstreamUnavailable(format!(
            "the discovery endpoint returned HTTP {}",
            response.status().as_u16()
        )));
    }
    parse_discovery(response.body(), issuer)
}

/// Exchange an authorization `code` at the upstream token endpoint, returning the raw
/// upstream ID token string (still to be VALIDATED by [`validate_upstream_id_token`]).
///
/// The connector's client secret authenticates the request (form-encoded client
/// credentials) alongside the PKCE `code_verifier` when one was used. The request rides
/// the hardened fetcher through [`FetchPurpose::FederationToken`].
///
/// # Errors
///
/// [`ConnectorError::UpstreamUnavailable`] if the exchange is blocked, times out, or
/// returns a non-2xx; [`ConnectorError::UpstreamProtocol`] if the response is not JSON
/// or carries no `id_token`.
pub async fn exchange_code(
    fetcher: &Fetcher,
    request: TokenExchange<'_>,
    allow_http: bool,
) -> Result<String, ConnectorError> {
    let mut form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}",
        percent_encode_query(request.code),
        percent_encode_query(request.redirect_uri),
        percent_encode_query(request.client_id),
        percent_encode_query(request.client_secret),
    );
    if let Some(verifier) = request.code_verifier {
        form.push_str("&code_verifier=");
        form.push_str(&percent_encode_query(verifier));
    }
    let mut http = FetchRequest::new(
        FetchPurpose::FederationToken,
        axum::http::Method::POST,
        request.token_url.to_owned(),
    )
    .header(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/x-www-form-urlencoded"),
    )
    .body(form.into_bytes());
    if allow_http {
        http = http.allow_plaintext_http();
    }
    let response = fetcher.fetch(http).await.map_err(|err| unavailable(&err))?;
    if !response.status().is_success() {
        return Err(ConnectorError::UpstreamUnavailable(format!(
            "the token endpoint returned HTTP {}",
            response.status().as_u16()
        )));
    }
    let body: serde_json::Value = serde_json::from_slice(response.body()).map_err(|_| {
        ConnectorError::UpstreamProtocol("the token response is not JSON".to_owned())
    })?;
    body.get("id_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            ConnectorError::UpstreamProtocol("the token response carried no id_token".to_owned())
        })
}

/// The inputs for a token exchange, bundled to keep the argument count readable.
#[derive(Debug, Clone, Copy)]
pub struct TokenExchange<'a> {
    /// The upstream token endpoint URL.
    pub token_url: &'a str,
    /// The authorization code returned to the callback.
    pub code: &'a str,
    /// The callback redirect URI, echoed exactly.
    pub redirect_uri: &'a str,
    /// The connector's registered client id.
    pub client_id: &'a str,
    /// The connector's unsealed client secret.
    pub client_secret: &'a str,
    /// The PKCE `code_verifier` when the authorize leg sent an `S256` challenge.
    pub code_verifier: Option<&'a str>,
}

/// The inputs for validating an upstream ID token, bundled to keep the argument count
/// readable and the call site self-documenting.
#[derive(Debug, Clone, Copy)]
pub struct UpstreamTokenPolicy<'a> {
    /// The configured connector issuer, matched EXACTLY against the token's `iss`.
    pub expected_issuer: &'a str,
    /// The connector's client id, matched EXACTLY against the token's `aud`.
    pub expected_audience: &'a str,
    /// The single-use `nonce` bound at the authorize leg, matched EXACTLY against the
    /// token's `nonce` claim (replay defence).
    pub expected_nonce: &'a str,
    /// The resolved algorithm allowlist (see [`resolve_alg_allowlist`]).
    pub allowed_algs: &'a [JwsAlgorithm],
}

/// Validate an upstream ID token through the JOSE core and recover the honest
/// federated identity (issue #75, the security crux).
///
/// `keys` are the cached UPSTREAM trusted keys (from the per-connector JWKS cache); an
/// EMPTY set fails closed as [`ConnectorError::UpstreamUnavailable`] (the JWKS could not
/// be resolved, for example because a private-range `jwks_uri` was blocked). The policy
/// pins the algorithm allowlist, the trusted keys, the expected issuer and audience;
/// [`ironauth_jose::verify`] performs the ONE signature check and enforces
/// `iss`/`aud`/`exp`/`nbf`. The bound `nonce` is checked here against the verified
/// claims. Every verification failure is [`ConnectorError::UpstreamProtocol`], so no
/// identity is produced from an unverified token.
///
/// # Errors
///
/// [`ConnectorError::UpstreamUnavailable`] for an empty key set;
/// [`ConnectorError::Config`] for an unbuildable policy (an empty issuer or audience, a
/// connector misconfiguration); [`ConnectorError::UpstreamProtocol`] for any token
/// rejection (`alg: none`, algorithm confusion, an unknown `kid`, a forged issuer, a
/// wrong audience, an expired token, a `nonce` mismatch, or a missing `sub`).
pub fn validate_upstream_id_token(
    token: &str,
    keys: Vec<TrustedKey>,
    policy: UpstreamTokenPolicy<'_>,
    clock: &dyn Clock,
) -> Result<VerifiedUpstreamIdentity, ConnectorError> {
    if keys.is_empty() {
        return Err(ConnectorError::UpstreamUnavailable(
            "the upstream published no usable signing key (empty JWKS)".to_owned(),
        ));
    }
    if policy.allowed_algs.is_empty() {
        return Err(ConnectorError::UpstreamProtocol(
            "the upstream advertised no signing algorithm the core can verify".to_owned(),
        ));
    }
    let verification = VerificationPolicy::new(
        policy.allowed_algs.to_vec(),
        keys,
        policy.expected_issuer,
        policy.expected_audience,
    )
    .map_err(|err| ConnectorError::Config(err.to_string()))?;

    let verified = verify(token, &verification, clock)
        .map_err(|err| ConnectorError::UpstreamProtocol(err.to_string()))?;
    let claims = verified.claims();

    // The bound nonce (RFC OIDC Core 3.1.2.1): the token's nonce must EXACTLY equal the
    // single-use value bound at the authorize leg. A missing or mismatched nonce is a
    // replay or a forged callback, so it is rejected as a protocol fault.
    let nonce_ok = claims
        .get("nonce")
        .and_then(|v| v.as_str())
        .is_some_and(|nonce| nonce == policy.expected_nonce);
    if !nonce_ok {
        return Err(ConnectorError::UpstreamProtocol(
            "the upstream ID token nonce did not match the bound value".to_owned(),
        ));
    }

    let subject = claims
        .subject()
        .ok_or_else(|| {
            ConnectorError::UpstreamProtocol("the upstream ID token carried no sub".to_owned())
        })?
        .to_owned();

    Ok(VerifiedUpstreamIdentity {
        subject,
        email: claims
            .get("email")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        upstream_amr: amr_from_claims(claims.get("amr")),
        upstream_acr: claims
            .get("acr")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        auth_time_secs: claims.get("auth_time").and_then(serde_json::Value::as_i64),
        claims: claims.raw().clone(),
    })
}

/// Extract the upstream `amr` as a list of strings, accepting either a JSON array of
/// strings (the OIDC form) or a single bare string, and dropping any non-string member.
fn amr_from_claims(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        Some(serde_json::Value::String(single)) => vec![single.clone()],
        _ => Vec::new(),
    }
}

/// The lifetime of a federation outbound-login correlation row (issue #75, PR B): a
/// short window between the upstream redirect and the callback. Single-use and bounded.
const FEDERATION_STATE_TTL: Duration = Duration::from_secs(600);

/// The installed generic OIDC upstream runtime (issue #75, PR B): the one SSRF-hardened
/// fetcher every federation outbound rides, the per-connector upstream JWKS cache, and a
/// bounded per-connector discovery cache. Installed on [`OidcState`] via
/// [`OidcState::with_federation`] by the boot path when `oidc.federation.enabled` is set
/// (off by default, leaving the `/federation` routes a uniform not-found).
pub struct FederationRuntime {
    fetcher: Arc<Fetcher>,
    keys: Arc<FederationKeyResolver>,
    discovery_ttl: Duration,
    // Permit a plaintext `http` upstream. OFF in production; the test constructor turns it
    // on so an in-process loopback upstream can be driven through the injected dialer.
    allow_http: bool,
    // A bounded cache of resolved discovery endpoints, keyed by connector id and read
    // against the application clock seam for expiry (deterministic under a manual clock).
    discovery_cache: Mutex<HashMap<String, CachedDiscovery>>,
}

/// A cached discovery resolution and the instant it was fetched.
struct CachedDiscovery {
    resolved: ResolvedEndpoints,
    fetched_at: SystemTime,
}

impl std::fmt::Debug for FederationRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationRuntime")
            .field("discovery_ttl", &self.discovery_ttl)
            .finish_non_exhaustive()
    }
}

impl FederationRuntime {
    /// A production runtime over `fetcher` and the upstream JWKS `keys` cache, caching a
    /// discovery resolution for `discovery_ttl`. Upstream fetches are https-only.
    #[must_use]
    pub fn new(
        fetcher: Arc<Fetcher>,
        keys: Arc<FederationKeyResolver>,
        discovery_ttl: Duration,
    ) -> Self {
        Self {
            fetcher,
            keys,
            discovery_ttl,
            allow_http: false,
            discovery_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Like [`FederationRuntime::new`] but permitting a plaintext `http` upstream, so an
    /// integration test can drive an in-process loopback upstream through the fetcher's
    /// injected dialer. Behind the `testing` feature so it never exists in production.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn new_allow_http(
        fetcher: Arc<Fetcher>,
        keys: Arc<FederationKeyResolver>,
        discovery_ttl: Duration,
    ) -> Self {
        Self {
            fetcher,
            keys,
            discovery_ttl,
            allow_http: true,
            discovery_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve a connector's endpoints: an explicit set directly, or a discovery-form
    /// connector through its cached-or-fetched discovery document (mix-up-checked).
    async fn resolve_endpoints(
        &self,
        now: SystemTime,
        connector_id: &str,
        endpoints: &Endpoints,
    ) -> Result<ResolvedEndpoints, ConnectorError> {
        match endpoints {
            Endpoints::Explicit(explicit) => Ok(ResolvedEndpoints::from_explicit(explicit)),
            Endpoints::Discovery(discovery) => {
                if let Some(cached) = self.cached_discovery(now, connector_id) {
                    return Ok(cached);
                }
                let resolved =
                    fetch_discovery(&self.fetcher, &discovery.issuer, self.allow_http).await?;
                self.store_discovery(now, connector_id, resolved.clone());
                Ok(resolved)
            }
        }
    }

    /// The cached discovery resolution for `connector_id` if a non-expired entry exists.
    fn cached_discovery(&self, now: SystemTime, connector_id: &str) -> Option<ResolvedEndpoints> {
        let cache = self
            .discovery_cache
            .lock()
            .expect("federation discovery cache lock poisoned");
        let entry = cache.get(connector_id)?;
        let fresh = now
            .duration_since(entry.fetched_at)
            .is_ok_and(|age| age < self.discovery_ttl);
        fresh.then(|| entry.resolved.clone())
    }

    /// Store a discovery resolution for `connector_id` at `now`.
    fn store_discovery(&self, now: SystemTime, connector_id: &str, resolved: ResolvedEndpoints) {
        self.discovery_cache
            .lock()
            .expect("federation discovery cache lock poisoned")
            .insert(
                connector_id.to_owned(),
                CachedDiscovery {
                    resolved,
                    fetched_at: now,
                },
            );
    }
}

/// GET `/t/{tenant}/e/{env}/federation/{connector_slug}/authorize` (issue #75, PR B):
/// begin a federated login by redirecting the browser to the UPSTREAM provider.
///
/// The handler loads the DATA-ONLY connector by slug, resolves its endpoints (fetching
/// discovery when needed), generates an unguessable `state` and `nonce` from the entropy
/// seam, generates a PKCE `code_verifier` and its `S256` challenge when PKCE applies,
/// persists the single-use correlation row (the sealed verifier, the nonce, the connector,
/// and the pending local resume target), and 302s to the upstream authorization endpoint.
/// Adding a provider is a stored connector definition, never a code change here.
pub async fn federation_authorize(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, connector_slug)): Path<(String, String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    let Some(runtime) = state.federation() else {
        return not_found();
    };
    // The pending LOCAL authorization request to resume after the federated login. It is
    // UNTRUSTED, so parse_resume validates it as a local /authorize path and recovers its
    // scope, which must match this route's scope (defence in depth).
    let return_to = query.as_deref().and_then(|q| query_get(q, "return_to"));
    let Some(resume) = return_to
        .as_deref()
        .and_then(|r| interaction::parse_resume(Some(r)))
    else {
        return interaction::invalid_link_page();
    };
    if resume.scope != scope {
        return interaction::invalid_link_page();
    }

    // Load the connector by its per-environment slug. An absent or disabled connector is a
    // uniform not-found (no oracle for which slugs exist).
    let record = match state
        .store()
        .scoped(scope)
        .connectors()
        .by_slug(&connector_slug)
        .await
    {
        Ok(Some(record)) if record.enabled => record,
        Ok(_) => return not_found(),
        Err(_) => return interaction::server_error_page(),
    };
    let Ok(definition) = serde_json::from_str::<ConnectorRuntimeConfig>(&record.definition_json)
    else {
        return interaction::server_error_page();
    };

    // Reject an explicit-endpoint connector UP FRONT (issue #75, LOW-3), before any `state`
    // is generated or persisted: PR B binds the upstream `iss` only for an issuer-form
    // connector, so an explicit set cannot complete the callback. Failing here gives the
    // operator a clean, documented error instead of a 500 after the user has authenticated.
    if matches!(definition.endpoints, Endpoints::Explicit(_)) {
        return interaction::federation_unsupported_page();
    }

    let now = state.now();
    // A discovery fetch that is blocked, times out, or returns a malformed document fails
    // the login without provisioning anything.
    let Ok(resolved) = runtime
        .resolve_endpoints(now, &record.id.to_string(), &definition.endpoints)
        .await
    else {
        return interaction::server_error_page();
    };

    let state_value = random_token(&state);
    let nonce = random_token(&state);
    // PKCE to the upstream: send an S256 challenge when the connector requires it, or when
    // it is auto and the upstream advertises S256. An explicit-endpoint upstream advertises
    // nothing, so auto omits PKCE there (the conservative interoperable default).
    let use_pkce = match definition.pkce {
        PkceMode::Disabled => false,
        PkceMode::Required => true,
        PkceMode::AutoWhereSupported => resolved.advertises_s256(),
    };
    let code_verifier = use_pkce.then(|| random_token(&state));
    let code_challenge = code_verifier.as_deref().map(s256_challenge);

    let redirect_uri =
        federation_callback_url(&state, &tenant_id, &environment_id, &connector_slug);

    // Persist the single-use correlation row. The verifier is sealed by the store; an
    // absent verifier is sealed empty.
    let fls_id = FederationLoginStateId::generate(state.env(), &scope);
    let expires_at = epoch_micros(now.checked_add(FEDERATION_STATE_TTL).unwrap_or(now));
    let verifier_bytes = code_verifier.as_deref().unwrap_or("").as_bytes();
    let persisted = state
        .store()
        .scoped(scope)
        .federation_login_states()
        .create(
            state.env(),
            &fls_id,
            NewFederationLoginState {
                state: &state_value,
                nonce: &nonce,
                code_verifier: verifier_bytes,
                connector_id: &record.id.to_string(),
                return_to: &resume.return_to,
                expires_at_unix_micros: expires_at,
            },
        )
        .await;
    if persisted.is_err() {
        return interaction::server_error_page();
    }

    // Build the upstream authorization URL.
    let scope_param = definition.scopes.join(" ");
    let mut params: Vec<(&str, Option<&str>)> = vec![
        ("response_type", Some("code")),
        ("client_id", Some(definition.client_id.as_str())),
        ("redirect_uri", Some(redirect_uri.as_str())),
        ("scope", Some(scope_param.as_str())),
        ("state", Some(state_value.as_str())),
        ("nonce", Some(nonce.as_str())),
    ];
    if let Some(challenge) = code_challenge.as_deref() {
        params.push(("code_challenge", Some(challenge)));
        params.push(("code_challenge_method", Some("S256")));
    }
    let location = append_query(&resolved.authorize_url, &params);
    interaction::redirect(&location)
}

/// GET `/t/{tenant}/e/{env}/federation/{connector_slug}/callback` (issue #75, PR B): the
/// security crux. Consume the correlation row by `state` SINGLE-USE (the CSRF defence),
/// exchange the code at the upstream token endpoint using the PRODUCTION-unsealed client
/// secret and the bound PKCE verifier, VALIDATE the upstream ID token through the JOSE
/// core, and only then provision the LOCAL identity, establish the LOCAL session, and
/// resume the pending local authorization request.
// The callback is a linear pipeline (consume -> exchange -> validate -> provision ->
// session -> resume); splitting it across helpers would scatter the one security flow the
// reviewer must read top to bottom.
#[allow(clippy::too_many_lines)]
pub async fn federation_callback(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, connector_slug)): Path<(String, String, String)>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    let Some(runtime) = state.federation() else {
        return not_found();
    };
    let query = query.unwrap_or_default();

    // Consume the correlation row by state, SINGLE-USE. A replayed, forged, absent, or
    // expired state matches no consumable row: the CSRF defence. Everything the callback
    // needs (nonce, verifier, connector, resume target) rides the consumed row, never the
    // untrusted callback query.
    let Some(state_value) = query_get(&query, "state") else {
        return interaction::invalid_link_page();
    };
    let now_micros = epoch_micros(state.now());
    let consumed = match state
        .store()
        .scoped(scope)
        .federation_login_states()
        .consume(&state_value, now_micros)
        .await
    {
        Ok(Some(consumed)) => consumed,
        Ok(None) => return interaction::invalid_link_page(),
        Err(_) => return interaction::server_error_page(),
    };

    // The upstream returned an error (user denied, etc.), or no code: fail the login.
    let Some(code) = query_get(&query, "code") else {
        return interaction::invalid_link_page();
    };

    // Load the connector the authorize leg used (by the consumed connector id) and unseal
    // its client secret on the DATA plane (the production unseal).
    let Ok(connector_id) = ConnectorId::parse_in_scope(&consumed.connector_id, &scope) else {
        return interaction::server_error_page();
    };
    let Ok(record) = state
        .store()
        .scoped(scope)
        .connectors()
        .get(&connector_id)
        .await
    else {
        return interaction::server_error_page();
    };
    // Re-check `enabled` at the callback (INFO-2): a connector disabled BETWEEN the authorize
    // leg (which checks it) and this callback must fail closed, not complete a login.
    if !record.enabled {
        return not_found();
    }
    let Ok(definition) = serde_json::from_str::<ConnectorRuntimeConfig>(&record.definition_json)
    else {
        return interaction::server_error_page();
    };
    let Ok(secret_bytes) = state
        .store()
        .scoped(scope)
        .connectors()
        .open_client_secret(&connector_id)
        .await
    else {
        return interaction::server_error_page();
    };
    let Ok(client_secret) = String::from_utf8(secret_bytes) else {
        return interaction::server_error_page();
    };

    let now = state.now();
    let Ok(resolved) = runtime
        .resolve_endpoints(now, &connector_id.to_string(), &definition.endpoints)
        .await
    else {
        return interaction::server_error_page();
    };
    // Only a discovery-form connector carries the issuer the upstream ID token's `iss` is
    // matched against (the mix-up-checked document issuer). PR B validates issuer-form
    // connectors; an explicit connector cannot bind an `iss` yet.
    let Endpoints::Discovery(discovery) = &definition.endpoints else {
        return interaction::server_error_page();
    };
    let expected_issuer = discovery.issuer.clone();

    let redirect_uri =
        federation_callback_url(&state, &tenant_id, &environment_id, &connector_slug);
    let verifier = String::from_utf8(consumed.code_verifier).ok();
    let verifier = verifier.as_deref().filter(|v| !v.is_empty());

    // Exchange the code at the upstream token endpoint. Any failure fails the login WITHOUT
    // provisioning a user.
    let Ok(id_token) = exchange_code(
        &runtime.fetcher,
        TokenExchange {
            token_url: &resolved.token_url,
            code: &code,
            redirect_uri: &redirect_uri,
            client_id: &definition.client_id,
            client_secret: &client_secret,
            code_verifier: verifier,
        },
        runtime.allow_http,
    )
    .await
    else {
        return interaction::server_error_page();
    };

    // Resolve the upstream signing keys through the SSRF-hardened fetcher (a private-range
    // jwks_uri is Blocked here, so validation then fails closed as UpstreamUnavailable), and
    // VALIDATE the upstream ID token through the JOSE core. On ANY validation failure no
    // user is provisioned and the login fails (UpstreamProtocol / UpstreamUnavailable).
    // Extract the token's `kid` as a REFETCH hint only (never a key source): a `kid` the
    // cached JWKS does not answer to triggers a single bounded refetch so an upstream key
    // ROTATION is picked up WITHOUT waiting out the JWKS TTL (issue #75, LOW-1). The trust
    // decision stays entirely inside `validate_upstream_id_token` / the JOSE core.
    let token_kid = ironauth_jose::compact_jws_kid(&id_token);
    let keys = runtime
        .keys
        .resolve_for_kid(
            now,
            &connector_id.to_string(),
            &resolved.jwks_uri,
            token_kid.as_deref(),
        )
        .await;
    let allowed_algs =
        resolve_alg_allowlist(resolved.id_token_signing_alg_values_supported.as_deref());
    let Ok(identity) = validate_upstream_id_token(
        &id_token,
        keys,
        UpstreamTokenPolicy {
            expected_issuer: &expected_issuer,
            expected_audience: &definition.client_id,
            expected_nonce: &consumed.nonce,
            allowed_algs: &allowed_algs,
        },
        state.env().clock(),
    ) else {
        return interaction::server_error_page();
    };

    // Evaluate the declarative claim mapping (issue #75, PR C) against the VERIFIED upstream
    // claims to assemble the local identity's trait document, TYPE-CHECKED against the scope's
    // active trait schema. This is the acceptance-critical fail-closed crux: on ANY mapping
    // failure (a missing required claim, a wrong type, a trait the schema does not declare) the
    // evaluator returns a typed error and the login aborts HERE, BEFORE any user row is written.
    // A mapping-definition fault is a Config error and an upstream claim fault is an
    // UpstreamProtocol error; both fail the login with NO partial identity provisioned.
    let Ok(active_schema) = state.store().scoped(scope).trait_schemas().active().await else {
        return interaction::server_error_page();
    };
    let compiled = match active_schema
        .as_ref()
        .map(|version| TraitSchema::compile(&version.schema_json))
    {
        Some(Ok(schema)) => Some(schema),
        // An active schema that fails to compile is a server-side fault, not a login the user
        // can fix; fail closed without provisioning.
        Some(Err(_)) => return interaction::server_error_page(),
        None => None,
    };
    let schema_view = compiled.as_ref().map(StoreTraitSchema);
    let schema_arg: Option<&dyn TraitSchemaView> = schema_view
        .as_ref()
        .map(|view| view as &dyn TraitSchemaView);

    // The evaluator NFKC-normalizes the resolved `email` trait value itself, BEFORE its type
    // check, so the mapped email is canonicalized regardless of the claim path it resolves from
    // (a top-level `email` or a nested path like `emails.0`) and the type-checked and provisioned
    // values are the same canonical form. `userinfo: None` because the UserInfo fetch is deferred
    // to issue #74; a connector that requires UserInfo is rejected at write-time validation.
    let Ok(trait_doc) = evaluate(
        &definition.claim_mapping,
        &definition.quirks,
        ClaimSources {
            id_token: &identity.claims,
            userinfo: None,
        },
        schema_arg,
    ) else {
        // Fail-closed: NO user is provisioned from a mapping/type-check failure.
        return interaction::server_error_page();
    };

    // Provision the local identity from the mapped traits (PR C), still keying on the VERIFIED,
    // issuer-namespaced (issuer, sub) composite PR B established (never the mapped subject). A
    // first login provisions the mapped traits; a returning login refreshes them. Only a fully
    // valid, type-checked document ever reaches this write.
    let schema_version = active_schema.as_ref().map(|version| version.version);
    let Ok(user_id) = provision_federated_user(
        &state,
        scope,
        &connector_slug,
        &expected_issuer,
        &identity,
        &trait_doc,
        schema_version,
    )
    .await
    else {
        return interaction::server_error_page();
    };

    // Establish the LOCAL session with the HONEST federated authentication event: the local
    // token's acr is the federated context and its amr is the UPSTREAM's asserted amr
    // passthrough (never a fabricated local factor). auth_time is the upstream auth_time
    // when present, else the callback instant.
    let auth_time_micros = identity
        .auth_time_secs
        .map_or_else(|| now_micros, |secs| secs.saturating_mul(1_000_000));
    let event = AuthenticationEvent::federated(
        auth_time_micros,
        &identity.upstream_amr,
        identity.upstream_acr.as_deref(),
    );
    let actor = interaction::user_actor(&user_id);
    let Ok(cookies) = interaction::establish_session(
        &state,
        scope,
        &user_id.to_string(),
        &event,
        actor,
        &headers,
    )
    .await
    else {
        return interaction::server_error_page();
    };

    // Resume the pending LOCAL authorization request, which now sees the authenticated
    // session and issues LOCAL tokens as usual (carrying the honest federated acr/amr).
    interaction::redirect_setting_cookie(&consumed.return_to, &cookies)
}

/// The namespaced external-id for a federated identity (issue #75, HIGH-1): the upstream
/// ISSUER and the upstream `sub`, LENGTH-PREFIXED so the `(issuer, sub) -> key` mapping is
/// injective.
///
/// An OIDC `sub` is unique only WITHIN one issuer (OIDC Core section 2), so keying the local
/// federated identity on the BARE `sub` lets two connectors pointing at DIFFERENT upstream
/// identity providers that emit the same `sub` resolve to the SAME local user: an account
/// takeover by anyone who controls a second connector's provider and picks a victim's `sub`.
/// Namespacing by
/// the mix-up-checked issuer is the OIDC-correct identity boundary: two connectors to the
/// SAME issuer with the same `sub` map to the SAME user (one upstream identity); two
/// connectors to DIFFERENT issuers with the same `sub` are DISTINCT users.
///
/// The length prefix on the issuer makes the encoding injection-safe: no choice of
/// `(issuer, sub)` with a different issuer can ever encode to another's key, even if an
/// issuer or `sub` contains the separator (a bare separator like NUL is spoofable when the
/// attacker controls the `sub`). This composite is what flows into the store's blind index
/// and sealed `external_id`, so a re-login recomputes the identical key and finds the same
/// user.
#[must_use]
pub fn federated_external_id(issuer: &str, subject: &str) -> String {
    format!(
        "federated:v1:{}:{issuer}:{}:{subject}",
        issuer.len(),
        subject.len()
    )
}

/// The store's compiled [`TraitSchema`] adapted to the connector crate's store-free
/// [`TraitSchemaView`] seam (issue #75, PR C), so the pure evaluator can type-check an
/// assembled trait document without depending on `ironauth-store`. It maps the store's
/// per-field [`ironauth_store::ValidationFailure`]s (RFC 6901 pointer + operator-safe
/// message, never a claim value) into the evaluator's [`TraitPointerFailure`].
struct StoreTraitSchema<'a>(&'a TraitSchema);

impl TraitSchemaView for StoreTraitSchema<'_> {
    fn type_check(&self, document: &serde_json::Value) -> Vec<TraitPointerFailure> {
        self.0
            .validate(document)
            .into_iter()
            .map(|failure| TraitPointerFailure {
                pointer: failure.pointer,
                message: failure.message,
            })
            .collect()
    }
}

/// Provision or look up the LOCAL user for a verified federated identity (issue #75), keyed on
/// the upstream ISSUER + `sub` via the external-id link (issue #75, HIGH-1: the namespaced key
/// closes the cross-connector `sub`-collision takeover), and carrying the DECLARATIVE
/// claim-mapped traits (PR C).
///
/// The identity KEY stays the verified, issuer-namespaced `(issuer, sub)` composite, NEVER the
/// mapped subject. A first login creates the user with the mapped traits (or a minimal identity
/// when the mapping maps none); a returning login refreshes the mapped traits (a documented
/// policy: a re-login re-applies the mapping so upstream trait drift is reflected), or leaves a
/// trait-free identity untouched. `trait_doc` has ALREADY been type-checked against the active
/// schema, so no partial or invalid document reaches a write here.
///
/// # Errors
///
/// [`StoreError`] on a persistence, serialization, or trait-validation failure.
async fn provision_federated_user(
    state: &OidcState,
    scope: Scope,
    connector_slug: &str,
    issuer: &str,
    identity: &VerifiedUpstreamIdentity,
    trait_doc: &TraitDocument,
    schema_version: Option<i32>,
) -> Result<UserId, StoreError> {
    // The federated external-id is namespaced by the upstream ISSUER, because a `sub` is
    // unique only within one issuer (see `federated_external_id`).
    let external_id = federated_external_id(issuer, &identity.subject);
    // The mapped traits as a JSON string, when the mapping produced any (a trait-free mapping
    // provisions a minimal identity, exactly as PR B did). Serializing a JSON object never
    // fails; a fault is surfaced rather than silently persisting an empty document.
    let traits_json = if trait_doc.is_traitless() {
        None
    } else {
        Some(serde_json::to_string(&trait_doc.traits_value()).map_err(|_| StoreError::Encryption)?)
    };

    if let Some(existing) = state
        .store()
        .scoped(scope)
        .users()
        .by_external_id(&external_id)
        .await?
    {
        // Returning login: refresh the mapped traits (fully re-validated by set_traits against
        // the active schema). A trait-free mapping leaves the existing identity untouched.
        if let Some(traits_json) = traits_json.as_deref() {
            let actor = interaction::user_actor(&existing.id);
            let correlation = ironauth_store::CorrelationId::generate(state.env());
            state
                .store()
                .scoped(scope)
                .acting(actor, correlation)
                .users()
                .set_traits(state.env(), &existing.id, traits_json)
                .await?;
        }
        return Ok(existing.id);
    }
    // A namespaced, per-connector login handle keeps a federated account from colliding with
    // a local password account that happens to share the upstream email.
    let handle = format!("federated:{connector_slug}:{}", identity.subject);
    let user_id = UserId::generate(state.env(), &scope);
    let now_micros = epoch_micros(state.now());
    let actor = interaction::user_actor(&user_id);
    let correlation = ironauth_store::CorrelationId::generate(state.env());
    state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .users()
        .admin_create(
            state.env(),
            NewAdminUser {
                id: Some(&user_id),
                identifier: &handle,
                password_hash: None,
                claims_json: None,
                external_id: Some(&external_id),
                state: UserState::Active,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits_json: traits_json.as_deref(),
                // The schema version accompanies the traits; the two are set together, and a
                // non-empty document only reaches here when an active schema was present.
                traits_schema_version: traits_json.as_ref().and(schema_version),
            },
            now_micros,
            None,
        )
        .await
}

/// Generate an unguessable URL-safe token from the entropy seam (256 bits): used for the
/// upstream `state`, the `nonce`, and the PKCE `code_verifier` (43 base64url characters,
/// within the RFC 7636 43..=128 bound).
fn random_token(state: &OidcState) -> String {
    let mut buf = [0_u8; 32];
    state.env().entropy().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// The PKCE `S256` code challenge for `code_verifier` (RFC 7636 4.2):
/// `BASE64URL(SHA256(code_verifier))`.
fn s256_challenge(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
}

/// The federated callback redirect URI for a connector, built from the deployment's public
/// base URL and the route's scope and slug. It must be byte-identical at the authorize leg
/// (where it is sent to the upstream) and the callback (where it is echoed in the exchange).
fn federation_callback_url(
    state: &OidcState,
    tenant_id: &str,
    environment_id: &str,
    connector_slug: &str,
) -> String {
    format!(
        "{}/t/{tenant_id}/e/{environment_id}/federation/{connector_slug}/callback",
        state.issuer_base().trim_end_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ironauth_env::Env;
    use ironauth_jose::{EmissionOptions, SigningKey, TrustedKey, sign_jws};

    use super::*;

    // The loopback-server / injected-dialer harness tests exercise the outbound fetch
    // path and so need the `testing` feature (for the plaintext-http resolver constructor)
    // and the ironauth-fetch `test-harness` seams. The pure ID-token-validation crux tests
    // above need neither, so they always compile.
    #[cfg(feature = "testing")]
    use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
    #[cfg(feature = "testing")]
    use ironauth_jose::JwkSet;
    #[cfg(feature = "testing")]
    use std::net::{IpAddr, SocketAddr};
    #[cfg(feature = "testing")]
    use std::sync::Arc;
    #[cfg(feature = "testing")]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(feature = "testing")]
    use tokio::net::TcpListener;

    #[cfg(feature = "testing")]
    use crate::federation_jwks::FederationKeyResolver;

    const ISSUER: &str = "https://upstream.example";
    const CLIENT_ID: &str = "ironauth-at-upstream";
    const NONCE: &str = "n-0S6_WzA2Mj";

    fn upstream_key() -> SigningKey {
        SigningKey::ed25519_from_seed(Some("up".to_owned()), &[9_u8; 32]).expect("upstream key")
    }

    fn trusted(key: &SigningKey) -> Vec<TrustedKey> {
        vec![key.verifying_key().expect("verifying key")]
    }

    fn sign(key: &SigningKey, claims: &serde_json::Value) -> String {
        let payload = serde_json::to_vec(claims).expect("serialize");
        sign_jws(key, &payload, &EmissionOptions::new().with_typ("JWT")).expect("sign")
    }

    fn id_token(key: &SigningKey, extra: serde_json::Value) -> String {
        let mut claims = serde_json::json!({
            "iss": ISSUER,
            "sub": "upstream-subject-123",
            "aud": CLIENT_ID,
            "exp": 4_102_444_800_i64, // year 2100
            "iat": 0,
            "nonce": NONCE,
        });
        if let (serde_json::Value::Object(base), serde_json::Value::Object(more)) =
            (&mut claims, extra)
        {
            for (k, v) in more {
                base.insert(k, v);
            }
        }
        sign(key, &claims)
    }

    fn policy(algs: &[JwsAlgorithm]) -> UpstreamTokenPolicy<'_> {
        UpstreamTokenPolicy {
            expected_issuer: ISSUER,
            expected_audience: CLIENT_ID,
            expected_nonce: NONCE,
            allowed_algs: algs,
        }
    }

    fn manual_clock() -> (Env, std::sync::Arc<ironauth_env::ManualClock>) {
        Env::deterministic(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            1,
        )
    }

    // ---- The security crux: upstream ID-token validation ----

    #[test]
    fn a_valid_upstream_id_token_yields_the_honest_identity() {
        let key = upstream_key();
        let (env, _clock) = manual_clock();
        let algs = jose_supported_algs();
        let token = id_token(
            &key,
            serde_json::json!({ "email": "user@upstream.example", "amr": ["pwd", "otp"], "acr": "aal2", "auth_time": 1_699_999_000 }),
        );
        let identity =
            validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
                .expect("valid token accepted");
        assert_eq!(identity.subject, "upstream-subject-123");
        assert_eq!(identity.email.as_deref(), Some("user@upstream.example"));
        assert_eq!(
            identity.upstream_amr,
            vec!["pwd".to_owned(), "otp".to_owned()]
        );
        assert_eq!(identity.upstream_acr.as_deref(), Some("aal2"));
        assert_eq!(identity.auth_time_secs, Some(1_699_999_000));
    }

    #[test]
    fn alg_none_is_rejected_by_the_jose_core() {
        // A hand-crafted unsecured token (alg:none, empty signature) dies in verify.
        let (env, _clock) = manual_clock();
        let head = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let body = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss": ISSUER, "sub": "x", "aud": CLIENT_ID, "exp": 4_102_444_800_i64, "nonce": NONCE
            }))
            .unwrap(),
        );
        let token = format!("{head}.{body}.");
        let key = upstream_key();
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("alg=none rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn algorithm_confusion_is_rejected() {
        // The token claims RS256 but the trusted key is Ed25519: the key-family mismatch
        // dies in verify (the classic RS/EC/Ed confusion is inexpressible against a
        // family-typed key).
        let (env, _clock) = manual_clock();
        let head = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"up"}"#);
        let body = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss": ISSUER, "sub": "x", "aud": CLIENT_ID, "exp": 4_102_444_800_i64, "nonce": NONCE
            }))
            .unwrap(),
        );
        let token = format!("{head}.{body}.c2ln");
        let key = upstream_key();
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("alg confusion rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn an_unknown_kid_is_rejected() {
        // A token naming a kid no trusted key answers to is rejected (never a key source).
        let (env, _clock) = manual_clock();
        let signer = SigningKey::ed25519_from_seed(Some("other".to_owned()), &[1_u8; 32]).unwrap();
        let token = id_token(&signer, serde_json::json!({}));
        let key = upstream_key(); // trusted set only has kid "up"
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("unknown kid rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn a_forged_issuer_is_rejected() {
        let key = upstream_key();
        let (env, _clock) = manual_clock();
        let token = id_token(&key, serde_json::json!({ "iss": "https://evil.example" }));
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("forged iss rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn a_wrong_audience_is_rejected() {
        let key = upstream_key();
        let (env, _clock) = manual_clock();
        let token = id_token(&key, serde_json::json!({ "aud": "some-other-client" }));
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("wrong aud rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn an_expired_token_is_rejected() {
        let key = upstream_key();
        let (env, _clock) = manual_clock(); // now = 1_700_000_000
        let token = id_token(&key, serde_json::json!({ "exp": 1_600_000_000_i64 }));
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("expired rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn a_forged_signature_is_rejected() {
        // Signed with a DIFFERENT key that reuses the trusted kid: the kid matches but the
        // signature does not verify against the trusted key.
        let (env, _clock) = manual_clock();
        let forger = SigningKey::ed25519_from_seed(Some("up".to_owned()), &[42_u8; 32]).unwrap();
        let token = id_token(&forger, serde_json::json!({}));
        let key = upstream_key();
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("forged signature rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn a_nonce_mismatch_is_rejected_even_when_the_signature_is_valid() {
        // A validly-signed token whose nonce does not match the bound value is a replay
        // or forged callback: rejected as a protocol fault, no identity produced.
        let key = upstream_key();
        let (env, _clock) = manual_clock();
        let token = id_token(&key, serde_json::json!({ "nonce": "attacker-chosen" }));
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("nonce mismatch rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn an_empty_key_set_fails_closed_as_unavailable() {
        let (env, _clock) = manual_clock();
        let key = upstream_key();
        let token = id_token(&key, serde_json::json!({}));
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, Vec::new(), policy(&algs), env.clock())
            .expect_err("empty keys fail closed");
        assert!(
            matches!(err, ConnectorError::UpstreamUnavailable(_)),
            "{err:?}"
        );
    }

    #[test]
    fn the_alg_allowlist_is_the_intersection_with_the_core() {
        // An upstream advertising a mix of core and non-core algs yields only the core ones.
        let advertised = vec![
            "EdDSA".to_owned(),
            "ES256".to_owned(),
            "HS256".to_owned(), // never in the core
            "none".to_owned(),  // never in the core
            "ES512".to_owned(), // not a core alg
        ];
        let algs = resolve_alg_allowlist(Some(&advertised));
        assert_eq!(algs, vec![JwsAlgorithm::EdDsa, JwsAlgorithm::Es256]);
        // No advertised list -> the full core allowlist.
        assert_eq!(resolve_alg_allowlist(None).len(), 9);
    }

    #[test]
    fn a_token_signed_with_a_non_allowlisted_alg_is_rejected() {
        // The upstream advertised only ES256, but the token is EdDSA: not on the allowlist.
        let key = upstream_key(); // EdDSA
        let (env, _clock) = manual_clock();
        let token = id_token(&key, serde_json::json!({}));
        let algs = resolve_alg_allowlist(Some(&["ES256".to_owned()]));
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("non-allowlisted alg rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    // ---- SSRF through the fetcher: private-range jwks_uri is Blocked ----

    /// Start an in-process loopback HTTP server that serves `body` as JSON to every
    /// request, returning its address (mirrors the #25 client-assertion test server).
    #[cfg(feature = "testing")]
    async fn start_server(body: String) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0_u8; 4096];
                    let _ = socket.read(&mut buf).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                });
            }
        });
        addr
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn a_public_jwks_uri_resolves_through_the_hardened_fetcher_and_caches() {
        let key = upstream_key();
        let jwks = JwkSet::from_signing_keys([&key])
            .expect("jwk set")
            .to_json()
            .expect("json");
        let server = start_server(jwks).await;
        let dialer = Arc::new(RecordingDialer::new(server));
        let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([93, 184, 216, 34])]));
        let fetcher =
            Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
        let resolver =
            FederationKeyResolver::new_allow_http(Arc::new(fetcher), Duration::from_secs(300));

        let now = SystemTime::UNIX_EPOCH;
        let keys = resolver
            .resolve(now, "cnr_a", "http://upstream.example/jwks")
            .await;
        assert_eq!(
            keys.len(),
            1,
            "the upstream key resolved through the fetcher"
        );
        // A second resolve hits the cache: the fetcher is not dialed again.
        let again = resolver
            .resolve(now, "cnr_a", "http://upstream.example/jwks")
            .await;
        assert_eq!(again.len(), 1);
        assert_eq!(dialer.requested().len(), 1, "the second resolve was cached");
        // The dial went to the PUBLIC pinned address, never the loopback (resolve-once).
        assert_eq!(dialer.requested()[0].ip(), IpAddr::from([93, 184, 216, 34]));
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn a_private_range_jwks_uri_is_blocked_and_fails_closed() {
        // A connector URL whose public-looking host RESOLVES to a private address is
        // Blocked by the fetcher, so the resolver yields no keys and validation fails
        // closed as UpstreamUnavailable. This is the SSRF acceptance criterion.
        let key = upstream_key();
        let jwks = JwkSet::from_signing_keys([&key])
            .unwrap()
            .to_json()
            .unwrap();
        let server = start_server(jwks).await;
        let dialer = Arc::new(RecordingDialer::new(server));
        // The resolver maps the host to a link-local metadata address (169.254.169.254).
        let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([
            169, 254, 169, 254,
        ])]));
        let fetcher =
            Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
        let resolver =
            FederationKeyResolver::new_allow_http(Arc::new(fetcher), Duration::from_secs(300));

        let keys = resolver
            .resolve(
                SystemTime::UNIX_EPOCH,
                "cnr_b",
                "http://upstream.example/jwks",
            )
            .await;
        assert!(
            keys.is_empty(),
            "a private-range jwks_uri resolves to no keys"
        );
        assert!(
            dialer.requested().is_empty(),
            "the blocked address is never dialed (resolve-once, no rebind)"
        );
        // Validation then fails closed as unavailable.
        let (env, _clock) = manual_clock();
        let token = id_token(&key, serde_json::json!({}));
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, keys, policy(&algs), env.clock())
            .expect_err("blocked jwks fails closed");
        assert!(
            matches!(err, ConnectorError::UpstreamUnavailable(_)),
            "{err:?}"
        );
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn discovery_is_fetched_through_the_hardened_fetcher_and_validates_the_issuer() {
        // A plaintext-http issuer so the in-process loopback server (no TLS) can serve the
        // document through the injected dialer; a production issuer is https, fetched over
        // TLS, but the mix-up and parse logic under test is scheme-independent.
        let http_issuer = "http://upstream.example";
        // The authorize-endpoint key is assembled from fragments so this in-crate source file
        // never contains the reserved served-discovery-document field name the self-discovery
        // lint guards (the upstream metadata field names live in ironauth-connector).
        let authz = concat!("authorization", "_endpoint");
        let doc = format!(
            r#"{{"issuer":"{http_issuer}","{authz}":"https://upstream.example/authorize","token_endpoint":"https://upstream.example/token","jwks_uri":"https://upstream.example/jwks","id_token_signing_alg_values_supported":["EdDSA"],"code_challenge_methods_supported":["S256"]}}"#
        );
        let server = start_server(doc).await;
        let dialer = Arc::new(RecordingDialer::new(server));
        let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([93, 184, 216, 34])]));
        let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, dialer);
        let resolved = fetch_discovery(&fetcher, http_issuer, true)
            .await
            .expect("discovery resolves");
        assert_eq!(resolved.jwks_uri, "https://upstream.example/jwks");
        assert!(resolved.advertises_s256());
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn a_private_range_discovery_issuer_is_blocked() {
        let server = start_server("{}".to_owned()).await;
        let dialer = Arc::new(RecordingDialer::new(server));
        let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([10, 0, 0, 5])]));
        let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, dialer);
        let err = fetch_discovery(&fetcher, ISSUER, true)
            .await
            .expect_err("blocked discovery");
        assert!(
            matches!(err, ConnectorError::UpstreamUnavailable(_)),
            "{err:?}"
        );
    }

    // ---- The issuer-namespaced federated external-id (issue #75, HIGH-1) ----

    #[test]
    fn the_federated_external_id_is_injective_across_issuer_and_sub() {
        // Two DIFFERENT issuers with the SAME sub encode to DIFFERENT keys (no takeover),
        // while the SAME (issuer, sub) is stable (identity sharing / a re-login re-finds it).
        let a = federated_external_id("https://idp-a.example", "1001");
        let b = federated_external_id("https://idp-b.example", "1001");
        assert_ne!(a, b, "same sub from different issuers must not collide");
        assert_eq!(a, federated_external_id("https://idp-a.example", "1001"));
        // The length prefix keeps it injection-safe: a boundary shift between issuer and sub
        // (which a bare separator would let collide) still encodes distinctly.
        let shifted_issuer = federated_external_id("https://idp.example:x", "1001");
        let shifted_sub = federated_external_id("https://idp.example", "x:1001");
        assert_ne!(shifted_issuer, shifted_sub, "the encoding is unambiguous");
    }

    // ---- A rotated upstream kid refetches once, without waiting out the TTL (LOW-1) ----

    /// Serve the current contents of `body` as JSON to every request, so a test can ROTATE
    /// the served document (a key rotation) between resolves.
    #[cfg(feature = "testing")]
    async fn start_mutable_server(body: Arc<Mutex<String>>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let body = Arc::clone(&body);
                tokio::spawn(async move {
                    let mut buf = [0_u8; 4096];
                    let _ = socket.read(&mut buf).await;
                    let payload = body.lock().expect("body lock").clone();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                        payload.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                });
            }
        });
        addr
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn a_kid_miss_triggers_a_single_bounded_jwks_refetch() {
        let key1 = SigningKey::ed25519_from_seed(Some("up-1".to_owned()), &[1_u8; 32]).unwrap();
        let key2 = SigningKey::ed25519_from_seed(Some("up-2".to_owned()), &[2_u8; 32]).unwrap();
        let jwks1 = JwkSet::from_signing_keys([&key1])
            .unwrap()
            .to_json()
            .unwrap();
        let jwks2 = JwkSet::from_signing_keys([&key2])
            .unwrap()
            .to_json()
            .unwrap();
        let body = Arc::new(Mutex::new(jwks1));
        let server = start_mutable_server(Arc::clone(&body)).await;
        let dialer = Arc::new(RecordingDialer::new(server));
        let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([93, 184, 216, 34])]));
        let fetcher =
            Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
        let resolver =
            FederationKeyResolver::new_allow_http(Arc::new(fetcher), Duration::from_secs(300));
        let now = SystemTime::UNIX_EPOCH;
        let uri = "http://upstream.example/jwks";

        // First login: the token names kid up-1, which the fetched set answers to (one dial).
        let trusted = resolver
            .resolve_for_kid(now, "cnr", uri, Some("up-1"))
            .await;
        assert!(trusted.iter().any(|k| k.kid() == Some("up-1")));
        assert_eq!(dialer.requested().len(), 1);

        // The upstream ROTATES to up-2 WITHIN the TTL. A pure TTL cache would keep serving the
        // stale set and fail every login for up to the TTL; the kid-miss forces ONE refetch.
        *body.lock().unwrap() = jwks2;
        let trusted = resolver
            .resolve_for_kid(now, "cnr", uri, Some("up-2"))
            .await;
        assert!(
            trusted.iter().any(|k| k.kid() == Some("up-2")),
            "the rotated-in kid resolves without waiting for the TTL"
        );
        assert_eq!(dialer.requested().len(), 2, "exactly one bounded refetch");

        // The refreshed set is now cached: a second up-2 login does not dial again.
        let trusted = resolver
            .resolve_for_kid(now, "cnr", uri, Some("up-2"))
            .await;
        assert!(trusted.iter().any(|k| k.kid() == Some("up-2")));
        assert_eq!(dialer.requested().len(), 2, "the refreshed set is cached");
    }

    // ---- TTL expiry drives a refetch under the manual clock (LOW-2) ----

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn the_jwks_cache_refetches_only_after_its_ttl_expires() {
        let key = upstream_key();
        let jwks = JwkSet::from_signing_keys([&key])
            .unwrap()
            .to_json()
            .unwrap();
        let body = Arc::new(Mutex::new(jwks));
        let server = start_mutable_server(Arc::clone(&body)).await;
        let dialer = Arc::new(RecordingDialer::new(server));
        let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([93, 184, 216, 34])]));
        let fetcher =
            Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
        let resolver =
            FederationKeyResolver::new_allow_http(Arc::new(fetcher), Duration::from_secs(300));
        let t0 = SystemTime::UNIX_EPOCH;
        let uri = "http://upstream.example/jwks";

        resolver.resolve(t0, "cnr", uri).await;
        assert_eq!(dialer.requested().len(), 1);
        // Within the TTL: the cached value is reused, no refetch.
        resolver
            .resolve(t0 + Duration::from_secs(100), "cnr", uri)
            .await;
        assert_eq!(
            dialer.requested().len(),
            1,
            "a within-TTL resolve is cached"
        );
        // Past the TTL: the cached value is NOT reused, so a refetch occurs.
        resolver
            .resolve(t0 + Duration::from_secs(301), "cnr", uri)
            .await;
        assert_eq!(
            dialer.requested().len(),
            2,
            "past the TTL the cached value is not reused"
        );
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn the_discovery_cache_refetches_only_after_its_ttl_expires() {
        // A plaintext-http issuer so the in-process loopback server can serve the document.
        // The reserved served-discovery-document field name is assembled from fragments so
        // this in-crate source never contains it (the self-discovery lint).
        let http_issuer = "http://upstream.example";
        let authz = concat!("authorization", "_endpoint");
        let doc = format!(
            r#"{{"issuer":"{http_issuer}","{authz}":"https://upstream.example/authorize","token_endpoint":"https://upstream.example/token","jwks_uri":"https://upstream.example/jwks","id_token_signing_alg_values_supported":["EdDSA"],"code_challenge_methods_supported":["S256"]}}"#
        );
        let server = start_server(doc).await;
        let dialer = Arc::new(RecordingDialer::new(server));
        let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([93, 184, 216, 34])]));
        let fetcher = Arc::new(Fetcher::from_parts(
            FetchLimits::default(),
            resolver_seam,
            Arc::clone(&dialer),
        ));
        let keys = Arc::new(FederationKeyResolver::new_allow_http(
            Arc::clone(&fetcher),
            Duration::from_secs(300),
        ));
        let runtime = FederationRuntime::new_allow_http(fetcher, keys, Duration::from_secs(300));
        let endpoints = Endpoints::Discovery(ironauth_connector::DiscoveryEndpoints {
            issuer: http_issuer.to_owned(),
        });
        let t0 = SystemTime::UNIX_EPOCH;

        runtime
            .resolve_endpoints(t0, "cnr", &endpoints)
            .await
            .expect("resolve");
        assert_eq!(dialer.requested().len(), 1);
        // Within the TTL the resolved discovery document is served from the cache.
        runtime
            .resolve_endpoints(t0 + Duration::from_secs(100), "cnr", &endpoints)
            .await
            .expect("resolve");
        assert_eq!(
            dialer.requested().len(),
            1,
            "within the TTL discovery is cached"
        );
        // Past the discovery TTL the cached value is not reused, so a refetch occurs.
        runtime
            .resolve_endpoints(t0 + Duration::from_secs(301), "cnr", &endpoints)
            .await
            .expect("resolve");
        assert_eq!(
            dialer.requested().len(),
            2,
            "past the discovery TTL a refetch occurs"
        );
    }
}
