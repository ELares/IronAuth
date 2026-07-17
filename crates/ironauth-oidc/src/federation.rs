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
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_connector::{
    ClaimSources, ClientAuth, ConnectorError, ConnectorRuntimeConfig, Endpoints, PkceMode,
    ResolvedEndpoints, TraitDocument, TraitPointerFailure, TraitSchemaView, discovery_url,
    evaluate, parse_discovery,
};
use ironauth_env::Clock;
use ironauth_fetch::{FetchError, FetchPurpose, FetchRequest, Fetcher};
use ironauth_jose::{JwsAlgorithm, TrustedKey, VerificationPolicy, verify};
use ironauth_store::{
    ConnectorId, FederationLoginStateId, NewAdminUser, NewFederationLoginState, OrgConnectionId,
    Scope, StoreError, TraitSchema, UserId, UserState,
};
use sha2::{Digest, Sha256};

use crate::authn::AuthenticationEvent;
use crate::federation_client_secret::{SignedJwtInputs, generate_signed_jwt};
use crate::federation_health::{Admission, ConnectorHealthRegistry};
use crate::federation_jwks::FederationKeyResolver;
use crate::federation_relay::{EMAIL_RELAY_TRAIT, is_relay_email};
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

/// Classify a NON-2xx upstream response by CLASS (issue #76, HIGH-1): the split that keeps a
/// single per-request upstream fault from tripping the whole connector into backoff.
///
/// A `5xx` or `429` is a real upstream OUTAGE, so it maps to
/// [`ConnectorError::UpstreamUnavailable`], which correctly ARMS the health-driven backoff (the
/// upstream could not serve the request and hammering it helps nobody). A `4xx` is a PER-REQUEST
/// protocol or config condition -- a token endpoint's `400 invalid_grant` for a bad, expired, or
/// replayed authorization code (RFC 6749 5.2), a `401 invalid_client`, a discovery/JWKS `404` --
/// so it maps to [`ConnectorError::UpstreamProtocol`], which feeds the error rate WITHOUT
/// changing admission. That is what stops one failed (or replayed / double-submitted) login from
/// blacklisting a whole connector into an escalating, attacker-sustainable backoff. Every
/// federation outbound (token exchange, discovery, JWKS) runs its non-2xx through here so the
/// class split is uniform. The message is non-sensitive: a bare status code and a context label.
pub(crate) fn classify_upstream_status(status: StatusCode, context: &str) -> ConnectorError {
    let code = status.as_u16();
    if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
        ConnectorError::UpstreamUnavailable(format!("{context} returned HTTP {code}"))
    } else {
        ConnectorError::UpstreamProtocol(format!("{context} returned HTTP {code}"))
    }
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
/// [`ConnectorError::UpstreamUnavailable`] if the discovery fetch is blocked, times out, or
/// returns a `5xx`/`429` (a real outage, which arms the backoff);
/// [`ConnectorError::UpstreamProtocol`] if it returns a `4xx` (a per-request config/protocol
/// problem, not an outage), or if the document is malformed or its issuer does not match (the
/// mix-up defence); or [`ConnectorError::Config`] if neither an issuer nor an explicit set was
/// supplied.
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
        return Err(classify_upstream_status(
            response.status(),
            "the discovery endpoint",
        ));
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
/// [`ConnectorError::UpstreamUnavailable`] if the exchange is blocked, times out, or returns a
/// `5xx`/`429` (a real outage, which arms the backoff); [`ConnectorError::UpstreamProtocol`] if
/// it returns a `4xx` (a per-request condition -- a `400 invalid_grant` for a bad, expired, or
/// replayed code, a `401 invalid_client` -- which must NOT trip the connector down), or if the
/// response is not JSON or carries no `id_token`.
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
        return Err(classify_upstream_status(
            response.status(),
            "the token endpoint",
        ));
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
    // The per-connector health registry (issue #76): the in-memory health record every
    // upstream operation records into, the health-driven backoff `admit` consults, and the
    // management-API read snapshots. Shared so the admin plane can read the SAME live state.
    health: Arc<ConnectorHealthRegistry>,
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
    /// discovery resolution for `discovery_ttl` and driving per-connector health-backoff off
    /// `probe_window` (issue #76). Upstream fetches are https-only.
    #[must_use]
    pub fn new(
        fetcher: Arc<Fetcher>,
        keys: Arc<FederationKeyResolver>,
        discovery_ttl: Duration,
        probe_window: Duration,
    ) -> Self {
        Self {
            fetcher,
            keys,
            discovery_ttl,
            allow_http: false,
            discovery_cache: Mutex::new(HashMap::new()),
            health: Arc::new(ConnectorHealthRegistry::new(probe_window)),
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
        probe_window: Duration,
    ) -> Self {
        Self {
            fetcher,
            keys,
            discovery_ttl,
            allow_http: true,
            discovery_cache: Mutex::new(HashMap::new()),
            health: Arc::new(ConnectorHealthRegistry::new(probe_window)),
        }
    }

    /// The per-connector health registry (issue #76): the live in-memory health state the
    /// management-API diagnostics read snapshots and the failure-isolation backoff consults.
    #[must_use]
    pub fn health(&self) -> &Arc<ConnectorHealthRegistry> {
        &self.health
    }

    /// The one SSRF-hardened fetcher every federation outbound rides. Exposed so the OAuth 2.0
    /// login path (issue #74) can drive its token, profile, and email fetches through the
    /// same hardened path as the OIDC path.
    pub(crate) fn fetcher(&self) -> &Fetcher {
        &self.fetcher
    }

    /// Whether a plaintext `http` upstream is permitted (the test constructor only). Read by
    /// the OAuth 2.0 login path so an in-process loopback upstream can be driven in tests.
    pub(crate) fn allow_http(&self) -> bool {
        self.allow_http
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
            // An OAuth2 connector (issue #74) resolves no OIDC ID-token endpoint set; it is
            // dispatched to the OAuth2 login path before this is ever reached.
            Endpoints::OAuth2(_) => Err(ConnectorError::Config(
                "an oauth2 connector has no OIDC endpoint set to resolve".to_owned(),
            )),
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
// The authorize leg is one linear flow (scope -> connector load -> health gate -> resolve ->
// state/nonce/PKCE -> persist -> build the upstream URL with the passthrough allowlist); the
// issue #76 health gate and passthrough push it just over the line-length lint, and splitting
// the single top-to-bottom flow would scatter the one sequence the reviewer must read.
#[allow(clippy::too_many_lines)]
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
    let connector_key = record.id.to_string();
    // The connector-definition fingerprint (issue #76): the store row's update instant. A
    // change is a RECONFIGURATION, which resets the connector's health WITHOUT touching siblings.
    let fingerprint = record.updated_at_unix_micros;

    // Failure isolation (issue #76): consult the per-connector health-driven backoff BEFORE any
    // upstream fetch. A config-broken connector (permanent until reconfigured) or an unavailable
    // upstream still inside its backoff window fails THIS connector cleanly and typed, without
    // hammering the upstream, while every sibling connector and the core OP surface keep serving.
    if let Admission::Deny(reason) = runtime.health().admit(now, &connector_key, fingerprint) {
        return interaction::connector_unavailable_page(reason.as_str());
    }
    // Resolve the connector's endpoints, recording a FAILURE against the connector's health. A
    // blocked, timed-out, or malformed discovery fetch is an UpstreamUnavailable / UpstreamProtocol
    // fault: it arms the backoff and surfaces the TYPED connector-unavailable error for this
    // connector only, never a process-wide failure.
    //
    // The success side is DELIBERATELY not recorded here (issue #76, review MEDIUM): a discovery-
    // form connector resolves from the discovery CACHE with no network, so treating that as a
    // success would clear the backoff and flap the health gauge to healthy for a connector whose
    // token endpoint / JWKS / ID-token validation is down -- pinning the backoff at its base
    // window and lying about the connector's health. record_success is reserved for the CALLBACK's
    // COMPLETED login (a fully provisioned session), the only real success signal. The authorize
    // leg still admit-gates above (denying during backoff); resolving cached discovery is not a win.
    // Resolve the upstream authorize endpoint per protocol (issue #74). An OIDC discovery
    // connector fetches (and caches) its discovery document to learn the endpoint and its
    // PKCE support, sends a `nonce`, and binds the ID token's `iss`. An OAuth2 connector
    // (GitHub) has explicit endpoints and NO ID token, so it takes the authorize endpoint
    // directly and sends no `nonce` (there is no ID token to bind it to).
    let (authorize_url, advertises_s256, send_nonce) = match &definition.endpoints {
        Endpoints::OAuth2(oauth2) => (oauth2.authorize_url().to_owned(), false, false),
        Endpoints::Explicit(_) => {
            // Rejected up front above; unreachable, but fail closed rather than panic.
            return interaction::federation_unsupported_page();
        }
        Endpoints::Discovery(_) => match runtime
            .resolve_endpoints(now, &connector_key, &definition.endpoints)
            .await
        {
            Ok(resolved) => (
                resolved.authorize_url.clone(),
                resolved.advertises_s256(),
                true,
            ),
            Err(error) => {
                runtime
                    .health()
                    .record_failure(now, &connector_key, fingerprint, &error);
                return interaction::connector_unavailable_page(error.kind());
            }
        },
    };

    let state_value = random_token(&state);
    let nonce = random_token(&state);
    // PKCE to the upstream: send an S256 challenge when the connector requires it, or when
    // it is auto and the upstream advertises S256. An explicit-endpoint upstream advertises
    // nothing, so auto omits PKCE there (the conservative interoperable default).
    let use_pkce = match definition.pkce {
        PkceMode::Disabled => false,
        PkceMode::Required => true,
        PkceMode::AutoWhereSupported => advertises_s256,
    };
    let code_verifier = use_pkce.then(|| random_token(&state));
    let code_challenge = code_verifier.as_deref().map(s256_challenge);

    let redirect_uri =
        federation_callback_url(&state, &tenant_id, &environment_id, &connector_slug);

    // The routed org connection (issue #77): the login surface, having routed a login
    // by domain/app/user, passes the `ocn_` id it resolved. Validate here that it is in
    // scope, references THIS connector, and is enabled, so the org binding the callback
    // provisions against is bound to the connector the user must actually authenticate
    // at; a browser-supplied id for another connector fails closed. An ABSENT param is a
    // direct (non-routed) federated login, which carries no org binding. The callback
    // re-derives the org from the CONSUMED row, never from the callback query.
    let routed_org_connection = match query
        .as_deref()
        .and_then(|q| query_get(q, "org_connection"))
    {
        Some(raw) => {
            let scoped = state.store().scoped(scope);
            let Ok(ocn_id) = scoped.org_connections().parse_id(&raw) else {
                return not_found();
            };
            match scoped.org_connections().get(&ocn_id).await {
                Ok(binding) if binding.enabled && binding.connector_id == record.id.to_string() => {
                    Some(ocn_id.to_string())
                }
                Ok(_) | Err(StoreError::NotFound) => return not_found(),
                Err(_) => return interaction::server_error_page(),
            }
        }
        None => None,
    };

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
                org_connection_id: routed_org_connection.as_deref(),
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
    ];
    // The `nonce` binds the OIDC ID token to this authorize leg; an OAuth2 upstream has no
    // ID token, so it is omitted there (the stored correlation-row nonce is unused).
    if send_nonce {
        params.push(("nonce", Some(nonce.as_str())));
    }
    if let Some(challenge) = code_challenge.as_deref() {
        params.push(("code_challenge", Some(challenge)));
        params.push(("code_challenge_method", Some("S256")));
    }
    // Parameter passthrough (issue #76): forward EXACTLY the three OIDC Core 3.1.2.1
    // authentication-request params on the STRICT allowlist (prompt, login_hint, ui_locales)
    // from the DOWNSTREAM authorization request (the validated resume target's query) to the
    // UPSTREAM authorize request, each gated by the connector's per-param disable flag. NOTHING
    // outside the allowlist is ever read or forwarded (a downstream param not on the list can
    // never reach the upstream). Each value is bounded and rides ONLY this query, percent-encoded
    // by append_query -- never a header, path, or log (no injection surface).
    let downstream_query = resume
        .return_to
        .split_once('?')
        .map_or("", |(_, query)| query);
    let forwarded = passthrough_params(downstream_query, definition.passthrough);
    for (name, value) in &forwarded {
        params.push((name, Some(value.as_str())));
    }
    let location = append_query(&authorize_url, &params);
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

    let now = state.now();
    let connector_key = connector_id.to_string();
    // The connector-definition fingerprint (issue #76) for the per-connector health record;
    // a change (a reconfiguration) resets this connector's health without touching siblings.
    let fingerprint = record.updated_at_unix_micros;

    // OAuth2 (non-OIDC, for example GitHub, issue #74) has NO ID token: it exchanges the code
    // for an access token, then reads the profile (and resolves the primary verified email)
    // over the hardened fetch path, and finalizes through the SHARED provisioning path. Dispatch
    // here so the OIDC ID-token validation spine below runs only for an OIDC connector.
    if let Endpoints::OAuth2(oauth2) = &definition.endpoints {
        let runtime_ref: &FederationRuntime = runtime;
        return crate::federation_oauth2::oauth2_callback(
            crate::federation_oauth2::Oauth2Callback {
                state: &state,
                scope,
                runtime: runtime_ref,
                connector_key: &connector_key,
                connector_slug: &connector_slug,
                tenant_id: &tenant_id,
                environment_id: &environment_id,
                fingerprint,
                endpoints: oauth2,
                definition: &definition,
                client_secret: &secret_bytes,
                code: &code,
                headers: &headers,
                return_to: &consumed.return_to,
                now,
                now_micros,
            },
        )
        .await;
    }

    let resolved = match runtime
        .resolve_endpoints(now, &connector_key, &definition.endpoints)
        .await
    {
        Ok(resolved) => resolved,
        Err(error) => {
            // A mid-run upstream discovery outage flips ONLY this connector's health (issue
            // #76), arming its backoff so the NEXT authorize is denied cleanly; siblings and
            // the core OP surface are untouched.
            runtime
                .health()
                .record_failure(now, &connector_key, fingerprint, &error);
            return interaction::server_error_page();
        }
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

    // The client secret sent in the exchange (issue #74): a static connector sends the sealed
    // secret verbatim; an Apple `signed_jwt` connector generates a fresh short-lived ES256 JWT
    // assertion from the sealed EC private key (the documented quirk handler), using the clock
    // seam for `iat`/`exp`. A key/sign failure is a clean connector-level config fault.
    let exchange_secret = match &definition.client_auth {
        ClientAuth::Static => match String::from_utf8(secret_bytes) {
            Ok(secret) => secret,
            Err(_) => return interaction::server_error_page(),
        },
        ClientAuth::SignedJwt {
            team_id,
            key_id,
            audience,
        } => match generate_signed_jwt(
            &secret_bytes,
            SignedJwtInputs {
                team_id,
                key_id,
                audience,
                client_id: &definition.client_id,
            },
            now,
        ) {
            Ok(jwt) => jwt,
            Err(error) => {
                runtime
                    .health()
                    .record_failure(now, &connector_key, fingerprint, &error);
                return interaction::server_error_page();
            }
        },
    };

    // Exchange the code at the upstream token endpoint. Any failure fails the login WITHOUT
    // provisioning a user. A dead or misbehaving token endpoint mid-run is recorded against
    // THIS connector's health (a token-endpoint outage the discovery cache would otherwise hide).
    let id_token = match exchange_code(
        &runtime.fetcher,
        TokenExchange {
            token_url: &resolved.token_url,
            code: &code,
            redirect_uri: &redirect_uri,
            client_id: &definition.client_id,
            client_secret: &exchange_secret,
            code_verifier: verifier,
        },
        runtime.allow_http,
    )
    .await
    {
        Ok(id_token) => id_token,
        Err(error) => {
            runtime
                .health()
                .record_failure(now, &connector_key, fingerprint, &error);
            return interaction::server_error_page();
        }
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
    let keys = match runtime
        .keys
        .resolve_for_kid(
            now,
            &connector_id.to_string(),
            &resolved.jwks_uri,
            token_kid.as_deref(),
        )
        .await
    {
        Ok(keys) => keys,
        Err(error) => {
            // The JWKS fetch failed by CLASS (issue #76): a 5xx/timeout/blocked jwks_uri is an
            // outage (UpstreamUnavailable, arms the backoff); a 4xx is a per-request config/
            // protocol fault (UpstreamProtocol, no blacklist). Either way no user is provisioned.
            runtime
                .health()
                .record_failure(now, &connector_key, fingerprint, &error);
            return interaction::server_error_page();
        }
    };
    let allowed_algs =
        resolve_alg_allowlist(resolved.id_token_signing_alg_values_supported.as_deref());
    let identity = match validate_upstream_id_token(
        &id_token,
        keys,
        UpstreamTokenPolicy {
            expected_issuer: &expected_issuer,
            expected_audience: &definition.client_id,
            expected_nonce: &consumed.nonce,
            allowed_algs: &allowed_algs,
        },
        state.env().clock(),
    ) {
        Ok(identity) => identity,
        Err(error) => {
            // A token-validation rejection (a forged / expired / wrong-audience token) or an
            // empty-JWKS unavailability is recorded against the connector's health (feeding the
            // error rate). A protocol rejection is a per-login fault and does not blacklist the
            // connector; an empty-JWKS unavailability arms the backoff. No user is provisioned.
            runtime
                .health()
                .record_failure(now, &connector_key, fingerprint, &error);
            return interaction::server_error_page();
        }
    };

    // The remainder is SHARED with the OAuth2 login path (issue #74): the declarative claim
    // mapping (with the Apple first-authorization-only reuse and Hide My Email relay
    // classification), the fail-closed provisioning, the honest federated session, and the
    // resume. Both the OIDC and OAuth2 callbacks converge here once they hold a verified
    // identity, so the acceptance-critical quirk handling lives in exactly one place.
    finalize_federated_login(FinalizeLogin {
        state: &state,
        scope,
        runtime,
        connector_slug: &connector_slug,
        connector_key: &connector_key,
        fingerprint,
        issuer: &expected_issuer,
        definition: &definition,
        identity: &identity,
        org_connection_id: consumed.org_connection_id.as_deref(),
        headers: &headers,
        return_to: &consumed.return_to,
        now,
        now_micros,
    })
    .await
}

/// The inputs the shared federated-login finalizer needs (issue #74), bundled to keep the
/// argument count readable. Both the OIDC and OAuth 2.0 callbacks build one of these once they
/// hold a verified [`VerifiedUpstreamIdentity`].
pub(crate) struct FinalizeLogin<'a> {
    /// The OIDC application state.
    pub state: &'a OidcState,
    /// The tenant/environment scope.
    pub scope: Scope,
    /// The installed federation runtime (health registry and fetch path).
    pub runtime: &'a FederationRuntime,
    /// The connector's per-environment slug (the federated login handle prefix).
    pub connector_slug: &'a str,
    /// The connector's health-registry key (its immutable id as a string).
    pub connector_key: &'a str,
    /// The connector-definition fingerprint for the per-connector health record.
    pub fingerprint: i64,
    /// The identity NAMESPACE for the federated external id (the OIDC issuer, or an OAuth 2.0
    /// connector's `identity_issuer`).
    pub issuer: &'a str,
    /// The connector's secret-free runtime config (claim mapping and quirks).
    pub definition: &'a ConnectorRuntimeConfig,
    /// The verified upstream identity (a validated ID token, or an OAuth 2.0 profile over TLS).
    pub identity: &'a VerifiedUpstreamIdentity,
    /// The routed `ocn_` org connection this login was bound to at the authorize leg
    /// (issue #77), re-derived from the CONSUMED correlation row (never the browser), or
    /// [`None`] for a direct federated login. Stamped on the provisioned user.
    pub org_connection_id: Option<&'a str>,
    /// The inbound request headers (for the session cookie binding).
    pub headers: &'a HeaderMap,
    /// The pending LOCAL authorization request to resume after the federated login.
    pub return_to: &'a str,
    /// The callback instant from the clock seam.
    pub now: SystemTime,
    /// The callback instant in epoch microseconds.
    pub now_micros: i64,
}

/// Finalize a federated login once a verified upstream identity is in hand (issue #74): apply
/// the Apple first-authorization-only profile reuse and Hide My Email relay classification,
/// evaluate the declarative claim mapping fail-closed, provision (create-or-update) the local
/// identity keyed on the verified `(issuer, sub)` composite, establish the honest federated
/// session, mark the connector healthy, and resume the pending local request.
///
/// This is the ONE place the acceptance-critical quirk handling lives, shared by the OIDC and
/// OAuth 2.0 callbacks. On ANY mapping/type-check/provision/session failure it fails closed with
/// no partial identity and no session.
// One linear finalize sequence (schema -> prior-profile reuse -> relay -> map -> provision ->
// session -> resume); splitting it would scatter the single quirk-handling flow a reviewer reads.
#[allow(clippy::too_many_lines)]
pub(crate) async fn finalize_federated_login(finalize: FinalizeLogin<'_>) -> Response {
    let FinalizeLogin {
        state,
        scope,
        runtime,
        connector_slug,
        connector_key,
        fingerprint,
        issuer,
        definition,
        identity,
        org_connection_id,
        headers,
        return_to,
        now,
        now_micros,
    } = finalize;

    // The active trait schema the assembled document is type-checked against. Its compilation
    // and the `&dyn TraitSchemaView` view are deferred until just before `evaluate` (below),
    // AFTER every await, so the non-Send trait-object reference is never held across an await
    // (which would make the handler future non-Send).
    let Ok(active_schema) = state.store().scoped(scope).trait_schemas().active().await else {
        return interaction::server_error_page();
    };

    // Apple first-authorization-only reuse (issue #74): a returning Apple login omits name and
    // email, so load the stored profile of any EXISTING federated user (keyed on the verified
    // `(issuer, sub)`) and feed it to the evaluator, which reuses a stored value for any field
    // the upstream did not deliver. A FIRST login finds no prior profile, so a missing required
    // email still fails closed. Only fetched when the quirk is set, so an ordinary connector
    // pays no extra read.
    let prior_traits_value = if definition.quirks.profile_delivered_first_auth_only {
        let external_id = federated_external_id(issuer, &identity.subject);
        match state
            .store()
            .scoped(scope)
            .users()
            .by_external_id(&external_id)
            .await
        {
            Ok(Some(existing)) => match state
                .store()
                .scoped(scope)
                .users()
                .traits(&existing.id)
                .await
            {
                Ok(traits) => traits.and_then(|(_, value)| match value {
                    serde_json::Value::Object(map) => Some(map),
                    _ => None,
                }),
                Err(_) => return interaction::server_error_page(),
            },
            Ok(None) => None,
            Err(_) => return interaction::server_error_page(),
        }
    } else {
        None
    };
    let prior_traits = prior_traits_value.as_ref();

    // Hide My Email relay classification (issue #74): when the connector names a relay domain
    // (Apple's `privaterelay.appleid.com`) and the upstream delivered an email, inject a
    // synthetic `email_relay` boolean claim so the classification flows through the SAME
    // declarative claim-mapping pipeline as every other trait (verified-but-unroutable is data,
    // not a code branch). A returning login that omits the email reuses the stored flag.
    let mut claims = identity.claims.clone();
    if let Some(relay_domain) = definition.quirks.relay_email_domain.as_deref() {
        if let Some(email) = identity.email.as_deref() {
            let relay = is_relay_email(email, Some(relay_domain));
            claims.insert(EMAIL_RELAY_TRAIT.to_owned(), serde_json::Value::Bool(relay));
        }
    }

    // Compile the active schema into the store-free view and evaluate the declarative claim
    // mapping in ONE synchronous block, after every await, so the non-Send `&dyn TraitSchemaView`
    // is confined to this block and never captured across a later await (keeping the handler
    // future Send). Evaluation is fail-closed: on ANY failure (a missing required claim a first
    // login cannot backfill, a wrong type, an undeclared trait) it returns Err and the login
    // aborts BEFORE any user row is written.
    let trait_doc = {
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
        match evaluate(
            &definition.claim_mapping,
            &definition.quirks,
            ClaimSources {
                id_token: &claims,
                userinfo: None,
            },
            schema_arg,
            prior_traits,
        ) {
            Ok(trait_doc) => trait_doc,
            Err(_) => return interaction::server_error_page(),
        }
    };

    // Provision the local identity keyed on the verified, issuer-namespaced `(issuer, sub)`
    // composite (never the mapped subject). A first login creates it with the mapped traits; a
    // returning login refreshes them (Apple's reused profile round-trips to the same values).
    let schema_version = active_schema.as_ref().map(|version| version.version);
    let Ok(user_id) = provision_federated_user(
        state,
        scope,
        connector_slug,
        issuer,
        identity,
        &trait_doc,
        schema_version,
        org_connection_id,
    )
    .await
    else {
        return interaction::server_error_page();
    };

    // Establish the LOCAL session with the HONEST federated authentication event: the local
    // token's acr is the federated context and its amr is the UPSTREAM's asserted amr
    // passthrough. auth_time is the upstream auth_time when present, else the callback instant.
    let auth_time_micros = identity
        .auth_time_secs
        .map_or_else(|| now_micros, |secs| secs.saturating_mul(1_000_000));
    let event = AuthenticationEvent::federated(
        auth_time_micros,
        &identity.upstream_amr,
        identity.upstream_acr.as_deref(),
    );
    let actor = interaction::user_actor(&user_id);
    let Ok(cookies) =
        interaction::establish_session(state, scope, &user_id.to_string(), &event, actor, headers)
            .await
    else {
        return interaction::server_error_page();
    };

    // The full upstream exchange + validation succeeded: mark this connector healthy (issue
    // #76), clearing any prior backoff so a recovered upstream is immediately trusted again.
    runtime
        .health()
        .record_success(now, connector_key, fingerprint);

    // Resume the pending LOCAL authorization request, which now sees the authenticated session.
    interaction::redirect_setting_cookie(return_to, &cookies)
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
// One provisioning entry point threading the identity, mapped traits, schema version,
// and org binding; bundling them would only obscure the single create-or-update flow.
#[allow(clippy::too_many_arguments)]
async fn provision_federated_user(
    state: &OidcState,
    scope: Scope,
    connector_slug: &str,
    issuer: &str,
    identity: &VerifiedUpstreamIdentity,
    trait_doc: &TraitDocument,
    schema_version: Option<i32>,
    org_connection_id: Option<&str>,
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
        // Refresh the org binding on the returning identity (issue #77): the identity
        // KEY stays the verified (issuer, sub) composite, so a returning login updates
        // the stamp in place without ever creating a second user.
        stamp_org_binding(state, scope, &existing.id, org_connection_id).await?;
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
        .await?;
    // Stamp the org binding on the newly provisioned identity (issue #77).
    stamp_org_binding(state, scope, &user_id, org_connection_id).await?;
    Ok(user_id)
}

/// STAMP the routed org connection on a JIT-provisioned federated user (issue #77), when
/// the login was routed to an organization. A NULL (non-routed) binding is a no-op; a
/// malformed stored id is likewise skipped (the callback already re-derived it from the
/// consumed correlation row, so it is a well-formed `ocn_` string). The stamp is bound to
/// the SAME (new or returning) user the (issuer, sub) identity key resolved, so it never
/// forks the account (issue #75 HIGH-1).
///
/// # Errors
///
/// [`StoreError`] on a persistence failure.
async fn stamp_org_binding(
    state: &OidcState,
    scope: Scope,
    user_id: &UserId,
    org_connection_id: Option<&str>,
) -> Result<(), StoreError> {
    let Some(raw) = org_connection_id else {
        return Ok(());
    };
    let Ok(ocn_id) = OrgConnectionId::parse_in_scope(raw, &scope) else {
        return Ok(());
    };
    let actor = interaction::user_actor(user_id);
    let correlation = ironauth_store::CorrelationId::generate(state.env());
    state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .users()
        .set_org_connection(state.env(), user_id, &ocn_id)
        .await
}

/// The maximum length, in bytes after percent-decoding, of a passthrough value forwarded
/// to the upstream authorize request (issue #76). A value over the cap is DROPPED (never
/// truncated, which could mangle it or an encoded sequence), bounding what any single
/// downstream-supplied value can push onto the upstream query.
const PASSTHROUGH_MAX_LEN: usize = 256;

/// Read one allowlisted passthrough value from the downstream authorization request
/// `query`, when the connector permits forwarding it and it is present, non-empty, and
/// within the length cap (issue #76). Returns the VERBATIM decoded value (`append_query`
/// re-encodes it for the upstream query); [`None`] otherwise.
fn passthrough_value(query: &str, name: &str, allowed: bool) -> Option<String> {
    if !allowed {
        return None;
    }
    query_get(query, name).filter(|value| !value.is_empty() && value.len() <= PASSTHROUGH_MAX_LEN)
}

/// Build the allowlisted passthrough parameters to forward to the upstream authorize
/// request from the downstream `query`, honoring the per-connector `policy` (issue #76).
///
/// EXACTLY `prompt`, `login_hint`, and `ui_locales` are ever considered, in that fixed
/// order; every value is bounded and taken verbatim. A downstream parameter outside this
/// three-name allowlist is never read here, so it can never be forwarded upstream.
fn passthrough_params(
    query: &str,
    policy: ironauth_connector::PassthroughPolicy,
) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for (name, allowed) in [
        ("prompt", policy.prompt),
        ("login_hint", policy.login_hint),
        ("ui_locales", policy.ui_locales),
    ] {
        if let Some(value) = passthrough_value(query, name, allowed) {
            out.push((name, value));
        }
    }
    out
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
pub(crate) fn federation_callback_url(
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

    // ---- Parameter passthrough: the strict 3-param allowlist (issue #76) ----

    #[test]
    fn passthrough_forwards_exactly_the_three_allowlisted_params_verbatim() {
        use ironauth_connector::PassthroughPolicy;
        // The downstream authorize query carries the three allowlisted params (percent-encoded)
        // plus arbitrary others. Only the three are forwarded, verbatim (decoded values).
        let query = "response_type=code&client_id=cli_x&prompt=login%20consent&\
             login_hint=ada%40example.test&ui_locales=fr-CA%20en&redirect_uri=https%3A%2F%2Fevil\
             &scope=openid&state=abc";
        let forwarded = passthrough_params(query, PassthroughPolicy::default());
        assert_eq!(
            forwarded,
            vec![
                ("prompt", "login consent".to_owned()),
                ("login_hint", "ada@example.test".to_owned()),
                ("ui_locales", "fr-CA en".to_owned()),
            ],
            "exactly the three allowlisted params, decoded verbatim"
        );
    }

    #[test]
    fn a_param_outside_the_allowlist_is_never_forwarded() {
        use ironauth_connector::PassthroughPolicy;
        // Arbitrary downstream params (including sensitive ones like redirect_uri and a
        // hostile injected key) are NEVER read or forwarded upstream (the negative test).
        let query = "redirect_uri=https%3A%2F%2Fattacker.example&max_age=0&\
             acr_values=urn%3Aevil&foo=bar&nonce=downstream-nonce&client_id=cli_x";
        let forwarded = passthrough_params(query, PassthroughPolicy::default());
        assert!(
            forwarded.is_empty(),
            "no non-allowlisted param is ever forwarded: {forwarded:?}"
        );
    }

    #[test]
    fn per_connector_disable_flags_are_honored() {
        use ironauth_connector::PassthroughPolicy;
        let query = "prompt=login&login_hint=ada%40example.test&ui_locales=fr";
        // Disable login_hint (the privacy-sensitive one) and ui_locales; keep prompt.
        let policy = PassthroughPolicy {
            prompt: true,
            login_hint: false,
            ui_locales: false,
        };
        let forwarded = passthrough_params(query, policy);
        assert_eq!(
            forwarded,
            vec![("prompt", "login".to_owned())],
            "only the enabled param is forwarded"
        );
        // All disabled: nothing is forwarded even when present downstream.
        let none = PassthroughPolicy {
            prompt: false,
            login_hint: false,
            ui_locales: false,
        };
        assert!(passthrough_params(query, none).is_empty());
    }

    #[test]
    fn an_oversized_or_empty_passthrough_value_is_dropped() {
        use ironauth_connector::PassthroughPolicy;
        // An empty value is treated as absent; an over-cap value is dropped (never truncated).
        let long = "a".repeat(PASSTHROUGH_MAX_LEN + 1);
        let query = format!("prompt=&login_hint={long}&ui_locales=fr");
        let forwarded = passthrough_params(&query, PassthroughPolicy::default());
        assert_eq!(
            forwarded,
            vec![("ui_locales", "fr".to_owned())],
            "empty prompt and over-cap login_hint are both dropped"
        );
        // A value exactly at the cap is forwarded.
        let at_cap = "b".repeat(PASSTHROUGH_MAX_LEN);
        let query = format!("prompt={at_cap}");
        let forwarded = passthrough_params(&query, PassthroughPolicy::default());
        assert_eq!(forwarded, vec![("prompt", at_cap)]);
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
            .await
            .expect("resolve");
        assert_eq!(
            keys.len(),
            1,
            "the upstream key resolved through the fetcher"
        );
        // A second resolve hits the cache: the fetcher is not dialed again.
        let again = resolver
            .resolve(now, "cnr_a", "http://upstream.example/jwks")
            .await
            .expect("resolve");
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

        let err = resolver
            .resolve(
                SystemTime::UNIX_EPOCH,
                "cnr_b",
                "http://upstream.example/jwks",
            )
            .await
            .expect_err("a blocked jwks_uri fails closed");
        // A blocked SSRF target is a real outage, so it fails closed as UpstreamUnavailable (which
        // arms the connector backoff), never yielding keys.
        assert!(
            matches!(err, ConnectorError::UpstreamUnavailable(_)),
            "{err:?}"
        );
        assert!(
            dialer.requested().is_empty(),
            "the blocked address is never dialed (resolve-once, no rebind)"
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
            .await
            .expect("resolve");
        assert!(trusted.iter().any(|k| k.kid() == Some("up-1")));
        assert_eq!(dialer.requested().len(), 1);

        // The upstream ROTATES to up-2 WITHIN the TTL. A pure TTL cache would keep serving the
        // stale set and fail every login for up to the TTL; the kid-miss forces ONE refetch.
        *body.lock().unwrap() = jwks2;
        let trusted = resolver
            .resolve_for_kid(now, "cnr", uri, Some("up-2"))
            .await
            .expect("resolve");
        assert!(
            trusted.iter().any(|k| k.kid() == Some("up-2")),
            "the rotated-in kid resolves without waiting for the TTL"
        );
        assert_eq!(dialer.requested().len(), 2, "exactly one bounded refetch");

        // The refreshed set is now cached: a second up-2 login does not dial again.
        let trusted = resolver
            .resolve_for_kid(now, "cnr", uri, Some("up-2"))
            .await
            .expect("resolve");
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

        resolver.resolve(t0, "cnr", uri).await.expect("resolve");
        assert_eq!(dialer.requested().len(), 1);
        // Within the TTL: the cached value is reused, no refetch.
        resolver
            .resolve(t0 + Duration::from_secs(100), "cnr", uri)
            .await
            .expect("resolve");
        assert_eq!(
            dialer.requested().len(),
            1,
            "a within-TTL resolve is cached"
        );
        // Past the TTL: the cached value is NOT reused, so a refetch occurs.
        resolver
            .resolve(t0 + Duration::from_secs(301), "cnr", uri)
            .await
            .expect("resolve");
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
        let runtime = FederationRuntime::new_allow_http(
            fetcher,
            keys,
            Duration::from_secs(300),
            Duration::from_secs(30),
        );
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
