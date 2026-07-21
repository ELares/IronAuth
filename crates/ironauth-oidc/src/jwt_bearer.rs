// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 7521 4.1 / RFC 7523 2.1 JWT bearer assertion grant
//! (`urn:ietf:params:oauth:grant-type:jwt-bearer`, issue #26).
//!
//! An assertion signed by a REGISTERED external issuer is exchanged for a
//! short-lived access token issued under a REGISTERED mapped IronAuth identity.
//! This is the substrate under workload identity federation (M13): SPIRE JWT-SVIDs,
//! Kubernetes projected tokens, and GitHub Actions OIDC exchanging for IronAuth
//! tokens with zero stored secrets.
//!
//! # The exchange
//!
//! 1. Read the RFC 7521 `assertion` (the external JWT). It is REQUIRED.
//! 2. Identify and authenticate the PRESENTING OAuth client. The client declares
//!    the `(tenant, environment)` scope (a `cli_` id embeds it, exactly as the
//!    client-credentials grant recovers scope), is authenticated through the ONE
//!    shared [`crate::client_auth::authenticate_client`] seam, and its id becomes
//!    the issued token's audience. A confidential client's authentication failure
//!    is the spec-exact `invalid_client`, INDEPENDENT of the assertion; a public
//!    (`none`) client is permitted, because the assertion (not the client secret)
//!    is the authorization grant.
//! 3. Validate the assertion (RFC 7523 3) against the trusted external issuer's
//!    keys THROUGH the same allowlist JOSE [`verify`] path #8/#25 use (`EdDSA` +
//!    ES256/384 + RS256/384/512 + PS256/384/512; ES512 is unrepresentable and thus
//!    rejected), NEVER the assertion's own `alg` header: require `iss`/`sub`/`aud`/
//!    `exp`, enforce the clock-skew bounds via `env.clock()`, and (when the
//!    assertion carries one) spend a single-use `jti`.
//! 4. Map the verified `(external issuer + sub, plus an optional claim gate)` to a
//!    REGISTERED IronAuth principal. An unmapped subject is REJECTED, never
//!    auto-provisioned.
//! 5. Mint a SHORT-LIVED access token under the mapped principal (its `sub`),
//!    audienced to the presenting client (the #29 `resolve_access_token_target`
//!    seam with no resource, an empty resource set), through the SAME signing core
//!    and grant chain the other grants use, so it is revocable and introspectable by
//!    construction.
//!    NO refresh token is issued (RFC 7521 4.1: re-present the assertion instead).
//!
//! # What is REUSED from the client authentication suite (#25)
//!
//! - **The audience policy knob.** The set of audiences an assertion may be
//!   addressed to comes from the ONE [`OidcState::client_assertion_audiences`]
//!   (issuer-or-token-endpoint by default, issuer-only under the strict switch), so
//!   a FAPI-shaped deployment flips ONE config switch for both client assertions
//!   and this grant. The clock-skew bound is the same
//!   [`OidcState::client_assertion_skew`].
//! - **The JOSE verify matrix.** The exact [`crate::client_auth::ASYMMETRIC_ALGS`]
//!   allowlist, so a client assertion and an external-issuer assertion accept
//!   identical algorithms and never trust a token's own `alg` header.
//! - **The `jwks_uri` fetch path.** A registered issuer's `jwks_uri` resolves through
//!   the SAME SSRF-hardened [`crate::client_keys::ClientKeyResolver`] a
//!   `private_key_jwt` client's keys do.
//! - **The diagnostics channel.** Every FAILURE returns the uniform, opaque
//!   `invalid_grant` on the wire and records a rich, structured reason OUT OF BAND
//!   in the SAME `client_auth_diagnostics` sink client authentication uses.
//!
//! # The jti replay scoping choice
//!
//! An external issuer's `jti` lives in its OWN `external_assertion_jtis` table,
//! keyed by `(tenant, environment, issuer, jti)`, DISTINCT from the #25
//! `client_assertion_jtis` table keyed by the OAuth client id. The two tables are
//! separate row spaces, so a hostile external issuer that chose a `jti` equal to
//! some client's assertion `jti` can NEVER collide with (and thus never invalidate
//! or replay past) a client-assertion `jti`. It reuses the identical
//! prune-then-insert single-use mechanism (a primary-key conflict is a replay).

use std::time::Duration;

use axum::http::{HeaderMap, header};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_jose::{
    JwsAlgorithm, RejectReason, TrustedKey, VerificationPolicy, VerifiedToken, verify,
};
use ironauth_store::{
    ClientAuthDiagnosticReason, ClientCredentialsAccess, ClientId, CorrelationId,
    ExternalAssertionIssuerRecord, GrantId, IssueClientCredentials, JtiOutcome,
    NewClientAuthDiagnostic, NewOpaqueAccessToken, Scope,
};
use serde_json::Value;

use crate::client_auth::{
    self, ASYMMETRIC_ALGS, ClientAuthError, ClientAuthInputs, parse_presented,
    peek_assertion_header,
};
use crate::client_credentials::validate_m2m_scope;
use crate::error::TokenError;
use crate::state::OidcState;
use crate::token::{TokenParams, map_store_error, token_ok};
use crate::tokens::{self, ClientCredentialsMintRequest, MintedAccessToken};
use crate::util::{client_service_actor, epoch_micros};

/// The diagnostic `auth_method` marker recorded for a jwt-bearer grant failure, so
/// its out-of-band diagnostics are distinguishable from client-authentication ones
/// in the shared `client_auth_diagnostics` sink.
const JWT_BEARER_METHOD_MARKER: &str = "jwt-bearer";

/// The `client_credentials` grant handler for
/// `urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC 7521 4.1, issue #26).
///
/// # Errors
///
/// [`TokenError::InvalidRequest`] when the `assertion` is absent;
/// [`TokenError::InvalidClient`] when the presenting client fails authentication
/// independently; [`TokenError::InvalidGrant`] (uniform, with the specific reason
/// recorded out of band) for every assertion-validation or subject-mapping failure;
/// [`TokenError::ServerError`] on a signing or persistence fault.
pub async fn jwt_bearer_grant(
    state: &OidcState,
    headers: &HeaderMap,
    params: TokenParams,
) -> Result<Response, TokenError> {
    // 1. The assertion (the external JWT) is REQUIRED (RFC 7521 4.1).
    let assertion = params
        .assertion
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokenError::InvalidRequest("assertion is required".to_owned()))?;

    // 2. Identify and authenticate the presenting client. It declares the scope (a
    //    `cli_` id embeds it) and becomes the token audience; a confidential client's
    //    authentication failure is invalid_client, INDEPENDENT of the assertion. A
    //    public (`none`) client is permitted (the assertion is the authorization).
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let inputs = ClientAuthInputs {
        authorization,
        client_id: params.client_id.as_deref(),
        client_secret: params.client_secret.as_deref(),
        client_assertion: params.client_assertion.as_deref(),
        client_assertion_type: params.client_assertion_type.as_deref(),
    };
    let presented = parse_presented(
        inputs.authorization,
        inputs.client_id,
        inputs.client_secret,
        inputs.client_assertion,
        inputs.client_assertion_type,
    )
    .map_err(|_| TokenError::InvalidClient {
        via_basic: is_basic_scheme(authorization),
    })?;
    let via_basic = presented.via_basic();
    let scope = ClientId::parse_declared_scope(presented.client_id())
        .map(|id| id.scope())
        .map_err(|_| TokenError::InvalidClient { via_basic })?;
    let authenticated = client_auth::authenticate_client(state, scope, inputs)
        .await
        .map_err(|error| match error {
            ClientAuthError::InvalidRequest(message) => {
                TokenError::InvalidRequest(message.to_owned())
            }
            ClientAuthError::InvalidClient { via_basic } => TokenError::InvalidClient { via_basic },
        })?;
    let client_id_str = authenticated.client_id;

    // 3. Validate the requested `scope` against the SHARED machine-grant policy
    //    (issue #23's `validate_m2m_scope`, reused here): a mapped-identity
    //    assertion-grant token is a machine token with no interactive user, so
    //    `openid`/`offline_access` are out of policy (invalid_scope). Do this BEFORE
    //    touching the assertion so an out-of-policy scope never spends the assertion's
    //    single-use jti. The returned value is the normalized (whitespace-collapsed)
    //    granted scope, echoed into the issued token.
    let requested_scope = validate_m2m_scope(params.scope.as_deref())?;

    // 4-5. Validate the assertion against a registered external issuer and map its
    //       subject to an IronAuth principal. A validation/mapping failure is the
    //       uniform invalid_grant with the specific reason recorded out of band; a
    //       store/persistence fault fails closed as a server_error (no diagnostic).
    let principal = match validate_and_map(state, scope, assertion).await {
        Ok(principal) => principal,
        Err(JwtBearerError::Reject(reason)) => {
            record_diagnostic(state, scope, &client_id_str, assertion, reason).await;
            return Err(TokenError::InvalidGrant);
        }
        Err(JwtBearerError::Server) => return Err(TokenError::ServerError),
    };

    // 6. Mint the short-lived access token under the mapped principal and persist
    //    the grant. No ID token, no refresh token (RFC 7521 4.1).
    mint_and_persist(
        state,
        scope,
        &client_id_str,
        &principal,
        requested_scope.as_deref(),
    )
    .await
}

/// Why the jwt-bearer grant could not issue a token, split so the caller maps each
/// class to the right wire error.
enum JwtBearerError {
    /// A validation or mapping failure: the uniform `invalid_grant`, with `reason`
    /// recorded out of band via the diagnostics channel.
    Reject(ClientAuthDiagnosticReason),
    /// A store or key-resolution fault: fail closed as an opaque `server_error`, with
    /// NO (misleading) diagnostic.
    Server,
}

/// Validate the external `assertion` against a registered issuer (RFC 7523 3) and
/// resolve its verified `(issuer, sub)` to a REGISTERED IronAuth principal.
///
/// Returns the mapped principal on success. A verification, trust, or mapping
/// failure is a [`JwtBearerError::Reject`] carrying the specific out-of-band reason;
/// a store fault during a lookup is a [`JwtBearerError::Server`].
async fn validate_and_map(
    state: &OidcState,
    scope: Scope,
    assertion: &str,
) -> Result<String, JwtBearerError> {
    // Peek the UNVERIFIED `iss` to find WHICH registered issuer to verify against.
    // Reading it before verification introduces no trust: the policy below enforces
    // `iss` cryptographically against the value we looked the issuer up by (exactly
    // as #25 peeks an assertion's `sub` to look the client up).
    let claimed_iss = peek_unverified_claim(assertion, "iss").ok_or(JwtBearerError::Reject(
        ClientAuthDiagnosticReason::AssertionIssuerUntrusted,
    ))?;
    // Resolve the registered, ENABLED external issuer. A store fault is a server
    // error; an absent or disabled issuer is an untrusted-issuer rejection.
    let record = match state
        .store()
        .scoped(scope)
        .external_assertion_issuers()
        .by_issuer(&claimed_iss)
        .await
    {
        Ok(Some(record)) if record.enabled => record,
        Ok(_) => {
            return Err(JwtBearerError::Reject(
                ClientAuthDiagnosticReason::AssertionIssuerUntrusted,
            ));
        }
        Err(_) => return Err(JwtBearerError::Server),
    };

    // Verify the assertion through the ONE hardened JOSE path against the issuer's
    // keys, the SHARED audience policy, and the SHARED skew bound. The policy
    // enforces `iss == record.issuer` and the algorithm allowlist, so the token's
    // own `alg` header is never trusted.
    let keys = resolve_issuer_keys(state, &record).await;
    let algorithms = allowed_algs(&record);
    let audiences = state.client_assertion_audiences(&scope);
    let skew = state.client_assertion_skew();
    let verified = verify_external_assertion(
        assertion,
        &keys,
        &algorithms,
        &record.issuer,
        &audiences,
        skew,
        state.env().clock(),
    )
    .ok_or(JwtBearerError::Reject(
        ClientAuthDiagnosticReason::AssertionInvalid,
    ))?;

    // RFC 7523 3: `sub` and `exp` are REQUIRED. A missing or empty `sub` is invalid.
    let subject = verified
        .claims()
        .subject()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(JwtBearerError::Reject(
            ClientAuthDiagnosticReason::AssertionInvalid,
        ))?
        .to_owned();
    let exp = verified
        .claims()
        .expiration()
        .ok_or(JwtBearerError::Reject(
            ClientAuthDiagnosticReason::AssertionInvalid,
        ))?;

    // Spend the OPTIONAL single-use `jti` AFTER verification (so any accepted
    // assertion is single-use) and BEFORE the mapping check (so an assertion is
    // single-use even across a failed mapping, like the #25 client-assertion path).
    spend_optional_jti(state, scope, &record.issuer, &verified, exp, skew).await?;

    // Resolve the REGISTERED subject to an IronAuth principal (reject by default).
    resolve_mapped_principal(state, scope, &record.issuer, &subject, &verified).await
}

/// Spend the OPTIONAL single-use `jti` (RFC 7523 makes it optional on the
/// authorization grant): record it in the DISTINCT external-issuer replay cache. An
/// empty/whitespace value is treated as absent (no replay protection). A replay is a
/// rejection; a store fault fails closed as a server error.
async fn spend_optional_jti(
    state: &OidcState,
    scope: Scope,
    issuer: &str,
    verified: &VerifiedToken,
    exp: i64,
    skew: Duration,
) -> Result<(), JwtBearerError> {
    let Some(jti) = verified
        .claims()
        .get("jti")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        // BY DESIGN (accepted residual): a jti-less assertion has NO replay
        // protection within its `exp` + skew window. RFC 7523 makes `jti` OPTIONAL on
        // the authorization grant (unlike client authentication), so we accept the
        // assertion; replay is bounded by the short `aud` + `exp` window, matching the
        // #25 client-assertion posture. An issuer that wants strict single-use mints a
        // `jti` (which is then spent below).
        return Ok(());
    };
    // Retain the jti until its assertion can no longer be accepted, PLUS one whole
    // second (the same +1s margin the #25 cache documents), so a prune never reopens
    // a replay window.
    let skew_secs = i64::try_from(skew.as_secs()).unwrap_or(i64::MAX);
    let expires_secs = exp.saturating_add(skew_secs).saturating_add(1);
    let expires_micros = expires_secs.saturating_mul(1_000_000);
    match state
        .store()
        .scoped(scope)
        .external_assertion_jtis()
        .record(state.env(), issuer, jti, expires_micros)
        .await
    {
        Ok(JtiOutcome::Recorded) => Ok(()),
        Ok(JtiOutcome::Replayed) => Err(JwtBearerError::Reject(
            ClientAuthDiagnosticReason::ReplayedJti,
        )),
        // A store fault recording the jti fails closed: we will not let an assertion
        // through without recording its single use.
        Err(_) => Err(JwtBearerError::Server),
    }
}

/// Resolve the verified `(issuer, subject)` to a REGISTERED IronAuth principal
/// through the explicit subject-mapping rules, applying the rule's OPTIONAL claim
/// gate against the verified claims. An absent rule (or a failed claim gate) is the
/// reject-by-default posture: an unmapped subject is rejected, NEVER auto-provisioned.
/// A store fault fails closed as a server error.
async fn resolve_mapped_principal(
    state: &OidcState,
    scope: Scope,
    issuer: &str,
    subject: &str,
    verified: &VerifiedToken,
) -> Result<String, JwtBearerError> {
    let mapping = match state
        .store()
        .scoped(scope)
        .external_assertion_subject_mappings()
        .resolve(issuer, subject)
        .await
    {
        Ok(Some(mapping)) => mapping,
        Ok(None) => {
            return Err(JwtBearerError::Reject(
                ClientAuthDiagnosticReason::AssertionSubjectUnmapped,
            ));
        }
        Err(_) => return Err(JwtBearerError::Server),
    };
    // The OPTIONAL claim gate: when the rule pins an additional claim, the verified
    // assertion MUST carry it with the exact value.
    if let Some(claim) = &mapping.match_claim {
        let expected = mapping.match_value.as_deref().unwrap_or_default();
        let actual = verified.claims().get(claim).and_then(Value::as_str);
        if actual != Some(expected) {
            return Err(JwtBearerError::Reject(
                ClientAuthDiagnosticReason::AssertionSubjectUnmapped,
            ));
        }
    }
    // BY DESIGN (accepted residual): the mapped `principal` is OPERATOR-AUTHORED (a
    // registered mapping rule) and is NOT liveness-checked at mint. Cross-tenant
    // misuse is contained by RLS plus the assertion's own verified `iss`/signature;
    // intra-tenant correctness relies on the privileged authorship of the mapping
    // rule. A mint-time in-scope principal-liveness check (rejecting a mapping to a
    // deactivated principal) is deferred defense-in-depth, not a correctness gap here.
    Ok(mapping.principal)
}

/// Verify an external assertion's signature and RFC 7523 claim rules through the ONE
/// hardened JOSE [`verify`] path, trying each acceptable audience in turn.
///
/// The `iss` is enforced to equal `issuer` by the policy; `exp`/`nbf`/`iat` are
/// enforced within `skew`; the algorithm must be in `algorithms` (which excludes
/// ES512 and never reads the token's own header). Returns the full [`VerifiedToken`]
/// on success (so the caller can read the `sub`, `exp`, `jti`, and any claim the
/// mapping gate pins), or `None` on any failure (uniform). Pure and synchronous: key
/// resolution and the jti recording are the caller's async concerns.
fn verify_external_assertion(
    assertion: &str,
    keys: &[TrustedKey],
    algorithms: &[JwsAlgorithm],
    issuer: &str,
    audiences: &[String],
    skew: Duration,
    clock: &dyn ironauth_env::Clock,
) -> Option<VerifiedToken> {
    if keys.is_empty() || algorithms.is_empty() || audiences.is_empty() {
        return None;
    }
    for audience in audiences {
        let Ok(policy) =
            VerificationPolicy::new(algorithms.to_vec(), keys.to_vec(), issuer, audience.clone())
        else {
            return None;
        };
        let policy = policy.with_skew(skew);
        match verify(assertion, &policy, clock) {
            Ok(verified) => return Some(verified),
            // An audience mismatch under one acceptable audience just means try the
            // next; any other failure is a hard, uniform rejection.
            Err(error) if error.reason() == RejectReason::AudienceMismatch => {}
            Err(_) => return None,
        }
    }
    None
}

/// The JWS algorithms a registered issuer's assertions may be signed with: its
/// pinned `signing_alg_allow` (a space-separated per-issuer allowlist) intersected
/// with the supported asymmetric set, otherwise the full asymmetric set. A pinned
/// name this core does not implement (for example ES512) yields an EMPTY allowlist,
/// so the assertion is rejected.
fn allowed_algs(record: &ExternalAssertionIssuerRecord) -> Vec<JwsAlgorithm> {
    match record.signing_alg_allow.as_deref() {
        Some(list) => list
            .split_whitespace()
            .filter_map(JwsAlgorithm::from_jose_name)
            .filter(|alg| ASYMMETRIC_ALGS.contains(alg))
            .collect(),
        None => ASYMMETRIC_ALGS.to_vec(),
    }
}

/// Resolve a registered issuer's verification keys: inline pinned `jwks` if set,
/// otherwise its `jwks_uri` fetched (and cached) through the SAME SSRF-hardened
/// resolver a `private_key_jwt` client's keys use (#25). Returns an empty set (fail
/// closed) when neither is available or the resolution yields no usable key.
async fn resolve_issuer_keys(
    state: &OidcState,
    record: &ExternalAssertionIssuerRecord,
) -> Vec<TrustedKey> {
    if let Some(inline) = &record.jwks {
        return ironauth_jose::trusted_keys_from_jwks(inline.as_bytes());
    }
    if let Some(uri) = &record.jwks_uri {
        if let Some(resolver) = state.client_key_resolver() {
            return resolver.resolve(state.now(), uri).await;
        }
    }
    Vec::new()
}

/// Resolve the mapped principal, mint the short-lived access token under it, record
/// it against a fresh grant (audited as `jwt_bearer_assertion.issue`), and build the
/// `200 OK` response. The token is audienced to the presenting `client_id` (the #29
/// `resolve_access_token_target` seam with no resource, an empty resource set), so
/// its `aud` is the client and it stays revocable/introspectable by the #22
/// endpoints. There is NO ID token and NO refresh token (RFC 7521 4.1).
async fn mint_and_persist(
    state: &OidcState,
    scope: Scope,
    client_id_str: &str,
    principal: &str,
    requested_scope: Option<&str>,
) -> Result<Response, TokenError> {
    // The token audience: the presenting client with no resource (an empty resource
    // set), exactly as the client-credentials default resolves. The empty-resource
    // branch is infallible, so a failure here can only be an internal error.
    let target = state
        .resolve_access_token_target(&scope, &[], client_id_str)
        .await
        .map_err(|_| TokenError::ServerError)?;
    let entry = state
        .issuer_entry(&scope)
        .await
        .ok_or(TokenError::ServerError)?;
    let signer = entry.signer(state.now()).ok_or(TokenError::ServerError)?;
    let issuer = state.issuer_for(&scope);
    // The mapped-identity access token carries the RFC 9068 protocol claims with the
    // mapped principal as `sub` and NO auth-context claims (there was no interactive
    // user authentication event to derive an acr/auth_time from), reusing the SAME
    // claim builder and signing core as the M2M grant. No per-issuer custom claims.
    let no_custom = serde_json::Map::new();
    let (minted, expires_in) = tokens::mint_client_credentials_access_token(
        state,
        signer,
        entry.policy(),
        &ClientCredentialsMintRequest {
            scope,
            issuer: &issuer,
            subject: principal,
            client_id: client_id_str,
            oauth_scope: requested_scope,
            custom_claims: &no_custom,
        },
        &target,
    )
    .map_err(|()| TokenError::ServerError)?;

    // Persist a fresh grant + record the access token against it, so the token is
    // revocable and introspectable by construction (the SAME grant chain). The
    // client id was a valid scoped identifier when it authenticated, so it parses
    // here; a parse failure is defensive fail-closed server error.
    let client_id = state
        .store()
        .scoped(scope)
        .clients()
        .parse_id(client_id_str)
        .map_err(|_| TokenError::ServerError)?;
    let grant_id = GrantId::generate(state.env(), &scope);
    let access = match &minted {
        MintedAccessToken::Jwt { jti, .. } => ClientCredentialsAccess::Jwt { jti },
        MintedAccessToken::Opaque {
            digest,
            jti,
            audiences,
            expires_at_unix_micros,
            ..
        } => ClientCredentialsAccess::Opaque(NewOpaqueAccessToken {
            token_digest: digest.as_str(),
            // Bound to THIS grant by the issuing method, so left None here.
            grant_id: None,
            subject: principal,
            client_id: client_id_str,
            audience: audiences.first().map_or("", String::as_str),
            audiences,
            scope: requested_scope,
            jti,
            expires_at_unix_micros: *expires_at_unix_micros,
        }),
    };
    state
        .store()
        .scoped(scope)
        .acting(
            client_service_actor(&client_id),
            CorrelationId::generate(state.env()),
        )
        .authorization()
        .issue_jwt_bearer_assertion(
            state.env(),
            IssueClientCredentials {
                grant_id: &grant_id,
                client_id: &client_id,
                subject: principal,
                created_at_unix_micros: epoch_micros(state.now()),
                access,
            },
        )
        .await
        .map_err(map_store_error)?;

    Ok(jwt_bearer_response(&minted, expires_in, requested_scope))
}

/// Record a jwt-bearer grant failure diagnostic out of band, best effort, in the
/// SAME `client_auth_diagnostics` sink client authentication uses. A failure to
/// record is logged and swallowed: the diagnostic is a side channel for operators,
/// never a gate on the grant decision.
async fn record_diagnostic(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    assertion: &str,
    reason: ClientAuthDiagnosticReason,
) {
    // Verbosity off makes recording a no-op (issue #91); the grant decision and its
    // wire response are unchanged. The JWT bearer grant records only the base fields
    // (no derived skew / hint), so nothing extra is gated by `standard` vs `verbose`.
    if state.diagnostics_verbosity() == ironauth_config::DiagnosticVerbosity::Off {
        return;
    }
    let (alg, kid) = peek_assertion_header(assertion);
    if let Err(error) = state
        .store()
        .scoped(scope)
        .client_auth_diagnostics()
        .record(
            state.env(),
            state.diagnostic_retention_micros(),
            NewClientAuthDiagnostic {
                client_id,
                auth_method: JWT_BEARER_METHOD_MARKER,
                reason,
                key_id: kid.as_deref(),
                signing_alg: alg.as_deref(),
                skew_seconds: None,
                expected: None,
            },
        )
        .await
    {
        tracing::warn!(%error, "could not record a jwt-bearer grant diagnostic");
    }
}

/// Build the `200 OK` token response (RFC 6749 5.1) for the jwt-bearer grant: the
/// access token, its type and lifetime, and the granted scope when present. There is
/// deliberately NO `refresh_token` (RFC 7521 4.1) and no `id_token` (there is no
/// interactive user).
fn jwt_bearer_response(
    minted: &MintedAccessToken,
    expires_in: i64,
    scope: Option<&str>,
) -> Response {
    let mut body = serde_json::json!({
        "access_token": minted.token(),
        "token_type": "Bearer",
        "expires_in": expires_in,
    });
    if let Some(scope) = scope {
        body["scope"] = serde_json::json!(scope);
    }
    token_ok(&body.to_string())
}

/// Read a top-level string claim from a compact JWS's (UNVERIFIED) payload, for
/// deriving WHICH registered issuer to verify against. The verification then binds
/// `iss` cryptographically, so reading it before verification introduces no trust.
fn peek_unverified_claim(assertion: &str, name: &str) -> Option<String> {
    let payload = assertion.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value.get(name).and_then(Value::as_str).map(str::to_owned)
}

/// Whether the `Authorization` header presents the Basic scheme, so a failed
/// authentication before the shared seam runs still carries the RFC 6749 5.2
/// `WWW-Authenticate: Basic` header. Safe on any bytes: it compares the ASCII scheme
/// token without slicing on a char boundary.
fn is_basic_scheme(authorization: Option<&str>) -> bool {
    authorization.is_some_and(|value| {
        let value = value.trim_start();
        value.len() >= 6 && value.as_bytes()[..6].eq_ignore_ascii_case(b"basic ")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pinned_es512_allowlist_is_empty_and_a_multi_alg_allowlist_parses() {
        // A pinned ES512 is unrepresentable, so the allowlist is empty and every
        // assertion is rejected; a multi-alg pin parses to exactly its supported
        // members and drops an unknown token.
        let mut record = ExternalAssertionIssuerRecord {
            id: sample_issuer_id(),
            issuer: "https://issuer.test".to_owned(),
            jwks: Some("{}".to_owned()),
            jwks_uri: None,
            signing_alg_allow: Some("ES512".to_owned()),
            enabled: true,
        };
        assert!(
            allowed_algs(&record).is_empty(),
            "ES512 is unrepresentable, so the allowlist is empty"
        );

        record.signing_alg_allow = Some("EdDSA ES256 bogus".to_owned());
        assert_eq!(
            allowed_algs(&record),
            vec![JwsAlgorithm::EdDsa, JwsAlgorithm::Es256],
            "a multi-alg pin parses to its supported members and drops the unknown token"
        );

        // No pin: the full supported asymmetric set applies.
        record.signing_alg_allow = None;
        assert_eq!(allowed_algs(&record), ASYMMETRIC_ALGS.to_vec());
    }

    #[test]
    fn peek_unverified_claim_reads_a_top_level_string() {
        // A JWS whose payload is {"iss":"https://issuer.test","sub":"wl-1"}.
        let payload = URL_SAFE_NO_PAD.encode(br#"{"iss":"https://issuer.test","sub":"wl-1"}"#);
        let assertion = format!("aGVhZGVy.{payload}.c2ln");
        assert_eq!(
            peek_unverified_claim(&assertion, "iss").as_deref(),
            Some("https://issuer.test")
        );
        assert_eq!(
            peek_unverified_claim(&assertion, "sub").as_deref(),
            Some("wl-1")
        );
        assert!(peek_unverified_claim(&assertion, "aud").is_none());
        // A non-JWS or a garbage payload reads nothing rather than panicking.
        assert!(peek_unverified_claim("not-a-jws", "iss").is_none());
    }

    #[test]
    fn verify_with_no_keys_fails_closed() {
        // A keyless issuer is rejected at registration, but if one somehow reached
        // here, verification fails CLOSED: no key means no acceptance.
        let clock = ironauth_env::ManualClock::new(std::time::SystemTime::UNIX_EPOCH);
        assert!(
            verify_external_assertion(
                "aGVhZGVy.cGF5.c2ln",
                &[],
                ASYMMETRIC_ALGS,
                "https://issuer.test",
                &["https://issuer.test".to_owned()],
                Duration::from_secs(60),
                &clock,
            )
            .is_none(),
            "an empty key set fails closed"
        );
    }

    /// A throwaway `xai_` id for the pure allowlist test.
    fn sample_issuer_id() -> ironauth_store::ExternalIssuerId {
        use ironauth_env::Env;
        use ironauth_store::{EnvironmentId, ExternalIssuerId, Scope, TenantId};
        let (env, _) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 7);
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        ExternalIssuerId::generate(&env, &scope)
    }
}
