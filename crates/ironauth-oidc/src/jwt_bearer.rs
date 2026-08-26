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
//!    auto-provisioned. When (and ONLY when) that principal is a lifecycle-bearing
//!    `usr_` user, apply the account-lifecycle fence (issue #52's invariant, extended
//!    here by issue #241): a blocked, disabled, or deleted user obtains no new tokens by
//!    ANY path, and a trusted external issuer holding a valid assertion is a path. A
//!    WORKLOAD principal carries no lifecycle and is deliberately not checked, because a
//!    `users`-table read would fail closed on every legitimate workload assertion. See
//!    [`MappedPrincipal`] for what the two are told apart by.
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
//! - **The diagnostics channel.** Every failure of the assertion, the subject
//!   mapping, or the per-client SCOPE ALLOWLIST returns the uniform, opaque
//!   `invalid_grant` on the wire and records a rich, structured reason OUT OF BAND
//!   in the SAME `client_auth_diagnostics` sink client authentication uses.
//!
//!   THREE failures are deliberately NOT uniform with those, and naming them is the
//!   point of saying "every" so precisely. A malformed request is `invalid_request`
//!   and a CONFIDENTIAL client's own authentication failure is `invalid_client`,
//!   both spec-mandated and both decided before the assertion is looked at. And a
//!   requested scope on the [`crate::client_credentials`] `DISALLOWED_M2M_SCOPES`
//!   FLOOR answers `invalid_scope`, because that denylist is a PUBLIC COMPILE-TIME
//!   CONSTANT: the spec-exact answer discloses nothing a caller could not read in
//!   the source. A refusal by the PER-CLIENT allowlist is not in that company. It is
//!   operator-written configuration, this grant permits a PUBLIC presenting client,
//!   and the scope check runs BEFORE the assertion is touched, so `invalid_scope`
//!   there would be an unauthenticated read of that configuration one token at a
//!   time. It joins the uniform `invalid_grant` instead ([`resolve_machine_scope`]).
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
    ExpectedTyp, JwsAlgorithm, RejectReason, TrustedKey, VerificationPolicy, VerifiedToken, verify,
};
use ironauth_store::FederatedSource;
use ironauth_store::{
    ClientAuthDiagnosticReason, ClientCredentialsAccess, ClientId, CorrelationId,
    ExternalAssertionIssuerRecord, GrantId, IssueClientCredentials, JtiOutcome,
    NewClientAuthDiagnostic, NewOpaqueAccessToken, Scope, StoredClientId, UserId,
};
use serde_json::Value;

use crate::client_auth::{
    self, ASYMMETRIC_ALGS, AssertionReject, ClientAuthError, ClientAuthInputs,
    map_assertion_reject, parse_presented, peek_assertion_header,
};
use crate::client_credentials::{M2mScopeRefusal, load_scope_policy, validate_m2m_scope};
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
/// recorded out of band) for every assertion-validation or subject-mapping failure
/// AND for a per-client scope-allowlist refusal, which is folded in there
/// deliberately (see [`resolve_machine_scope`]); [`TokenError::InvalidScope`] for the
/// public `DISALLOWED_M2M_SCOPES` floor, the one refusal that keeps the spec-exact
/// code; [`TokenError::ServerError`] on a signing, persistence, or allowlist-read
/// fault.
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
    // The ONE shared grant-restriction seam (issue #763): this client must be
    // registered for the grant it just presented.
    crate::token::enforce_registered_grant_for(
        state,
        &authenticated,
        crate::registry::GrantType::JwtBearer,
    )?;
    let client_id_str = authenticated.client_id;

    // 3. Validate the requested `scope` against the SHARED machine-grant policy
    //    (issue #23's `validate_m2m_scope`, reused here): a mapped-identity
    //    assertion-grant token is a machine token with no interactive user, so
    //    `openid`/`offline_access` are out of policy (invalid_scope). Issue #98 adds
    //    the per-client allowlist beneath that floor; the client whose allowlist
    //    applies is the PRESENTING one, which is the client this token is minted for.
    //    Do this BEFORE touching the assertion so an out-of-policy scope never spends
    //    the assertion's single-use jti, which is why the allowlist read sits here too
    //    rather than later. That ordering is also why the allowlist refusal cannot
    //    answer `invalid_scope`: nothing has authenticated the caller yet on this
    //    grant. `resolve_machine_scope` owns that mapping.
    let requested_scope = resolve_machine_scope(
        state,
        scope,
        &client_id_str,
        via_basic,
        params.scope.as_deref(),
        assertion,
    )
    .await?;

    // 4-5. Validate the assertion against a registered external issuer and map its
    //       subject to an IronAuth principal. A validation/mapping failure is the
    //       uniform invalid_grant with the specific reason recorded out of band; a
    //       store/persistence fault fails closed as a server_error (no diagnostic).
    let mapped = match validate_and_map(state, scope, assertion).await {
        Ok(mapped) => mapped,
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
        &mapped.principal,
        requested_scope.as_deref(),
        FederatedSource {
            issuer: &mapped.issuer,
            subject: &mapped.subject,
        },
    )
    .await
}

/// Read the PRESENTING client's per-client scope allowlist (issue #98) and validate
/// the requested `scope` against the shared machine-grant policy, returning the
/// normalized granted scope.
///
/// # The wire answer is NOT the one `client_credentials` gives, and the difference is a security control
///
/// This grant deliberately permits a PUBLIC (`none`) presenting client, because the
/// ASSERTION is the authorization grant rather than a client secret, and the scope
/// check runs before the assertion is touched so an out-of-policy request cannot
/// spend a single-use `jti`. Those two facts together mean a caller holding NO
/// credential and a garbage assertion reaches this check. If an allowlist refusal
/// answered `invalid_scope` while everything downstream answered `invalid_grant`, that
/// caller could separate an allowlisted scope from a non-allowlisted one one request
/// at a time and read the client's operator-written configuration off the wire.
///
/// So an allowlist refusal joins this grant's uniform `invalid_grant` and records
/// [`ClientAuthDiagnosticReason::ScopeNotAllowlisted`] out of band through the SAME
/// [`record_diagnostic`] channel every other jwt-bearer failure uses: the operator
/// still learns exactly what happened, and the caller learns nothing.
///
/// The FLOOR refusal keeps the spec-exact `invalid_scope`. `DISALLOWED_M2M_SCOPES` is
/// a public compile-time constant, identical for every client and every deployment, so
/// answering it discloses nothing; the two-valued `openid`/`offline_access` answer
/// predates the allowlist and stays.
///
/// A CONFIDENTIAL client is not exposed either way: `authenticate_client` has already
/// refused it with `invalid_client` before this runs.
///
/// # Errors
///
/// [`TokenError::InvalidClient`] if the authenticated client id no longer parses in
/// scope, or the allowlist read finds no such client;
/// [`TokenError::InvalidScope`] for a floor refusal; [`TokenError::InvalidGrant`] for
/// an allowlist refusal; [`TokenError::ServerError`] if the allowlist read faults
/// (it fails CLOSED, never as an unrestricted issuance).
async fn resolve_machine_scope(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    via_basic: bool,
    requested: Option<&str>,
    assertion: &str,
) -> Result<Option<String>, TokenError> {
    let presenting_id = state
        .store()
        .scoped(scope)
        .client_scope_policies()
        .parse_id(client_id)
        .map_err(|_| TokenError::InvalidClient { via_basic })?;
    let policy = load_scope_policy(state, scope, &presenting_id, via_basic).await?;
    match validate_m2m_scope(requested, &policy) {
        Ok(granted) => Ok(granted),
        Err(M2mScopeRefusal::Floor) => Err(TokenError::InvalidScope),
        Err(M2mScopeRefusal::Allowlist) => {
            record_diagnostic(
                state,
                scope,
                client_id,
                assertion,
                ClientAuthDiagnosticReason::ScopeNotAllowlisted,
            )
            .await;
            Err(TokenError::InvalidGrant)
        }
    }
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
/// A mapped federated identity, with the trust anchor that vouched for it.
struct MappedFederation {
    /// The IronAuth principal the external subject maps to.
    principal: String,
    /// The external issuer's `iss` value.
    issuer: String,
    /// The external subject, before mapping.
    subject: String,
}

async fn validate_and_map(
    state: &OidcState,
    scope: Scope,
    assertion: &str,
) -> Result<MappedFederation, JwtBearerError> {
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
    // The header `kid`, UNVERIFIED and used only as a staleness hint. Via the purpose-built
    // `ironauth_jose::compact_jws_kid`, which is documented for exactly this ("a JWKS-refetch
    // HINT on upstream key rotation") and enforces an 8 KB header bound. A local copy without
    // that bound would run an unbounded base64 and JSON decode on an unauthenticated request,
    // BEFORE `verify()`'s own size caps apply.
    let kid = ironauth_jose::compact_jws_kid(assertion);
    let keys = resolve_issuer_keys(state, &record, kid.as_deref()).await;
    let algorithms = allowed_algs(&record);
    // NARROWED by the issuer's own allowlist (issue #126 criterion 3). The shared policy
    // is the deployment floor and this can only restrict it, never widen it: an issuer that
    // could widen would be a way to escape the floor, which is the opposite of a trust
    // policy. `None` leaves the shared set untouched, so every issuer registered before this
    // column existed behaves exactly as it did.
    //
    // Without this, an assertion addressed to the shared audience is acceptable from ANY
    // registered issuer -- a GitHub Actions token and a Kubernetes projected token land at
    // the same audience, so a trust anchor that should only speak to one can present
    // assertions addressed to another's.
    let audiences = narrowed_audiences(&state.client_assertion_audiences(&scope), &record);
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
    .map_err(|reject| JwtBearerError::Reject(map_assertion_reject(&reject)))?;

    // RFC 7523 3: `sub` and `exp` are REQUIRED. A missing or empty `sub` is invalid.
    //
    // THE EMPTINESS CHECK TRIMS AND THE VALUE DOES NOT, and the difference is a live gate.
    // This read `.map(str::trim)`, which normalized the subject before the mapping lookup
    // compared it with `=`. `str::trim` strips the whole Unicode `White_Space` set, not
    // just ASCII space, so every registered mapping was reachable by a family of about
    // twenty-five distinct subject strings: measured, `...refs/heads/main` followed by
    // U+00A0, U+2028, U+202F or U+3000 was each issued the mapped principal, and a git ref
    // may legally contain all four (git forbids ASCII space and control characters, not
    // these).
    //
    // The trim stays where it belongs. An all-whitespace `sub` is still empty and still
    // rejected, which is what it was there for; what it no longer does is decide which
    // mapping the caller matched. The lookup now compares the subject the issuer actually
    // signed, which is what "binds the exact repository and ref" has to mean.
    let subject = verified
        .claims()
        .subject()
        .filter(|value| !value.trim().is_empty())
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
    let principal =
        resolve_mapped_principal(state, scope, &record.issuer, &subject, &verified).await?;
    // The external issuer and subject travel OUT with the principal, so the audit row can
    // say which trust anchor vouched for the issuance (issue #126 criterion 5). Returned
    // together rather than re-derived at the call site: re-peeking the assertion there
    // would be a second parse of a credential this function has already verified.
    Ok(MappedFederation {
        principal,
        issuer: record.issuer,
        subject,
    })
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
    // The user-lifecycle fence (issue #52's invariant, extended here by issue #241).
    // Applies to a lifecycle-bearing principal ONLY; see `MappedPrincipal`.
    fence_mapped_principal(state, scope, &mapping.principal).await?;
    Ok(mapping.principal)
}

/// What KIND of thing an operator's subject-mapping rule points at, which decides
/// whether the user-lifecycle fence applies to it (issue #241).
///
/// # Why this is a type and not an `if`
///
/// This grant carries two populations through one code path. One is WORKLOAD federation
/// (SPIRE JWT-SVIDs, Kubernetes projected tokens, GitHub Actions OIDC, issue #26), where
/// the mapped principal names a service account or a workload and there is no `users` row
/// anywhere. The other is a mapping an operator wrote onto a real end-user account, which
/// is the hole issue #241 closes: a trusted external issuer could keep minting for that
/// account after it was blocked, disabled, or deleted.
///
/// A fence that ran on both would not be hardening, it would be an outage:
/// `UserRepo::state_for_subject` queries the `users` table, finds nothing for a workload
/// id, and fails CLOSED, refusing EVERY legitimate workload assertion in the deployment.
/// So the two populations must be told apart, and the only question is by what.
///
/// # What it is keyed on, and why that cannot drift
///
/// By PARSING, through [`ironauth_store::UserId`]'s own constructors, never by comparing
/// the principal against a spelled-out `"usr_"`. The prefix these constructors enforce is
/// `<UserKind as ScopedKind>::PREFIX`, a single associated constant on the marker type
/// that also defines what a `UserId` IS everywhere else in the product. There is no
/// second copy of it in this file to fall out of step with the first.
///
/// The difference is not stylistic. A literal comparison is a fact about SPELLING, and it
/// silently answers for identifier kinds that do not exist yet: introduce a `usrv_`
/// verified-user prefix and `starts_with("usr_")` sweeps it into the fence with no
/// compile error and no test change; introduce a lifecycle-bearing kind spelled anything
/// else and it silently escapes. Parsing is a fact about the TYPE: a future kind is a
/// different `ScopedKind` with a different `PREFIX`, so `UserId::parse_in_scope` rejects
/// it, and it acquires this fence only when somebody deliberately gives it one.
///
/// # Three outcomes, because two would leak
///
/// The obvious shape is "parses in scope, or does not". It is wrong at one edge. A
/// principal that is a well-formed user id belonging to ANOTHER tenant or environment
/// fails `parse_in_scope` exactly as an opaque workload string does, so a two-valued test
/// waves it through UNFENCED under the workload branch: a user-bound token, minted with
/// no lifecycle check, for a subject this scope cannot even read the state of.
/// [`MappedPrincipal::ForeignUser`] separates it and REFUSES, which is the only
/// answer available. This scope cannot resolve a foreign user's state (RLS and the
/// tenant/environment SQL filter both stop it), so the fence cannot be applied to it, and
/// an unfenceable user-bound mint is exactly what this issue exists to prevent.
pub(crate) enum MappedPrincipal {
    /// A [`ironauth_store::UserId`] minted in THIS scope: lifecycle bearing and
    /// readable here, so the fence applies.
    User,
    /// A user-kind id minted in ANOTHER tenant or environment: lifecycle bearing but
    /// unfenceable from here. Refused.
    ForeignUser,
    /// Not a user id at all: a workload or service-account principal, which carries no
    /// lifecycle. The fence does not apply and MUST not, or workload federation breaks.
    Workload,
}

impl MappedPrincipal {
    /// Classify `principal` against `scope`, structurally.
    ///
    /// [`ScopedId::parse_declared_scope`] is used here to ask a question its usual
    /// caveat does not cover. That caveat forbids using it to decide whether untrusted
    /// input names an IN-SCOPE resource, because it performs no scope check and would be
    /// a cross-scope existence oracle. Nothing like that happens here: the input is
    /// OPERATOR-AUTHORED configuration rather than caller-supplied, it is asked only
    /// what KIND of identifier it is, no row is looked up, and the answer is a REFUSAL
    /// whose wire form is this grant's uniform `invalid_grant`, byte-identical to every
    /// other mapping failure. A caller cannot vary the principal and so cannot read
    /// anything out of the distinction.
    pub(crate) fn classify(principal: &str, scope: &Scope) -> Self {
        if UserId::parse_in_scope(principal, scope).is_ok() {
            return MappedPrincipal::User;
        }
        if UserId::parse_declared_scope(principal).is_ok() {
            return MappedPrincipal::ForeignUser;
        }
        MappedPrincipal::Workload
    }
}

/// Apply the user-lifecycle fence to a mapped principal before it is minted for
/// (issue #241): a blocked, disabled, or deleted user obtains no new tokens by ANY path,
/// and a trusted external issuer holding a valid assertion is a path.
///
/// A [`MappedPrincipal::Workload`] principal is returned to unchanged: it carries no
/// lifecycle, and checking it would fail closed on every legitimate workload assertion.
/// A [`MappedPrincipal::User`] is fenced against the SAME
/// [`crate::token::subject_can_authenticate`] read the refresh grant is fenced by, and a
/// [`MappedPrincipal::ForeignUser`] is refused unread.
///
/// A refusal is [`JwtBearerError::Reject`] carrying
/// [`ClientAuthDiagnosticReason::PrincipalNotAuthenticatable`], so the wire stays the
/// uniform `invalid_grant` while an operator gets the specific reason out of band and can
/// tell "this account is fenced" apart from "you never wrote this mapping". A store fault
/// is [`JwtBearerError::Server`]: fail CLOSED, never mint on an unread lifecycle.
async fn fence_mapped_principal(
    state: &OidcState,
    scope: Scope,
    principal: &str,
) -> Result<(), JwtBearerError> {
    match MappedPrincipal::classify(principal, &scope) {
        MappedPrincipal::Workload => Ok(()),
        MappedPrincipal::ForeignUser => Err(JwtBearerError::Reject(
            ClientAuthDiagnosticReason::PrincipalNotAuthenticatable,
        )),
        MappedPrincipal::User => {
            match crate::token::subject_can_authenticate(state, scope, principal).await {
                Ok(true) => Ok(()),
                Ok(false) => Err(JwtBearerError::Reject(
                    ClientAuthDiagnosticReason::PrincipalNotAuthenticatable,
                )),
                Err(_) => Err(JwtBearerError::Server),
            }
        }
    }
}

/// Verify an external assertion's signature and RFC 7523 claim rules through the ONE
/// hardened JOSE [`verify`] path, trying each acceptable audience in turn.
///
/// The `iss` is enforced to equal `issuer` by the policy; `exp`/`nbf`/`iat` are
/// enforced within `skew`; the algorithm must be in `algorithms` (which excludes
/// ES512 and never reads the token's own header). Returns the full [`VerifiedToken`]
/// on success (so the caller can read the `sub`, `exp`, `jti`, and any claim the
/// mapping gate pins), or the TERMINAL [`AssertionReject`] on failure so the caller can map
/// it to a specific diagnostic reason (issue #126). The WIRE decision is unchanged: the caller
/// collapses ANY `Err` into the opaque `invalid_grant`, so the sharper reject reaches the
/// operator's out-of-band record and never a caller.
///
/// An audience mismatch under one candidate is not terminal, because the next acceptable
/// audience may match; exhausting them all is, and that is what the final `Err` reports. Pure
/// and synchronous: key resolution and the jti recording are the caller's async concerns.
fn verify_external_assertion(
    assertion: &str,
    keys: &[TrustedKey],
    algorithms: &[JwsAlgorithm],
    issuer: &str,
    audiences: &[String],
    skew: Duration,
    clock: &dyn ironauth_env::Clock,
) -> Result<VerifiedToken, AssertionReject> {
    // The REASON, not just the failure. Every refusal here used to collapse into one
    // `None`, so an operator reading the diagnostics could not tell a stale JWKS from an
    // audience mismatch from a bad signature -- which is issue #126's error-handling
    // criterion, and the sibling `private_key_jwt` path has answered it since #91 with the
    // classifier this now shares. The wire response is unchanged and stays opaque; only the
    // out-of-band record gets sharper.
    if keys.is_empty() || algorithms.is_empty() || audiences.is_empty() {
        return Err(AssertionReject::NoUsableKey);
    }
    for audience in audiences {
        // An RFC 7523 assertion from an external issuer, signed with ITS keys. RFC 7523
        // registers no media type for the assertion, so `typ` cannot be the separator
        // (issue #192); the registered issuer, its keys, and this deployment's own
        // token endpoint as the `aud` are. Both the issuer and the keys come from an
        // operator-registered grant, so that separation is a CONFIGURATION property,
        // not a structural one, and the acceptable audiences include this issuer
        // itself: an operator who registered this deployment as its own external
        // issuer would have IronAuth's tokens reach the signature check with `typ`
        // unread. No default configuration does, and nothing here is reachable without
        // registering the grant.
        let Ok(policy) = VerificationPolicy::new(
            algorithms.to_vec(),
            keys.to_vec(),
            issuer,
            audience.clone(),
            ExpectedTyp::ForeignIssuer,
        ) else {
            return Err(AssertionReject::NoUsableKey);
        };
        let policy = policy.with_skew(skew);
        match verify(assertion, &policy, clock) {
            Ok(verified) => return Ok(verified),
            // An audience mismatch under one acceptable audience just means try the
            // next; any other failure is a hard, uniform rejection.
            Err(error) if error.reason() == RejectReason::AudienceMismatch => {}
            Err(error) => return Err(AssertionReject::Jose(error.reason())),
        }
    }
    // Every acceptable audience was tried and none matched, so THIS is the terminal
    // audience mismatch rather than one more candidate to skip.
    Err(AssertionReject::Jose(RejectReason::AudienceMismatch))
}

/// Intersect the deployment's shared audience policy with this issuer's allowlist.
///
/// `None` on the issuer means the shared policy applies unchanged, matching how
/// `signing_alg_allow` already behaves so an operator learns one rule rather than two.
///
/// The intersection is what makes an unusable allowlist FAIL CLOSED rather than dangerous:
/// an issuer whose allowlist shares nothing with the shared policy ends up able to address
/// nothing, so its assertions are refused. The alternative -- treating an empty intersection
/// as "no constraint" -- would turn a typo into a silently wider trust boundary.
fn narrowed_audiences(shared: &[String], record: &ExternalAssertionIssuerRecord) -> Vec<String> {
    let Some(allow) = record.audience_allow.as_deref() else {
        return shared.to_vec();
    };
    let permitted: Vec<&str> = allow.split_whitespace().collect();
    shared
        .iter()
        .filter(|audience| permitted.contains(&audience.as_str()))
        .cloned()
        .collect()
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
    kid: Option<&str>,
) -> Vec<TrustedKey> {
    if let Some(inline) = &record.jwks {
        return ironauth_jose::trusted_keys_from_jwks(inline.as_bytes());
    }
    if let Some(uri) = &record.jwks_uri {
        if let Some(resolver) = state.client_key_resolver() {
            // The assertion's UNVERIFIED `kid` is passed so a rotation is discovered without
            // waiting out the cache TTL (issue #126 criterion 4). Passing it introduces no
            // trust: it selects nothing and authorises nothing, it only tells the resolver
            // that the cached set may be stale, and the refetch it can trigger is rate
            // limited per URI precisely because the value is attacker-chosen.
            return resolver.resolve_for_kid(state.now(), uri, kid).await;
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
    federation: FederatedSource<'_>,
) -> Result<Response, TokenError> {
    // The token audience: the presenting client with no resource (an empty resource
    // set), exactly as the client-credentials default resolves. The empty-resource
    // branch is infallible, so a failure here can only be an internal error.
    let target = state
        .resolve_access_token_target(&scope, &[], client_id_str)
        .await
        .map_err(|_| TokenError::ServerError)?;
    let entry = crate::token::grant_issuer_entry(state, scope).await?;
    let signer = entry.signer(state.now()).ok_or(TokenError::ServerError)?;
    let issuer = state.issuer_for(&scope);
    // The mapped-identity access token carries the RFC 9068 protocol claims with the
    // mapped principal as `sub` and NO auth-context claims (there was no interactive
    // user authentication event to derive an acr/auth_time from), reusing the SAME
    // claim builder and signing core as the M2M grant.
    // No per-issuer STATIC claims, and none of the presenting client's
    // `clients.custom_token_claims` either: this token speaks for a mapped federated principal,
    // and that blob describes the client's own service account. The client's declarative
    // MAPPING and its hook DO run, which issue #113 criterion 1 names `jwt:bearer` for
    // explicitly. The source document is empty, so with nothing configured this is the empty
    // bag it always was.
    let no_custom = crate::claims_mapping_at_issuance::apply_to_machine_token(
        state.store(),
        state.hook_engine(),
        scope,
        client_id_str,
        // The wire value, from the registry, not a literal beside it. Issue #113 asks the
        // grant to be identified in the payload, and a hook that gates on it is reading
        // this string: a door with its own copy can hand a guest a grant name the
        // endpoint does not accept, and only a test comparing two literals would notice.
        crate::registry::GrantType::JwtBearer.as_str(),
        Some(principal),
        &serde_json::Map::new(),
    )
    .await
    .map_err(|_| TokenError::ServerError)?;
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
            // A mapped federated identity acts for itself: no `act` chain (issue #125).
            act: None,
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
            // The JWT bearer assertion grant carries no DPoP proof: a bearer token.
            dpop_jkt: None,
        }),
    };
    state
        .store()
        .scoped(scope)
        .acting(
            client_service_actor(StoredClientId::Registered(&client_id)),
            CorrelationId::generate(state.env()),
        )
        .authorization()
        .issue_jwt_bearer_assertion_from(
            state.env(),
            IssueClientCredentials {
                grant_id: &grant_id,
                client_id: &client_id,
                subject: principal,
                created_at_unix_micros: epoch_micros(state.now()),
                access,
            },
            // WHICH trust anchor vouched for this issuance (issue #126 criterion 5). The
            // grant records the mapped principal; without this the trail cannot say who
            // said it should exist, so an operator responding to a compromised issuer
            // cannot tell which issuances came from it.
            Some(federation),
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
            audience_allow: None,
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
        //
        // An UNRESOLVABLE key source, which is narrower than a stale one. A stale set is not
        // empty (an inline `jwks` always resolves, and a failed refetch falls back to the
        // still valid cached set), so a rotation reaches the verifier and is diagnosed as
        // `assertion_kid_unknown`. This path is the empty set, and `map_assertion_reject`
        // still folds it into the coarse `assertion_invalid` an operator reads. What the seam
        // distinguishes is what a dedicated diagnostic would build on, and that would mean
        // adding to a vocabulary published in the OpenAPI document.
        let clock = ironauth_env::ManualClock::new(std::time::SystemTime::UNIX_EPOCH);
        let rejected = verify_external_assertion(
            "aGVhZGVy.cGF5.c2ln",
            &[],
            ASYMMETRIC_ALGS,
            "https://issuer.test",
            &["https://issuer.test".to_owned()],
            Duration::from_secs(60),
            &clock,
        );
        assert!(
            matches!(rejected, Err(AssertionReject::NoUsableKey)),
            "an empty key set fails closed, and says why"
        );
    }

    #[test]
    fn the_lifecycle_discriminator_separates_users_foreign_users_and_workloads() {
        use ironauth_env::Env;
        use ironauth_store::{EnvironmentId, TenantId};

        let (env, _) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 11);
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        let other = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));

        // A real user id minted in THIS scope is lifecycle bearing: the fence applies.
        let mine = UserId::generate(&env, &scope).to_string();
        assert!(
            matches!(
                MappedPrincipal::classify(&mine, &scope),
                MappedPrincipal::User
            ),
            "an in-scope usr_ id is lifecycle bearing"
        );

        // The same KIND of id from another tenant is still lifecycle bearing, but this
        // scope cannot read its state, so it is refused rather than waved through. This
        // is the case a two-valued `parses in scope or not` test would misclassify as a
        // workload and mint for unfenced.
        let foreign = UserId::generate(&env, &other).to_string();
        assert!(
            matches!(
                MappedPrincipal::classify(&foreign, &scope),
                MappedPrincipal::ForeignUser
            ),
            "a usr_ id from another scope is unfenceable here, not a workload"
        );

        // Workload principals: the population that MUST skip the fence, or every SPIRE /
        // Kubernetes / GitHub Actions assertion in the deployment fails closed. Note the
        // second one: an operator-authored label may legitimately begin with the four
        // characters `usr_` without being an identifier at all, so a `starts_with` test
        // would fence it and take the deployment down.
        for workload in [
            "spiffe://cluster.test/ns/prod/sa/alpha",
            "usr_workload_alpha",
            "sva_not-a-user",
            "",
        ] {
            assert!(
                matches!(
                    MappedPrincipal::classify(workload, &scope),
                    MappedPrincipal::Workload
                ),
                "{workload:?} carries no lifecycle and must skip the fence"
            );
        }

        // The discriminator is keyed on the KIND, not the spelling: another scoped id
        // type minted in the caller's OWN scope still is not a user.
        let client = ironauth_store::ClientId::generate(&env, &scope).to_string();
        assert!(
            matches!(
                MappedPrincipal::classify(&client, &scope),
                MappedPrincipal::Workload
            ),
            "an in-scope id of a DIFFERENT kind is not lifecycle bearing"
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
