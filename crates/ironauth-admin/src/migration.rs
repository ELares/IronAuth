// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OUTBOUND lazy-migration credential-verification endpoint (issue #58): the
//! mirror of IronAuth's inbound migration hook, so a successor system can migrate
//! AWAY from IronAuth exactly as easily as IronAuth migrates off an incumbent.
//!
//! `POST .../migration/verify-credential` lets a successor present a user's
//! identifier plus password during ITS OWN lazy migration and receive a verdict
//! (and, on success, an optional profile of the user's claims and traits). The
//! successor then rehashes the credential into its native store on that user's next
//! login, so a whole user base migrates off IronAuth with no forced password reset,
//! the same trust-builder IronAuth's inbound import gives a tenant leaving an
//! incumbent.
//!
//! The verification reuses the SAME algorithm-tagged verify layer the login path
//! does ([`ironauth_import::ForeignHash`]), which recognizes the native Argon2id PHC
//! string AND every foreign scheme through one dispatch, so a user still on an
//! imported foreign hash verifies identically to one on the native verifier. The
//! endpoint never mutates state (no verify-then-rehash: the departing successor owns
//! the upgrade) and never logs the identifier, password, or hash.
//!
//! # Posture (issue #250 moved this; read the whole section before changing an order)
//!
//! Enablement and its credential are PER ENVIRONMENT and live in the addressed
//! environment's own sealed secret ([`OUTBOUND_VERIFICATION_SECRET_NAME`] in
//! `environment_secrets`, issue #45), never in deployment-global config. There is
//! deliberately no process-wide fallback: an environment with no such secret has the
//! endpoint OFF, which is every environment until an operator writes one, so the
//! default is still off. Enablement and the credential are ONE FACT (the secret's
//! existence IS the enablement), so there is no "enabled but uncredentialed" state to
//! fail closed on, and disabling destroys the credential rather than leaving it lying
//! sealed.
//!
//! ## Every refusal is the SAME uniform not-found, and that is a tightening
//!
//! Before issue #250 the endpoint answered 401 for a missing or wrong bearer inside
//! the ONE globally configured scope, and 404 everywhere else. Per-environment
//! enablement makes that 401 an ENUMERATION ORACLE: an unauthenticated prober would
//! walk `(tenant, environment)` pairs and read off which ones have an outbound
//! migration armed, from the status alone, in one request each. So the 401 is gone.
//! Missing bearer, wrong bearer, disabled environment, absent environment, and a
//! malformed path id are now ONE byte-identical [`ApiError::NotFound`], and the only
//! non-404 this endpoint can produce for an unauthorized caller is nothing at all.
//! `outbound_verification.rs` pins the pairs byte for byte.
//!
//! That uniformity is also why the `Bearer` SCHEME is matched case insensitively (RFC
//! 7235 section 2.1 makes it case insensitive on the wire). A case-sensitive match
//! fails closed, so it is not a security defect, but with one answer for everything a
//! successor whose client uppercases the scheme would present a correct token and get
//! an answer indistinguishable from "not enabled", with nothing anywhere to debug.
//!
//! ## The check ORDER carries that property, and it is not free to reorder
//!
//! 1. The BEARER is read FIRST, and a request without one is refused with the uniform
//!    not-found BEFORE ANY DATABASE ACCESS. That is what keeps an unauthenticated
//!    probe from learning anything at all, and it is also what keeps the endpoint
//!    answerable over a never-connected pool.
//! 2. The path scope is parsed (pure parsing, still no database access).
//! 3. The addressed environment's sealed secret is read. ONE read of ONE shape decides
//!    absent-tenant, absent-environment, and feature-off alike: all three are a
//!    zero-row `SELECT` on `environment_secrets` and all three answer the uniform
//!    not-found, so none is distinguishable from another by status, body, or the shape
//!    of the work done. The read spends the SAME three round trips and three AEAD opens
//!    whether the secret is there or not; see the cost section below for why, and for
//!    the residual that is left.
//! 4. The presented bearer is compared against the opened secret in CONSTANT TIME
//!    ([`crate::hash::constant_time_eq`], which SHA-256s both sides first so neither
//!    the length nor the first differing byte leaks).
//!
//! ### What holds step 1 in place is ONE test, and not the one you would guess
//!
//! It is `openapi_contract::the_outbound_bearer_check_runs_before_any_database_access`,
//! and nothing else. The witness this section used to name,
//! `openapi_contract::served_routes_match_documented_routes`, CANNOT SEE THE ORDER:
//! MEASURED, a handler mutated to read the secret BEFORE the bearer check compiles and
//! survives the entire `ironauth-admin` suite (392 tests over 46 binaries), because
//! that sweep's router carries no master key, so the read short-circuits at
//! `Store::master` before it issues a query, and [`stored_outbound_token`] collapses
//! every store error to `None`. The reordered handler answers the same 404 over a
//! never-connected pool.
//!
//! The pin that does work is OBSERVABLE rather than status-shaped: a router over a
//! lazy pool WITH a master key, aimed at a socket that counts inbound connections. A
//! request with no bearer must answer 404 having opened NONE, and a request with a
//! garbage bearer must open one. The second half is the anti-vacuity control: without
//! it, a route that never reaches the store for any reason would pass.
//!
//! ### The cost of the two branches was flattened, and the residual is a NUMBER
//!
//! This section previously conceded a residual on the reasoning that reading it needed
//! a valid bearer and many samples. That was wrong twice. It is reachable with NO
//! credential at all (any garbage bearer reaches the envelope open, and `ratelimit.rs`
//! stamps constant placeholder headers and counts nothing), and the delta was not the
//! AEAD but TWO DATABASE ROUND TRIPS: the cheap read costs one `SELECT` on a miss and
//! three on a hit. MEASURED at 600 interleaved unauthenticated samples per branch, the
//! armed median was 1.44x the disabled median, the armed 1st percentile sat ABOVE the
//! disabled median, and a single-sample classifier at the midpoint of the medians got
//! 0.977 recall at 0.022 false positives. One request per pair.
//!
//! Step 3 therefore reads through
//! [`open_value_under_platform_key_at_uniform_cost`](ironauth_store::EnvironmentSecretRepo::open_value_under_platform_key_at_uniform_cost),
//! whose miss branch spends the same two key lookups and the same three AEAD opens the
//! hit branch does. After that the ratio is 1.041 to 1.045 over three runs, the armed
//! 1st percentile is BELOW the disabled median in every one, and the same classifier
//! falls to 0.69 to 0.81 recall at 0.21 to 0.36 false positives.
//!
//! It is not zero, and it is stated as a number rather than as an adjective: about 14
//! microseconds on a 318 microsecond baseline, from the hit branch decoding two key
//! rows and unwrapping two real keys where the miss branch's decoy lookups return none.
//! Closing that last part would mean the miss branch unwrapping real key material,
//! which needs a version it can only learn from a FOURTH query. `outbound_timing_probe.rs`
//! is the harness, `#[ignore]`d, with the command in the issue #250 CHANGELOG entry.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use ironauth_config::SecretString;
use ironauth_import::ForeignHash;
use ironauth_store::{CorrelationId, Scope, StoreError, TenantId};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::hash::constant_time_eq;
use crate::input::parse_json;
use crate::org_context::{require_live_environment, require_present_environment, resolve_scope};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// The reserved per-environment secret name that holds an environment's outbound
/// lazy-migration verification token (issue #250).
///
/// Its PRESENCE in a scope is the enablement, and its VALUE is the shared bearer a
/// successor system presents. It is an ordinary `environment_secrets` row, so it is
/// sealed under the scope's envelope DEK exactly like every other environment secret
/// (issue #48), it is invisible to any other environment by forced row-level
/// security, and rotating it is a plain overwrite that bumps the row's version.
///
/// The name is dotted rather than bare so an operator reading a secret listing can
/// see at a glance that IronAuth owns it, and it is a `const` rather than a literal
/// at each site so the writer and the reader can never drift apart.
pub const OUTBOUND_VERIFICATION_SECRET_NAME: &str = "ironauth.outbound_verification_token";

/// A successor system's credential-verification request (issue #58): a user's login
/// handle and the candidate password to check. Neither is ever logged; the password
/// is compared only against the stored one-way verifier. No `Debug` is derived so a
/// stray struct dump cannot spill the password.
#[derive(Deserialize, ToSchema)]
pub struct VerifyCredentialRequest {
    /// The login handle to verify.
    pub identifier: String,
    /// The candidate password (never logged or echoed).
    pub password: String,
}

/// The verdict returned to the successor (issue #58): whether the credential is
/// valid and, on success, the stable subject and the user's exportable profile. No
/// `Debug` is derived so the profile (claims and traits are PII) cannot spill.
#[derive(Serialize, ToSchema)]
pub struct VerifyCredentialResponse {
    /// Whether the identifier plus password verified against the stored credential
    /// AND the account is permitted to authenticate. A wrong password, an unknown
    /// account, and a fenced account (blocked, disabled, pending verification) all
    /// return `false`, with no oracle distinguishing them.
    pub verified: bool,
    /// The stable pseudonymous subject (the `usr_` id) of the verified user, present
    /// only when `verified` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The user's profile, present only on a successful verification, so the
    /// successor can seed its own record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<VerifyProfile>,
}

/// The optional profile returned alongside a successful verification (issue #58):
/// the user's standard claims and identity traits, so the successor migrates the
/// full identity, not merely the credential.
#[derive(Serialize, ToSchema)]
pub struct VerifyProfile {
    /// The user's OIDC standard-claim document, or null when the user has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
    /// The user's identity-traits document, or null when the user has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traits: Option<serde_json::Value>,
}

/// Extract the `Bearer` token from the `Authorization` header, or [`None`].
///
/// Returning an [`Option`] rather than an [`ApiError`] is deliberate (issue #250):
/// every failure on this endpoint is the ONE uniform not-found, so there is no
/// distinct "missing credential" answer for this helper to build, and handing back a
/// typed error would invite a future edit to surface it. An empty or whitespace-only
/// bearer is [`None`]: an empty presented token must never be able to match anything,
/// and a stored secret is refused at write time if it trims to empty, so the two ends
/// agree.
///
/// The SCHEME is matched case insensitively, per RFC 7235 section 2.1, which makes it
/// case insensitive on the wire. A case-sensitive match fails CLOSED, so it is not a
/// security defect; it is a DEBUGGING one, and a bad one specifically here. Every
/// refusal on this endpoint is the same uniform not-found, so a successor system whose
/// HTTP client normalizes the scheme to `BEARER` would present a correct token and
/// receive an answer byte-identical to "this environment is not armed", with nothing
/// anywhere to distinguish the two.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;
    let (scheme, credential) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = credential.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_owned())
}

/// Open the addressed environment's outbound-verification secret, or [`None`] when
/// the endpoint is not enabled THERE (issue #250).
///
/// Every failure collapses to [`None`], and that is the uniform-not-found property in
/// one function:
///
/// * an absent tenant, an absent environment, and a live environment that simply has
///   no such secret are all a zero-row read of `environment_secrets` and all answer
///   [`None`], so none is distinguishable from another;
/// * a scope whose key hierarchy is gone (a crypto-shredded, offboarded tenant) fails
///   the envelope open and answers [`None`] rather than a 500, because a 500 would
///   reveal that the row EXISTS, which is exactly the fact this endpoint hides;
/// * a store failure answers [`None`] too. Failing closed on an outbound credential
///   oracle costs an operator a verification they can retry; failing open would hand
///   a third party a live password oracle.
///
/// Nothing here is logged. The value never reaches a `tracing` field, an error body,
/// or a `Debug` (it is wrapped in [`SecretString`], whose `Debug` and `Display` are
/// both redacted), so the only thing that ever happens to it is the constant-time
/// comparison at the one call site.
///
/// The read is
/// [`open_value_under_platform_key_at_uniform_cost`](ironauth_store::EnvironmentSecretRepo::open_value_under_platform_key_at_uniform_cost)
/// rather than the cheap read, and that choice is the anti-timing half of the uniform
/// not-found: the plain read costs one database round trip on a miss and three on a
/// hit, which separated an armed environment from a disabled one for a caller
/// presenting nothing but a garbage bearer. The uniform-cost read spends the same
/// three round trips and three AEAD opens either way.
async fn stored_outbound_token(state: &AdminState, scope: Scope) -> Option<SecretString> {
    let sealed = state
        .store()
        .scoped(scope)
        .environment_secrets()
        .open_value_under_platform_key_at_uniform_cost(OUTBOUND_VERIFICATION_SECRET_NAME)
        .await
        .ok()?;
    let value = String::from_utf8(sealed).ok()?;
    let trimmed = value.trim();
    // Stated exactly rather than left to look load bearing: NO TEST CAN KILL A MUTANT
    // THAT DELETES THESE THREE LINES, and that is a fact about the code rather than a
    // gap in the tests. Two other guards already make an empty stored token match
    // nothing. `bearer_token` refuses an empty or whitespace-only PRESENTED bearer, so
    // the comparison below is never reached with an empty left side; and
    // `constant_time_eq` SHA-256s both sides, so a non-empty presented token can never
    // equal an empty stored one anyway. Removing this leaves behaviour identical in
    // every reachable state.
    //
    // It stays as the third of three because it is the only one of them that is local
    // to THIS function: the other two are properties of a helper above and of a hash
    // below, either of which a future edit could change without ever reading this line.
    // `outbound_verification.rs::an_empty_stored_token_authorizes_nothing` writes an
    // all-whitespace secret through the store (the shipped PUT cannot produce one: it
    // refuses anything under 32 bytes after trimming) and pins the BEHAVIOUR, which is
    // what a reader actually needs, without pretending to pin this branch.
    if trimmed.is_empty() {
        return None;
    }
    Some(SecretString::new(trimmed))
}

/// Resolve the `(tenant, environment)` scope from the path, parsing both ids through
/// the management repositories (a malformed id is the uniform not-found). This
/// endpoint is not authorized by a management [`Principal`] (the successor presents
/// the environment's own outbound shared token instead), so it resolves the scope
/// directly rather than through [`resolve_scope`].
///
/// It performs NO database access, and that is load bearing rather than incidental:
/// `parse_id` is pure parsing on both halves, so the refusal of a request that carries
/// no bearer stays entirely database-free. What MEASURES that is
/// `openapi_contract::the_outbound_bearer_check_runs_before_any_database_access`, which
/// counts connections opened against the pool, and NOT the whole-surface sweep in the
/// same file: that sweep drives every documented route over a pool it never connects,
/// which is a weaker statement and one a reordered handler satisfies too.
fn scope_from_path(
    state: &AdminState,
    tenant_id: &str,
    environment_id: &str,
) -> Result<Scope, ApiError> {
    let tenant: TenantId = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(tenant_id)?;
    let environment = state
        .store()
        .management()
        .environments(state.bootstrap_operator_id(), tenant)
        .parse_id(environment_id)?;
    Ok(Scope::new(tenant, environment))
}

/// Verify a user credential for a successor system's lazy migration.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/migration/verify-credential",
    operation_id = "verifyMigrationCredential",
    tag = "exit",
    request_body = VerifyCredentialRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The verification verdict. On success it carries the stable \
         subject and the user's profile (claims and traits), so the successor migrates the full \
         identity. A wrong password, unknown account, or fenced account returns verified=false \
         with no distinguishing oracle. Enabled and credentialed PER ENVIRONMENT through the \
         outbound-verification management endpoints; documented at docs/exit-guide.md.", body = VerifyCredentialResponse),
        (status = 400, description = "Malformed request, from a caller that already presented \
         this environment's outbound verification token", body = ErrorBody),
        (status = 404, description = "The uniform refusal. A missing bearer, a wrong bearer, an \
         environment with outbound verification disabled, an absent environment, an absent \
         tenant, and a malformed path id are ONE byte-identical answer, so no caller learns \
         which of them applied", body = ErrorBody)
    )
)]
pub async fn verify_credential(
    State(state): State<AdminState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    // 1. The bearer FIRST, and before any database access at all (issue #250). A
    //    request with no credential is the uniform not-found, indistinguishable from
    //    an absent route, and it costs one header read: an unauthenticated prober
    //    cannot enumerate which environments have an outbound migration armed, and
    //    cannot make this endpoint issue a query either.
    let Some(presented) = bearer_token(&headers) else {
        return Err(ApiError::NotFound);
    };
    // 2. The path scope, still database-free: a malformed tenant or environment id is
    //    the same uniform not-found.
    let scope = scope_from_path(&state, &tenant_id, &environment_id)?;
    // 3. Enablement AND the credential together, from THIS environment's own sealed
    //    secret. Absent tenant, absent environment, and feature-off are one zero-row
    //    read and one answer. There is no deployment-global fallback to consult.
    let Some(expected) = stored_outbound_token(&state, scope).await else {
        return Err(ApiError::NotFound);
    };
    // 4. Constant-time comparison, so a wrong token leaks neither its length nor the
    //    position of its first wrong byte, and a mismatch is the SAME uniform
    //    not-found a disabled environment gives.
    if !constant_time_eq(presented.as_bytes(), expected.expose().as_bytes()) {
        return Err(ApiError::NotFound);
    }
    let request: VerifyCredentialRequest = parse_json(&body)?;

    let verdict = verify_and_profile(&state, scope, &request).await?;
    let body = serde_json::to_string(&verdict).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Look the user up by login handle, verify the candidate password against the
/// stored one-way verifier (native Argon2id or the imported foreign hash, through
/// the shared [`ForeignHash`] dispatch), and, on success, gather the exportable
/// profile. Fenced accounts and unknown handles both return a negative verdict.
async fn verify_and_profile(
    state: &AdminState,
    scope: Scope,
    request: &VerifyCredentialRequest,
) -> Result<VerifyCredentialResponse, ApiError> {
    let user = state
        .store()
        .scoped(scope)
        .users()
        .by_identifier(&request.identifier)
        .await?;
    let Some(user) = user else {
        // Absent account: spend a comparable Argon2id verification through the SAME
        // entry, then the uniform negative, so an absent identifier is timing-
        // indistinguishable from a wrong password and the endpoint is not a
        // user-enumeration oracle (mirroring the login path's `verify_absent`).
        let _ = password_matches(None, None, &request.password);
        return Ok(negative());
    };
    // A fenced account (blocked, disabled, pending verification) never verifies: the
    // credential may be correct but the account is not permitted to authenticate,
    // exactly the login fence. The verification work is STILL spent (through the same
    // entry) so a fenced account is timing-indistinguishable from a wrong password,
    // with no distinguishing signal.
    if !user.state.can_authenticate() {
        let _ = password_matches(
            Some(&user.password_hash),
            user.foreign_password_hash.as_deref(),
            &request.password,
        );
        return Ok(negative());
    }
    if !password_matches(
        Some(&user.password_hash),
        user.foreign_password_hash.as_deref(),
        &request.password,
    ) {
        return Ok(negative());
    }

    // Verified: gather the exportable profile so the successor seeds the full
    // identity. A profile read failure never downgrades a valid verdict; the profile
    // is simply omitted.
    //
    // The traits below are the FULL document, admin-only fields included, and that is a
    // decision rather than an oversight (issue #53). It looks like a self-service read (an
    // end user's password is one of its two inputs) and it is not one: the request cannot be
    // made at all without the OPERATOR's per-environment sealed bearer, which is what arms
    // this endpoint. Its trust level is the operator's, and its purpose is the exit covenant
    // (a successor seeds the WHOLE identity so a user base migrates off IronAuth with no
    // forced reset). Redacting here would make the migration LOSSY in exactly the dimension
    // an operator can least reconstruct, which is the failure the covenant exists to
    // prevent. It is the same verdict, for the same reason, as `exportIdentities`, the other
    // route that returns the decrypted document.
    let subject = user.id.to_string();
    let claims = state
        .store()
        .scoped(scope)
        .users()
        .claims_for_subject(&subject)
        .await
        .ok()
        .flatten()
        .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
        .filter(|value| !value.as_object().is_some_and(serde_json::Map::is_empty));
    let traits = state
        .store()
        .scoped(scope)
        .users()
        .traits(&user.id)
        .await
        .ok()
        .flatten()
        .map(|(_, value)| value);
    Ok(VerifyCredentialResponse {
        verified: true,
        subject: Some(subject),
        profile: Some(VerifyProfile { claims, traits }),
    })
}

/// The uniform negative verdict, carrying no subject and no profile, so a wrong
/// password, an unknown account, and a fenced account are indistinguishable.
fn negative() -> VerifyCredentialResponse {
    VerifyCredentialResponse {
        verified: false,
        subject: None,
        profile: None,
    }
}

/// The SINGLE password-verification entry every outbound-verify branch routes
/// through (issue #58): a present, absent, or fenced account ALL spend one Argon2id
/// verification here, so none is a user-enumeration timing oracle. This mirrors the
/// login path, which spends Argon2 time on the wrong-password, fenced, and absent
/// branches alike.
///
/// * `native` = `Some` carries the user's native Argon2id verifier (or the unusable
///   sentinel for a foreign-only account, which fails to parse and falls through to
///   `foreign`); the native PHC string and every foreign scheme verify through one
///   [`ForeignHash`] dispatch.
/// * `native` = `None` means there is NO account (an absent identifier): a comparable
///   dummy Argon2id verification is spent through the SAME primitive the login path
///   uses ([`ironauth_oidc::verify_absent`]), then a non-match is returned, so the
///   absent branch costs the same as a real verify.
fn password_matches(native: Option<&str>, foreign: Option<&str>, password: &str) -> bool {
    match native {
        Some(native) => {
            let bytes = password.as_bytes();
            let native_ok = ForeignHash::parse(native).is_ok_and(|hash| hash.verify(bytes));
            native_ok
                || foreign
                    .and_then(|stored| ForeignHash::parse(stored).ok())
                    .is_some_and(|hash| hash.verify(bytes))
        }
        // No account: spend the dummy Argon2id work, always a non-match. This runs the
        // Argon2 verify INLINE rather than through the admission-controlled pool because
        // the admin crate does not host the hashing pool, and this #58 outbound
        // credential-verify migration endpoint is a far lower-risk surface than the two
        // unauthenticated OIDC endpoints the pool exists to protect: it is off in every
        // environment by default and it is reached only by a caller that already
        // presented THAT environment's own sealed token (issue #250 made the scoping
        // per-environment rather than one configured pair, which narrows this argument
        // rather than widening it), so it is not an unauthenticated cross-tenant DoS
        // lever. Justified exception to the pool boundary; see
        // scripts/hashing-pool-boundary.sh.
        None => ironauth_oidc::verify_absent(password), // pool-boundary-allow: #58 migration verify is off by default, authorized by the addressed environment's own sealed token; admin crate hosts no pool.
    }
}

// ---------------------------------------------------------------------------
// The MANAGEMENT half (issue #250): enable, inspect, rotate, and disable one
// environment's outbound-verification credential.
//
// These three are ordinary management endpoints and behave like every other one on
// the environment prefix: they take a management `Principal`, they resolve the scope
// through `resolve_scope` (so a management key scoped elsewhere gets the loud
// wrong-scope error rather than a silent success), and a write is audited.
//
// The environment precondition is NOT the same on all three, and the split is the
// issue #250 correction rather than a shortcut. The PUT arms a credential oracle, so
// it takes the ordinary `require_live_environment`: arming something inside an
// environment an operator believes is decommissioned is the defect issues #411 and
// #451 are about. The DELETE destroys one, so it takes `require_present_environment`:
// requiring liveness to DISARM made the soft delete a one-way door, because the sealed
// credential survives the deletion and no route could then destroy it. The GET takes
// the same `present` precondition as the DELETE, so the read and the disable agree
// about which environments they will talk about at all. They are deliberately NOT a generic
// environment-secrets API: they address exactly the one reserved name
// `OUTBOUND_VERIFICATION_SECRET_NAME`, so this surface cannot be used to write or
// read back any other environment secret, and in particular cannot be used to
// exfiltrate a connector credential.
//
// They carry no `Idempotency-Key` arm, following `client_scopes.rs` and
// `resource_servers.rs`: the key exists so a retried CREATE cannot mint two rows,
// and a PUT of an absolute value onto a per-scope singleton is naturally idempotent
// (applying the same token twice reaches the same state, bumping only the version).

/// One environment's outbound-verification state, WITHOUT the token (issue #250).
///
/// This view is what makes the feature operable, and it is metadata only by
/// construction: it is built from [`ironauth_store::EnvironmentSecretMetadata`],
/// which the store reads with a `SELECT` that does not name the `ciphertext` column
/// at all, so there is no code path from this response to a secret value. A token,
/// once written, is never readable back through any endpoint; it is rotated or it is
/// deleted.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OutboundVerificationView {
    /// Whether the outbound credential-verification endpoint is enabled for THIS
    /// environment. True exactly when this environment holds an outbound-verification
    /// token; the endpoint is a uniform not-found in every environment where this is
    /// false, which is every environment until an operator enables it.
    pub enabled: bool,
    /// The monotonic write version of the stored token, bumped by every rotation, or
    /// null when disabled. An operator confirms a rotation landed by watching this
    /// advance, which is the only reason it is published: the value itself never is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i32>,
    /// When the token was first written, in milliseconds since the Unix epoch, or
    /// null when disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at_unix_ms: Option<i64>,
    /// When the token was last rotated, in milliseconds since the Unix epoch, or null
    /// when disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at_unix_ms: Option<i64>,
}

impl OutboundVerificationView {
    /// The disabled view: no version and no timestamps, so the response for an
    /// environment that has never enabled the feature is a fixed three-byte-key
    /// object and carries nothing else to read.
    fn disabled() -> Self {
        Self {
            enabled: false,
            version: None,
            created_at_unix_ms: None,
            updated_at_unix_ms: None,
        }
    }

    /// The enabled view, from the secret's metadata (never its value).
    fn enabled(metadata: &ironauth_store::EnvironmentSecretMetadata) -> Self {
        Self {
            enabled: true,
            version: Some(metadata.version),
            created_at_unix_ms: Some(metadata.created_at_unix_micros / 1000),
            updated_at_unix_ms: Some(metadata.updated_at_unix_micros / 1000),
        }
    }
}

/// The body that enables or rotates an environment's outbound-verification token.
///
/// No `Debug` is derived, exactly as [`VerifyCredentialRequest`] derives none, so a
/// stray struct dump cannot spill the token an operator is writing.
#[derive(Deserialize, ToSchema)]
pub struct SetOutboundVerificationRequest {
    /// The shared bearer a successor system will present to this environment's
    /// credential-verification endpoint. Writing it enables the endpoint for this
    /// environment; writing it again rotates it, and the previous value stops working
    /// the moment the write commits. It is sealed under this environment's envelope
    /// key and is never readable back through any endpoint.
    pub token: String,
}

/// The smallest token this surface will store, in bytes.
///
/// This is a floor on a credential an operator chooses, not a password policy: the
/// endpoint it guards is a live password oracle for a whole user base, so a token
/// short enough to be guessed online would defeat the point of sealing it.
///
/// The number is 32 because that is the entropy IronAuth itself mints for the two
/// comparable shared secrets: `keys::SECRET_BYTES` (a management key) and
/// `INVITATION_TOKEN_SECRET_BYTES` in `ironauth-store` are both 32. Those are 32
/// bytes of ENTROPY and this is 32 bytes of whatever an operator typed, which is a
/// weaker thing; the floor is a wall against an obviously guessable value, not a
/// promise about the value's strength.
const MIN_OUTBOUND_TOKEN_BYTES: usize = 32;

/// Read one environment's outbound-verification state (never its token).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/migration/outbound-verification",
    operation_id = "getOutboundVerification",
    tag = "exit",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Whether outbound verification is enabled for this \
         environment, with the stored token's version and timestamps. The token itself is never \
         returned.", body = OutboundVerificationView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found. The environment must EXIST; a soft-deleted one \
         still answers, exactly as every other management read does, and exactly as the DELETE \
         on this same path does", body = ErrorBody)
    )
)]
pub async fn get_outbound_verification(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    // The SAME precondition the DELETE on this path takes, and for the same reason it
    // is `present` rather than `live`: an operator reading the state of a decommissioned
    // environment must get the truth, and the read and the disable must agree about
    // which environments they are willing to talk about. Without it this GET answered
    // `200 {"enabled":false}` for a `(tenant, environment)` that was never created,
    // which is a claim about a thing that does not exist and disagrees with the DELETE
    // next to it.
    require_present_environment(&state, &scope).await?;
    let view = match state
        .store()
        .scoped(scope)
        .environment_secrets()
        .metadata(OUTBOUND_VERIFICATION_SECRET_NAME)
        .await
    {
        Ok(metadata) => OutboundVerificationView::enabled(&metadata),
        Err(StoreError::NotFound) => OutboundVerificationView::disabled(),
        Err(error) => return Err(error.into()),
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Enable, or rotate, one environment's outbound-verification token.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/migration/outbound-verification",
    operation_id = "setOutboundVerification",
    tag = "exit",
    request_body = SetOutboundVerificationRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The token was sealed for this environment. Outbound \
         verification is now enabled here, and any previous token stopped working. The response \
         carries the new version and timestamps, never the token.", body = OutboundVerificationView),
        (status = 400, description = "Malformed request, or a token shorter than the 32-byte floor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or a lapsed sudo elevation", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found. The environment must be live: an absent or \
         soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn set_outbound_verification(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // Prove the parent environment is LIVE before sealing anything into it, exactly as
    // every other environment-scoped write does: a write into a soft-deleted
    // environment would arm a credential oracle inside something an operator believes
    // is decommissioned.
    require_live_environment(&state, &scope).await?;

    let request: SetOutboundVerificationRequest = parse_json(&body)?;
    let token = request.token.trim();
    if token.len() < MIN_OUTBOUND_TOKEN_BYTES {
        // The message names the floor and the length it received, never the token.
        return Err(ApiError::BadRequest(format!(
            "the outbound verification token must be at least {MIN_OUTBOUND_TOKEN_BYTES} bytes \
             after trimming (received {}): it authorizes a live credential-verification oracle \
             for this environment's whole user base",
            token.len()
        )));
    }
    // The store is what seals: `put` fetches this scope's active envelope DEK
    // (provisioning the scope's key hierarchy on first use), seals the plaintext with
    // the tenant, environment, secret name, and DEK version bound as associated data,
    // and writes ONLY the ciphertext. The plaintext reaches no row, no audit envelope,
    // and no response.
    // A deployment with no platform master key cannot seal, and the store answers
    // `StoreError::Encryption` for that rather than substituting a plaintext write.
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .environment_secrets()
        .put_under_platform_key(
            state.env(),
            OUTBOUND_VERIFICATION_SECRET_NAME,
            token.as_bytes(),
            None,
        )
        .await?;

    // Re-read the METADATA through the same address, so the response reports what was
    // actually stored (and, in particular, the version the rotation actually reached).
    let metadata = state
        .store()
        .scoped(scope)
        .environment_secrets()
        .metadata(OUTBOUND_VERIFICATION_SECRET_NAME)
        .await?;
    let body = serde_json::to_string(&OutboundVerificationView::enabled(&metadata))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Disable one environment's outbound verification, destroying its token.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/migration/outbound-verification",
    operation_id = "deleteOutboundVerification",
    tag = "exit",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Outbound verification is disabled for this environment and \
         its token is gone. Idempotent: disabling an already-disabled environment is the same 204."),
        (status = 401, description = "Missing or invalid credential, or a lapsed sudo elevation", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found: the environment was never created. A SOFT-DELETED \
         environment is NOT refused here, deliberately, because destroying a credential is the \
         closing direction and must never require its parent to be live", body = ErrorBody),
        (status = 409, description = "A live environment variable in this scope still references \
         the outbound-verification secret, so deleting it would leave a dangling reference. \
         Remove the referring variable first. Documented because it is structurally reachable \
         through the config-promotion apply, not because this surface creates such a reference", body = ErrorBody)
    )
)]
pub async fn delete_outbound_verification(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // PRESENT, not LIVE, and that asymmetry with `set_outbound_verification` above is
    // the point rather than an oversight (issue #250).
    //
    // Soft-deleting an environment cascades to almost nothing, so the sealed credential
    // survives the deletion and the verify endpoint KEEPS ANSWERING 200 with a verified
    // credential and the user's profile. That behaviour is deliberate and older than
    // this endpoint (a successor draining an environment is exactly who is still
    // reading it). What must therefore never happen is the OFF SWITCH being fenced:
    // with a liveness check here, an armed environment that is then deleted can no
    // longer be disarmed by any route, and there is no environment-restore endpoint to
    // get back to a state where it could be. MEASURED before this line said `present`:
    // environment DELETE 204, verify 200 verified, disable 404, rotate 404.
    //
    // ABSENT still refuses, and that half is not decorative: deleting a row that was
    // never there violates no foreign key, so the store answers its own not-found and
    // the idempotency arm below turns it into a 204. Dropping this call therefore does
    // NOT fail the absent-environment sweep by way of a constraint; it fails it by way
    // of this check and nothing else.
    require_present_environment(&state, &scope).await?;
    match state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .environment_secrets()
        .delete(state.env(), OUTBOUND_VERIFICATION_SECRET_NAME)
        .await
    {
        // The two success arms are deliberately the SAME answer, which is why they are
        // written as one: disabling something already disabled is a SUCCESS, not a 404,
        // because the caller asked for a state and that state holds. A 404 for the
        // absent case would also rebuild, on the management side, exactly the
        // enablement oracle the verify endpoint refuses to be, for any credential that
        // can address the environment at all.
        Ok(()) | Err(StoreError::NotFound) => Ok(no_content()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A native Argon2id PHC verifier for `password`, exactly what the login path
    /// stores for a normally-registered user.
    fn argon2_hash(password: &str) -> String {
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::encode_b64(b"outbound-verify-salt").expect("salt");
        argon2::Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .expect("argon2 hash")
            .to_string()
    }

    /// The user-enumeration timing-oracle defense (issue #58): the absent branch, the
    /// fenced/wrong-password branch, and the correct-password branch ALL route through
    /// the one `password_matches` entry, so absent, wrong-password, and correct are
    /// timing-indistinguishable. Asserting wall-clock is flaky; this asserts the
    /// STRUCTURAL property (one shared entry, and the absent branch is not a
    /// short-circuit) plus the correctness of each verdict.
    #[test]
    fn absent_and_wrong_password_route_through_the_same_verify_entry() {
        let native = argon2_hash("correct horse");

        // The correct password matches through the shared entry.
        assert!(
            password_matches(Some(&native), None, "correct horse"),
            "the correct password verifies through the shared entry"
        );
        // A wrong password does not match, routing through the SAME entry (a real
        // Argon2id verify is spent).
        assert!(
            !password_matches(Some(&native), None, "wrong"),
            "a wrong password does not verify"
        );
        // An ABSENT account (native = None) routes through the SAME entry and spends
        // the dummy Argon2id verify rather than short-circuiting, and never matches:
        // it is timing-indistinguishable from a wrong password, so the endpoint is not
        // a user-enumeration oracle.
        assert!(
            !password_matches(None, None, "correct horse"),
            "an absent account never verifies, and spends the dummy verify work"
        );
        assert!(
            !password_matches(None, None, ""),
            "an absent account with an empty candidate never verifies"
        );
    }
}
