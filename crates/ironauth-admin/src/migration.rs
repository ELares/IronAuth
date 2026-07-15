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
//! # Posture
//!
//! Enablement and its credential are environment-scoped config, DISABLED BY DEFAULT
//! ([`ironauth_config::AdminConfig::outbound_verification_enabled`] /
//! `outbound_verification_token`). Exposing a live credential oracle to a third
//! party is an explicit per-deployment opt-in: when disabled the endpoint is a
//! uniform not-found, and even when enabled it authorizes ONLY a caller presenting
//! the configured shared token (a distinct credential from the operator token and
//! every management key). A request missing a bearer is unauthorized exactly as the
//! rest of the management API is.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use ironauth_import::ForeignHash;
use ironauth_store::{Scope, TenantId};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::response::json;
use crate::state::AdminState;

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

/// Extract the `Bearer` token from the `Authorization` header, or the uniform
/// unauthorized error (consistent with the rest of the management API: a request
/// missing a credential is 401 before anything else).
fn bearer_token(headers: &HeaderMap) -> Result<String, ApiError> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("missing Authorization header".to_owned()))?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            ApiError::Unauthorized("expected a non-empty Authorization: Bearer token".to_owned())
        })?;
    Ok(token.to_owned())
}

/// Resolve the `(tenant, environment)` scope from the path, parsing both ids through
/// the management repositories (a malformed id is the uniform not-found). This
/// endpoint is not authorized by a management [`crate::auth::Principal`] (the
/// successor presents the outbound shared token instead), so it resolves the scope
/// directly rather than through `require_environment`.
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
        .environments(tenant)
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
         with no distinguishing oracle. Enabled and credentialed through environment-scoped \
         config; documented at docs/exit-guide.md.", body = VerifyCredentialResponse),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid outbound verification token", body = ErrorBody),
        (status = 404, description = "The endpoint is disabled, or the environment was not found", body = ErrorBody)
    )
)]
pub async fn verify_credential(
    State(state): State<AdminState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    // A missing bearer is unauthorized exactly as everywhere else, checked before the
    // enablement gate so an unauthenticated probe is a uniform 401.
    let token = bearer_token(&headers)?;
    // Disabled by default: the endpoint is a uniform not-found until an operator
    // opts in, so its existence is not revealed to a credentialed-but-unenabled call.
    if !state.outbound_verification_enabled() {
        return Err(ApiError::NotFound);
    }
    // Enabled: authorize ONLY the configured outbound token (fail closed when unset).
    if !state.match_outbound_verification_token(&token) {
        return Err(ApiError::Unauthorized(
            "invalid outbound verification token".to_owned(),
        ));
    }
    let scope = scope_from_path(&state, &tenant_id, &environment_id)?;
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
        return Ok(negative());
    };
    // A fenced account (blocked, disabled, pending verification) never verifies: the
    // credential may be correct but the account is not permitted to authenticate,
    // exactly the login fence, with no distinguishing signal.
    if !user.state.can_authenticate() {
        return Ok(negative());
    }
    let password = request.password.as_bytes();
    // The native Argon2id PHC string and every foreign scheme verify through one
    // dispatch; the unusable sentinel (a credential-less or foreign-only account)
    // fails to parse and falls through to the foreign hash.
    let native_ok = ForeignHash::parse(&user.password_hash).is_ok_and(|hash| hash.verify(password));
    let foreign_ok = !native_ok
        && user
            .foreign_password_hash
            .as_deref()
            .and_then(|stored| ForeignHash::parse(stored).ok())
            .is_some_and(|hash| hash.verify(password));
    if !(native_ok || foreign_ok) {
        return Ok(negative());
    }

    // Verified: gather the exportable profile so the successor seeds the full
    // identity. A profile read failure never downgrades a valid verdict; the profile
    // is simply omitted.
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
