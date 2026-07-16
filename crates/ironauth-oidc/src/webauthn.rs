// SPDX-License-Identifier: MIT OR Apache-2.0

//! The WebAuthn passkey ceremony endpoints (issue #65).
//!
//! Four scope-routed JSON endpoints implement WebAuthn Level 3 registration and
//! authentication, mounted under `/t/{tenant}/e/{environment}/webauthn/...`. The
//! per-environment RP ID and origin are resolved from the serving origin (or the
//! configured override, validated at startup), so the ceremony is bound to the
//! right relying party and environment scope.
//!
//! - `register/options` and `register/verify` enroll a passkey for the
//!   AUTHENTICATED user (a session cookie is required). `register/options`
//!   populates `excludeCredentials` from the user's existing passkeys so the same
//!   authenticator cannot enrol twice.
//! - `authenticate/options` and `authenticate/verify` sign a user in with a
//!   discoverable credential (conditional UI). The assertion resolves the user
//!   through the credential's stored subject; on success the same server-side
//!   session the password login establishes is created, recording a passkey
//!   [`AuthenticationEvent`] so the honest `phr`/`phrh` ACR and amr flow through
//!   the whole token chain.
//!
//! Every ceremony draws its single-use challenge from the store's challenge table
//! (minted from the entropy seam, consumed exactly once), verifies the response in
//! the pure `ironauth-webauthn` core, and persists only AFTER a successful
//! verification, so a cancelled or failed ceremony leaves no partial row. Every
//! failure returns the same non-enumerating, user-actionable error.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{
    ConsumedChallenge, CorrelationId, NewWebauthnCredential, Scope, StoreError, UserId,
    WebauthnCeremony, WebauthnCredentialId, WebauthnCredentialOutcome, WebauthnCredentialRecord,
};
use ironauth_webauthn::{
    AuthenticationResponse, CredentialDescriptor, RegisteredCredential, RegistrationResponse,
    SignCountVerdict, StoredCredential, UserVerification, VerificationParams,
    authentication_options, registration_options, verify_authentication, verify_registration,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::authn::AuthenticationEvent;
use crate::interaction;
use crate::state::{OidcState, WebauthnRelyingParty};
use crate::util::epoch_micros;
use crate::wellknown::{not_found, parse_scope};

/// The default nickname applied to a newly registered passkey when the client sends
/// none.
const DEFAULT_NICKNAME: &str = "Passkey";
/// The WebAuthn ceremony timeout advertised to the client, in milliseconds.
const CEREMONY_TIMEOUT_MS: u64 = 300_000;

/// The registration-verify request body: the challenge handle and the ceremony
/// response.
#[derive(Debug, Deserialize)]
pub struct RegisterVerifyBody {
    /// The challenge handle returned by `register/options`.
    #[serde(rename = "challengeId")]
    challenge_id: String,
    /// The optional nickname (repeated here so verify can seal it).
    #[serde(default)]
    nickname: Option<String>,
    /// The `navigator.credentials.create` result.
    credential: RegistrationResponse,
}

/// The authentication-verify request body: the challenge handle and the assertion.
#[derive(Debug, Deserialize)]
pub struct AuthenticateVerifyBody {
    /// The challenge handle returned by `authenticate/options`.
    #[serde(rename = "challengeId")]
    challenge_id: String,
    /// The `navigator.credentials.get` result.
    credential: AuthenticationResponse,
}

/// `POST /t/{tenant}/e/{environment}/webauthn/register/options`: begin a passkey
/// registration for the authenticated user. Returns the
/// `PublicKeyCredentialCreationOptions` plus the single-use challenge handle.
pub async fn register_options(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !state.webauthn_enabled() {
        return not_found();
    }
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let (scope, subject) = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Some(rp) = state.webauthn_relying_party() else {
        return ceremony_error();
    };

    // excludeCredentials: every passkey the user already has, so the authenticator
    // refuses to enrol the same one twice (the dedupe).
    let Ok(descriptors) = state
        .store()
        .scoped(scope)
        .webauthn_credentials()
        .descriptors(&subject)
        .await
    else {
        return ceremony_error();
    };
    let exclude: Vec<CredentialDescriptor> = descriptors
        .into_iter()
        .map(|d| CredentialDescriptor {
            id: d.credential_id,
            transports: d.transports,
        })
        .collect();

    let Ok(issued) = state
        .store()
        .scoped(scope)
        .webauthn_challenges()
        .issue(
            state.env(),
            WebauthnCeremony::Register,
            Some(&subject),
            challenge_ttl_secs(&state),
        )
        .await
    else {
        return ceremony_error();
    };

    let user = ironauth_webauthn::CeremonyUser {
        // The user handle is the opaque usr_ id, never a plain email.
        id: subject.to_string().into_bytes(),
        name: subject.to_string(),
        display_name: subject.to_string(),
    };
    let options = registration_options(
        &relying_party(&rp),
        &user,
        &issued.challenge,
        &exclude,
        CEREMONY_TIMEOUT_MS,
        uv_requirement(&state),
    );
    json_response(
        StatusCode::OK,
        json!({ "challengeId": issued.id, "publicKey": options }),
    )
}

/// `POST /t/{tenant}/e/{environment}/webauthn/register/verify`: verify a
/// registration ceremony and persist the passkey for the authenticated user.
pub async fn register_verify(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<RegisterVerifyBody>,
) -> Response {
    if !state.webauthn_enabled() {
        return not_found();
    }
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let (scope, subject) = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Some(rp) = state.webauthn_relying_party() else {
        return ceremony_error();
    };

    let Some(challenge) = consume(
        &state,
        scope,
        &body.challenge_id,
        WebauthnCeremony::Register,
    )
    .await
    else {
        return ceremony_error();
    };
    // A registration challenge is bound to the subject it was issued for.
    if challenge.subject.as_deref() != Some(subject.to_string().as_str()) {
        return ceremony_error();
    }

    let params = VerificationParams {
        rp_id: &rp.rp_id,
        allowed_origins: &rp.origins,
        expected_challenge: &challenge.challenge,
        require_user_verification: state.webauthn_require_user_verification(),
    };
    let registered: RegisteredCredential = match verify_registration(&body.credential, &params) {
        Ok(credential) => credential,
        Err(_) => return ceremony_error(),
    };

    let nickname = body
        .nickname
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty() && n.len() <= 200)
        .unwrap_or(DEFAULT_NICKNAME);
    let new_credential = NewWebauthnCredential {
        credential_id: &registered.credential_id,
        cose_public_key: &registered.cose_public_key,
        sign_count: registered.sign_count,
        aaguid: &registered.aaguid,
        transports: &registered.transports,
        backup_eligible: registered.backup_eligible,
        backup_state: registered.backup_state,
        discoverable: registered.discoverable,
        nickname,
    };
    let actor = interaction::user_actor(&subject);
    match state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .webauthn_credentials()
        .register(state.env(), &subject, &new_credential)
        .await
    {
        Ok(id) => json_response(
            StatusCode::CREATED,
            json!({
                "id": id.to_string(),
                "nickname": nickname,
                "backup_eligible": registered.backup_eligible,
                "backup_state": registered.backup_state,
                "discoverable": registered.discoverable,
                "aaguid": hex(&registered.aaguid),
                "transports": registered.transports,
            }),
        ),
        // A duplicate authenticator (past the excludeCredentials hint) is a
        // user-actionable conflict, distinct only in status from the generic error.
        Err(StoreError::Conflict) => json_response(
            StatusCode::CONFLICT,
            json!({ "error": "already_registered" }),
        ),
        Err(_) => ceremony_error(),
    }
}

/// `POST /t/{tenant}/e/{environment}/webauthn/authenticate/options`: begin a
/// discoverable-credential sign-in. No session is required (this IS the sign-in).
pub async fn authenticate_options(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !state.webauthn_enabled() {
        return not_found();
    }
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    let Some(rp) = state.webauthn_relying_party() else {
        return ceremony_error();
    };
    let Ok(issued) = state
        .store()
        .scoped(scope)
        .webauthn_challenges()
        .issue(
            state.env(),
            WebauthnCeremony::Authenticate,
            None,
            challenge_ttl_secs(&state),
        )
        .await
    else {
        return ceremony_error();
    };
    // Empty allowCredentials: a discoverable-credential / conditional-UI sign-in.
    let options = authentication_options(
        &rp.rp_id,
        &issued.challenge,
        &[],
        CEREMONY_TIMEOUT_MS,
        uv_requirement(&state),
    );
    json_response(
        StatusCode::OK,
        json!({ "challengeId": issued.id, "publicKey": options }),
    )
}

/// `POST /t/{tenant}/e/{environment}/webauthn/authenticate/verify`: verify an
/// assertion, apply the clone-detection policy, and establish the sign-in session.
// A linear ceremony handler: consume the challenge, resolve the credential, verify,
// apply the clone policy, and establish the session. Splitting it would scatter the
// fail-closed early returns that are the point.
#[allow(clippy::too_many_lines)]
pub async fn authenticate_verify(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<AuthenticateVerifyBody>,
) -> Response {
    if !state.webauthn_enabled() {
        return not_found();
    }
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    let Some(rp) = state.webauthn_relying_party() else {
        return ceremony_error();
    };

    let Some(challenge) = consume(
        &state,
        scope,
        &body.challenge_id,
        WebauthnCeremony::Authenticate,
    )
    .await
    else {
        return ceremony_error();
    };

    // Resolve the credential the assertion presented (a discoverable sign-in
    // resolves the user THROUGH the credential's stored subject).
    let Some(raw_id) = body
        .credential
        .raw_id
        .as_deref()
        .or(body.credential.id.as_deref())
        .and_then(ironauth_webauthn::b64_decode)
    else {
        return ceremony_error();
    };
    // A missing credential is indistinguishable on the wire from a bad signature:
    // both are the generic ceremony error.
    let Ok(Some(target)) = state
        .store()
        .scoped(scope)
        .webauthn_credentials()
        .find_for_assertion(&raw_id)
        .await
    else {
        return ceremony_error();
    };

    // Defensive userHandle check (WebAuthn L3 7.2): the subject is resolved through
    // the credential id (above), so the userHandle is not trusted for resolution.
    // But if the response carries one, it MUST match the credential's stored
    // subject; a mismatch is a malformed or crafted assertion and is refused.
    if let Some(handle_b64) = body.credential.response.user_handle.as_deref() {
        let Some(handle) = ironauth_webauthn::b64_decode(handle_b64) else {
            return ceremony_error();
        };
        if handle != target.subject.as_bytes() {
            return ceremony_error();
        }
    }

    let params = VerificationParams {
        rp_id: &rp.rp_id,
        allowed_origins: &rp.origins,
        expected_challenge: &challenge.challenge,
        require_user_verification: state.webauthn_require_user_verification(),
    };
    let stored = StoredCredential {
        cose_public_key: &target.cose_public_key,
        sign_count: target.sign_count,
    };
    let Ok(outcome) = verify_authentication(&body.credential, &stored, &params) else {
        return ceremony_error();
    };

    // Clone-detection policy: a regressing counter records the event and applies
    // the per-deployment warn/block policy.
    let regressed = matches!(
        outcome.sign_count_verdict,
        SignCountVerdict::Regressed { .. }
    );
    let block = regressed && state.webauthn_clone_detection_block();
    let Ok(credential_id) = WebauthnCredentialId::parse_in_scope(&target.id, &scope) else {
        return ceremony_error();
    };
    // The assertion resolves the subject through the credential; parse it back to a
    // typed id for the acting principal and the session.
    let Ok(subject) = UserId::parse_in_scope(&target.subject, &scope) else {
        return ceremony_error();
    };

    // Backup-eligibility immutability (WebAuthn L3 7.2): BE is fixed for a
    // credential's life. The assurance (phr vs phrh) is derived from the STORED,
    // registration-time BE, never from this assertion's mutable flag. A DIVERGENCE
    // between the presented BE and the stored BE is a spec violation and a signal of
    // a cloned or spoofed authenticator: reject the sign-in with the non-enumerating
    // ceremony error and write a security/audit event. No partial state is advanced.
    if outcome.backup_eligible != target.backup_eligible {
        let _ = state
            .store()
            .scoped(scope)
            .acting(
                interaction::user_actor(&subject),
                CorrelationId::generate(state.env()),
            )
            .webauthn_credentials()
            .record_backup_eligibility_mismatch(
                state.env(),
                &credential_id,
                target.backup_eligible,
                outcome.backup_eligible,
            )
            .await;
        return ceremony_error();
    }

    let policy_detail = if block {
        "clone detection: sign-count regression, policy=block"
    } else if regressed {
        "clone detection: sign-count regression, policy=warn"
    } else {
        "assertion recorded"
    };
    let record = state
        .store()
        .scoped(scope)
        .acting(
            interaction::user_actor(&subject),
            CorrelationId::generate(state.env()),
        )
        .webauthn_credentials()
        .record_assertion(
            state.env(),
            &credential_id,
            outcome.sign_count,
            outcome.backup_state,
            regressed,
            policy_detail,
        )
        .await;
    if record.is_err() {
        return ceremony_error();
    }
    if block {
        // The policy blocks the sign-in on a detected clone; the event is recorded.
        return json_response(
            StatusCode::FORBIDDEN,
            json!({ "error": "credential_blocked" }),
        );
    }

    // Record the honest event so the phr/phrh ACR and the amr flow through the whole
    // token chain. The assurance is derived from the STORED, registration-time BE
    // (trustworthy, immutable), NOT the assertion's mutable flag; the amr reflects
    // whether this assertion actually verified the user (`user_verified`), so a
    // presence-only login never claims a verification factor it did not perform.
    let event = AuthenticationEvent::passkey(
        epoch_micros(state.now()),
        target.backup_eligible,
        outcome.user_verified,
    );
    let Ok(cookies) = interaction::establish_session(
        &state,
        scope,
        &target.subject,
        &event,
        interaction::user_actor(&subject),
        &headers,
    )
    .await
    else {
        return ceremony_error();
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store");
    for value in cookies.header_values() {
        builder = builder.header(header::SET_COOKIE, value);
    }
    let payload = json!({
        "status": "ok",
        "acr": crate::authn::achieved_acr(event.methods()),
        "amr": crate::authn::amr_values(event.methods()),
    });
    builder
        .body(axum::body::Body::from(payload.to_string()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// `GET /t/{tenant}/e/{environment}/webauthn/credentials`: list the AUTHENTICATED
/// caller's OWN registered passkeys (issue #65) with their live metadata: the `pky_`
/// id, nickname, AAGUID and transports, the immutable registration-time BE and the
/// live BS (updated on every assertion), discoverability (rk), the clone-detected
/// flag, and the created/last-used timestamps. Filtered on the authenticated
/// subject, so another user's passkeys are never listed (the #61 IDOR discipline).
pub async fn list_credentials(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !state.webauthn_enabled() {
        return not_found();
    }
    let (scope, subject) = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Ok(records) = state
        .store()
        .scoped(scope)
        .webauthn_credentials()
        .list(&subject, i64::from(u8::MAX), None)
        .await
    else {
        return ceremony_error();
    };
    let passkeys: Vec<Value> = records.iter().map(passkey_json).collect();
    json_response(StatusCode::OK, json!({ "passkeys": passkeys }))
}

/// The rename-passkey request body: the credential to rename and the new nickname.
#[derive(Debug, Deserialize)]
pub struct RenameCredentialBody {
    /// The `pky_` credential id. Must be one of the caller's OWN passkeys; any other
    /// value (another user's, an absent one, a cross-scope one) is the uniform
    /// not-found.
    #[serde(rename = "credentialId")]
    credential_id: String,
    /// The new user-authored nickname (sealed at rest).
    nickname: String,
}

/// `POST /t/{tenant}/e/{environment}/webauthn/credentials/rename`: change the
/// nickname of one of the caller's OWN passkeys (issue #65). Same-origin guarded
/// (CSRF), authenticated by the caller's session, subject-bound at the store layer,
/// and audited on success. Another user's credential is the uniform not-found.
pub async fn rename_credential(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<RenameCredentialBody>,
) -> Response {
    if !state.webauthn_enabled() {
        return not_found();
    }
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let (scope, subject) = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let nickname = body.nickname.trim();
    if nickname.is_empty() || nickname.len() > 200 {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_nickname" }),
        );
    }
    let Ok(id) = state
        .store()
        .scoped(scope)
        .webauthn_credentials()
        .parse_id(&body.credential_id)
    else {
        return credential_not_found();
    };
    let outcome = state
        .store()
        .scoped(scope)
        .acting(
            interaction::user_actor(&subject),
            CorrelationId::generate(state.env()),
        )
        .webauthn_credentials()
        .rename(state.env(), &subject, &id, nickname)
        .await;
    match outcome {
        Ok(WebauthnCredentialOutcome::Applied) => json_response(
            StatusCode::OK,
            json!({ "id": id.to_string(), "nickname": nickname }),
        ),
        Ok(WebauthnCredentialOutcome::NotFound) => credential_not_found(),
        Err(_) => ceremony_error(),
    }
}

/// The remove-passkey request body: the credential to remove.
#[derive(Debug, Deserialize)]
pub struct RemoveCredentialBody {
    /// The `pky_` credential id. Must be one of the caller's OWN passkeys; any other
    /// value is the uniform not-found.
    #[serde(rename = "credentialId")]
    credential_id: String,
}

/// `POST /t/{tenant}/e/{environment}/webauthn/credentials/remove`: remove one of the
/// caller's OWN passkeys (issue #65). Same-origin guarded (CSRF), authenticated,
/// subject-bound at the store layer, and audited on success. Another user's
/// credential is the uniform not-found and is never removed.
pub async fn remove_credential(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<RemoveCredentialBody>,
) -> Response {
    if !state.webauthn_enabled() {
        return not_found();
    }
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let (scope, subject) = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Ok(id) = state
        .store()
        .scoped(scope)
        .webauthn_credentials()
        .parse_id(&body.credential_id)
    else {
        return credential_not_found();
    };
    let outcome = state
        .store()
        .scoped(scope)
        .acting(
            interaction::user_actor(&subject),
            CorrelationId::generate(state.env()),
        )
        .webauthn_credentials()
        .remove(state.env(), &subject, &id)
        .await;
    match outcome {
        Ok(WebauthnCredentialOutcome::Applied) => json_response(
            StatusCode::OK,
            json!({ "id": id.to_string(), "removed": true }),
        ),
        Ok(WebauthnCredentialOutcome::NotFound) => credential_not_found(),
        Err(_) => ceremony_error(),
    }
}

// --- helpers ---

/// Resolve the authenticated user (session subject) and scope for a registration
/// endpoint, or an error response.
async fn authenticate(
    state: &OidcState,
    tenant_id: &str,
    environment_id: &str,
    headers: &HeaderMap,
) -> Result<(Scope, UserId), Response> {
    let Some(scope) = parse_scope(tenant_id, environment_id) else {
        return Err(not_found());
    };
    let Some(session) = interaction::resolve_session(state, scope, headers).await else {
        return Err(unauthenticated());
    };
    let Ok(subject) = UserId::parse_in_scope(&session.subject, &scope) else {
        return Err(unauthenticated());
    };
    Ok((scope, subject))
}

/// Consume a single-use challenge for `ceremony`, returning its bytes and bound
/// subject, or `None` on any parse/consume failure.
async fn consume(
    state: &OidcState,
    scope: Scope,
    challenge_id: &str,
    ceremony: WebauthnCeremony,
) -> Option<ConsumedChallenge> {
    let handle = state
        .store()
        .scoped(scope)
        .webauthn_challenges()
        .parse_id(challenge_id)
        .ok()?;
    state
        .store()
        .scoped(scope)
        .webauthn_challenges()
        .consume(state.env(), &handle, ceremony)
        .await
        .ok()
        .flatten()
}

fn relying_party(rp: &WebauthnRelyingParty) -> ironauth_webauthn::RelyingParty {
    ironauth_webauthn::RelyingParty {
        id: rp.rp_id.clone(),
        name: "IronAuth".to_owned(),
    }
}

fn uv_requirement(state: &OidcState) -> UserVerification {
    if state.webauthn_require_user_verification() {
        UserVerification::Required
    } else {
        UserVerification::Preferred
    }
}

fn challenge_ttl_secs(state: &OidcState) -> i64 {
    i64::try_from(state.webauthn_challenge_ttl_secs()).unwrap_or(300)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The JSON projection of one registered passkey for the credential API (issue #65):
/// its `pky_` id, nickname, AAGUID and transports, the immutable registration-time
/// BE and the live BS, discoverability (rk), the clone-detected flag, and the
/// created/last-used timestamps. No secret is exposed (never the COSE key).
fn passkey_json(record: &WebauthnCredentialRecord) -> Value {
    json!({
        "id": record.id,
        "nickname": record.nickname,
        "aaguid": hex(&record.aaguid),
        "transports": record.transports,
        "backup_eligible": record.backup_eligible,
        "backup_state": record.backup_state,
        "discoverable": record.discoverable,
        "clone_detected": record.clone_detected,
        "created_at": record.created_at_unix_micros,
        "last_used_at": record.last_used_at_unix_micros,
    })
}

/// The uniform not-found for a credential the caller does not own (another user's,
/// an absent one, or a cross-scope id): byte-identical to a genuinely absent
/// resource, so it is never an existence oracle.
fn credential_not_found() -> Response {
    json_response(StatusCode::NOT_FOUND, json!({ "error": "not_found" }))
}

fn json_response(status: StatusCode, body: Value) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

/// The single non-enumerating ceremony error. Every failure (a bad challenge, a
/// bad signature, a missing credential, an origin/RP-ID mismatch) collapses to
/// this, so the response is never an oracle.
fn ceremony_error() -> Response {
    json_response(
        StatusCode::BAD_REQUEST,
        json!({
            "error": "ceremony_failed",
            "message": "The passkey could not be verified. Please try again.",
        }),
    )
}

fn forbidden() -> Response {
    json_response(StatusCode::FORBIDDEN, json!({ "error": "forbidden" }))
}

fn unauthenticated() -> Response {
    json_response(
        StatusCode::UNAUTHORIZED,
        json!({ "error": "unauthenticated" }),
    )
}
