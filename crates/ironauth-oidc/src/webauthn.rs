// SPDX-License-Identifier: MIT OR Apache-2.0

//! The WebAuthn passkey ceremony endpoints (issue #65).
//!
//! Four scope-routed JSON endpoints implement WebAuthn Level 3 registration and
//! authentication, mounted under `/t/{tenant}/e/{environment}/webauthn/...`. The
//! per-environment RP ID and origin are resolved from the serving origin (or the
//! configured override, validated at startup), so the ceremony is bound to the
//! right relying party and environment scope. The accepted origin set is the
//! serving origin PLUS the configured related origins (issue #67, WebAuthn Level 3
//! Related Origin Requests): an assertion from a listed related origin verifies
//! against the same RP ID, while an unlisted origin still fails with the
//! non-enumerating ceremony error. The related-origin allowlist is also the
//! cross-site CSRF allowlist for these endpoints (a related-origin ceremony is a
//! legitimately cross-site POST), via [`interaction::related_origin_ok`].
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
    AuthPath, ConsumedChallenge, CorrelationId, CredentialRemoveOutcome, NewWebauthnCredential,
    Scope, StoreError, UserId, WebauthnCeremony, WebauthnCredentialId, WebauthnCredentialOutcome,
    WebauthnCredentialRecord,
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
    let Some(rp) = state.webauthn_relying_party() else {
        return ceremony_error();
    };
    if !interaction::related_origin_ok(&headers, &rp.origins) {
        return forbidden();
    }
    let (scope, subject) = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(pair) => pair,
        Err(response) => return response,
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
    let Some(rp) = state.webauthn_relying_party() else {
        return ceremony_error();
    };
    if !interaction::related_origin_ok(&headers, &rp.origins) {
        return forbidden();
    }
    let (scope, subject) = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(pair) => pair,
        Err(response) => return response,
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

    // Attestation policy (issue #66 PR B): under the tenant's `direct` attestation
    // mode, evaluate the presented AAGUID against the allow/deny rules and validate
    // the attestation statement against the verified FIDO MDS3 cache. A non-allowlisted
    // AAGUID (or an unsupported format, a spoofed AAGUID, or a chain that does not reach
    // a trusted root) is a clean fail-closed REJECT, never a silent downgrade. The
    // returned verdict is stamped onto the credential row as a reg-time-immutable fact;
    // a login later reads it to record the attested rung.
    let Ok(attestation) =
        evaluate_registration_attestation(&state, scope, &body.credential, &registered).await
    else {
        return ceremony_error();
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
        attestation_type: attestation.attestation_type.as_str(),
        attestation_verified: attestation.model_verified,
        attestation_fmt: attestation.fmt,
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

/// Evaluate the tenant attestation policy for a registration (issue #66 PR B).
///
/// Returns the [`AttestationOutcome`] to stamp onto the credential row. In the
/// default `none` mode the credential records an unattested verdict and always
/// succeeds. Under `direct` mode this ENFORCES the policy: the AAGUID must be
/// explicitly allow-listed (a denied or unlisted AAGUID is `Err(())`, a fail-closed
/// reject), and the attestation statement is verified against the scope's verified
/// FIDO MDS3 cache; an unsupported format, a spoofed AAGUID, a bad signature, or a
/// chain that does not reach a trusted MDS3 root is `Err(())`. `model_verified` is
/// `true` only for a basic attestation whose chain terminated at a trusted root, so
/// the attested credential class is never claimed on an unproven authenticator.
async fn evaluate_registration_attestation(
    state: &OidcState,
    scope: Scope,
    credential: &RegistrationResponse,
    registered: &RegisteredCredential,
) -> Result<ironauth_webauthn::AttestationOutcome, ()> {
    use ironauth_webauthn::AttestationType;

    let mode = state
        .store()
        .scoped(scope)
        .attestation_config()
        .get()
        .await
        .map_err(|_| ())?
        .map_or_else(|| "none".to_owned(), |config| config.mode);

    if mode != "direct" {
        // No attestation requested: record the unattested verdict, always succeed.
        return Ok(ironauth_webauthn::AttestationOutcome {
            attestation_type: AttestationType::None,
            fmt: "none",
            model_verified: false,
        });
    }

    // Under `direct`, the AAGUID must be explicitly allow-listed.
    let disposition = state
        .store()
        .scoped(scope)
        .aaguid_rules()
        .disposition_for(&registered.aaguid)
        .await
        .map_err(|_| ())?;
    if disposition.as_deref() != Some("allow") {
        return Err(());
    }

    let attestation_bytes =
        ironauth_webauthn::b64_decode(&credential.response.attestation_object).ok_or(())?;
    let attestation =
        ironauth_webauthn::parse_attestation_object(&attestation_bytes).map_err(|_| ())?;
    let client_data_bytes =
        ironauth_webauthn::b64_decode(&credential.response.client_data_json).ok_or(())?;
    let client_data_hash = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&client_data_bytes)
    };
    let credential_key =
        ironauth_webauthn::parse_cose_key(&registered.cose_public_key).map_err(|_| ())?;

    // The trusted attestation roots for this AAGUID come from the VERIFIED MDS3 cache
    // (an empty set when no snapshot covers the model, so basic attestation fails
    // closed while self/none attestation still record an honest unverified verdict).
    let trust_anchors = mds3_trust_anchors_for(state, scope, &registered.aaguid).await?;
    let now_unix = epoch_micros(state.now()) / 1_000_000;

    ironauth_webauthn::verify_attestation(
        &attestation,
        &client_data_hash,
        &credential_key,
        &registered.aaguid,
        &trust_anchors,
        now_unix,
    )
    .map_err(|_| ())
}

/// The trusted attestation root certificates (raw DER) for an AAGUID, read from the
/// scope's verified MDS3 BLOB cache. An empty vector when no cache snapshot exists or
/// no entry covers the AAGUID, which makes a basic attestation fail closed.
async fn mds3_trust_anchors_for(
    state: &OidcState,
    scope: Scope,
    aaguid: &[u8; 16],
) -> Result<Vec<Vec<u8>>, ()> {
    let Some(cache) = state
        .store()
        .scoped(scope)
        .mds3_blob_cache()
        .get()
        .await
        .map_err(|_| ())?
    else {
        return Ok(Vec::new());
    };
    let payload: ironauth_webauthn::mds3::Mds3Payload =
        serde_json::from_value(cache.payload_jsonb).map_err(|_| ())?;
    Ok(payload
        .entries
        .into_iter()
        .find(|entry| &entry.aaguid == aaguid)
        .map(|entry| entry.attestation_root_certs)
        .unwrap_or_default())
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
    let Some(rp) = state.webauthn_relying_party() else {
        return ceremony_error();
    };
    if !interaction::related_origin_ok(&headers, &rp.origins) {
        return forbidden();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
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
    let Some(rp) = state.webauthn_relying_party() else {
        return ceremony_error();
    };
    if !interaction::related_origin_ok(&headers, &rp.origins) {
        return forbidden();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };

    // Credential-abuse regulation for the PASSKEY path (issue #64 MEDIUM-2), keyed on the
    // non-forgeable resolved peer IP and governed INDEPENDENTLY of the password path (its
    // own `AuthPath::Passkey` counters and bans). This RECORDS the attempt and applies any
    // IP-scoped or `all`-scoped ban plus the per-IP escalation, so a passkey/`all` ban
    // takes effect and passkey abuse throttles on its OWN counters; a password-failure
    // spray (a different path) can never throttle or ban the passkey path. No identifier is
    // presented in a discoverable sign-in, so the account dimension is checked below once
    // the assertion resolves the credential to its subject.
    let regulation_ctx = crate::abuse::AttemptContext {
        path: AuthPath::Passkey,
        scope,
        ip: crate::abuse::resolved_client_ip(&headers),
        identifier: None,
        account_id: None,
        client_id: None,
    };
    if let crate::abuse::RegulationOutcome::Throttled(snapshot) =
        state.regulate_before(&regulation_ctx).await
    {
        return passkey_throttled(&snapshot);
    }

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

    // Account-scoped passkey/`all` ban check (issue #64 MEDIUM-2): now that the assertion
    // has resolved the credential to its subject, honor an operator ban placed on THIS
    // account for the passkey path (or an `all` ban). Independent of the password path: a
    // `password` ban never matches here, so failed-password spray cannot lock the owner out
    // of passkey login. Fails closed, matching the password-path ban check.
    if state.passkey_account_banned(scope, &target.subject).await {
        return passkey_throttled(&crate::abuse::banned_snapshot(state.regulation()));
    }

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
    //
    // The attested rung (issue #66 PR B) is recorded through ONE path: when the
    // credential's STORED, registration-time `attestation_verified` fact is set (the
    // AAGUID was allow-listed and its attestation chained to the pinned FIDO MDS3
    // root), the login records the ATTESTED method, which derives the
    // `attested_passkey` acr; otherwise it records the plain passkey method. This is
    // the single source that keeps `satisfied_class` and the achieved acr in
    // agreement: both read the recorded method, and the method is derived from the one
    // stored fact, so an attested login satisfies an attested-class floor end to end
    // while a plain passkey never can.
    let auth_time = epoch_micros(state.now());
    let event = if target.attestation_verified {
        AuthenticationEvent::attested_passkey(
            auth_time,
            target.backup_eligible,
            outcome.user_verified,
        )
    } else {
        AuthenticationEvent::passkey(auth_time, target.backup_eligible, outcome.user_verified)
    };

    // Covenant self-check (issue #66 PR B): the credential class this login SATISFIES,
    // folded from the STORED facts (the tenant user-verification requirement and the
    // credential's reg-time `attestation_verified` column), must be BACKED by the acr
    // the event achieves. This is the runtime half of the reconciliation between the
    // two enforcement views: `satisfied_class` (fed from stored facts) and the achieved
    // acr (from the recorded method) are computed from independent inputs and must
    // agree, so an attested login both folds to the attested class AND achieves the
    // attested acr, while a plain passkey does neither. A divergence would be an
    // internal bug; fail closed rather than mint a token whose acr the satisfied class
    // does not back.
    let facts = crate::authn::CredentialFacts {
        require_user_verification: state.webauthn_require_user_verification(),
        attestation_verified: target.attestation_verified,
    };
    let satisfied = crate::authn::satisfied_class(&event, &facts);
    let order = state.acr_order();
    if !crate::step_up::acr_satisfies(
        crate::authn::achieved_acr(event.methods()),
        crate::authn::acr_for_class(satisfied),
        &order,
    ) {
        return ceremony_error();
    }
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

    // Successful passkey sign-in: relax the passkey-path per-IP throttle so a legitimate
    // user is not punished after a correct sign-in (issue #64 LOW-6). Keyed on the same
    // passkey-path context the attempt was recorded on.
    state.reset_after_success(&regulation_ctx).await;

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

/// The passwordless-signup `options` request body: the desired login handle.
#[derive(Debug, Deserialize)]
pub struct SignupOptionsBody {
    /// The desired login handle for the new passkey-only account. Advisory here (it
    /// shapes only the authenticator's display); the `verify` step's identifier is
    /// authoritative and the unique constraint governs a duplicate.
    identifier: Option<String>,
}

/// The passwordless-signup `verify` request body.
#[derive(Debug, Deserialize)]
pub struct SignupVerifyBody {
    /// The challenge handle returned by `signup/options`.
    #[serde(rename = "challengeId")]
    challenge_id: String,
    /// The authorization URL to resume at once the account is created and signed in.
    #[serde(rename = "returnTo")]
    return_to: String,
    /// The AUTHORITATIVE login handle for the new account (created here, at verify, so
    /// an abandoned ceremony never leaves an orphaned passwordless row).
    identifier: Option<String>,
    /// The optional passkey nickname (sealed at rest).
    #[serde(default)]
    nickname: Option<String>,
    /// The `navigator.credentials.create` result.
    credential: RegistrationResponse,
}

/// `POST /t/{tenant}/e/{environment}/webauthn/signup/options`: begin a PASSWORDLESS
/// signup (issue #66). No session is required (the account does not exist yet). Mints a
/// fresh subject id, binds a UV-REQUIRED registration challenge to it, and returns the
/// `PublicKeyCredentialCreationOptions`. The account itself is created only at `verify`,
/// once the passkey is proven, so an abandoned ceremony leaves nothing behind and the
/// signup path never touches a password screen/hash/policy step.
pub async fn register_passkey_signup_options(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<SignupOptionsBody>,
) -> Response {
    if !state.webauthn_enabled() {
        return not_found();
    }
    let Some(rp) = state.webauthn_relying_party() else {
        return ceremony_error();
    };
    if !interaction::related_origin_ok(&headers, &rp.origins) {
        return forbidden();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    // Closed registration (issue #64) blocks passkey-only signup exactly as it blocks
    // password registration: no account can be created. Uniform, reveals no account.
    if state.registration_closed() {
        return json_response(
            StatusCode::FORBIDDEN,
            json!({ "error": "registration_closed" }),
        );
    }
    let identifier = body
        .identifier
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if identifier.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "identifier_required" }),
        );
    }
    // Credential-abuse regulation for the REGISTER path (issue #64), keyed on the
    // canonical identifier and the resolved peer IP, so passkey-only signup spam throttles
    // on the SAME counters as password registration. No account existence is probed.
    let ctx = crate::abuse::AttemptContext {
        path: AuthPath::Register,
        scope,
        ip: crate::abuse::resolved_client_ip(&headers),
        identifier: Some(crate::abuse::canonical_login_identifier(identifier)),
        account_id: None,
        client_id: None,
    };
    if let crate::abuse::RegulationOutcome::Throttled(snapshot) = state.regulate_before(&ctx).await
    {
        return passkey_throttled(&snapshot);
    }
    // Pre-allocate the subject id: it binds the challenge now and creates the account at
    // verify, and it is the account's stable WebAuthn user handle (minted at INSERT).
    let subject = UserId::generate(state.env(), &scope);
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
        // The user handle is the opaque usr_ id bytes (what the account will store), never
        // a plain email.
        id: subject.to_string().into_bytes(),
        name: identifier.to_owned(),
        display_name: identifier.to_owned(),
    };
    // UV is REQUIRED for a passkey-only account: the passkey is the sole authenticator, so
    // presence alone must never suffice. Forced here regardless of the tenant default.
    let options = registration_options(
        &relying_party(&rp),
        &user,
        &issued.challenge,
        &[],
        CEREMONY_TIMEOUT_MS,
        UserVerification::Required,
    );
    json_response(
        StatusCode::OK,
        json!({ "challengeId": issued.id, "publicKey": options }),
    )
}

/// `POST /t/{tenant}/e/{environment}/webauthn/signup/verify`: complete a PASSWORDLESS
/// signup (issue #66). Verifies the UV-required registration, CREATES the passkey-only
/// account (unusable password sentinel + `passwordless = true`, no password code path
/// ever reached), persists the passkey, and establishes the HONEST passkey session
/// (`phr`/`phrh`, never a fabricated `pwd`), then resumes the authorization request.
// A linear ceremony: consume, verify (UV forced), attestation, create account, persist
// passkey, establish the honest session. The fail-closed early returns are the point.
#[allow(clippy::too_many_lines)]
pub async fn register_passkey_signup_verify(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<SignupVerifyBody>,
) -> Response {
    if !state.webauthn_enabled() {
        return not_found();
    }
    let Some(rp) = state.webauthn_relying_party() else {
        return ceremony_error();
    };
    if !interaction::related_origin_ok(&headers, &rp.origins) {
        return forbidden();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    // Re-check closed registration (issue #64) here too, for defense in depth (issue #66
    // INFO): the ceremony is already indirectly gated because no challenge is issued while
    // registration is closed, but re-checking on verify means a registration toggled closed
    // MID-ceremony cannot still complete an account. Uniform with the register path.
    if state.registration_closed() {
        return json_response(
            StatusCode::FORBIDDEN,
            json!({ "error": "registration_closed" }),
        );
    }
    // The resume target must be a valid authorization request in THIS scope, so the
    // honest passkey session can resume it; an invalid link is the uniform ceremony error.
    let Some(resume) =
        interaction::parse_resume(Some(&body.return_to)).filter(|resume| resume.scope == scope)
    else {
        return ceremony_error();
    };
    let identifier = body
        .identifier
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if identifier.is_empty() {
        return ceremony_error();
    }

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
    // The pre-allocated subject the challenge was issued for. It is server-minted (never
    // a wire value), so the created account and its handle are bound to it.
    let Some(subject) = challenge
        .subject
        .as_deref()
        .and_then(|s| UserId::parse_in_scope(s, &scope).ok())
    else {
        return ceremony_error();
    };

    // UV is REQUIRED: a passkey-only account must never be reachable by presence alone.
    let params = VerificationParams {
        rp_id: &rp.rp_id,
        allowed_origins: &rp.origins,
        expected_challenge: &challenge.challenge,
        require_user_verification: true,
    };
    let registered: RegisteredCredential = match verify_registration(&body.credential, &params) {
        Ok(credential) => credential,
        Err(_) => return ceremony_error(),
    };
    let Ok(attestation) =
        evaluate_registration_attestation(&state, scope, &body.credential, &registered).await
    else {
        return ceremony_error();
    };

    // CREATE the passkey-only account now (unusable password sentinel + passwordless), with
    // the pre-allocated id, so an abandoned ceremony left no orphan. A taken identifier is
    // the uniform conflict. No password screen/hash/policy is reachable on this path.
    let actor = interaction::user_actor(&subject);
    match state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .register_passwordless(state.env(), &subject, identifier)
        .await
    {
        Ok(_) => {}
        Err(StoreError::Conflict) => {
            return json_response(
                StatusCode::CONFLICT,
                json!({ "error": "already_registered" }),
            );
        }
        Err(_) => return ceremony_error(),
    }

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
        attestation_type: attestation.attestation_type.as_str(),
        attestation_verified: attestation.model_verified,
        attestation_fmt: attestation.fmt,
    };
    if state
        .store()
        .scoped(scope)
        .acting(
            interaction::user_actor(&subject),
            CorrelationId::generate(state.env()),
        )
        .webauthn_credentials()
        .register(state.env(), &subject, &new_credential)
        .await
        .is_err()
    {
        return ceremony_error();
    }

    // The HONEST authentication event: the user just PROVED a UV-required, origin-bound
    // passkey, so this is a phishing-resistant login (`phr`/`phrh`, or `attested_passkey`
    // when the model was attested), derived from the STORED registration-time backup
    // eligibility. UV was enforced above, so `user_verified` is true. There is NO `pwd`
    // method anywhere on this path: the acr can never fabricate a password factor.
    let auth_time = epoch_micros(state.now());
    let event = if attestation.model_verified {
        AuthenticationEvent::attested_passkey(auth_time, registered.backup_eligible, true)
    } else {
        AuthenticationEvent::passkey(auth_time, registered.backup_eligible, true)
    };
    let Ok(cookies) = interaction::establish_session(
        &state,
        scope,
        &subject.to_string(),
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
        "redirect": resume.return_to,
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
    /// The documented recovery acknowledgment (mirrors the #61 account-credential
    /// flow): when true, removing the caller's LAST usable login factor is permitted
    /// (the user accepts they will rely on account recovery). Absent or false blocks
    /// that removal so a passwordless user cannot silently strand themselves.
    #[serde(default, rename = "acknowledgeRecovery")]
    acknowledge_recovery: bool,
}

/// `POST /t/{tenant}/e/{environment}/webauthn/credentials/remove`: remove one of the
/// caller's OWN passkeys (issue #65). Same-origin guarded (CSRF), authenticated,
/// subject-bound at the store layer, and audited on success. Another user's
/// credential is the uniform not-found and is never removed. Removing the caller's
/// LAST usable login factor (counted across a native password, `account_credentials`,
/// and other passkeys) is blocked unless `acknowledgeRecovery` is set, so a
/// passwordless account cannot lock itself out.
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
        .remove(state.env(), &subject, &id, body.acknowledge_recovery)
        .await;
    match outcome {
        Ok(CredentialRemoveOutcome::Removed) => json_response(
            StatusCode::OK,
            json!({ "id": id.to_string(), "removed": true }),
        ),
        Ok(CredentialRemoveOutcome::NotFound) => credential_not_found(),
        Ok(CredentialRemoveOutcome::BlockedLastCredential) => json_response(
            StatusCode::CONFLICT,
            json!({
                "error": "last_credential",
                "error_description": "This is your last credential that can sign you in. \
                     Removing it would lock you out. Set acknowledgeRecovery to confirm you \
                     accept relying on account recovery.",
            }),
        ),
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

/// The uniform passkey-path throttle response when regulation refuses the ceremony (issue
/// #64 MEDIUM-2): a `429 Too Many Requests` carrying the standard rate-limit headers and
/// the same non-enumerating ceremony body every other passkey failure returns, so a
/// throttled or banned passkey ceremony is not distinguishable from any other failure.
fn passkey_throttled(snapshot: &ironauth_quota::RateLimitSnapshot) -> Response {
    let mut response = json_response(
        StatusCode::TOO_MANY_REQUESTS,
        json!({
            "error": "ceremony_failed",
            "message": "The passkey could not be verified. Please try again.",
        }),
    );
    crate::abuse::stamp_rate_limit_headers(&mut response, snapshot);
    response
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
