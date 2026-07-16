// SPDX-License-Identifier: MIT OR Apache-2.0

//! The self-service end-user account API (issue #61).
//!
//! An API-first surface an AUTHENTICATED end user manages their OWN account with:
//! list and revoke their OWN sessions, change their OWN password, and enroll, list,
//! and remove their OWN credentials. Every endpoint is authenticated by the user's
//! OWN session cookie (never the management API's admin credentials), is
//! scope-routed under `/t/{tenant}/e/{environment}/account/...` (so the read/write
//! runs under the right row-level-security scope), and acts ONLY on the
//! authenticated subject's resources. The hosted account pages (M9) consume this API
//! without any private endpoint.
//!
//! # The one security property: only ever your OWN account
//!
//! Every operation binds to the AUTHENTICATED subject recovered from the session
//! cookie, NEVER to a user-supplied user id. A session or credential the caller does
//! not own resolves to the uniform not-found and is never actionable: an IDOR here
//! would be account takeover. The session revoke additionally re-checks ownership at
//! the store layer (a subject-bound flip), so the guarantee is defense in depth, not
//! a single check.
//!
//! # CSRF on state changes
//!
//! Every state-changing POST (revoke, password change, credential enroll/remove) is
//! guarded by the same-origin header allowlist (issue #196) BEFORE any mutation, so
//! a cross-site auto-submit cannot drive an account change on the cookie's back.
//!
//! # Sensitive operations and step-up
//!
//! The sensitive operations (credential enrollment and removal, revoke-others, and
//! the password change) DECLARE a recent-re-authentication requirement (a
//! configurable max age). This issue ships the declaration and the enforcement SEAM:
//! the requirement is recorded in the audit trail and reported to the caller, and it
//! is ENFORCED end to end once M7's step-up issue lands. Until then the policy is
//! recorded and auditable but not gated on, exactly as the issue specifies.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{
    CorrelationId, CredentialRemoveOutcome, CredentialType, Scope, SessionFleetFilter, SessionId,
    SessionSummary, StoreError, UserId,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::interaction;
use crate::state::OidcState;
use crate::util::epoch_micros;
use crate::wellknown::{not_found, parse_scope};

/// The step-up recent-re-authentication max age (seconds) the sensitive account
/// operations DECLARE (issue #61). The declaration and the enforcement seam ship
/// now; enforcement activates end to end once M7's step-up issue lands. The value is
/// recorded in the audit trail (the operator-safe `detail`) and reported to the
/// caller. It is not attacker-controlled.
const STEP_UP_MAX_AGE_SECS: u64 = 300;

/// The operator-safe audit `detail` a sensitive account operation records: the
/// declared step-up policy. Never attacker-controlled free text.
fn step_up_detail() -> String {
    format!("step_up_max_age_secs={STEP_UP_MAX_AGE_SECS}")
}

/// The resolved account context of a self-service request: the scope, the
/// authenticated subject (as a typed `usr_` id and its string), and the session the
/// request is made from.
struct Account {
    scope: Scope,
    subject: UserId,
    subject_str: String,
    session_id: SessionId,
    auth_time_unix_micros: i64,
}

/// Resolve the scope from the path and the session cookie to an authenticated
/// account, or return the response to send instead (a uniform `404` for a malformed
/// scope, a `401` for no or an invalid session, a `401` for a subject that is not a
/// parseable user id of this scope).
async fn authenticate(
    state: &OidcState,
    tenant_id: &str,
    environment_id: &str,
    headers: &HeaderMap,
) -> Result<Account, Response> {
    let Some(scope) = parse_scope(tenant_id, environment_id) else {
        return Err(not_found());
    };
    let Some(session) = interaction::resolve_session(state, scope, headers).await else {
        return Err(unauthenticated());
    };
    // The subject the bootstrap issues is always a usr_ id of this scope; a value
    // that does not parse is treated as unauthenticated (defense in depth).
    let Ok(subject) = UserId::parse_in_scope(&session.subject, &scope) else {
        return Err(unauthenticated());
    };
    Ok(Account {
        scope,
        subject,
        subject_str: session.subject,
        session_id: session.session_id,
        auth_time_unix_micros: session.auth_time_unix_micros,
    })
}

/// The step-up policy object reported on a sensitive operation's response (issue
/// #61): the declared max age, whether the caller's session satisfies it right now,
/// and that enforcement is not yet active (M7 owns the gate). Reporting `satisfied`
/// is informational: the surface DECLARES the requirement, it does not yet reject.
fn step_up_status(state: &OidcState, auth_time_unix_micros: i64) -> Value {
    let now_micros = epoch_micros(state.now());
    let age_micros = now_micros.saturating_sub(auth_time_unix_micros);
    let max_age_micros = i64::try_from(STEP_UP_MAX_AGE_SECS)
        .unwrap_or(i64::MAX)
        .saturating_mul(1_000_000);
    json!({
        "max_age_secs": STEP_UP_MAX_AGE_SECS,
        "recent_reauth_satisfied": age_micros <= max_age_micros,
        "enforced": false,
    })
}

/// `GET /t/{tenant}/e/{environment}/account/sessions`: list the authenticated user's
/// OWN active sessions, each with its device metadata (user agent and a coarse
/// location hint derived from the observed IP), created and last-seen timestamps, and
/// a current-session marking. Reads ONLY the caller's own sessions (filtered on the
/// authenticated subject), so another user's sessions are never listed.
pub async fn list_sessions(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let account = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    let now_micros = epoch_micros(state.now());
    let listed = state
        .store()
        .scoped(account.scope)
        .session_fleet()
        .list(
            SessionFleetFilter {
                subject: Some(&account.subject_str),
                client_id: None,
            },
            i64::from(u8::MAX),
            None,
        )
        .await;
    let Ok(summaries) = listed else {
        return server_error();
    };
    let current = account.session_id.to_string();
    let sessions: Vec<Value> = summaries
        .iter()
        .filter(|summary| is_active(summary, now_micros))
        .map(|summary| session_json(summary, &current))
        .collect();
    json_response(StatusCode::OK, json!({ "sessions": sessions }))
}

/// The revoke-one-session request body: the session to revoke.
#[derive(Deserialize)]
pub struct RevokeSessionBody {
    /// The session id to revoke. Must be one of the caller's OWN sessions; any other
    /// value (another user's session, an absent one, a cross-scope one) is the
    /// uniform not-found.
    session_id: String,
}

/// `POST /t/{tenant}/e/{environment}/account/sessions/revoke`: revoke ONE of the
/// caller's own sessions. The session id is bound to the authenticated subject: a
/// session the caller does not own is the uniform not-found and is never revoked.
/// The revoke flows through the unified session-ended fan-out exactly as an admin
/// revoke does, and is audited to the end user.
pub async fn revoke_session(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<RevokeSessionBody>,
) -> Response {
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let account = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    // Parse the untrusted id under the caller's OWN scope; a malformed or cross-scope
    // id is the uniform not-found.
    let Ok(target) = SessionId::parse_in_scope(&body.session_id, &account.scope) else {
        return not_found_json();
    };
    // Confirm the session belongs to the caller BEFORE acting (the store additionally
    // re-checks ownership): another user's session id is the uniform not-found.
    let summary = state
        .store()
        .scoped(account.scope)
        .session_fleet()
        .get(&target)
        .await;
    match summary {
        Ok(Some(summary)) if summary.subject == account.subject_str => {}
        Ok(_) => return not_found_json(),
        Err(_) => return server_error(),
    }
    let actor = interaction::user_actor(&account.subject);
    let result = state
        .store()
        .scoped(account.scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .sessions()
        .self_revoke(state.env(), &account.subject, &target)
        .await;
    match result {
        Ok(outcome) => json_response(
            StatusCode::OK,
            json!({
                "session_id": target.to_string(),
                "revoked": outcome.session_flipped,
            }),
        ),
        Err(_) => server_error(),
    }
}

/// `POST /t/{tenant}/e/{environment}/account/sessions/revoke-others`: revoke every
/// session of the caller EXCEPT the one making the request (the "sign out everywhere
/// else" action). A sensitive operation: it declares the step-up requirement and is
/// audited to the end user. Each revoked session flows through the unified
/// session-ended fan-out.
pub async fn revoke_other_sessions(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let account = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    let actor = interaction::user_actor(&account.subject);
    let result = state
        .store()
        .scoped(account.scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .sessions()
        .self_revoke_others(
            state.env(),
            &account.subject,
            Some(&account.session_id),
            &step_up_detail(),
        )
        .await;
    match result {
        Ok(outcome) => json_response(
            StatusCode::OK,
            json!({
                "sessions_revoked": outcome.sessions_revoked,
                "step_up": step_up_status(&state, account.auth_time_unix_micros),
            }),
        ),
        Err(_) => server_error(),
    }
}

/// `GET /t/{tenant}/e/{environment}/account/credentials`: list the caller's OWN
/// enrolled credentials (passkeys, TOTP, recovery-code sets) with their metadata.
/// Filtered on the authenticated subject, so another user's credentials are never
/// listed.
pub async fn list_credentials(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let account = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    let listed = state
        .store()
        .scoped(account.scope)
        .account_credentials()
        .list(&account.subject, i64::from(u8::MAX), None)
        .await;
    let Ok(credentials) = listed else {
        return server_error();
    };
    let items: Vec<Value> = credentials
        .iter()
        .map(|credential| {
            json!({
                "id": credential.id,
                "type": credential.credential_type,
                "friendly_name": credential.friendly_name,
                "usable_for_login": credential.usable_for_login,
                "created_at": credential.created_at_unix_micros,
                "last_used_at": credential.last_used_at_unix_micros,
            })
        })
        .collect();
    json_response(StatusCode::OK, json!({ "credentials": items }))
}

/// The enroll-credential request body.
#[derive(Deserialize)]
pub struct EnrollCredentialBody {
    /// The factor kind: `passkey`, `totp`, or `recovery_code`.
    #[serde(rename = "type")]
    credential_type: String,
    /// The user-authored friendly name (sealed at rest).
    friendly_name: String,
}

/// `POST /t/{tenant}/e/{environment}/account/credentials`: enroll a credential for
/// the caller (a sensitive operation: it declares the step-up requirement and is
/// audited to the end user). The endpoint and its authorization contract ship here;
/// the concrete factor ceremonies wire in with the M7 factor issues.
pub async fn enroll_credential(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<EnrollCredentialBody>,
) -> Response {
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let account = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    let Some(credential_type) = CredentialType::parse(&body.credential_type) else {
        return bad_request("unsupported credential type");
    };
    let name = body.friendly_name.trim();
    if name.is_empty() || name.len() > 200 {
        return bad_request("friendly_name must be 1 to 200 characters");
    }
    let actor = interaction::user_actor(&account.subject);
    let result = state
        .store()
        .scoped(account.scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .account_credentials()
        .enroll(
            state.env(),
            &account.subject,
            credential_type,
            name,
            &step_up_detail(),
        )
        .await;
    match result {
        Ok(id) => json_response(
            StatusCode::CREATED,
            json!({
                "id": id.to_string(),
                "type": credential_type.as_str(),
                "friendly_name": name,
                "usable_for_login": credential_type.usable_for_login(),
                "step_up": step_up_status(&state, account.auth_time_unix_micros),
            }),
        ),
        Err(_) => server_error(),
    }
}

/// The remove-credential request body.
#[derive(Deserialize)]
pub struct RemoveCredentialBody {
    /// The credential id to remove. Must be one of the caller's OWN credentials; any
    /// other value is the uniform not-found.
    credential_id: String,
    /// The documented recovery acknowledgment: when true, removing the caller's LAST
    /// primary-login credential is permitted (the user accepts they will rely on
    /// password recovery). Absent or false blocks that removal.
    #[serde(default)]
    acknowledge_recovery: bool,
}

/// `POST /t/{tenant}/e/{environment}/account/credentials/remove`: remove one of the
/// caller's OWN credentials (a sensitive operation: it declares the step-up
/// requirement and is audited to the end user). The credential id is bound to the
/// authenticated subject: another user's credential is the uniform not-found. The
/// last-usable-credential guardrail blocks removing the caller's last primary-login
/// credential unless the recovery acknowledgment is present.
pub async fn remove_credential(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<RemoveCredentialBody>,
) -> Response {
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let account = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    let credentials = state.store().scoped(account.scope).account_credentials();
    let Ok(id) = credentials.parse_id(&body.credential_id) else {
        return not_found_json();
    };
    let actor = interaction::user_actor(&account.subject);
    let result = state
        .store()
        .scoped(account.scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .account_credentials()
        .remove(
            state.env(),
            &account.subject,
            &id,
            body.acknowledge_recovery,
            &step_up_detail(),
        )
        .await;
    match result {
        Ok(CredentialRemoveOutcome::Removed) => json_response(
            StatusCode::OK,
            json!({
                "id": id.to_string(),
                "removed": true,
                "step_up": step_up_status(&state, account.auth_time_unix_micros),
            }),
        ),
        Ok(CredentialRemoveOutcome::NotFound) => not_found_json(),
        Ok(CredentialRemoveOutcome::BlockedLastCredential) => json_response(
            StatusCode::CONFLICT,
            json!({
                "error": "last_credential",
                "error_description": "This is your last credential that can sign you in. \
                     Removing it would lock you out. Set acknowledge_recovery to confirm you \
                     accept relying on password recovery.",
            }),
        ),
        Err(_) => server_error(),
    }
}

/// The change-password request body.
#[derive(Deserialize)]
pub struct ChangePasswordBody {
    /// The caller's CURRENT password, verified against the stored Argon2id verifier
    /// before any change (never returned, never logged).
    current_password: String,
    /// The new password, hashed through the entropy seam and stored as a fresh
    /// Argon2id verifier (never returned, never logged).
    new_password: String,
}

/// `POST /t/{tenant}/e/{environment}/account/password`: change the caller's password.
/// Verifies the CURRENT password against the stored Argon2id verifier, writes a fresh
/// verifier at the same OWASP parameters, and (session-fixation defense) revokes every
/// OTHER session of the caller while keeping the one the change is made from. A
/// sensitive operation: it is audited to the end user and reports the step-up policy.
/// The password hash is never returned or logged.
pub async fn change_password(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordBody>,
) -> Response {
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let account = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    if body.new_password.is_empty() {
        return bad_request("new_password must not be empty");
    }
    // Read the stored verifier and verify the CURRENT password. A user that vanished
    // is unauthenticated; a wrong current password is a uniform 403 that reveals
    // nothing and changes nothing.
    let stored = state
        .store()
        .scoped(account.scope)
        .users()
        .password_hash_for_subject(&account.subject)
        .await;
    let stored_hash = match stored {
        Ok(Some(hash)) => hash,
        Ok(None) => return unauthenticated(),
        Err(_) => return server_error(),
    };
    // Verify the current password through the admission-controlled pool (issue #62),
    // off the async threads. An over-share tenant or a saturated pool is the
    // retryable 429/503; a pool fault is a generic server error.
    let current_ok = match state
        .verify_password(&account.scope, &body.current_password, &stored_hash)
        .await
    {
        Ok(ok) => ok,
        Err(crate::hashing_pool::HashRejection::Unavailable) => return server_error(),
        Err(rejection) => return rejection.to_response(),
    };
    if !current_ok {
        return json_response(
            StatusCode::FORBIDDEN,
            json!({
                "error": "invalid_password",
                "error_description": "The current password is incorrect.",
            }),
        );
    }
    // Hash the new password through the same pool (entropy from the env seam, never a
    // raw RNG). The plaintext never reaches the store; only the one-way verifier does.
    let new_hash = match state
        .hash_password(&account.scope, &body.new_password)
        .await
    {
        Ok(hash) => hash,
        Err(crate::hashing_pool::HashRejection::Unavailable) => return server_error(),
        Err(rejection) => return rejection.to_response(),
    };
    let actor = interaction::user_actor(&account.subject);
    let result = state
        .store()
        .scoped(account.scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .change_password(
            state.env(),
            &account.subject,
            &new_hash,
            Some(&account.session_id),
            &step_up_detail(),
        )
        .await;
    match result {
        Ok(outcome) => json_response(
            StatusCode::OK,
            json!({
                "changed": true,
                "other_sessions_revoked": outcome.sessions_revoked,
                "step_up": step_up_status(&state, account.auth_time_unix_micros),
            }),
        ),
        Err(StoreError::NotFound) => unauthenticated(),
        Err(_) => server_error(),
    }
}

/// Whether a fleet session summary is an ACTIVE session (the account UI lists only
/// where the user is currently signed in): not revoked, not ended (revoked or rotated
/// away), and within both its idle and absolute expiry at `now_micros`.
fn is_active(summary: &SessionSummary, now_micros: i64) -> bool {
    if summary.revoked_at_unix_micros.is_some() || summary.ended_at_unix_micros.is_some() {
        return false;
    }
    if summary
        .absolute_expires_at_unix_micros
        .is_some_and(|at| at <= now_micros)
    {
        return false;
    }
    if summary
        .idle_expires_at_unix_micros
        .is_some_and(|at| at <= now_micros)
    {
        return false;
    }
    true
}

/// The JSON projection of one active session for the account UI: its id, device
/// metadata (user agent and a coarse location hint), timestamps, and a
/// current-session marking (`current` is true for the session the request is made
/// from).
fn session_json(summary: &SessionSummary, current_id: &str) -> Value {
    json!({
        "id": summary.id,
        "current": summary.id == current_id,
        "user_agent": summary.user_agent,
        "coarse_location": coarse_location(summary.peer_ip.as_deref()),
        "created_at": summary.created_at_unix_micros,
        "last_seen_at": summary.last_seen_at_unix_micros,
    })
}

/// A COARSE location hint derived from the IP observed at authentication (issue #61),
/// or [`None`] when no peer IP was recorded (the peer-IP binding is off by default,
/// so most sessions carry none). This is a coarse NETWORK-locality hint, not a
/// street address: the last octet of an IPv4 address (and the low 80 bits of an IPv6
/// address) are zeroed, so the value can never single out a host, and a richer
/// geo-IP enrichment is a later, optional layer. A value that does not parse as an IP
/// yields [`None`] rather than echoing untrusted input.
fn coarse_location(peer_ip: Option<&str>) -> Option<String> {
    let raw = peer_ip?.trim();
    if let Ok(v4) = raw.parse::<std::net::Ipv4Addr>() {
        let [a, b, c, _] = v4.octets();
        return Some(format!("{a}.{b}.{c}.0/24"));
    }
    if let Ok(v6) = raw.parse::<std::net::Ipv6Addr>() {
        let segments = v6.segments();
        return Some(format!(
            "{:x}:{:x}:{:x}::/48",
            segments[0], segments[1], segments[2]
        ));
    }
    None
}

/// A JSON response at `status` with `no-store` caching (an account response is
/// per-user and must never be cached by a shared proxy). Takes the body by value so
/// every call site can pass a freshly-built `json!` object without a borrow.
#[allow(clippy::needless_pass_by_value)]
fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}

/// A `401` for a request with no or an invalid session. Generic: it never reveals
/// whether a session existed.
fn unauthenticated() -> Response {
    json_response(
        StatusCode::UNAUTHORIZED,
        json!({
            "error": "unauthenticated",
            "error_description": "Sign in to manage your account.",
        }),
    )
}

/// A `403` for a state-changing POST refused by the same-origin CSRF allowlist
/// (issue #196). Generic on purpose: it never reveals which signal failed and no
/// action is performed.
fn forbidden() -> Response {
    json_response(
        StatusCode::FORBIDDEN,
        json!({
            "error": "forbidden",
            "error_description": "This request could not be verified.",
        }),
    )
}

/// The uniform `404` for a resource the caller does not own (another user's session
/// or credential, an absent one, or a cross-scope id): byte-identical to a genuinely
/// absent resource, so it is never an existence oracle.
fn not_found_json() -> Response {
    json_response(
        StatusCode::NOT_FOUND,
        json!({
            "error": "not_found",
            "error_description": "No such resource.",
        }),
    )
}

/// A `400` for a malformed request body.
fn bad_request(message: &str) -> Response {
    json_response(
        StatusCode::BAD_REQUEST,
        json!({ "error": "invalid_request", "error_description": message }),
    )
}

/// A generic `500` that never reveals what failed.
fn server_error() -> Response {
    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({
            "error": "server_error",
            "error_description": "The request could not be processed.",
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coarse_location_zeroes_the_host_portion_and_rejects_non_ip() {
        assert_eq!(
            coarse_location(Some("203.0.113.42")),
            Some("203.0.113.0/24".to_owned())
        );
        assert_eq!(
            coarse_location(Some("2001:db8:abcd:1234::1")),
            Some("2001:db8:abcd::/48".to_owned())
        );
        // No recorded IP (the default), and an un-parseable value, both yield None:
        // the surface never echoes untrusted input as a location.
        assert_eq!(coarse_location(None), None);
        assert_eq!(coarse_location(Some("not-an-ip")), None);
    }
}
