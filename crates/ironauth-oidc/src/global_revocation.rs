// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Global Token Revocation receiver (`POST /global-token-revocation`, issue #36).
//!
//! This is the Okta Universal Logout shape specified in the individual Internet-Draft
//! `draft-parecki-oauth-global-token-revocation` (discussed in the OAuth WG but NOT
//! yet adopted): a single, strongly-authenticated, subject-scoped call that terminates
//! ALL of one subject's sessions and refresh-token families in one environment. It is
//! the account-takeover panic button, strictly stronger than back-channel logout
//! (which is per-session), because it also kills the refresh chain.
//!
//! # Why this is EXPERIMENTAL and gated
//!
//! The draft can still change its wire shape, so the endpoint ships behind the strict
//! config feature ladder (issue #4): the `global-token-revocation` experimental
//! feature is OFF by default and boots only when the operator acknowledges the exact
//! implemented draft revision ([`ironauth_config::GLOBAL_TOKEN_REVOCATION_DRAFT`]). The
//! router mounts this route only when [`OidcState::global_token_revocation_enabled`] is
//! true, which the boot path sets solely from that ladder gate. The implemented draft
//! revision is surfaced in `docs/CONFIG.md` (the feature ladder table) so an interop
//! mismatch with another implementer is diagnosable.
//!
//! # The authorization model (get this right, fail closed)
//!
//! Revoking every token a subject holds is a powerful primitive, so it MUST be strongly
//! authorized. The caller authenticates as a CONFIDENTIAL client through the same
//! client-auth suite the token endpoint uses, presented in the `Authorization` header
//! (`client_secret_basic`), never in the JSON body (which carries the subject). Three
//! doors are therefore bolted shut:
//!
//! - **No public `none` client.** A `client_id` is not a secret (it appears in the
//!   clear in front-channel authorize URLs), so a public `none` client presenting only
//!   its id has proven nothing and MUST NOT be able to nuke a subject. It gets the same
//!   uniform `401` a missing/bad credential returns (exactly like `/introspect`, which
//!   RFC 7662 also restricts to confidential clients). The endpoint never reads a
//!   `client_id` from the request, so a `none` client cannot even be identified here.
//! - **Never across tenants.** Authentication fixes the `(tenant, environment)` scope
//!   from the client's OWN id, and the subject identifier is parsed WITHIN that scope
//!   ([`ironauth_store::UserId::parse_in_scope`]). A subject id from another tenant
//!   fails to parse identically to a malformed one (a uniform `400`, no cross-tenant
//!   existence oracle), and the store's revoke-everything path re-checks the scope, so
//!   a global revoke can never reach a subject in a different tenant.
//! - **Fail closed on a store fault.** A persistence error is a `500`, never a silent
//!   `204`: a revoke that was due must be visible rather than falsely reported as done.
//!
//! The trust boundary is the TENANT: any confidential client in the environment may
//! globally revoke any subject in that same environment (the prompt's "confidential
//! client" authorizer, and the shape a trusted Universal Logout transmitter needs). A
//! FINER per-client capability gate (only a client granted a `global_revocation`
//! capability may call it) is a deliberate follow-up, not shipped in this experimental
//! cut; it would layer on top without changing the scope-fencing above.
//!
//! # Terminal fan-out and idempotency
//!
//! The store revokes the subject's sessions, their per-client sessions, and the
//! session-bound refresh families (and, under the hard-kill posture, the offline
//! families and their grants too) in ONE audited transaction, returning the exact set
//! of sessions it flipped. The endpoint then publishes a TERMINAL
//! [`SessionLifecycleEvent`] (cause [`SessionSignalCause::UserRevokedAll`], no
//! successor) per revoked session on the SAME
//! [`RevocationEventSink`](crate::RevocationEventSink) seam the existing session
//! lifecycle emit sites already use (it reuses the shared choke point rather than a
//! private path), so the downstream logout fan-out (issue #35) can terminate every
//! relying party's view of the subject WITHOUT touching this endpoint.
//!
//! Honest ordering, so this is not read as a half-measure: the DEFAULT sink is a no-op
//! (the [`NoopRevocationSink`](crate::NoopRevocationSink), like every other emit site
//! today), so this cut PRODUCES the terminal events on the shared seam but does not
//! itself deliver a logout. The durable, relying-party-facing landing arrives only once
//! issue #35 wires a real sink through
//! [`OidcState::with_revocation_sink`](crate::OidcState::with_revocation_sink); building
//! that durable delivery worker is #35's job and is deliberately NOT duplicated here.
//!
//! Because the revoke is `WHERE revoked_at IS NULL`, a repeated call for the same
//! subject flips nothing the second time and publishes no spurious event: the endpoint
//! is idempotent, always answering `204` for an authenticated, well-formed request. A
//! well-formed, in-scope subject that does not exist (or that holds nothing) takes that
//! same `204` path BY DESIGN, so the endpoint is not a subject-existence oracle (the
//! same no-oracle reasoning as the cross-tenant `400`): the uniform response reveals
//! nothing about whether the subject was real or held any live tokens.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{
    ActorRef, ClientId, CorrelationId, Scope, ServiceId, StoreError, UserId, UserRevocation,
};
use serde::Deserialize;

use crate::client_auth::{ClientAuthInputs, ClientAuthMethod, authenticate_client_self_scoped};
use crate::error::TokenError;
use crate::revocation::{SessionLifecycleEvent, SessionSignalCause};
use crate::state::OidcState;
use crate::util::client_service_actor;

/// The route the receiver mounts at (issue #36), when the experimental feature is
/// enabled and acknowledged.
pub const GLOBAL_TOKEN_REVOCATION_PATH: &str = "/global-token-revocation";

/// The Global Token Revocation request body (draft
/// `draft-parecki-oauth-global-token-revocation`): a JSON object carrying the subject
/// to revoke everything for, in the RFC 9493 Subject Identifier form.
///
/// Unknown fields are ignored (NOT denied): a transmitter may attach extra members for
/// a subject-identifier format this receiver does not consume, and rejecting the whole
/// request over one is needlessly brittle for an interop endpoint.
#[derive(Debug, Deserialize)]
struct GlobalTokenRevocationRequest {
    /// The subject to revoke everything for (RFC 9493 Subject Identifier).
    sub_id: SubjectIdentifier,
}

/// An RFC 9493 Subject Identifier (the subset this receiver consumes).
///
/// IronAuth's local subject is a scoped `usr_...` id, so the receiver consumes the
/// `opaque` format, whose `id` is that local subject. Other RFC 9493 formats (`email`,
/// `iss_sub`, ...) are recognized as WELL-FORMED but not yet mapped to a local subject;
/// they return a clean draft error rather than silently succeeding, so an interop
/// mismatch surfaces instead of a false "revoked nothing" `204`.
#[derive(Debug, Deserialize)]
struct SubjectIdentifier {
    /// The RFC 9493 identifier format (for example `opaque`).
    format: String,
    /// The opaque identifier value, present for the `opaque` format.
    #[serde(default)]
    id: Option<String>,
}

impl SubjectIdentifier {
    /// The local `usr_...` subject this identifier names, or [`None`] if the format is
    /// one this receiver does not (yet) map to a local subject.
    fn local_subject(&self) -> Option<&str> {
        match self.format.as_str() {
            "opaque" => self
                .id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
            _ => None,
        }
    }
}

/// `POST /global-token-revocation` (issue #36).
pub async fn global_token_revocation(
    State(state): State<OidcState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // 1. Authenticate a CONFIDENTIAL client through the Authorization header (the JSON
    //    body carries the subject, never a credential), fixing the (tenant,
    //    environment) scope from the client's own id. Any failure is a uniform 401.
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let inputs = ClientAuthInputs {
        authorization,
        client_id: None,
        client_secret: None,
        client_assertion: None,
        client_assertion_type: None,
    };
    let Ok((client, scope)) = authenticate_client_self_scoped(&state, inputs).await else {
        return unauthorized();
    };

    // 2. Fail closed on a public client. A `client_id` is not a secret, so a `none`
    //    client must never be able to revoke everything a subject holds (mirrors the
    //    RFC 7662 introspection restriction). A `none` client cannot in fact reach here
    //    (it presents no header credential to authenticate with), but the explicit
    //    check documents the invariant and backstops any future auth-method addition.
    if client.auth_method == ClientAuthMethod::None {
        return unauthorized();
    }

    // 3. Parse the draft-shaped subject identifier. A malformed body or an unmapped
    //    identifier format is a clean 400 (never a 204 that silently revoked nothing).
    let Ok(request) = serde_json::from_slice::<GlobalTokenRevocationRequest>(&body) else {
        return invalid_request("the request body must be a JSON object with a sub_id member");
    };
    let Some(subject_raw) = request.sub_id.local_subject() else {
        return invalid_request(
            "unsupported subject identifier: this receiver consumes the opaque format \
             (an RFC 9493 sub_id with format \"opaque\" and an id)",
        );
    };

    // 4. Parse the subject WITHIN the authenticated client's scope. A subject id from
    //    another tenant fails to parse identically to a malformed one (a uniform 400,
    //    no cross-tenant existence oracle), so a global revoke can never reach across
    //    the tenant boundary.
    let Ok(subject) = UserId::parse_in_scope(subject_raw, &scope) else {
        return invalid_request("the subject identifier does not resolve in this scope");
    };

    // 5. Revoke everything for the subject in one audited transaction, then fan the
    //    terminal session-ended signal out per revoked session. A store fault is a 500.
    match revoke_all_for_subject(&state, scope, &client.client_id, &subject).await {
        Ok(()) => no_content(),
        Err(error) => {
            tracing::error!(%error, "global token revocation store error");
            TokenError::ServerError.into_response()
        }
    }
}

/// Revoke every session and refresh-token family of `subject`, attributed to the
/// authenticated `client_id`, then publish a terminal [`SessionLifecycleEvent`] for
/// each session that was actually revoked.
async fn revoke_all_for_subject(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    subject: &UserId,
) -> Result<(), StoreError> {
    let actor = revoke_actor(state, scope, client_id);
    let correlation = CorrelationId::generate(state.env());
    let outcome: UserRevocation = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .sessions()
        .revoke_all_for_user(
            state.env(),
            subject,
            state.global_token_revocation_hard_kill(),
            None,
        )
        .await?;
    publish_terminal_signals(state, &scope, &outcome);
    Ok(())
}

/// Publish a TERMINAL session-ended signal (cause [`SessionSignalCause::UserRevokedAll`],
/// no successor) for each session the revoke flipped, so the downstream logout fan-out
/// (issue #35) terminates every relying party's view of the subject.
fn publish_terminal_signals(state: &OidcState, scope: &Scope, outcome: &UserRevocation) {
    for session_id in &outcome.revoked_session_ids {
        let signal = SessionLifecycleEvent {
            tenant: scope.tenant().to_string(),
            environment: scope.environment().to_string(),
            session_id: session_id.clone(),
            cause: SessionSignalCause::UserRevokedAll,
            successor_session_id: None,
        };
        state.revocation_sink().publish_session(&signal);
    }
}

/// The audit actor for a global revocation: the CONFIDENTIAL client that requested it
/// (the same stable service actor the token and revoke endpoints use). A malformed
/// stored client id is unreachable (the client just authenticated) but falls back to a
/// generated service actor rather than failing the revocation.
fn revoke_actor(state: &OidcState, scope: Scope, client_id: &str) -> ActorRef {
    match ClientId::parse_in_scope(client_id, &scope) {
        Ok(id) => client_service_actor(&id),
        Err(_) => ActorRef::service(ServiceId::generate(state.env())),
    }
}

/// The draft success response: `204 No Content` with no caching. Returned for every
/// authenticated, well-formed request, including a repeat that revoked nothing (the
/// receiver-side idempotency requirement).
fn no_content() -> Response {
    (
        StatusCode::NO_CONTENT,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
    )
        .into_response()
}

/// A `400 invalid_request` with the OAuth error body (via [`TokenError`]).
fn invalid_request(message: &str) -> Response {
    TokenError::InvalidRequest(message.to_owned()).into_response()
}

/// The uniform `401 invalid_client` for every client-authentication failure (missing,
/// bad, or a public `none` client), a `Basic` challenge and a body that reveals nothing
/// about the subject, so a missing credential and a bad one are indistinguishable.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (
                header::WWW_AUTHENTICATE,
                "Basic realm=\"ironauth\", charset=\"UTF-8\"",
            ),
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        r#"{"error":"invalid_client"}"#,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_subject_identifier_maps_to_the_local_subject() {
        // The draft request shape, pinned: a JSON object with an RFC 9493 sub_id in the
        // opaque format whose id is the local usr_ subject.
        let request: GlobalTokenRevocationRequest =
            serde_json::from_str(r#"{"sub_id":{"format":"opaque","id":"usr_abc123"}}"#)
                .expect("the draft opaque request shape parses");
        assert_eq!(request.sub_id.local_subject(), Some("usr_abc123"));
    }

    #[test]
    fn extra_members_are_ignored_not_rejected() {
        // An interop transmitter may attach extra members; the receiver ignores them.
        let request: GlobalTokenRevocationRequest = serde_json::from_str(
            r#"{"sub_id":{"format":"opaque","id":"usr_x","extra":"ignored"},"reason":"takeover"}"#,
        )
        .expect("extra members do not break parsing");
        assert_eq!(request.sub_id.local_subject(), Some("usr_x"));
    }

    #[test]
    fn an_unmapped_format_yields_no_local_subject() {
        // A well-formed but unmapped RFC 9493 format (email, iss_sub, ...) resolves to
        // no local subject, so the handler returns a clean 400 rather than a false 204.
        for body in [
            r#"{"sub_id":{"format":"email","email":"a@b.example"}}"#,
            r#"{"sub_id":{"format":"iss_sub","iss":"https://i.example","sub":"s"}}"#,
        ] {
            let request: GlobalTokenRevocationRequest =
                serde_json::from_str(body).expect("well-formed sub_id parses");
            assert!(
                request.sub_id.local_subject().is_none(),
                "an unmapped format must not resolve a local subject: {body}"
            );
        }
    }

    #[test]
    fn an_opaque_identifier_with_a_blank_id_resolves_nothing() {
        // A blank/whitespace id is not a subject: it must not resolve (the handler then
        // returns 400), never fall through to a scope parse of an empty string.
        let request: GlobalTokenRevocationRequest =
            serde_json::from_str(r#"{"sub_id":{"format":"opaque","id":"   "}}"#).expect("parses");
        assert!(request.sub_id.local_subject().is_none());
    }
}
