// SPDX-License-Identifier: MIT OR Apache-2.0

//! Gated subject-bound recipient verification (issue #1436).
//!
//! This core is deliberately unavailable in a production build. A testing-only
//! transport installer exercises the real HTTP/store boundaries; no runtime flag,
//! default sender, logger or ordinary message outbox can enable it. Delivery,
//! hosted recovery UI and controlled indexing of existing scopes must land before
//! a production installer is added. Nothing here creates or upgrades a session.

use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State, rejection::JsonRejection};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{
    CorrelationId, NewRecipientChallenge, RecipientAttempt, RecipientChallengeId, Scope,
    StoreError, UserId,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::state::OidcState;
use crate::util::epoch_micros;

/// A transient secret handed only to an explicit transport. No `Debug`, no
/// serialization and no plaintext persistence in the provider's ordinary outbox.
pub struct RecipientVerificationMessage<'a> {
    /// Exact isolated provider scope.
    pub scope: Scope,
    /// The account's stored primary delivery address, never the submitted alias.
    pub recipient: &'a str,
    /// A single-purpose eight-digit code, valid for five minutes.
    pub code: &'a str,
}

/// An explicit delivery failure. No raw transport errors or addresses reach logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientDeliveryFailure {
    /// The transport refused the message before acceptance.
    Refused,
    /// Acceptance cannot be established; the caller must not claim delivery.
    Uncertain,
}

/// Purpose-specific secret transport. It must acknowledge actual acceptance,
/// never a no-op, and must not persist or log the plaintext code. No implementation
/// or production installer ships with the gated core.
#[async_trait::async_trait]
pub trait RecipientVerificationTransport: Send + Sync {
    /// Deliver through a bounded, secret-safe transport. The provider also imposes
    /// an outer five-second deadline; timeout means uncertain delivery.
    async fn deliver(
        &self,
        message: RecipientVerificationMessage<'_>,
    ) -> Result<(), RecipientDeliveryFailure>;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartBody {
    email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifyBody {
    challenge_id: String,
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProofBody {
    email: String,
    nonce: String,
}

fn response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response()
}

fn unavailable() -> Response {
    response(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({"error": "recipient_verification_unavailable"}),
    )
}

fn refused() -> Response {
    response(
        StatusCode::FORBIDDEN,
        json!({"error": "recipient_not_verified"}),
    )
}

fn invalid() -> Response {
    response(StatusCode::BAD_REQUEST, json!({"error": "invalid_request"}))
}

fn store_error(error: &StoreError) -> Response {
    match error {
        StoreError::NotFound | StoreError::Conflict => refused(),
        StoreError::QuotaExceeded => response(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"error": "retry_later", "retry_after_seconds": 60}),
        ),
        _ => response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "temporarily_unavailable"}),
        ),
    }
}

async fn regulate(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    headers: &HeaderMap,
) -> Option<Response> {
    if let Some(response) = state
        .enforce_request_quota(&scope, headers, None, None)
        .await
    {
        return Some(response);
    }
    // Key regulation on the authenticated subject; body spellings cannot rotate
    // the throttle bucket. The durable store also enforces cooldown and attempts.
    let context = crate::email_otp::attempt_context(
        scope,
        ironauth_store::EmailFactorPurpose::VerifyAddress,
        &subject.to_string(),
        headers,
    );
    if matches!(
        state.regulate_before(&context).await,
        crate::abuse::RegulationOutcome::Throttled(_)
    ) {
        return Some(response(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"error": "retry_later"}),
        ));
    }
    None
}

pub(crate) async fn start(
    State(state): State<OidcState>,
    Path((tenant, environment)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Result<Json<StartBody>, JsonRejection>,
) -> Response {
    let Some(transport) = state.recipient_verification_transport() else {
        return unavailable();
    };
    if uri.query().is_some() {
        return invalid();
    }
    let (scope, subject) =
        match crate::account::recipient_subject(&state, &tenant, &environment, &headers).await {
            Ok(context) => context,
            Err(error) => return error,
        };
    let Ok(Json(body)) = body else {
        return invalid();
    };
    if !ironauth_store::recipient_verification::valid_recipient_email(&body.email) {
        return invalid();
    }
    if let Some(error) = regulate(&state, scope, &subject, &headers).await {
        return error;
    }
    let code = crate::email_otp::generate_numeric_code(&state, 8);
    let Ok(hash) = state.hash_password(&scope, &code).await else {
        return unavailable();
    };
    let id = RecipientChallengeId::generate(state.env(), &scope);
    let email = match state
        .store()
        .scoped(scope)
        .acting(
            crate::interaction::user_actor(&subject),
            CorrelationId::generate(state.env()),
        )
        .recipient_verification()
        .start(
            state.env(),
            NewRecipientChallenge {
                id: &id,
                subject: &subject,
                email: &body.email,
                code_hash: &hash,
                expires_at_unix_micros: epoch_micros(state.now()).saturating_add(300_000_000),
            },
        )
        .await
    {
        Ok(email) => email,
        Err(error) => return store_error(&error),
    };
    let delivery = tokio::time::timeout(
        Duration::from_secs(5),
        transport.deliver(RecipientVerificationMessage {
            scope,
            recipient: &email,
            code: &code,
        }),
    )
    .await;
    let (status, delivery_status) = match delivery {
        Ok(Ok(())) => (StatusCode::ACCEPTED, "accepted"),
        Ok(Err(RecipientDeliveryFailure::Refused)) => (StatusCode::SERVICE_UNAVAILABLE, "refused"),
        Ok(Err(RecipientDeliveryFailure::Uncertain)) | Err(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, "uncertain")
        }
    };
    // Even uncertain/refused delivery returns the challenge handle, never a secret.
    // If the mailbox did receive it, the owner may verify; otherwise retry after
    // the durable cooldown. We never label transport acceptance as inbox delivery.
    response(
        status,
        json!({"challenge_id": id.to_string(), "delivery": delivery_status, "expires_in": 300, "retry_after_seconds": 60}),
    )
}

pub(crate) async fn verify(
    State(state): State<OidcState>,
    Path((tenant, environment)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Result<Json<VerifyBody>, JsonRejection>,
) -> Response {
    if state.recipient_verification_transport().is_none() {
        return unavailable();
    }
    if uri.query().is_some() {
        return invalid();
    }
    let (scope, subject) =
        match crate::account::recipient_subject(&state, &tenant, &environment, &headers).await {
            Ok(context) => context,
            Err(error) => return error,
        };
    let Ok(Json(body)) = body else {
        return invalid();
    };
    if body.code.len() != 8 || !body.code.bytes().all(|byte| byte.is_ascii_digit()) {
        return invalid();
    }
    let Ok(id) = RecipientChallengeId::parse_in_scope(&body.challenge_id, &scope) else {
        return refused();
    };
    if let Some(error) = regulate(&state, scope, &subject, &headers).await {
        return error;
    }
    let challenge = match state
        .store()
        .scoped(scope)
        .recipient_verification()
        .challenge(state.env(), &subject, &id)
        .await
    {
        Ok(Some(challenge)) => challenge,
        Ok(None) => {
            let _ = state.verify_absent(&scope, &body.code).await;
            return refused();
        }
        Err(error) => return store_error(&error),
    };
    let Ok(matched) = state
        .verify_password(&scope, &body.code, &challenge.code_hash)
        .await
    else {
        return unavailable();
    };
    match state
        .store()
        .scoped(scope)
        .acting(
            crate::interaction::user_actor(&subject),
            CorrelationId::generate(state.env()),
        )
        .recipient_verification()
        .attempt(state.env(), &subject, &challenge, matched)
        .await
    {
        Ok(RecipientAttempt::Verified) => response(
            StatusCode::OK,
            json!({"verified": true, "verification_revision": id.to_string()}),
        ),
        Ok(RecipientAttempt::Refused) => refused(),
        Err(error) => store_error(&error),
    }
}

/// Online server-to-server proof, not a transferable credential. The relying
/// party binds issuer/client/public subject, fresh nonce, expected email and time.
/// It must query again for a new invitation acceptance, never store this as a
/// profile claim. Stored OIDC claim documents are not read by this endpoint.
pub(crate) async fn proof(
    State(state): State<OidcState>,
    Path((tenant, environment)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Result<Json<ProofBody>, JsonRejection>,
) -> Response {
    if state.recipient_verification_transport().is_none() {
        return unavailable();
    }
    if uri.query().is_some() {
        return invalid();
    }
    let Some(scope) = crate::wellknown::parse_scope(&tenant, &environment) else {
        return refused();
    };
    let Ok(Json(body)) = body else {
        return invalid();
    };
    if !(32..=128).contains(&body.nonce.len())
        || !body
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !ironauth_store::recipient_verification::valid_recipient_email(&body.email)
    {
        return invalid();
    }
    let issuer = state.issuer_for(&scope);
    let principal = match crate::userinfo::recipient_principal(
        &state,
        &headers,
        scope,
        &format!("{issuer}/account/recipient-proof"),
    )
    .await
    {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    if let Some(error) = regulate(&state, principal.scope, &principal.subject, &headers).await {
        return error;
    }
    let current = match state
        .store()
        .scoped(scope)
        .recipient_verification()
        .current(&principal.subject, &body.email)
        .await
    {
        Ok(Some(current)) => current,
        Ok(None) => return refused(),
        Err(error) => return store_error(&error),
    };
    let now = epoch_micros(state.now());
    let expires = now
        .saturating_add(30_000_000)
        .min(principal.expires_at_unix_micros);
    if expires <= now {
        return refused();
    }
    response(
        StatusCode::OK,
        json!({
            "purpose": "invitation_recipient", "iss": issuer, "aud": principal.client_id,
            "sub": state.resolve_public_subject(&principal.subject.to_string()), "nonce": body.nonce,
            "recipient_matches": true, "verification_revision": current.revision.to_string(),
            "verified_at_unix_micros": current.verified_at_unix_micros,
            "checked_at_unix_micros": now, "expires_at_unix_micros": expires,
        }),
    )
}
