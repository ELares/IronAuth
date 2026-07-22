// SPDX-License-Identifier: MIT OR Apache-2.0

//! User consent (connected apps) management surface (issue #88, PR 5).
//!
//! An admin reviews and revokes the remembered consents a USER holds: the clients
//! that user has authorized, keyed by SUBJECT under `/users/{user_id}/consents`
//! (mirroring the user-scoped session fleet ops), NOT by client (that is the admin
//! consent PRE-authorization surface, `client_admin_grants`). The two surfaces are
//! distinct: this one governs a user's OWN granted consents, that one governs an
//! admin's pre-authorization of a third-party client's scope.
//!
//! Three properties every surface here holds, exactly like the session fleet ops:
//!
//! - **Scope-fenced.** The user id and client id are parsed under the caller's OWN
//!   scope, so a user or client in another tenant or environment is the uniform
//!   not-found (the anti-oracle), never a cross-scope reach. Forced row-level security
//!   is the physical backstop.
//! - **Audited, in the same transaction.** A revocation writes its `consent.revoke`
//!   audit row in the SAME transaction as the flip and the refresh-family cascade
//!   (a revocation without its audit row is not representable).
//! - **Auto-grant filtered.** A client whose consent mode is `implicit` or that sets
//!   `skip_consent` never shows a consent screen, so a stored grant for it is not a
//!   meaningfully revocable authorization and is omitted from the list (the same
//!   filter the self-service surface applies).
//!
//! The revoke is a security mutation, so it is sudo-gated (a fresh privilege elevation
//! is required when sudo mode is on) exactly like a session revoke.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{ClientId, CorrelationId, StoreError, UserId};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::response::json;
use crate::sessions::scope_from_path;
use crate::state::AdminState;
use crate::views::{ConsentRevocationView, UserConsentList, UserConsentView};

/// Whether a client's consent is AUTO-GRANTED (issue #88): its consent mode is
/// `implicit`, or it sets the orthogonal `skip_consent` knob. Such a client never
/// prompts for consent, so a stored grant for it is not a meaningfully revocable
/// authorization and is filtered from the connected-apps list.
fn is_auto_grant(consent_mode: &str, skip_consent: bool) -> bool {
    consent_mode == "implicit" || skip_consent
}

/// Milliseconds since the Unix epoch from stored microseconds.
fn ms(micros: i64) -> i64 {
    micros / 1000
}

/// List the connected apps a user has granted a remembered consent to (issue #88),
/// oldest first, each enriched with the client's display name and logo when the client
/// still exists. Auto-grant clients (`implicit` or `skip_consent`) are filtered out; a
/// grant to a DELETED client is still listed by its client id (so it stays revocable).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/consents",
    operation_id = "listUserConsents",
    tag = "users",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The user's remembered consents", body = UserConsentList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn list_user_consents(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // A user id from another scope (or a malformed one) is the uniform not-found.
    let subject = UserId::parse_in_scope(&user_id, &scope).map_err(|_| StoreError::NotFound)?;

    let grants = state
        .store()
        .scoped(scope)
        .consents()
        .list_for_subject(&subject.to_string())
        .await?;
    let clients = state.store().scoped(scope).clients();
    let mut items: Vec<UserConsentView> = Vec::with_capacity(grants.len());
    for grant in &grants {
        // A client id recorded on a live consent parses in scope by construction; a
        // value that does not is skipped defensively rather than surfaced.
        let Ok(client_id) = ClientId::parse_in_scope(&grant.client_id, &scope) else {
            continue;
        };
        match clients.get(&client_id).await {
            Ok(client) => {
                // Auto-grant clients are not meaningfully revocable: omit them.
                if is_auto_grant(&client.consent_mode, client.skip_consent) {
                    continue;
                }
                items.push(UserConsentView {
                    client_id: grant.client_id.clone(),
                    display_name: Some(client.display_name),
                    logo_uri: client.logo_uri,
                    scope: grant.granted_scope.clone(),
                    granted_at_unix_ms: ms(grant.granted_at_unix_micros),
                    expires_at_unix_ms: grant.expires_at_unix_micros.map(ms),
                });
            }
            // The client was deleted after the grant: still list it (revocable) by id.
            Err(StoreError::NotFound) => items.push(UserConsentView {
                client_id: grant.client_id.clone(),
                display_name: None,
                logo_uri: None,
                scope: grant.granted_scope.clone(),
                granted_at_unix_ms: ms(grant.granted_at_unix_micros),
                expires_at_unix_ms: grant.expires_at_unix_micros.map(ms),
            }),
            Err(error) => return Err(error.into()),
        }
    }
    let list = UserConsentList { items };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Revoke a user's remembered consent to one client (issue #88). Stamps the consent
/// revoked and cascades to the (subject, client) refresh families in the store's single
/// transaction, so the connected app's live long-lived tokens die with the consent. A
/// security mutation, so it is sudo-gated. Idempotent: revoking an already-revoked or
/// absent grant is a no-op success (`revoked = false`).
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/consents/{client_id}/revoke",
    operation_id = "revokeUserConsent",
    tag = "users",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)"),
        ("client_id" = String, Path, description = "The client identifier (cli_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The consent was revoked", body = ConsentRevocationView),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn revoke_user_consent(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id, client_id)): Path<(String, String, String, String)>,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;

    // Both ids are parsed under the caller's OWN scope: a malformed or cross-scope user
    // id or client id is the uniform not-found BEFORE any mutating repository is reached.
    let subject = UserId::parse_in_scope(&user_id, &scope).map_err(|_| StoreError::NotFound)?;
    let client = ClientId::parse_in_scope(&client_id, &scope).map_err(|_| StoreError::NotFound)?;

    let revocation = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .consents()
        .revoke(
            state.env(),
            &subject.to_string(),
            &client.to_string(),
            state.now_unix_micros(),
        )
        .await?;

    let view = ConsentRevocationView {
        client_id: client.to_string(),
        revoked: revocation.consent_revoked,
        families_revoked: revocation.families_revoked,
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
