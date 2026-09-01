// SPDX-License-Identifier: MIT OR Apache-2.0

//! The agent vault exchange (issue #132): an agent trades its IronAuth token for the
//! downstream credential it is entitled to.
//!
//! The entitlement is the point. An agent presenting a valid IronAuth token is not thereby
//! entitled to every credential in the vault, or even to every credential of its own: it may
//! have what it DECLARED, held under its OWN agent id, and nothing else. Two independent
//! fences enforce that, and both are here rather than one being assumed:
//!
//!   1. the token must carry an `agent_id`, and the connection is read UNDER that id, so a
//!      token belonging to one agent cannot address another agent's row at all;
//!   2. the provider must be inside the agent's declared tool set, so an agent that never
//!      declared `google` cannot obtain a Google credential even if a connection exists.
//!
//! Every exchange is audited. Without that row IronAuth is the custodian of somebody else's
//! credential with no record of handing it over, which is the thing that makes a vault worse
//! than no vault.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{ActorRef, AgentPrincipalId, CorrelationId, ServiceId};
use serde::{Deserialize, Serialize};

use crate::state::OidcState;

/// The exchange request: which downstream provider the agent wants.
#[derive(Debug, Deserialize)]
pub struct ExchangeRequest {
    /// `google` or `github`.
    pub provider: String,
}

/// The exchange response.
///
/// Deliberately NOT `Debug`: a derived formatter on a struct holding a third-party access
/// token puts that token into the first log line or test failure that renders it.
#[derive(Serialize)]
pub struct ExchangeResponse {
    /// The downstream access token.
    pub access_token: String,
    /// The provider it is for, echoed so a caller holding several cannot mix them up.
    pub provider: String,
    /// What the provider actually granted, which is not always what was asked for.
    pub granted_scopes: Vec<String>,
}

/// A refusal, in the shape the token endpoint already uses.
fn refuse(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

/// `POST /agent/vault/exchange`.
///
/// A uniform 404 when the feature is off, so a deployment that never opted in does not
/// advertise a surface by refusing it differently from any other unknown path.
pub async fn exchange(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Json(request): Json<ExchangeRequest>,
) -> Response {
    if !state.agent_vault_enabled() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let Some(bearer) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "an agent access token is required",
        );
    };

    // Verified through the SAME sequence UserInfo uses, and for a sharper reason than it
    // has: this endpoint hands out somebody else's credential on the strength of the answer.
    // A locally decoded claim set would accept any signature at all.
    //
    // 1. the jti carries its scope, so a token from another environment does not resolve;
    // 2. the jti resolves to a live grant, so a revoked chain is refused;
    // 3. the token verifies cryptographically against that environment and client.
    let Some(jti_raw) = crate::userinfo::peek_jti(bearer) else {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "unreadable token",
        );
    };
    let Ok(jti) = ironauth_store::IssuedTokenId::parse_declared_scope(&jti_raw) else {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "unreadable token",
        );
    };
    let scope = jti.scope();
    let resolution = match state
        .store()
        .scoped(scope)
        .authorization()
        .resolve_access_token(&jti)
        .await
    {
        Ok(Some(resolution)) if resolution.active => resolution,
        Ok(_) => {
            return refuse(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "the token is not active",
            );
        }
        Err(_) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the token could not be resolved",
            );
        }
    };
    let Ok(verified) = state
        .verify_access_token(&scope, &resolution.client_id, bearer)
        .await
    else {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "the token does not verify",
        );
    };

    // FENCE ONE: the token must name an agent. A token without `agent_id` belongs to an
    // ordinary machine identity or a person, and neither has a vault. The claim is
    // ISSUER-SET and on the protected list, so a client cannot self-assert it.
    let Some(agent_claim) = verified
        .claims()
        .get("agent_id")
        .and_then(serde_json::Value::as_str)
    else {
        return refuse(
            StatusCode::FORBIDDEN,
            "invalid_token",
            "this token was not issued to an agent",
        );
    };
    let Ok(agent_id) = AgentPrincipalId::parse_in_scope(agent_claim, &scope) else {
        return refuse(
            StatusCode::FORBIDDEN,
            "invalid_token",
            "the agent identity is not of this scope",
        );
    };

    let store = state.store().scoped(scope);
    let Ok(agent) = store.agents().get(&agent_id).await else {
        return refuse(
            StatusCode::FORBIDDEN,
            "invalid_token",
            "the agent named by this token no longer exists",
        );
    };
    // A suspended or revoked agent holds no credential, exactly as it obtains no token.
    if !agent.can_obtain_tokens() {
        return refuse(
            StatusCode::FORBIDDEN,
            "access_denied",
            "this agent is not active",
        );
    }

    // FENCE TWO: the provider must be inside the DECLARED set, at the AGENT grain.
    if !agent.declares_tool(&request.provider) {
        let acting = state.store().scoped(scope).acting(
            ActorRef::service(ServiceId::generate(state.env())),
            CorrelationId::generate(state.env()),
        );
        let _ = acting
            .agents()
            .record_token_denied(state.env(), &agent_id, "vault-provider-undeclared")
            .await;
        return refuse(
            StatusCode::FORBIDDEN,
            "access_denied",
            "this agent did not declare that provider",
        );
    }

    // FENCE THREE: the provider must also be in THIS TOKEN's granted scope.
    //
    // Fence two is the agent grain and is not enough on its own. `gate_agent_issuance` goes
    // to real trouble to narrow a token per request: an agent declaring `google github` that
    // asks for `scope=github` receives a token whose scope claim is exactly `github`, which
    // is the least-privilege token that whole gate exists to produce. Without this fence that
    // narrowed token still opens the full declared vault, so it is worth strictly more than
    // the token endpoint said it was, and what it is worth is a credential IronAuth cannot
    // revoke.
    //
    // An ABSENT scope claim is refused here rather than waved through. `gate_agent_issuance`
    // permits a scope-less request because asking for nothing is not a widening, and a token
    // that asked for nothing is exactly the one with no claim on any provider.
    let granted_scope = verified
        .claims()
        .get("scope")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !granted_scope
        .split_whitespace()
        .any(|token| token == request.provider)
    {
        let acting = state.store().scoped(scope).acting(
            ActorRef::service(ServiceId::generate(state.env())),
            CorrelationId::generate(state.env()),
        );
        let _ = acting
            .agents()
            .record_token_denied(state.env(), &agent_id, "vault-provider-outside-token-scope")
            .await;
        return refuse(
            StatusCode::FORBIDDEN,
            "access_denied",
            "this token was not granted that provider",
        );
    }

    let connection = match store
        .agent_vault()
        .connection(&agent_id, &request.provider)
        .await
    {
        Ok(Some(connection)) => connection,
        Ok(None) => {
            return refuse(
                StatusCode::NOT_FOUND,
                "not_found",
                "this agent has no connection for that provider",
            );
        }
        Err(_) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the connection could not be read",
            );
        }
    };

    // A FAILED connection is refused DISTINCTLY from an absent one. "your Google connection
    // is broken" and "you have no Google connection" call for different operator actions,
    // and collapsing them would hide the one that is fixable.
    if !connection.is_usable(crate::util::epoch_micros(state.now())) {
        return refuse(
            StatusCode::CONFLICT,
            "connection_failed",
            "this connection is marked failed and must be re-established",
        );
    }

    // The exchange row, BEFORE the credential leaves. A record written afterwards is one a
    // crash can lose while the credential is already gone.
    let acting = state.store().scoped(scope).acting(
        ActorRef::service(ServiceId::generate(state.env())),
        CorrelationId::generate(state.env()),
    );
    if acting
        .agent_vault()
        .record_exchange(state.env(), &connection.id, &request.provider)
        .await
        .is_err()
    {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the exchange could not be recorded",
        );
    }

    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(ExchangeResponse {
            access_token: connection.access_token,
            provider: connection.provider,
            granted_scopes: connection.granted_scopes,
        }),
    )
        .into_response()
}
