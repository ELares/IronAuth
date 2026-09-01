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
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_jose::Confirmation;
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
///
/// The body arrives as [`Bytes`] and is parsed INSIDE the handler rather than extracted by
/// `Json<..>`. That is not a style choice. `Json` is a FALLIBLE extractor, so axum runs it
/// before the handler body: a request with no `Content-Type` was answered `415` while the
/// feature was off, and a genuinely unknown path answers `404`. The difference is a
/// feature-presence oracle available to an unauthenticated prober, which is exactly what the
/// paragraph above claims cannot happen. The two other flag-gated handlers in this crate
/// (`risk_signals`, `challenge`) take infallible bodies for the same reason.
#[allow(
    clippy::too_many_lines,
    reason = "the body is the authentication sequence and the two entitlement fences, in \
    order, and every step reads what the step before it produced. Splitting it would put a \
    fence in a function a future edit could reach the store without calling, which is the \
    one property this handler exists to hold"
)]
pub async fn exchange(
    State(state): State<OidcState>,
    headers: HeaderMap,
    method: axum::http::Method,
    body: Bytes,
) -> Response {
    if !state.agent_vault_enabled() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(request) = serde_json::from_slice::<ExchangeRequest>(&body) else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the request body must be a JSON object naming a provider",
        );
    };

    // Verified through the SAME sequence UserInfo uses, and for a sharper reason than it
    // has: this endpoint hands out somebody else's credential on the strength of the answer.
    // A locally decoded claim set would accept any signature at all.
    //
    // 1. the presentation is read by UserInfo's own reader, so the scheme is matched
    //    case-insensitively (RFC 7235) and a `DPoP <token>` presentation is accepted rather
    //    than 401'd for not spelling `Bearer` exactly;
    // 2. the jti carries its scope, so a token from another environment does not resolve;
    // 3. the jti resolves to a live grant, so a revoked chain is refused;
    // 4. the token verifies cryptographically against that environment and client;
    // 5. the RFC 9449 binding is enforced, which step 4 does not do.
    //
    // Step 5 was missing, and the comment here claimed parity with UserInfo while it was.
    // The direction of that gap is the dangerous one: a token carrying `cnf.jkt` was accepted
    // as a plain bearer, so the proof-of-possession binding simply did not apply at the one
    // endpoint that hands over a third party's credential.
    let Ok(presented) = crate::userinfo::presented_credential(&headers) else {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "an agent access token is required",
        );
    };
    let bearer = presented.token();
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

    // Step 5: the RFC 9449 binding. A token whose `cnf` names a proof key MUST arrive under
    // the `DPoP` scheme with a valid proof over this method and URL; an unbound token MUST be
    // a plain bearer. `confirmation_jkt` fails CLOSED on a confirmation that is not a `jkt`
    // (an mTLS binding, say), so a future binding type cannot be silently ignored here the
    // way it would be by a `cnf.get("jkt")` read.
    let Ok(confirmation) = Confirmation::from_claims(verified.claims()) else {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "the token does not verify",
        );
    };
    let Ok(expected_jkt) = crate::userinfo::confirmation_jkt(confirmation.as_ref()) else {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "the token does not verify",
        );
    };
    if let Err(failure) = crate::userinfo::enforce_dpop_outcome(
        &state,
        &scope,
        expected_jkt,
        &presented,
        method.as_str(),
        // THIS endpoint's URL, not UserInfo's. The verifier used to hardcode the userinfo
        // `htu`, which would have meant two things at once: a compliant client binding its
        // proof to `/agent/vault/exchange` is refused forever, and a proof minted for
        // `POST /userinfo` validates here. An `htu` shared between two resources is not a
        // binding between either of them and its proof.
        &crate::dpop::normalized_htu_for_agent_vault(&state),
        bearer,
    )
    .await
    {
        // The NONCE CHALLENGE is carried through rather than collapsed. A deployment with
        // `require_dpop_nonce` on has already ISSUED and RECORDED a nonce by the time this
        // returns, and answering a bare 401 would burn one per attempt and lock out every
        // compliant client permanently: it is being told to retry and given nothing to retry
        // with. Every OTHER failure collapses to the uniform refusal (RFC 9449 section 7.1),
        // which is the anti-oracle.
        return match failure {
            crate::userinfo::DpopRefusal::NeedsNonce { nonce } => (
                StatusCode::UNAUTHORIZED,
                [
                    (header::CACHE_CONTROL, "no-store".to_owned()),
                    (axum::http::HeaderName::from_static("dpop-nonce"), nonce),
                    (
                        header::WWW_AUTHENTICATE,
                        "DPoP error=\"use_dpop_nonce\", \
                         error_description=\"Authorization server requires nonce in DPoP proof\""
                            .to_owned(),
                    ),
                ],
                Json(serde_json::json!({
                    "error": "use_dpop_nonce",
                    "error_description": "retry with the DPoP nonce this response carries",
                })),
            )
                .into_response(),
            crate::userinfo::DpopRefusal::Rejected => refuse(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "the token does not verify",
            ),
        };
    }

    // FENCE ONE: the token must name an agent. A token without `agent_id` belongs to an
    // ordinary machine identity or a person, and neither has a vault. The claim is
    // ISSUER-SET and on the protected list, so a client cannot self-assert it.
    let Some(agent_claim) = verified
        .claims()
        .get("agent_id")
        .and_then(serde_json::Value::as_str)
    else {
        // 401, not 403. RFC 6750 section 3.1 pairs `invalid_token` with 401 and
        // `insufficient_scope` with 403, and every refusal in this group is a statement about
        // the TOKEN rather than about what its holder may do. A client that reads the error
        // code and the status together should not be given two answers.
        return refuse(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "this token was not issued to an agent",
        );
    };
    let Ok(agent_id) = AgentPrincipalId::parse_in_scope(agent_claim, &scope) else {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "the agent identity is not of this scope",
        );
    };

    let store = state.store().scoped(scope);
    let Ok(agent) = store.agents().get(&agent_id).await else {
        return refuse(
            StatusCode::UNAUTHORIZED,
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

    // ONE correlation id and ONE service actor for the whole REQUEST, minted here rather than
    // at each audited write. Each write used to generate its own, so the deny row and the
    // exchange row of a single request shared no correlation at all and an investigator
    // following one could not find the other. A correlation id that correlates nothing is
    // just another random column.
    let correlation = CorrelationId::generate(state.env());
    let request_actor = ActorRef::service(ServiceId::generate(state.env()));

    // FENCE TWO: the provider must be inside the DECLARED set, at the AGENT grain.
    if !agent.declares_tool(&request.provider) {
        let acting = state
            .store()
            .scoped(scope)
            .acting(request_actor, correlation);
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
        let acting = state
            .store()
            .scoped(scope)
            .acting(request_actor, correlation);
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

    // An UNUSABLE connection is refused DISTINCTLY from an absent one. "your Google
    // connection is broken" and "you have no Google connection" call for different operator
    // actions, and collapsing them would hide the one that is fixable.
    //
    // But "unusable" is TWO conditions, and the refusal used to name only one of them: an
    // `active` connection whose stored token had simply expired was reported as "marked
    // failed", from a comment congratulating itself for not collapsing distinguishable
    // states. The two are told apart here, because they are fixed differently: a failed
    // connection needs re-establishing, an expired one needs a fresh token stored for the
    // same connection.
    let now_micros = crate::util::epoch_micros(state.now());
    if connection.state != "active" {
        return refuse(
            StatusCode::CONFLICT,
            "connection_failed",
            "this connection is marked failed and must be re-established",
        );
    }
    if !connection.is_usable(now_micros) {
        return refuse(
            StatusCode::CONFLICT,
            "connection_expired",
            "the stored credential for this connection has expired and must be replaced",
        );
    }

    // The exchange row, BEFORE the credential leaves. A record written afterwards is one a
    // crash can lose while the credential is already gone.
    let acting = state
        .store()
        .scoped(scope)
        .acting(request_actor, correlation);
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
