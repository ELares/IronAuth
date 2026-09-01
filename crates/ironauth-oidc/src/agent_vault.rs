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

/// The exchange request: which downstream provider the agent wants, and for what.
#[derive(Debug, Deserialize)]
pub struct ExchangeRequest {
    /// The downstream provider.
    pub provider: String,

    /// The RFC 9396 authorization details this exchange is FOR, when the action is sensitive.
    ///
    /// Naming this is what makes an action sensitive, and that is deliberate: a server that
    /// decided sensitivity from a list of its own would be guessing at a question only the
    /// caller can answer, and a caller that could obtain a credential without saying what for
    /// would never be held to anything. Present, the exchange goes through the APPROVAL GATE
    /// and issues nothing until a human decides. Absent, it is an ordinary exchange.
    ///
    /// EXPLORATORY, like the rest of this surface: the shape a real deployment wants here is
    /// the open question, and pinning it to RFC 9396 rather than inventing one is the cheapest
    /// bet to unwind.
    #[serde(default)]
    pub authorization_details: Option<serde_json::Value>,
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
    /// What the APPROVER agreed to, present only on an approved sensitive exchange.
    ///
    /// Not an echo of the request. An approver who narrows a request must have the narrowed
    /// set be the one that takes effect, or the approval surface is decoration; this is that
    /// narrowed set, rendered from the decision rather than from what was asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<serde_json::Value>,
}

/// The answer to a sensitive exchange that is waiting on a human.
///
/// A distinct SHAPE and a distinct status, not an error: the caller has done nothing wrong and
/// the correct behaviour is to come back. It carries the approval id so a caller can poll one
/// thing rather than re-deriving which request it is waiting on.
#[derive(Debug, Serialize)]
pub struct ApprovalPending {
    /// Always `approval_pending`.
    pub status: String,
    /// The approval to poll.
    pub approval_id: String,
    /// When the request stops being answerable, in seconds since the epoch. After this the
    /// action is refused: a timeout issues no token, exactly as a denial does.
    pub expires_at: i64,
}

/// Refresh a connection's stored credential at its provider (issue #132, criterion 3).
///
/// The half of criterion 3 that did not exist. The vault STORED a refresh token and nothing
/// could spend it: refreshing means presenting that token at the provider's token endpoint
/// with the client credentials that provider issued, and until migration 0180 none of those
/// three things had anywhere to live.
///
/// Returns the fresh credential on success. A failure AT THE PROVIDER marks the connection and
/// returns the reason, which is the other half of the same criterion: one dead downstream is
/// visible and isolated instead of taking an agent's other connections with it. Marked, never
/// deleted, so an operator can see which one broke and why.
///
/// The three checks BEFORE the provider is contacted -- no refresh configuration, no stored
/// refresh token, no federation runtime -- return without marking, deliberately. Nothing is
/// wrong with the connection in any of them: the first two describe a connection that was
/// never set up to refresh, and the third describes a deployment that cannot reach any
/// provider at all. Marking would report a working credential as broken.
///
/// Rides the SSRF-hardened federation fetcher rather than a client of its own. The endpoint is
/// operator-supplied and dereferenced with a refresh token in the body, so it gets the same
/// address validation, redirect refusal and size bounds every other outbound in this system
/// gets. A deployment with no federation runtime installed cannot refresh, which is reported
/// as such rather than as a provider failure: nothing is wrong with the connection.
async fn refresh_connection(
    state: &OidcState,
    scope: ironauth_store::Scope,
    connection: &ironauth_store::VaultConnection,
    actor: ActorRef,
    correlation: CorrelationId,
) -> Result<RefreshedCredential, &'static str> {
    let Some(config) = connection.refresh.as_ref() else {
        return Err("this connection cannot refresh and must be re-established");
    };
    let Some(refresh_token) = connection.refresh_token.as_deref() else {
        return Err("this connection stored no refresh token");
    };
    let Some(federation) = state.federation() else {
        return Err("this deployment cannot reach a provider to refresh");
    };

    let form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
        crate::util::percent_encode_query(refresh_token),
        crate::util::percent_encode_query(&config.client_id),
        crate::util::percent_encode_query(&config.client_secret),
    );
    let mut http = ironauth_fetch::FetchRequest::new(
        ironauth_fetch::FetchPurpose::FederationToken,
        axum::http::Method::POST,
        config.token_endpoint.clone(),
    )
    .header(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/x-www-form-urlencoded"),
    )
    .header(
        header::ACCEPT,
        axum::http::HeaderValue::from_static("application/json"),
    )
    .body(form.into_bytes());
    if federation.allow_http() {
        http = http.allow_plaintext_http();
    }

    // EVERY failure below marks the connection, and the mark is what isolation means.
    let outcome = async {
        let response = federation
            .fetcher()
            .fetch(http)
            .await
            .map_err(|_| "the provider could not be reached")?;
        if !response.status().is_success() {
            return Err("the provider refused the refresh");
        }
        let body: serde_json::Value = serde_json::from_slice(response.body())
            .map_err(|_| "the provider's response is not JSON")?;
        let access_token = body
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .ok_or("the provider's response carried no access_token")?
            .to_owned();
        // A provider MAY rotate the refresh token and MAY omit it, in which case the stored
        // one stays valid. Keeping the old one on omission is the difference between a
        // connection that refreshes twice and one that refreshes once.
        let refresh_token = body
            .get("refresh_token")
            .and_then(serde_json::Value::as_str)
            .map_or_else(|| refresh_token.to_owned(), ToOwned::to_owned);
        let expires_in = body.get("expires_in").and_then(serde_json::Value::as_i64);
        Ok(RefreshedCredential {
            access_token,
            refresh_token,
            expires_in_secs: expires_in,
        })
    }
    .await;

    match outcome {
        Ok(refreshed) => Ok(refreshed),
        Err(reason) => {
            // Best effort: the refresh already failed, and failing to RECORD that must not
            // turn one dead downstream into a request that reports something else.
            let _ = state
                .store()
                .scoped(scope)
                .acting(actor, correlation)
                .agent_vault()
                .mark_failed(
                    state.env(),
                    &connection.id,
                    reason,
                    crate::util::epoch_micros(state.now()),
                )
                .await;
            Err(reason)
        }
    }
}

/// What a successful refresh returned.
///
/// Deliberately NOT `Debug`, for the reason every other type here is not: it holds two
/// downstream secrets.
struct RefreshedCredential {
    access_token: String,
    refresh_token: String,
    expires_in_secs: Option<i64>,
}

/// The digest that binds an approval to ONE action.
///
/// Over the CANONICAL serialization: `serde_json::Value` keeps object keys ordered, so two
/// requests differing only in key order digest the same and two differing in any value do not.
/// That equality is the whole control -- without it an approval for one action authorized every
/// action at that provider until it expired.
fn action_digest(details: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::to_vec(details).unwrap_or_default();
    let digest = Sha256::digest(&canonical);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// How long a raised approval stays answerable.
///
/// Bounded because the criterion says a TIMEOUT issues no tokens, and a request with no
/// deadline never times out: it blocks for ever, which is indistinguishable from a denial
/// nobody made. An hour is long enough for a human on another device and short enough that a
/// forgotten request does not sit authorizing something a week later.
const APPROVAL_WINDOW_MICROS: i64 = 60 * 60 * 1_000_000;

/// The `202` a sensitive exchange gets while it waits on a human.
fn pending_response(approval: &ironauth_store::VaultApproval) -> Response {
    (
        StatusCode::ACCEPTED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(ApprovalPending {
            status: "approval_pending".to_owned(),
            approval_id: approval.id.to_string(),
            expires_at: approval.expires_at_unix_micros / 1_000_000,
        }),
    )
        .into_response()
}

/// The acting store an approval RAISE is written through.
///
/// The DATA plane: raising a request is the agent's own action, and migration 0179 grants the
/// app role INSERT for exactly this, narrowed by a restrictive policy to rows that arrive
/// undecided. Deciding is the control plane's, and this store cannot reach it.
fn acting_for_approval(
    state: &OidcState,
    scope: ironauth_store::Scope,
    actor: ActorRef,
    correlation: CorrelationId,
) -> ironauth_store::ActingStore<'_> {
    state.store().scoped(scope).acting(actor, correlation)
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
    // EXPIRED: refresh it rather than refusing (issue #132, criterion 3).
    //
    // This is what makes the stored refresh token worth storing. An expired credential is not
    // a broken connection, it is one that needs renewing, and the agent asking for it is
    // exactly the moment to renew: refreshing on a schedule would spend a provider's rate
    // limit on connections nobody is using, and refreshing eagerly at store time would leave
    // the same problem an hour later.
    //
    // A refresh that FAILS marks the connection, which is the isolation half of the same
    // criterion: this agent's Google connection is now visibly broken and its GitHub one is
    // untouched. The refusal then names what actually happened rather than "expired", because
    // the operator's next action differs.
    let mut connection = connection;
    // `can_refresh`, NOT `refresh.is_some()`. The ordinary read never opens the client secret,
    // so the opened value is always `None` here and testing it made this whole branch dead
    // code: an expired connection fell straight through to the 409 below and the refresh path
    // had no live caller at all. The two fields answer different questions and this is the one
    // that asks whether a refresh is possible.
    if !connection.is_usable(now_micros) && connection.can_refresh {
        // Re-read WITH the refresh, which is the only read that opens the client secret.
        let refreshable = store
            .agent_vault()
            .connection_with_refresh(&agent_id, &request.provider)
            .await;
        match refreshable {
            Ok(Some(with_config)) => {
                match refresh_connection(&state, scope, &with_config, request_actor, correlation)
                    .await
                {
                    Ok(refreshed) => {
                        let expires_at = refreshed
                            .expires_in_secs
                            .and_then(|seconds| seconds.checked_mul(1_000_000))
                            .and_then(|micros| now_micros.checked_add(micros));
                        // An UPDATE through the DATA plane, which is the plane this
                        // request is already on and which migration 0178 grants exactly
                        // `SELECT, UPDATE` for. The upsert was wrong twice over: it needs
                        // `INSERT`, which this role deliberately does not hold ("a connection
                        // is established through an operator-driven flow, never as a side
                        // effect of a token request"), and it would have failed AFTER the
                        // refresh token was already spent at the provider.
                        let restored = state
                            .store()
                            .scoped(scope)
                            .acting(request_actor, correlation)
                            .agent_vault()
                            .refresh_stored_credential(
                                state.env(),
                                ironauth_store::RefreshedCredentialWrite {
                                    id: &with_config.id,
                                    agent_id: &agent_id,
                                    provider: &request.provider,
                                    access_token: &refreshed.access_token,
                                    refresh_token: Some(&refreshed.refresh_token),
                                    expires_at_unix_micros: expires_at,
                                },
                                now_micros,
                            )
                            .await;
                        if restored.is_err() {
                            // The refresh token has already been SPENT at the provider and may
                            // have been rotated, so the stored one is now potentially useless
                            // and the connection genuinely is broken. Marked, best effort:
                            // failing to record it must not change what this request answers.
                            let _ = state
                                .store()
                                .scoped(scope)
                                .acting(request_actor, correlation)
                                .agent_vault()
                                .mark_failed(
                                    state.env(),
                                    &with_config.id,
                                    "the refreshed credential could not be stored",
                                    now_micros,
                                )
                                .await;
                            return refuse(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "server_error",
                                "the refreshed credential could not be stored",
                            );
                        }
                        connection.access_token = refreshed.access_token;
                        connection.expires_at_unix_micros = expires_at;
                    }
                    Err(reason) => {
                        return refuse(StatusCode::CONFLICT, "connection_failed", reason);
                    }
                }
            }
            _ => {
                return refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "the connection could not be read",
                );
            }
        }
    }
    if !connection.is_usable(now_micros) {
        return refuse(
            StatusCode::CONFLICT,
            "connection_expired",
            "the stored credential for this connection has expired and must be replaced",
        );
    }

    // THE APPROVAL GATE (issue #132, criterion 4). Reached only when the request NAMES
    // authorization details, which is what makes an action sensitive.
    //
    // The criterion is "a seeded sensitive action BLOCKS until an out-of-band approval renders
    // its authorization_details; denial or timeout issues no tokens". Blocking cannot mean
    // holding the request open: the approver is a human on another device and the wait is
    // unbounded. It means the exchange issues NOTHING and hands back something to poll.
    //
    // The four answers, and every one of them decided by the row rather than by this code
    // remembering what it did last time:
    //
    //   - no approval yet     -> raise one, answer `approval_pending`, issue nothing;
    //   - pending             -> answer `approval_pending` again, issue nothing;
    //   - approved and live   -> issue, carrying what the APPROVER agreed to;
    //   - denied, or approved past its deadline -> refuse, issue nothing.
    //
    // A timeout is the absence of a decision, not an event: `authorizes` computes it from the
    // deadline on the row, so an approval nobody answered stops authorizing on its own and
    // needs no sweeper to have run for the refusal to be correct.
    let mut approved_details = None;
    let mut approved_for: Option<String> = None;
    if connection.requires_approval {
        // SENSITIVITY IS THE OPERATOR'S DECISION, not the agent's. This used to run when the
        // REQUEST named `authorization_details`, which meant a denied agent re-sent the same
        // exchange with the field omitted and received the identical credential: "denial
        // issues no tokens" was true of this block's interior and false of the endpoint. The
        // connection now carries the answer, and the agent cannot decline to enter the gate.
        let Some(requested_details) = request.authorization_details.as_ref() else {
            // A sensitive connection with no stated action is a bad request, not a bypass.
            // There is nothing for an approver to decide and nothing to bind an approval to.
            return refuse(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "this connection requires approval, so the request must state the \
                 authorization_details it is for",
            );
        };
        // The action, as a digest of its CANONICAL form, so an approval is bound to the exact
        // request it was raised for. `serde_json::Value` orders object keys, so two requests
        // that differ only in key order produce one digest -- and two that differ in any value
        // produce different ones, which is what stops an approval for a payment of one from
        // authorizing a payment of a million.
        let action_digest = action_digest(requested_details);

        let Ok(existing) = store
            .agent_vault_approvals()
            .latest_for(&agent_id, &request.provider, &action_digest)
            .await
        else {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the approval could not be read",
            );
        };

        // Four answers, and the ORDER matters: a row past its deadline is dead whatever its
        // state, so the expiry is checked before the state rather than after. Checking state
        // first is how the previous version deadlocked -- a pending row past its deadline
        // matched the pending arm and answered 202 forever, invisible to the approver's queue
        // (which excludes expired rows) and undecidable (the decision refuses them too), while
        // an approved row past its deadline answered 403 forever. Both were permanent, and
        // neither raised a replacement.
        let live = existing
            .as_ref()
            .is_some_and(|approval| now_micros < approval.expires_at_unix_micros);
        match existing {
            Some(approval) if live && approval.state == "approved" => {
                // What the approver AGREED to, which may be narrower than what was asked. An
                // approval that stated nothing means "exactly what was asked", so the request
                // is echoed rather than the field being dropped: a caller that received no
                // statement at all could not tell an unnarrowed approval from a missing one.
                approved_details = Some(
                    approval
                        .approved_details
                        .clone()
                        .unwrap_or_else(|| requested_details.clone()),
                );
                approved_for = Some(approval.id.to_string());
            }
            Some(approval) if live && approval.state == "pending" => {
                return pending_response(&approval);
            }
            // Denied, and still live. A denial stands for as long as it was given for, and
            // re-raising here would make it a speed bump. It stops standing when it expires,
            // which is the same rule the approval gets.
            Some(_) if live => {
                return refuse(
                    StatusCode::FORBIDDEN,
                    "access_denied",
                    "this action was not approved",
                );
            }
            // Nothing, or nothing still live: raise one. This is the arm that makes a timeout
            // recoverable rather than terminal.
            _ => {
                let approval_id =
                    ironauth_store::AgentVaultApprovalId::generate(state.env(), &scope);
                let expires_at = now_micros.saturating_add(APPROVAL_WINDOW_MICROS);
                match acting_for_approval(&state, scope, request_actor, correlation)
                    .agent_vault_approvals()
                    .request(
                        state.env(),
                        ironauth_store::NewVaultApproval {
                            id: &approval_id,
                            agent_id: &agent_id,
                            provider: &request.provider,
                            requested_details,
                            action_digest: &action_digest,
                            expires_at_unix_micros: expires_at,
                        },
                    )
                    .await
                {
                    Ok(()) => {}
                    // A concurrent exchange raised the same action first, which the unique
                    // partial index refuses. Not a fault: re-read and answer with the winner,
                    // so both callers poll the SAME approval. Answering 500 here would have
                    // been a server error for a request that behaved correctly, and inserting
                    // anyway would leave an approver deciding a row nothing reads.
                    Err(ironauth_store::StoreError::Conflict) => {
                        return match store
                            .agent_vault_approvals()
                            .latest_for(&agent_id, &request.provider, &action_digest)
                            .await
                        {
                            Ok(Some(winner)) => pending_response(&winner),
                            _ => refuse(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "server_error",
                                "the approval could not be read",
                            ),
                        };
                    }
                    Err(_) => {
                        return refuse(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "server_error",
                            "the approval could not be raised",
                        );
                    }
                }
                return (
                    StatusCode::ACCEPTED,
                    [(header::CACHE_CONTROL, "no-store")],
                    Json(ApprovalPending {
                        status: "approval_pending".to_owned(),
                        approval_id: approval_id.to_string(),
                        expires_at: expires_at / 1_000_000,
                    }),
                )
                    .into_response();
            }
        }
    }

    // What the exchange row says. The provider, and the APPROVAL that authorized it when one
    // did: without the second, nothing joins "credential handed over" to "approval that
    // permitted it", and accountability is the whole reason this row exists.
    let exchange_detail = match approved_for.as_ref() {
        Some(approval_id) => format!("{} approval={approval_id}", request.provider),
        None => request.provider.clone(),
    };

    // The exchange row, BEFORE the credential leaves. A record written afterwards is one a
    // crash can lose while the credential is already gone.
    let acting = state
        .store()
        .scoped(scope)
        .acting(request_actor, correlation);
    if acting
        .agent_vault()
        .record_exchange(state.env(), &connection.id, &exchange_detail)
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
            authorization_details: approved_details,
        }),
    )
        .into_response()
}
