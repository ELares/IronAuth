// SPDX-License-Identifier: MIT OR Apache-2.0

//! The registration-abuse challenge GATE (issue #80): the orchestration that ties the
//! per-environment config, the #79 risk conditioning, the `pow_challenges` store, and the
//! pluggable [`ChallengeProvider`](crate::pow::ChallengeProvider) together on the
//! registration, password-reset, and OTP-send surfaces.
//!
//! The built-in proof-of-work path is fully SERVER-SIDE and makes ZERO third-party calls:
//! the server mints a random challenge bound to the endpoint plus a request context
//! ([`issue_builtin_challenge`]), and later atomically consumes it single-use and verifies
//! the presented nonce ([`verify_solution`]). Challenge issuance is CONDITIONED on risk
//! ([`challenge_required`]) exactly the way the login step-up gate conditions on the #79
//! challenge action. An external adapter (Turnstile/reCAPTCHA) verifies a client token
//! through the audited fetch seam instead; an adapter outage degrades per the configured
//! fail-open / fail-closed policy. The built-in `PoW` has no outage mode.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_config::AdapterFailPolicy;
use ironauth_store::{NewPowChallenge, PowChallengeId, Scope};
use serde::Deserialize;

use crate::pow::{ChallengeVerdict, ChallengeVerifyRequest, PowSolution, context_binding};
use crate::risk::RiskLevel;
use crate::state::OidcState;
use crate::util::epoch_micros;

/// The stable per-endpoint labels a challenge is bound to (issue #80). A challenge minted
/// for one label can never be consumed at another, so a solution for the registration
/// endpoint does not satisfy the OTP-send endpoint (the context binding).
pub(crate) const ENDPOINT_REGISTER: &str = "register";
/// The password-reset / recovery endpoint label.
pub(crate) const ENDPOINT_RECOVER: &str = "recover";
/// The OTP-send endpoint label.
pub(crate) const ENDPOINT_OTP_SEND: &str = "otp_send";

/// Whether a challenge is REQUIRED for this attempt (issue #80): the `PoW` feature is on AND
/// the anonymous risk level meets the configured `challenge_at` threshold. Reuses the #79
/// `RiskLevel` threshold vocabulary, so `low` challenges every attempt while `med`
/// challenges only an elevated one (a suspect IP or a flagged disposable domain). `off`
/// (the threshold, distinct from the feature toggle) never challenges.
#[must_use]
pub(crate) fn challenge_required(
    state: &OidcState,
    ip: Option<&str>,
    disposable_flagged: bool,
) -> bool {
    let pow = &state.registration_abuse_config().pow;
    if !pow.enabled {
        return false;
    }
    let Some(floor) = RiskLevel::parse_threshold(&pow.challenge_at) else {
        return false;
    };
    let level = crate::risk::anonymous_challenge_level(state, ip, disposable_flagged);
    level.rank() >= floor.rank()
}

/// A freshly issued built-in proof-of-work challenge (issue #80).
#[derive(Debug, Clone)]
pub(crate) struct IssuedChallenge {
    /// The `pow_` challenge id the client returns with its nonce.
    pub id: PowChallengeId,
    /// The random challenge bytes the client must find a qualifying nonce for.
    pub challenge: Vec<u8>,
    /// The number of leading zero bits the solving nonce must produce.
    pub difficulty_bits: u8,
}

/// Mint a built-in proof-of-work challenge (issue #80), bound to `endpoint` plus `context`,
/// via the store. The challenge randomness comes from `env.entropy()` and the expiry from
/// `env.clock()`, so the whole path is deterministic under a test's manual clock and fixed
/// entropy, and it makes ZERO third-party calls. Returns `None` only on a persistence
/// failure (the caller then omits the challenge rather than failing the page).
pub(crate) async fn issue_builtin_challenge(
    state: &OidcState,
    scope: Scope,
    endpoint: &str,
    context: &str,
) -> Option<IssuedChallenge> {
    let pow = &state.registration_abuse_config().pow;
    let difficulty = pow.difficulty_bits;
    let mut challenge = [0_u8; 32];
    state.env().entropy().fill_bytes(&mut challenge);
    let id = PowChallengeId::generate(state.env(), &scope);
    let context_hash = context_binding(endpoint, context);
    let ttl_micros =
        i64::try_from(pow.challenge_ttl_secs.saturating_mul(1_000_000)).unwrap_or(i64::MAX);
    let expires_at_micros = epoch_micros(state.now()).saturating_add(ttl_micros);
    state
        .store()
        .scoped(scope)
        .pow_challenges()
        .mint(
            &id,
            &NewPowChallenge {
                challenge: &challenge,
                difficulty_bits: i32::from(difficulty),
                context_hash: &context_hash,
                expires_at_micros,
            },
        )
        .await
        .ok()?;
    Some(IssuedChallenge {
        id,
        challenge: challenge.to_vec(),
        difficulty_bits: difficulty,
    })
}

/// The solution material a client presents (issue #80). For the built-in `PoW` the client
/// returns the challenge id, the nonce (base64url), and the same request context it was
/// issued for; for an external adapter it returns the widget response token.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PresentedSolution<'a> {
    /// The `pow_` challenge id (built-in `PoW`).
    pub challenge_id: Option<&'a str>,
    /// The nonce, base64url no-pad (built-in `PoW`).
    pub nonce: Option<&'a str>,
    /// The request context the challenge was issued for (built-in `PoW`).
    pub context: &'a str,
    /// The external adapter response token (Turnstile/reCAPTCHA).
    pub token: Option<&'a str>,
    /// The resolved peer IP, forwarded to an external adapter.
    pub remote_ip: Option<&'a str>,
}

/// VERIFY a presented challenge solution (issue #80), returning whether it PASSED. For the
/// built-in `PoW` this atomically CONSUMES the challenge single-use (replay-proof) and
/// context-bound, then verifies the nonce meets the issued difficulty, with ZERO
/// third-party calls. For an external adapter it verifies the token through the provider,
/// mapping an outage (`Unavailable`) through the configured fail-open / fail-closed policy.
/// A missing or malformed solution is a plain failure.
pub(crate) async fn verify_solution(
    state: &OidcState,
    scope: Scope,
    endpoint: &str,
    solution: &PresentedSolution<'_>,
) -> bool {
    let provider = state.challenge_provider();
    if provider.kind().is_external() {
        // The adapter path: verify the client token via the provider (an outbound call
        // through the audited fetch seam). The built-in PoW never reaches here.
        let Some(token) = solution.token else {
            return false;
        };
        let verdict = provider
            .verify(ChallengeVerifyRequest {
                token: Some(token),
                remote_ip: solution.remote_ip,
                pow: None,
            })
            .await;
        return match verdict {
            ChallengeVerdict::Passed => true,
            ChallengeVerdict::Failed => false,
            // Only an adapter can be unavailable; degrade per the configured policy.
            ChallengeVerdict::Unavailable => matches!(
                state.registration_abuse_config().pow.fail_policy,
                AdapterFailPolicy::FailOpen
            ),
        };
    }

    // The built-in self-contained PoW path.
    let (Some(id_str), Some(nonce_b64)) = (solution.challenge_id, solution.nonce) else {
        return false;
    };
    let Ok(id) = PowChallengeId::parse_in_scope(id_str, &scope) else {
        return false;
    };
    let Ok(nonce) = URL_SAFE_NO_PAD.decode(nonce_b64.as_bytes()) else {
        return false;
    };
    let context_hash = context_binding(endpoint, solution.context);
    let now = epoch_micros(state.now());
    // Atomic single-use, expiry, and context-bound consume: at most one caller wins the
    // spend, a spent/expired/unknown id or a mismatched context yields None. A mismatched
    // context leaves the challenge unspent, so a solution for one endpoint/context can
    // never be replayed or outsourced to another.
    let consumed = state
        .store()
        .scoped(scope)
        .pow_challenges()
        .consume(&id, &context_hash, now)
        .await;
    let Ok(Some(view)) = consumed else {
        return false;
    };
    let difficulty = u8::try_from(view.difficulty_bits).unwrap_or(u8::MAX);
    let verdict = provider
        .verify(ChallengeVerifyRequest {
            pow: Some(PowSolution {
                challenge: &view.challenge,
                nonce: &nonce,
                difficulty_bits: difficulty,
            }),
            token: None,
            remote_ip: None,
        })
        .await;
    matches!(verdict, ChallengeVerdict::Passed)
}

/// The `POST /pow/challenge` request body (issue #80): which endpoint the challenge is for
/// and an optional caller-supplied request context to bind it to.
#[derive(Debug, Deserialize)]
pub struct IssueRequest {
    /// The endpoint label the challenge is for (`register`, `recover`, or `otp_send`).
    pub endpoint: Option<String>,
    /// An optional caller-supplied request context the challenge is bound to. The client
    /// echoes it back on submit; a solution issued for one context does not satisfy
    /// another.
    #[serde(default)]
    pub context: String,
}

/// `POST /t/{tenant}/e/{environment}/pow/challenge`: issue a self-contained proof-of-work
/// challenge (issue #80) for the requested endpoint. The response carries the challenge id,
/// the challenge bytes (base64url), and the difficulty; the client finds a nonce and
/// returns it on the target endpoint. Makes ZERO third-party calls. When the `PoW` feature is
/// off, or an external adapter is configured (which issues its own client-side widget), the
/// endpoint is a uniform 404, so it never advertises a disabled defense.
pub async fn pow_challenge_issue(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<IssueRequest>,
) -> Response {
    let _ = &headers;
    let Some(scope) = crate::wellknown::parse_scope(&tenant_id, &environment_id) else {
        return not_found_json();
    };
    let pow = &state.registration_abuse_config().pow;
    // The issuance endpoint serves the BUILT-IN PoW only: an external adapter issues its
    // widget client-side, so a server-minted challenge would be meaningless. A disabled
    // feature or an adapter provider is a uniform not-found.
    if !pow.enabled || state.challenge_provider().kind().is_external() {
        return not_found_json();
    }
    let endpoint = match body.endpoint.as_deref() {
        Some(ENDPOINT_REGISTER) => ENDPOINT_REGISTER,
        Some(ENDPOINT_RECOVER) => ENDPOINT_RECOVER,
        Some(ENDPOINT_OTP_SEND) => ENDPOINT_OTP_SEND,
        _ => return bad_request_json("unknown endpoint"),
    };
    let Some(issued) = issue_builtin_challenge(&state, scope, endpoint, &body.context).await else {
        return crate::interaction::server_error_page();
    };
    let payload = serde_json::json!({
        "challenge_id": issued.id.to_string(),
        "challenge": URL_SAFE_NO_PAD.encode(&issued.challenge),
        "difficulty_bits": issued.difficulty_bits,
        "algorithm": "sha256-leading-zero-bits",
    });
    json_response(StatusCode::OK, &payload)
}

/// A minimal JSON body response.
fn json_response(status: StatusCode, value: &serde_json::Value) -> Response {
    let body = value.to_string();
    let mut response = Response::new(axum::body::Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    response
}

/// A uniform JSON 404 (the endpoint is unmounted-shaped when the defense is off).
fn not_found_json() -> Response {
    json_response(
        StatusCode::NOT_FOUND,
        &serde_json::json!({"error": "not_found"}),
    )
}

/// A JSON 400 for a malformed issue request.
fn bad_request_json(message: &str) -> Response {
    json_response(
        StatusCode::BAD_REQUEST,
        &serde_json::json!({"error": "invalid_request", "error_description": message}),
    )
}
