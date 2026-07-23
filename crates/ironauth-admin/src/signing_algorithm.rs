// SPDX-License-Identifier: MIT OR Apache-2.0

//! The compatibility-wizard management surface (issue #93, Bet 2).
//!
//! Two operator-plane endpoints:
//!
//! - GET `/v1/interop/signing-recommendations` surfaces the interop table
//!   ([`crate::signing_interop`]) as JSON, so the SPA renders exactly the
//!   Rust-unit-tested source of truth with no duplicated content.
//! - PUT `.../clients/{client_id}/signing-algorithm` writes a per-client
//!   `id_token_signed_response_alg` through, after the ONE security-relevant check:
//!   the algorithm must be in the wizard set `{EdDSA, ES256, RS256}` (layer 1) AND in
//!   the environment's ACTUALLY signable set (layer 2), so an operator can never pin
//!   an algorithm the mint would silently fall back from.
//!
//! The per-client column is data-plane writable only (the control role holds no grant
//! on it), and the Idempotency-Key replay table is control-plane only, so the write
//! and its idempotency row are inherently on different roles. The write (an absolute
//! value PUT, naturally idempotent) is performed on the data plane through the shared
//! [`ironauth_oidc::IssuerRegistry`]'s store, then the response is recorded on the
//! control plane; a concurrent duplicate that stored the key first is resolved by
//! replaying the original response.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_jose::JwsAlgorithm;
use ironauth_store::{CorrelationId, Scope, StoreError, TenantId};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::response::json;
use crate::signing_interop;
use crate::state::AdminState;

/// The three algorithms the wizard may pin: exactly the set every environment
/// provisions in its JWKS. An algorithm outside this set is rejected at layer 1 even
/// if the environment could somehow sign it, so the wizard's output is a closed set.
const WIZARD_ALGS: [JwsAlgorithm; 3] = [
    JwsAlgorithm::EdDsa,
    JwsAlgorithm::Es256,
    JwsAlgorithm::Rs256,
];

/// One interop-table row as surfaced by the recommendations endpoint.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SigningRecommendationView {
    /// The stable verifier identifier (for example `aws_api_gateway`).
    #[schema(example = "aws_api_gateway")]
    pub verifier: String,
    /// The human-readable label.
    #[schema(example = "AWS API Gateway JWT authorizers")]
    pub label: String,
    /// The recommended JOSE algorithm name.
    #[schema(example = "RS256")]
    pub recommended: String,
    /// The one-line reason for the recommendation.
    pub reason: String,
    /// The supported minus recommended alternatives (JOSE algorithm names).
    pub alternatives: Vec<String>,
    /// The algorithms this verifier can verify (JOSE algorithm names).
    pub supported: Vec<String>,
}

/// The body of a set-signing-algorithm request.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SetClientSigningAlgorithmRequest {
    /// The JOSE algorithm name to pin, one of `EdDSA`, `ES256`, `RS256`.
    #[schema(example = "RS256")]
    pub algorithm: String,
}

/// The updated per-client signing-algorithm state.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClientSigningAlgorithmView {
    /// The client identifier (`cli_...`).
    pub client_id: String,
    /// The algorithm now recorded for this client's ID tokens.
    #[schema(example = "RS256")]
    pub id_token_signed_response_alg: String,
}

/// Surface the token-signing compatibility interop table (issue #93).
#[utoipa::path(
    get,
    path = "/v1/interop/signing-recommendations",
    operation_id = "getSigningRecommendations",
    tag = "dcr",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The interop table of per-verifier recommendations", body = [SigningRecommendationView]),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane", body = ErrorBody)
    )
)]
pub async fn get_signing_recommendations(principal: Principal) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let rows: Vec<SigningRecommendationView> = signing_interop::Verifier::ALL
        .iter()
        .map(|&verifier| {
            let cell = signing_interop::cell(verifier);
            let rec = signing_interop::recommend(verifier);
            SigningRecommendationView {
                verifier: verifier.as_str().to_owned(),
                label: cell.label().to_owned(),
                recommended: rec.recommended.as_jose_name().to_owned(),
                reason: rec.reason.to_owned(),
                alternatives: rec
                    .alternatives
                    .iter()
                    .map(|alg| alg.as_jose_name().to_owned())
                    .collect(),
                supported: cell
                    .supported()
                    .iter()
                    .map(|alg| alg.as_jose_name().to_owned())
                    .collect(),
            }
        })
        .collect();
    let body = serde_json::to_string(&rows).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Pin the ID-token signing algorithm for one client (issue #93).
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/signing-algorithm",
    operation_id = "setClientSigningAlgorithm",
    tag = "dcr",
    request_body = SetClientSigningAlgorithmRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The client identifier (cli_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying with the \
         same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The updated per-client signing-algorithm state", body = ClientSigningAlgorithmView),
        (status = 400, description = "Malformed request, or an algorithm outside the wizard set", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent client or another scope)", body = ErrorBody),
        (status = 422, description = "The environment cannot sign the requested algorithm, or the Idempotency-Key was reused with a different request", body = ErrorBody)
    )
)]
pub async fn set_client_signing_algorithm(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;

    // The idempotency fingerprint is over the method, concrete path (which names the
    // client), and body (which names the algorithm), so a replay for the same client
    // and algorithm returns the original response and a reuse for a different algorithm
    // is a fingerprint mismatch (422), not a wrong result.
    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("PUT", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let request: SetClientSigningAlgorithmRequest = parse_json(&body)?;

    // Layer 1: the value must parse and be in the wizard set. A malformed name, `none`,
    // an HMAC name, PS*, ES384/RS384/RS512, or any unknown value is a 400 and the column
    // is left unchanged.
    let alg = JwsAlgorithm::from_jose_name(&request.algorithm)
        .filter(|candidate| WIZARD_ALGS.contains(candidate))
        .ok_or_else(|| {
            ApiError::BadRequest("algorithm must be one of EdDSA, ES256, RS256".to_owned())
        })?;

    // Layer 2: the algorithm must be in the environment's ACTUALLY signable set (the
    // same computation the DCR negotiation uses, so the two can never disagree). This is
    // the security-relevant line: it forbids pinning an algorithm the mint could not
    // sign with, which mint time would silently fall back from. A missing registry, an
    // unprovisioned environment, or a non-signable algorithm all fail closed (422) with
    // the column unchanged.
    let registry = state.signing_registry().ok_or_else(|| {
        ApiError::Unprocessable("the environment signing capability cannot be verified".to_owned())
    })?;
    let entry = registry.entry_for(&scope).await.ok_or_else(|| {
        ApiError::Unprocessable("the environment has no signing capability".to_owned())
    })?;
    let now = state.env().clock().now_utc();
    if !entry.signable_id_token_algs(now).contains(&alg) {
        return Err(ApiError::Unprocessable(format!(
            "the environment cannot sign {}",
            alg.as_jose_name()
        )));
    }

    // Write through the DATA plane: the per-client id_token_signed_response_alg column is
    // data-plane writable only (the control role holds no grant), so the write flows
    // through the shared registry's store, under forced row-level security.
    let data_store = registry.store().ok_or_else(|| {
        ApiError::Unprocessable("the environment signing capability cannot be verified".to_owned())
    })?;
    let id = data_store.scoped(scope).clients().parse_id(&client_id)?;
    data_store
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .clients()
        .set_id_token_signed_response_alg(state.env(), &id, alg.as_jose_name())
        .await?;

    let view = ClientSigningAlgorithmView {
        client_id: id.to_string(),
        id_token_signed_response_alg: alg.as_jose_name().to_owned(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;

    // Record the response on the CONTROL plane (the only role that can write the
    // idempotency table), completing the two-phase idempotency: the data-plane write
    // above already committed. A concurrent request that stored the same key first
    // surfaces as a conflict, resolved by replaying the now-committed original response.
    match state
        .store()
        .management()
        .idempotency()
        .record(&credential_ref, &key, &fingerprint, 200, &body_string)
        .await
    {
        Ok(()) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// Resolve the `(tenant, environment)` scope from the path, parsing both ids through
/// the management repositories (a malformed id is the uniform not-found).
fn scope_from_path(
    state: &AdminState,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(TenantId, Scope), ApiError> {
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(tenant_id)?;
    let environment = state
        .store()
        .management()
        .environments(tenant)
        .parse_id(environment_id)?;
    Ok((tenant, Scope::new(tenant, environment)))
}
