// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `client_credentials` grant (RFC 6749 4.4, issue #23): an authenticated
//! confidential client obtains a machine-to-machine (M2M) access token for its own
//! first-class SERVICE-ACCOUNT PRINCIPAL.
//!
//! The exchange:
//!
//! 1. Recover the `(tenant, environment)` scope from the CLAIMED client id (a `cli_`
//!    id embeds it), so the RLS-scoped client authentication can run. The claim is
//!    unverified here; the client then proves possession of its secret within this
//!    scope, exactly as a management key declares its scope then proves its secret.
//! 2. AUTHENTICATE the client through the ONE shared seam
//!    ([`client_auth::authenticate_client`]): RFC 6749 4.4 REQUIRES client
//!    authentication, so a PUBLIC client (auth method `none`, which proves nothing)
//!    is refused as `invalid_client`.
//! 3. Validate the requested `scope` against the M2M policy (`invalid_scope` for an
//!    out-of-policy request).
//! 4. Resolve the client's STABLE service-account principal (minted lazily on the
//!    first issuance, read back every time after), which is the token's `sub`.
//! 5. Mint ONLY the access token (at+jwt or opaque per the #29 target), carrying the
//!    RFC 9068 claims plus the per-client STATIC custom claims. No ID token (there is
//!    no user) and NO refresh token (RFC 6749 4.4.3).
//! 6. Persist a fresh machine GRANT and record the access token against it, so the
//!    token is revocable and introspectable by the #22 endpoints by construction
//!    (the SAME grant-chain the code/refresh tokens use).
//!
//! # Covenant: no metering on the issuance path
//!
//! There is deliberately NO metering, counting-for-billing, or quota hook anywhere
//! in this module (a covenant of the M2M path). `scripts/no-m2m-metering.sh` asserts
//! it as a CI lint; the audit row written by `issue_client_credentials` is a
//! SECURITY audit (who/what/when for revocation and forensics), not a meter.

use axum::http::{HeaderMap, header};
use axum::response::Response;
use ironauth_store::{
    ClientCredentialsAccess, ClientId, CorrelationId, GrantId, IssueClientCredentials,
    NewOpaqueAccessToken, Scope,
};
use serde_json::json;

use crate::client_auth::{
    self, ClientAuthError, ClientAuthInputs, ClientAuthMethod, parse_presented,
};
use crate::error::TokenError;
use crate::state::OidcState;
use crate::token::{TokenParams, map_store_error, token_ok};
use crate::tokens::{self, ClientCredentialsMintRequest, MintedAccessToken};
use crate::util::{client_service_actor, epoch_micros};

/// OAuth scope values a client-credentials (machine) request may NOT ask for (issue
/// #23). Both are user/OIDC-centric and meaningless for an M2M principal:
///
/// - `openid` triggers OIDC and an ID token, which requires an authenticated end
///   user; a client-credentials token has a machine `sub`, no user.
/// - `offline_access` requests a refresh token, which RFC 6749 4.4.3 forbids on this
///   grant.
///
/// A request naming either is an out-of-policy `invalid_scope`. The full per-client
/// scope allowlist (RBAC) is M10; this is the M2-slice policy that gives a concrete,
/// spec-aligned rejection without pre-building RBAC.
const DISALLOWED_M2M_SCOPES: &[&str] = &["openid", "offline_access"];

/// The `client_credentials` grant handler (issue #23).
pub async fn client_credentials_grant(
    state: &OidcState,
    headers: &HeaderMap,
    params: TokenParams,
) -> Result<Response, TokenError> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let inputs = ClientAuthInputs {
        authorization,
        client_id: params.client_id.as_deref(),
        client_secret: params.client_secret.as_deref(),
        client_assertion: params.client_assertion.as_deref(),
        client_assertion_type: params.client_assertion_type.as_deref(),
    };

    // 1. Recover the scope from the CLAIMED client id so the scoped authentication
    //    can run. A parse failure or a client id that declares no valid scope is a
    //    uniform invalid_client (a Basic attempt drives the 401 WWW-Authenticate).
    let presented = parse_presented(
        inputs.authorization,
        inputs.client_id,
        inputs.client_secret,
        inputs.client_assertion,
        inputs.client_assertion_type,
    )
    .map_err(|_| TokenError::InvalidClient {
        via_basic: is_basic_scheme(authorization),
    })?;
    let via_basic = presented.via_basic();
    let scope = ClientId::parse_declared_scope(presented.client_id())
        .map(|id| id.scope())
        .map_err(|_| TokenError::InvalidClient { via_basic })?;

    // 2. Authenticate the client (RFC 6749 4.4 REQUIRES it). The shared seam
    //    verifies the secret in scope and records any failure out of band, so
    //    enforcement matches the code and refresh grants.
    let authenticated = client_auth::authenticate_client(state, scope, inputs)
        .await
        .map_err(|error| match error {
            ClientAuthError::InvalidRequest(message) => {
                TokenError::InvalidRequest(message.to_owned())
            }
            ClientAuthError::InvalidClient { via_basic } => TokenError::InvalidClient { via_basic },
        })?;
    let client_id = state
        .store()
        .scoped(scope)
        .clients()
        .parse_id(&authenticated.client_id)
        .map_err(|_| TokenError::InvalidClient { via_basic })?;

    // A PUBLIC client (auth method `none`) authenticates with nothing, so it can
    // never satisfy the client-credentials grant's mandatory client authentication
    // (RFC 6749 4.4). Refuse it as invalid_client.
    let record = state
        .store()
        .scoped(scope)
        .clients()
        .auth_record(&client_id)
        .await
        .map_err(map_store_error)?;
    if record.auth_method == ClientAuthMethod::None.as_str() {
        return Err(TokenError::InvalidClient { via_basic });
    }

    // 3. Validate the requested scope against the M2M policy.
    let requested_scope = validate_m2m_scope(params.scope.as_deref())?;

    // 4-6. Resolve the principal, mint the access token, persist the machine grant,
    //      and build the response.
    mint_and_persist(state, scope, &client_id, requested_scope.as_deref()).await
}

/// Resolve the client's service-account principal, mint the M2M access token, record
/// it against a fresh machine grant, and build the `200 OK` response (issue #23,
/// steps 4-6 of the exchange). Split out of [`client_credentials_grant`] so each half
/// stays readable; the client is already authenticated and its scope proven.
async fn mint_and_persist(
    state: &OidcState,
    scope: Scope,
    client_id: &ClientId,
    requested_scope: Option<&str>,
) -> Result<Response, TokenError> {
    // The STABLE service-account principal (the token's sub), minted lazily on the
    // first issuance and read back every time after, so `sub` is consistent across
    // issuances and DISTINCT from client_id.
    let principal = state
        .store()
        .scoped(scope)
        .acting(
            client_service_actor(client_id),
            CorrelationId::generate(state.env()),
        )
        .service_accounts()
        .ensure(state.env(), client_id)
        .await
        .map_err(map_store_error)?;
    let subject = principal.to_string();
    let client_id_str = client_id.to_string();

    // The per-client STATIC custom claims (fail-open: a malformed stored config
    // under-claims rather than failing issuance; the protected-claim guard is in the
    // mint regardless).
    let custom_claims = load_custom_claims(state, scope, client_id).await;

    // Resolve the access-token target: format (per resource-server config / env
    // default) and the default M2M audience (per config). The client-credentials
    // grant does not compose with RFC 8707 resource indicators in issue #28 (there is
    // no prior authorization to downscope from), so it always resolves the no-resource
    // target: the configurable default audience. The empty-resource branch is
    // infallible, so a failure here can only be an internal error.
    let default_audience = state.client_credentials_default_audience(&scope, &client_id_str);
    let target = state
        .resolve_access_token_target(&scope, &[], &default_audience)
        .await
        .map_err(|_| TokenError::ServerError)?;

    // Mint ONLY the access token: no ID token, and NO refresh token (RFC 6749 4.4.3).
    let entry = state
        .issuer_entry(&scope)
        .await
        .ok_or(TokenError::ServerError)?;
    let signer = entry.signer(state.now()).ok_or(TokenError::ServerError)?;
    let issuer = state.issuer_for(&scope);
    let (minted, expires_in) = tokens::mint_client_credentials_access_token(
        state,
        signer,
        entry.policy(),
        &ClientCredentialsMintRequest {
            scope,
            issuer: &issuer,
            subject: &subject,
            client_id: &client_id_str,
            oauth_scope: requested_scope,
            custom_claims: &custom_claims,
        },
        &target,
    )
    .map_err(|()| TokenError::ServerError)?;

    // Persist a fresh machine grant + record the access token against it, so the token
    // is revocable and introspectable by the #22 endpoints by construction.
    let grant_id = GrantId::generate(state.env(), &scope);
    let access = match &minted {
        MintedAccessToken::Jwt { jti, .. } => ClientCredentialsAccess::Jwt { jti },
        MintedAccessToken::Opaque {
            digest,
            jti,
            audiences,
            expires_at_unix_micros,
            ..
        } => ClientCredentialsAccess::Opaque(NewOpaqueAccessToken {
            token_digest: digest.as_str(),
            // Bound to THIS grant by the issuing method, so left None here.
            grant_id: None,
            subject: subject.as_str(),
            client_id: client_id_str.as_str(),
            audience: audiences.first().map_or("", String::as_str),
            audiences,
            scope: requested_scope,
            jti,
            expires_at_unix_micros: *expires_at_unix_micros,
        }),
    };
    state
        .store()
        .scoped(scope)
        .acting(
            client_service_actor(client_id),
            CorrelationId::generate(state.env()),
        )
        .authorization()
        .issue_client_credentials(
            state.env(),
            IssueClientCredentials {
                grant_id: &grant_id,
                client_id,
                subject: subject.as_str(),
                created_at_unix_micros: epoch_micros(state.now()),
                access,
            },
        )
        .await
        .map_err(map_store_error)?;

    Ok(client_credentials_response(
        &minted,
        expires_in,
        requested_scope,
    ))
}

/// Whether the `Authorization` header presents the Basic scheme, so a failed
/// authentication carries the RFC 6749 5.2 `WWW-Authenticate: Basic` header. Safe on
/// any bytes: it compares the ASCII scheme token without slicing on a char boundary.
fn is_basic_scheme(authorization: Option<&str>) -> bool {
    authorization.is_some_and(|value| {
        let value = value.trim_start();
        value.len() >= 6 && value.as_bytes()[..6].eq_ignore_ascii_case(b"basic ")
    })
}

/// Validate a requested machine-grant `scope` against the M2M policy (issue #23),
/// returning the normalized granted scope (whitespace-collapsed) or [`None`] when
/// none was requested.
///
/// Shared with the jwt-bearer assertion grant (issue #26): a mapped-identity
/// assertion-grant token is a machine token with no interactive user, so it is
/// governed by the SAME policy (no `openid`, no `offline_access`), reusing this one
/// helper rather than duplicating the check.
///
/// # Errors
///
/// [`TokenError::InvalidScope`] if any requested token is out of policy (see
/// [`DISALLOWED_M2M_SCOPES`]).
pub(crate) fn validate_m2m_scope(raw: Option<&str>) -> Result<Option<String>, TokenError> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let tokens: Vec<&str> = raw.split_whitespace().collect();
    if tokens
        .iter()
        .any(|token| DISALLOWED_M2M_SCOPES.contains(token))
    {
        return Err(TokenError::InvalidScope);
    }
    Ok(Some(tokens.join(" ")))
}

/// Load a client's per-client STATIC custom claims within scope (issue #23).
///
/// Fail-open: a store read error, an absent config, or a stored value that is not a
/// JSON OBJECT all yield an empty map (logged), so a misconfiguration under-claims
/// rather than bricking every issuance for the client. The protected-registered-claim
/// guard lives in the mint regardless, so this never returns claims that could
/// override `iss`/`sub`/`aud`/... anyway.
async fn load_custom_claims(
    state: &OidcState,
    scope: Scope,
    client_id: &ClientId,
) -> serde_json::Map<String, serde_json::Value> {
    let raw = match state
        .store()
        .scoped(scope)
        .clients()
        .custom_token_claims(client_id)
        .await
    {
        Ok(Some(raw)) => raw,
        Ok(None) => return serde_json::Map::new(),
        Err(error) => {
            tracing::warn!(%error, "could not read client custom claims; issuing without them");
            return serde_json::Map::new();
        }
    };
    match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(serde_json::Value::Object(object)) => object,
        // A non-object stored config (array/scalar/null) is a misconfiguration:
        // under-claim rather than fail the issuance.
        Ok(_) => {
            tracing::warn!("client custom claims are not a JSON object; issuing without them");
            serde_json::Map::new()
        }
        Err(error) => {
            tracing::warn!(%error, "client custom claims are not valid JSON; issuing without them");
            serde_json::Map::new()
        }
    }
}

/// Build the `200 OK` client-credentials token response (RFC 6749 4.4.3 / 5.1): the
/// access token, its type and lifetime, and the granted scope when present. There is
/// deliberately NO `refresh_token` (RFC 6749 4.4.3 forbids it on this grant) and no
/// `id_token` (there is no user).
fn client_credentials_response(
    minted: &MintedAccessToken,
    expires_in: i64,
    scope: Option<&str>,
) -> Response {
    let mut body = json!({
        "access_token": minted.token(),
        "token_type": "Bearer",
        "expires_in": expires_in,
    });
    if let Some(scope) = scope {
        body["scope"] = json!(scope);
    }
    token_ok(&body.to_string())
}
