// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 8628 device authorization grant (issue #24): the back-channel
//! device-authorization endpoint a constrained device starts a flow at, and the
//! token-endpoint grant arm the device polls.
//!
//! A constrained device (a CLI, a TV, an `IoT` device) that cannot host a browser
//! POSTs to the device-authorization endpoint and receives a `device_code` (a
//! machine bearer credential it polls the token endpoint with) plus a short,
//! transcription-friendly `user_code` (a human types it into the verification page,
//! which lives in [`crate::device_verify`]). The device polls the token endpoint at
//! the advertised `interval` until a human approves the flow, at which point the
//! poll returns tokens.
//!
//! Two scope tenets are load-bearing here:
//!
//! - the `device_code` is a scope-declaring bearer credential exactly like an opaque
//!   access token: its wire form is `ira_dc_<jti>~<secret>`, where `<jti>` is a
//!   `dc_` scoped id embedding the flow's `(tenant, environment)` (so the GLOBAL
//!   `/token` endpoint recovers the scope and runs the RLS-scoped digest resolve) and
//!   `<secret>` is 256 bits from the entropy seam. Only the SHA-256 digest of the
//!   WHOLE token is stored;
//! - the `user_code` is drawn from a RESTRICTED, transcription-friendly alphabet
//!   (RFC 8628 section 6.1) and stored only as a hash.
//!
//! Neither the `device_code` nor the `user_code` is ever logged in plaintext (they
//! are redacted from every `Debug`, and only handles and digests are traced).

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, Form, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_env::Env;
use ironauth_store::{
    ApprovedDeviceGrant, ClientId, CorrelationId, DeviceCodeId, DevicePollOutcome,
    DeviceRedeemOutcome, IssuedTokenRecord, NewDeviceCode, NewOpaqueAccessToken, NewRefreshFamily,
    RefreshFamilyId, Scope, StoreError, TokenKind,
};
use serde::Deserialize;
use serde_json::json;

use crate::client_auth::{self, AuthenticatedClient, ClientAuthError, ClientAuthInputs};
use crate::error::TokenError;
use crate::registry::GrantType;
use crate::state::OidcState;
use crate::tokens::{self, IssuedTokens, MintRequest, MintedAccessToken};
use crate::util::{client_service_actor, epoch_micros, percent_encode_query};

/// The scannable prefix on every device code (issue #24): `ira` (the product
/// namespace), `dc` (device code). Mirrors the opaque access token's `ira_at_`.
const DEVICE_CODE_PREFIX: &str = "ira_dc_";

/// The number of random bytes in a device code's secret suffix: 32 bytes = 256 bits
/// of entropy from the ironauth-env seam, so a device code cannot be guessed.
const DEVICE_CODE_SECRET_BYTES: usize = 32;

/// The RFC 8628 section 6.1 restricted, transcription-friendly user-code alphabet:
/// twenty upper-case consonants with the visually ambiguous letters and every digit
/// removed, so a human transcribes a code without confusing O/0, I/1/L, and so on.
const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";

/// The number of characters in a user code. Twenty symbols to the eighth power is
/// about 2.56e10 codes; with a short TTL and per-source and per-flow rate limits, the
/// probability of guessing a live code within its lifetime is negligible (RFC 8628
/// section 5.1).
const USER_CODE_LENGTH: usize = 8;

/// The largest alphabet-length multiple that fits in a byte (12 * 20 = 240). A random
/// byte at or above this is rejected so `byte % 20` carries no modulo bias.
const USER_CODE_REJECT_ABOVE: u8 = 240;

/// The number of times issuance retries on a user-code (or device-code) collision
/// before giving up. A collision is astronomically unlikely per active window, so a
/// small bound is ample.
const USER_CODE_ISSUE_ATTEMPTS: u32 = 5;

/// The `offline_access` scope token (OIDC Core 11): its presence makes the issued
/// refresh-token family survive RP logout.
const OFFLINE_ACCESS_SCOPE: &str = "offline_access";

/// The device-authorization endpoint request (RFC 8628 section 3.1). The client
/// authenticates the same way as at the token endpoint; a public device client
/// presents only its `client_id`. Not `Debug` (it carries a client secret).
#[derive(Deserialize)]
pub struct DeviceAuthorizationParams {
    /// The requesting client.
    client_id: Option<String>,
    /// The client secret for `client_secret_post` authentication.
    client_secret: Option<String>,
    /// The JWT client assertion for `private_key_jwt` / `client_secret_jwt`.
    client_assertion: Option<String>,
    /// The RFC 7521 `client_assertion_type` accompanying `client_assertion`.
    client_assertion_type: Option<String>,
    /// The requested OAuth `scope`, echoed into the issued tokens.
    scope: Option<String>,
}

/// A device-authorization endpoint error (RFC 8628 section 3.2, RFC 6749 5.2 shape).
enum DeviceAuthError {
    /// A required parameter is missing or malformed.
    InvalidRequest(&'static str),
    /// Client authentication failed. `via_basic` drives the 401 + `WWW-Authenticate`.
    InvalidClient {
        /// Whether the client attempted Basic authentication.
        via_basic: bool,
    },
    /// The authenticated client is not permitted the device grant (its grant
    /// allowlist does not contain the `device_code` URN).
    UnauthorizedClient,
    /// An unexpected server-side condition.
    ServerError,
}

impl DeviceAuthError {
    fn code(&self) -> &'static str {
        match self {
            DeviceAuthError::InvalidRequest(_) => "invalid_request",
            DeviceAuthError::InvalidClient { .. } => "invalid_client",
            DeviceAuthError::UnauthorizedClient => "unauthorized_client",
            DeviceAuthError::ServerError => "server_error",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            DeviceAuthError::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            DeviceAuthError::InvalidClient { .. } => StatusCode::UNAUTHORIZED,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    fn description(&self) -> &'static str {
        match self {
            DeviceAuthError::InvalidRequest(message) => message,
            DeviceAuthError::InvalidClient { .. } => "client authentication failed",
            DeviceAuthError::UnauthorizedClient => {
                "the client is not permitted the device authorization grant"
            }
            DeviceAuthError::ServerError => "the request could not be processed",
        }
    }
}

impl IntoResponse for DeviceAuthError {
    fn into_response(self) -> Response {
        let body = json!({
            "error": self.code(),
            "error_description": self.description(),
        })
        .to_string();
        let mut response = (
            self.status(),
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            body,
        )
            .into_response();
        if let DeviceAuthError::InvalidClient { via_basic: true } = self {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Basic realm=\"ironauth\", charset=\"UTF-8\""),
            );
        }
        response
    }
}

/// The transport PEER IP of a request (issue #24), for the best-effort per-source
/// rate-limit source key. The address the server's `ConnectInfo<SocketAddr>` reports
/// (installed by `into_make_service_with_connect_info`), never a caller-controlled
/// header. The extractor NEVER fails: an absent `ConnectInfo` (for example an
/// in-process test router) is `None`, which collapses to a single shared bucket.
pub(crate) struct PeerIp(pub(crate) Option<IpAddr>);

impl<S> FromRequestParts<S> for PeerIp
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Infallible> {
        Ok(PeerIp(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip()),
        ))
    }
}

/// `POST /device_authorization` (RFC 8628 section 3.1): start a device flow.
pub async fn device_authorization(
    State(state): State<OidcState>,
    PeerIp(peer): PeerIp,
    headers: HeaderMap,
    Form(params): Form<DeviceAuthorizationParams>,
) -> Response {
    match device_authorization_inner(&state, &headers, &params, peer).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn device_authorization_inner(
    state: &OidcState,
    headers: &HeaderMap,
    params: &DeviceAuthorizationParams,
    peer: Option<IpAddr>,
) -> Result<Response, DeviceAuthError> {
    // Authenticate the client and recover its scope from the presented client_id (the
    // endpoint is global, exactly like the token endpoint's self-scoped auth). A
    // public device client presents only its client_id.
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
    let (client, scope) = client_auth::authenticate_client_self_scoped(state, inputs)
        .await
        .map_err(|error| map_client_auth_error(&error))?;
    let client_id = ClientId::parse_in_scope(&client.client_id, &scope)
        .map_err(|_| DeviceAuthError::ServerError)?;

    // Gate on the per-client grant allowlist: the device grant is opt-in per client.
    let profile = state
        .store()
        .scoped(scope)
        .device_codes()
        .client_device_profile(&client_id)
        .await
        .map_err(|_| DeviceAuthError::ServerError)?
        .ok_or(DeviceAuthError::UnauthorizedClient)?;
    if !grant_types_allow_device(&profile.grant_types) {
        return Err(DeviceAuthError::UnauthorizedClient);
    }

    let now = state.now();
    let created_micros = epoch_micros(now);
    let expires_micros = epoch_micros(now.checked_add(state.device_code_ttl()).unwrap_or(now));
    let interval_secs = i32::try_from(state.device_poll_interval_secs()).unwrap_or(i32::MAX);
    let requested_scope = params
        .scope
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let initiation_hint = request_source_hint(peer);

    // Issue the flow, retrying on the (astronomically unlikely) user-code collision.
    let mut last_error: Option<StoreError> = None;
    for _ in 0..USER_CODE_ISSUE_ATTEMPTS {
        let device_code_id = DeviceCodeId::generate(state.env(), &scope);
        let device_code = generate_device_code(state.env(), &device_code_id);
        let (user_code_display, user_code_normalized) = generate_user_code(state.env());
        let digest = ironauth_store::device_code_digest(&device_code);
        let user_hash = ironauth_store::user_code_hash(&user_code_normalized);
        let actor = client_service_actor(&client_id);
        let correlation = CorrelationId::generate(state.env());
        let result = state
            .store()
            .scoped(scope)
            .acting(actor, correlation)
            .device_codes()
            .issue(
                state.env(),
                NewDeviceCode {
                    device_code_id: &device_code_id,
                    device_code_digest: &digest,
                    user_code_hash: &user_hash,
                    client_id: &client_id,
                    requested_scope,
                    interval_secs,
                    initiation_hint: initiation_hint.as_deref(),
                    expires_at_unix_micros: expires_micros,
                    created_at_unix_micros: created_micros,
                },
            )
            .await;
        match result {
            Ok(()) => {
                let verification_uri = state.verification_uri_for(&scope);
                let verification_uri_complete = format!(
                    "{verification_uri}?user_code={}",
                    percent_encode_query(&user_code_display)
                );
                let body = json!({
                    "device_code": device_code,
                    "user_code": user_code_display,
                    "verification_uri": verification_uri,
                    "verification_uri_complete": verification_uri_complete,
                    "expires_in": state.device_code_ttl().as_secs(),
                    "interval": state.device_poll_interval_secs(),
                })
                .to_string();
                return Ok(device_ok(&body));
            }
            Err(StoreError::Conflict) => {
                last_error = Some(StoreError::Conflict);
            }
            Err(error) => {
                tracing::error!(%error, "device authorization issuance failed");
                return Err(DeviceAuthError::ServerError);
            }
        }
    }
    tracing::error!(
        ?last_error,
        "device authorization issuance exhausted retries"
    );
    Err(DeviceAuthError::ServerError)
}

/// The RFC 8628 token-endpoint poll (`grant_type=urn:...:device_code`, issue #24).
///
/// # Errors
///
/// The RFC 8628 section 3.5 error set: `authorization_pending`, `slow_down`,
/// `access_denied`, `expired_token`, plus `invalid_grant` / `invalid_client` /
/// `invalid_request` for the usual failures.
pub async fn device_code_grant(
    state: &OidcState,
    headers: &HeaderMap,
    params: crate::token::TokenParams,
) -> Result<Response, TokenError> {
    let device_code = params
        .device_code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokenError::InvalidRequest("device_code is required".to_owned()))?;
    // Recover the flow's scope from the device code's embedded handle, exactly as the
    // refresh grant recovers scope from a refresh token's handle.
    let scope = device_code_scope(device_code).ok_or(TokenError::InvalidGrant)?;

    // Authenticate the client BEFORE touching poll state, so an unauthenticated caller
    // cannot advance a flow. A public device client presents only its client_id.
    let authenticated = authenticate_token_client(state, scope, headers, &params).await?;

    let now_micros = epoch_micros(state.now());
    let slow_down_increment = i64::try_from(state.device_slow_down_increment_secs()).unwrap_or(0);
    let outcome = state
        .store()
        .scoped(scope)
        .device_codes()
        .poll(device_code, now_micros, slow_down_increment)
        .await
        .map_err(crate::token::map_store_error)?;

    match outcome {
        DevicePollOutcome::Pending => Err(TokenError::AuthorizationPending),
        DevicePollOutcome::SlowDown { .. } => Err(TokenError::SlowDown),
        DevicePollOutcome::Denied => Err(TokenError::AccessDenied),
        DevicePollOutcome::Expired => Err(TokenError::ExpiredToken),
        DevicePollOutcome::Unknown => Err(TokenError::InvalidGrant),
        DevicePollOutcome::Approved(grant) => {
            // The device code is bound to the client it was issued to (RFC 8628): a
            // different client cannot redeem it.
            if grant.client_id != authenticated.client_id {
                return Err(TokenError::InvalidGrant);
            }
            issue_device_tokens(state, scope, grant).await
        }
    }
}

/// Mint tokens for an approved flow, then atomically redeem it (issue #24). Mirrors
/// the code grant: the tokens are pre-signed BEFORE the single-use consume, so a
/// signing failure never burns the flow.
async fn issue_device_tokens(
    state: &OidcState,
    scope: Scope,
    grant: ApprovedDeviceGrant,
) -> Result<Response, TokenError> {
    let minted = mint_device_tokens(state, scope, &grant).await?;

    // What the redeem transaction records for the minted tokens (issue #29): the ID
    // token is always an issued_tokens row; the access token is an issued_tokens row
    // when it is an at+jwt, or an opaque_access_tokens row when it is opaque.
    let mut records: Vec<IssuedTokenRecord> = vec![IssuedTokenRecord {
        id: minted.id_jti,
        kind: TokenKind::Id,
    }];
    let opaque = match &minted.access {
        MintedAccessToken::Jwt { jti, .. } => {
            records.push(IssuedTokenRecord {
                id: *jti,
                kind: TokenKind::Access,
            });
            None
        }
        MintedAccessToken::Opaque {
            digest,
            jti,
            audience,
            expires_at_unix_micros,
            ..
        } => Some(NewOpaqueAccessToken {
            token_digest: digest,
            grant_id: None,
            subject: &grant.subject,
            client_id: &grant.client_id,
            audience,
            scope: grant.requested_scope.as_deref(),
            jti,
            expires_at_unix_micros: *expires_at_unix_micros,
        }),
    };

    let actor = client_service_actor(
        &ClientId::parse_in_scope(&grant.client_id, &scope).map_err(|_| TokenError::ServerError)?,
    );
    let correlation = CorrelationId::generate(state.env());
    let outcome = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .device_codes()
        .redeem_approved(
            state.env(),
            &grant.device_code_id,
            &grant.grant_id,
            &records,
            opaque,
        )
        .await
        .map_err(crate::token::map_store_error)?;

    match outcome {
        DeviceRedeemOutcome::Redeemed => {
            let refresh = issue_device_refresh(state, scope, &grant).await;
            Ok(device_token_response(
                &minted,
                grant.requested_scope.as_deref(),
                refresh.as_deref(),
            ))
        }
        // Already redeemed (a concurrent poll won, or a re-poll after success): the
        // device code issues tokens at most once.
        DeviceRedeemOutcome::NotApprovable => Err(TokenError::InvalidGrant),
    }
}

/// Mint the ID and access tokens for an approved device flow (issue #24). Reuses the
/// SAME pure minting core as the code grant; the auth-context claims derive from the
/// approving human's session, frozen onto the flow at approval. A device flow has no
/// `nonce` (RFC 8628 carries none), so the ID token omits it.
async fn mint_device_tokens(
    state: &OidcState,
    scope: Scope,
    grant: &ApprovedDeviceGrant,
) -> Result<IssuedTokens, TokenError> {
    let entry = state
        .issuer_entry(&scope)
        .await
        .ok_or(TokenError::ServerError)?;
    let signer = entry.signer(state.now()).ok_or(TokenError::ServerError)?;
    let issuer = state.issuer_for(&scope);
    let subject = state.resolve_public_subject(&grant.subject);
    let target = state
        .resolve_access_token_target(&scope, None, &grant.client_id)
        .await;
    let extra_claims = serde_json::Map::new();
    tokens::mint(
        state,
        signer,
        entry.policy(),
        &MintRequest {
            scope,
            issuer: &issuer,
            subject: &subject,
            client_id: &grant.client_id,
            nonce: None,
            oauth_scope: grant.requested_scope.as_deref(),
            auth_methods: &grant.auth_methods,
            auth_time_unix_micros: grant.auth_time_unix_micros,
            at_hash: None,
            c_hash: None,
            extra_claims: &extra_claims,
            id_token_signer: None,
        },
        &target,
    )
    .map_err(|()| TokenError::ServerError)
}

/// Open a refresh-token family for an approved device flow, if the environment issues
/// refresh tokens (issue #24, #21). A failure only costs this exchange its refresh
/// token (logged), never the whole exchange, exactly like the code grant.
///
/// DELIBERATE decision (issue #24): the device grant issues a refresh token whenever
/// the environment issues them AT ALL, regardless of whether `offline_access` was
/// requested. This DIVERGES from the authorization-code grant, which gates a web
/// client's refresh token on an explicit `offline_access` consent. RFC 8628 does not
/// forbid it, and it matches the device-flow UX: a CLI, a TV, or another constrained
/// device that just completed a one-time cross-device human approval expects a durable
/// session and cannot cheaply re-run that approval. `offline_access` still governs the
/// refresh LIFETIME here (the idle and absolute TTLs below, and whether the family
/// survives RP logout), just not WHETHER a refresh token is issued.
async fn issue_device_refresh(
    state: &OidcState,
    scope: Scope,
    grant: &ApprovedDeviceGrant,
) -> Option<String> {
    if !state.issue_refresh_tokens() {
        return None;
    }
    let offline = grant.requested_scope.as_deref().is_some_and(|value| {
        value
            .split_whitespace()
            .any(|token| token == OFFLINE_ACCESS_SCOPE)
    });
    let minted = tokens::mint_refresh_token(state, &scope);
    let family_id = RefreshFamilyId::generate(state.env(), &scope);
    let now = state.now();
    let created = epoch_micros(now);
    let idle_expires = epoch_micros(
        now.checked_add(state.refresh_idle_ttl(offline))
            .unwrap_or(now),
    );
    let absolute_expires = epoch_micros(
        now.checked_add(state.refresh_max_lifetime(offline))
            .unwrap_or(now),
    );
    let Ok(client_id) = ClientId::parse_in_scope(&grant.client_id, &scope) else {
        return None;
    };
    let actor = client_service_actor(&client_id);
    let correlation = CorrelationId::generate(state.env());
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .refresh()
        .issue(
            state.env(),
            NewRefreshFamily {
                family_id: &family_id,
                token_jti: &minted.jti,
                token_digest: &minted.digest,
                grant_id: &grant.grant_id,
                subject: &grant.subject,
                client_id: &grant.client_id,
                scope: grant.requested_scope.as_deref(),
                auth_methods: &grant.auth_methods,
                offline,
                created_at_unix_micros: created,
                idle_expires_at_unix_micros: idle_expires,
                absolute_expires_at_unix_micros: absolute_expires,
            },
        )
        .await;
    match result {
        Ok(()) => Some(minted.token),
        Err(error) => {
            tracing::warn!(%error, "could not open a refresh-token family for a device flow");
            None
        }
    }
}

/// Build the RFC 6749 5.1 success body for a device exchange (issue #24): the access
/// token, an ID token, `expires_in`, and (when present) the granted scope and a
/// refresh token.
fn device_token_response(
    minted: &IssuedTokens,
    oauth_scope: Option<&str>,
    refresh_token: Option<&str>,
) -> Response {
    let mut body = json!({
        "access_token": minted.access.token(),
        "token_type": "Bearer",
        "expires_in": minted.expires_in_secs,
        "id_token": minted.id_token,
    });
    if let Some(scope) = oauth_scope {
        body["scope"] = json!(scope);
    }
    if let Some(refresh) = refresh_token {
        body["refresh_token"] = json!(refresh);
    }
    crate::token::token_ok(&body.to_string())
}

/// Authenticate the token-endpoint client for the device grant through the ONE
/// reusable seam. A public device client (auth method `none`) authenticates with only
/// its `client_id`, exactly as the code grant permits.
async fn authenticate_token_client(
    state: &OidcState,
    scope: Scope,
    headers: &HeaderMap,
    params: &crate::token::TokenParams,
) -> Result<AuthenticatedClient, TokenError> {
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
    client_auth::authenticate_client(state, scope, inputs)
        .await
        .map_err(|error| match error {
            ClientAuthError::InvalidRequest(message) => {
                TokenError::InvalidRequest(message.to_owned())
            }
            ClientAuthError::InvalidClient { via_basic } => TokenError::InvalidClient { via_basic },
        })
}

fn map_client_auth_error(error: &ClientAuthError) -> DeviceAuthError {
    match error {
        ClientAuthError::InvalidRequest(message) => DeviceAuthError::InvalidRequest(message),
        ClientAuthError::InvalidClient { via_basic } => DeviceAuthError::InvalidClient {
            via_basic: *via_basic,
        },
    }
}

/// Whether a space-separated grant-type allowlist contains the `device_code` URN.
fn grant_types_allow_device(grant_types: &str) -> bool {
    grant_types
        .split_whitespace()
        .any(|token| token == GrantType::DEVICE_CODE_URN)
}

/// Generate a device code (issue #24): the `ira_dc_` prefix, the scope-declaring
/// `dc_` handle, the `~` delimiter, and 256 bits of entropy from the seam. Only the
/// digest of the whole token is stored.
fn generate_device_code(env: &Env, device_code_id: &DeviceCodeId) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut bytes = [0_u8; DEVICE_CODE_SECRET_BYTES];
    env.entropy().fill_bytes(&mut bytes);
    format!(
        "{DEVICE_CODE_PREFIX}{device_code_id}{}{}",
        tokens::OPAQUE_ACCESS_TOKEN_DELIMITER,
        URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Recover the flow's `(tenant, environment)` scope from a presented device code
/// (issue #24), or [`None`] when it is malformed. The device code embeds its scope in
/// the clear through its `dc_` handle, so the GLOBAL token endpoint routes it without
/// a database lookup; the secret suffix and the whole-token digest are what bind it.
fn device_code_scope(device_code: &str) -> Option<Scope> {
    let rest = device_code.strip_prefix(DEVICE_CODE_PREFIX)?;
    let handle = rest.split(tokens::OPAQUE_ACCESS_TOKEN_DELIMITER).next()?;
    DeviceCodeId::parse_declared_scope(handle)
        .ok()
        .map(|id| id.scope())
}

/// Generate a user code (issue #24, RFC 8628 6.1): `USER_CODE_LENGTH` characters from
/// the restricted alphabet, unbiased by rejection sampling, drawn from the entropy
/// seam. Returns the display form (`XXXX-XXXX`, grouped for transcription) and the
/// normalized form (no separator) that is hashed for matching.
fn generate_user_code(env: &Env) -> (String, String) {
    let mut chars: Vec<u8> = Vec::with_capacity(USER_CODE_LENGTH);
    let mut buffer = [0_u8; 32];
    while chars.len() < USER_CODE_LENGTH {
        env.entropy().fill_bytes(&mut buffer);
        for &byte in &buffer {
            if chars.len() >= USER_CODE_LENGTH {
                break;
            }
            if byte < USER_CODE_REJECT_ABOVE {
                let index = (byte % 20) as usize;
                chars.push(USER_CODE_ALPHABET[index]);
            }
        }
    }
    // Every character is ASCII from the alphabet, so this is valid UTF-8.
    let normalized = String::from_utf8(chars).unwrap_or_default();
    let display = format!("{}-{}", &normalized[0..4], &normalized[4..USER_CODE_LENGTH]);
    (display, normalized)
}

/// Normalize a submitted user code for matching (issue #24): keep only alphanumerics
/// (dropping the display hyphen and any spaces) and upper-case them, so a human who
/// types the code with or without its separator, in any case, matches the same row.
#[must_use]
pub fn normalize_user_code(raw: &str) -> String {
    raw.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// A coarse, operator-safe initiation-location hint from the request source (issue
/// #24): the peer IP, or [`None`] when the server installed no connection info. This
/// is the cross-device BCP cue a human uses to recognize a flow they did not start;
/// richer `GeoIP` enrichment is deferred to the M9 hosted pages.
fn request_source_hint(peer: Option<IpAddr>) -> Option<String> {
    peer.map(|addr| addr.to_string())
}

/// The 200 JSON emitter for the device-authorization endpoint, with the no-store
/// headers RFC 8628 requires (issue #24).
fn device_ok(body: &str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        body.to_owned(),
    )
        .into_response()
}
