// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CIBA backchannel authentication endpoint (issue #131, OpenID Connect Client Initiated
//! Backchannel Authentication Flow -- Core 1.0 section 7).
//!
//! A client asks for a user it NAMES but does not have in front of it to be authenticated.
//! The endpoint answers an `auth_req_id`, the user decides on their own device, and the
//! client obtains tokens by polling the token endpoint.
//!
//! # The wire credential, and why the id in it is not the secret
//!
//! The `auth_req_id` is `ira_bar_<jti>~<secret>`, exactly the shape the device grant uses for
//! its device code. The `bar_` segment is a NON-secret routing handle that declares its
//! `(tenant, environment)` in the clear, so the GLOBAL token endpoint can recover the scope
//! from a presented `auth_req_id` before it knows anything else about it. The 256-bit suffix
//! is the secret, and only the SHA-256 digest of the whole string is stored -- a database
//! dump yields nothing replayable.
//!
//! # What this module deliberately does not do
//!
//! It creates requests; it does not decide them. The approval surface that renders
//! `binding_message` on the user's authentication device, and the ping notification
//! delivery, are separate surfaces. Keeping creation here means the endpoint's refusals (an
//! unknown user, a malformed hint, a client not allowed the grant) are all answered before
//! any human is bothered, which is the property that makes CIBA safe to expose: a client
//! cannot use it to spam approval prompts at users it has guessed the names of.

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::ciba::{DeliveryMode, bounded_expiry};
use ironauth_store::rar::validate_authorization_details;
use ironauth_store::{
    BackchannelAuthRequestId, ClientBackchannelProfile, ClientId, NewBackchannelRequest, Scope,
};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

use crate::client_auth::{self, ClientAuthInputs};
use crate::state::OidcState;

/// The CIBA grant type a client must be allowed before it may use this endpoint.
const CIBA_GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";

/// The longest `binding_message` this endpoint accepts.
///
/// CIBA Core says it should be "relatively short" and suitable for display on a constrained
/// device, without naming a number. 140 is chosen to fit a notification without truncation.
/// A bound is required rather than merely advisable: the message is rendered on the user's
/// authentication device, so an unbounded one is a client writing arbitrary-length content
/// onto someone else's screen.
const MAX_BINDING_MESSAGE: usize = 140;

/// The wire prefix of an `auth_req_id`, mirroring the device grant's `ira_dc_`.
const AUTH_REQ_ID_PREFIX: &str = "ira_bar_";

/// Bytes of entropy in an `auth_req_id`'s secret suffix: 32 bytes = 256 bits, the same
/// budget the device code carries.
const AUTH_REQ_ID_SECRET_BYTES: usize = 32;

/// Form parameters of a backchannel authentication request.
#[derive(Debug, Deserialize)]
pub struct BackchannelAuthParams {
    /// The requesting client.
    client_id: Option<String>,
    /// The client secret for `client_secret_post` authentication.
    client_secret: Option<String>,
    /// The JWT client assertion for `private_key_jwt` / `client_secret_jwt`.
    client_assertion: Option<String>,
    /// The RFC 7521 `client_assertion_type` accompanying `client_assertion`.
    client_assertion_type: Option<String>,
    /// The requested OAuth `scope`.
    scope: Option<String>,
    /// The identifier of the user to authenticate.
    login_hint: Option<String>,
    /// An ID token previously issued to this client, naming the user.
    id_token_hint: Option<String>,
    /// The message to render on the user's authentication device.
    binding_message: Option<String>,
    /// The bearer token a ping notification must carry back. Its PRESENCE selects ping mode.
    client_notification_token: Option<String>,
    /// How long the client wants the request to live, in seconds.
    requested_expiry: Option<i64>,
    /// The RFC 9396 `authorization_details` document, as JSON text.
    authorization_details: Option<String>,
}

/// A backchannel authentication endpoint error (CIBA Core section 13).
#[derive(Debug, PartialEq, Eq)]
pub enum CibaError {
    /// The client could not be authenticated.
    InvalidClient {
        /// Whether the credentials arrived via HTTP Basic, which decides `WWW-Authenticate`.
        via_basic: bool,
    },
    /// The client is not allowed the CIBA grant.
    UnauthorizedClient,
    /// The request is malformed: no hint, more than one hint, or a `binding_message` that is
    /// too long.
    InvalidRequest(&'static str),
    /// The hint named nobody this deployment knows.
    UnknownUserId,
    /// The `authorization_details` document is malformed, oversized, or names a type this
    /// deployment has not registered (#131 criterion 4).
    InvalidAuthorizationDetails,
    /// The request could not be processed.
    ServerError,
}

impl CibaError {
    const fn status(&self) -> StatusCode {
        match self {
            Self::InvalidClient { .. } => StatusCode::UNAUTHORIZED,
            Self::UnauthorizedClient => StatusCode::FORBIDDEN,
            Self::InvalidRequest(_) | Self::UnknownUserId | Self::InvalidAuthorizationDetails => {
                StatusCode::BAD_REQUEST
            }
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    const fn code(&self) -> &'static str {
        match self {
            Self::InvalidClient { .. } => "invalid_client",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::InvalidRequest(_) => "invalid_request",
            Self::UnknownUserId => "unknown_user_id",
            // RFC 9396 section 5 names this exact code for a rejected document.
            Self::InvalidAuthorizationDetails => "invalid_authorization_details",
            Self::ServerError => "server_error",
        }
    }

    const fn description(&self) -> &'static str {
        match self {
            Self::InvalidClient { .. } => "the client could not be authenticated",
            Self::UnauthorizedClient => "this client may not use the backchannel grant",
            Self::InvalidRequest(why) => why,
            // Deliberately the same words for every unresolvable hint. See the handler.
            Self::UnknownUserId => "the request did not identify a user",
            Self::InvalidAuthorizationDetails => {
                "authorization_details is malformed or names an unregistered type"
            }
            Self::ServerError => "the request could not be processed",
        }
    }
}

impl IntoResponse for CibaError {
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
        if let Self::InvalidClient { via_basic: true } = self {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Basic realm=\"ironauth\", charset=\"UTF-8\""),
            );
        }
        response
    }
}

/// `POST /backchannel_authenticate` (CIBA Core section 7.1).
pub async fn backchannel_authenticate(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Form(params): Form<BackchannelAuthParams>,
) -> Response {
    match backchannel_authenticate_inner(&state, &headers, &params).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

/// Exactly one user hint, and which one it is.
///
/// CIBA Core requires exactly one of `login_hint`, `id_token_hint` and `login_hint_token`.
/// BOTH failure directions are refused: none, because the request names nobody, and more
/// than one, because two hints that disagree have no defined winner and picking one silently
/// authenticates a user the client did not unambiguously ask for.
fn single_hint(params: &BackchannelAuthParams) -> Result<&str, CibaError> {
    let present: Vec<&str> = [
        params.login_hint.as_deref(),
        params.id_token_hint.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .collect();
    match present.len() {
        0 => Err(CibaError::InvalidRequest(
            "exactly one of login_hint or id_token_hint is required",
        )),
        1 => Ok(present[0]),
        _ => Err(CibaError::InvalidRequest(
            "exactly one hint may be supplied; two hints have no defined winner",
        )),
    }
}

/// Whether a client's registered grant list allows the CIBA grant.
fn grant_types_allow_ciba(grant_types: &str) -> bool {
    grant_types.split_whitespace().any(|g| g == CIBA_GRANT_TYPE)
}

/// The request-shape checks that must pass BEFORE any user lookup happens.
///
/// Ordered deliberately: a malformed request must never cause a user lookup, so it cannot be
/// used to time one or to probe which identifiers exist by measuring how long a refusal takes.
/// Returns the single hint on success.
fn validate_shape(params: &BackchannelAuthParams) -> Result<&str, CibaError> {
    let hint = single_hint(params)?;
    if let Some(message) = params.binding_message.as_deref() {
        if message.chars().count() > MAX_BINDING_MESSAGE {
            return Err(CibaError::InvalidRequest(
                "binding_message is too long to render on an authentication device",
            ));
        }
    }
    Ok(hint)
}

/// Reconcile the client's REGISTERED delivery mode with what this request carries.
///
/// The mode is read from the registration, never inferred from the request. CIBA Core makes
/// it a registered property, and inferring it would let a client registered for poll talk the
/// server into calling a URL simply by adding a parameter.
///
/// Both mismatches are refused, and the second is the one worth stating:
///
/// * **Ping without a `client_notification_token`.** The token is what lets the client
///   authenticate the ping as genuinely ours. Sending an unauthenticated notification would
///   train the client to accept pings from anyone who knows its endpoint.
/// * **Poll WITH a `client_notification_token`.** Nothing would ever be sent, so the client
///   has handed us a bearer credential we store and never use -- a secret held for no reason,
///   which is the kind of thing that leaks in a dump and buys the holder something later.
fn reconcile_delivery(
    params: &BackchannelAuthParams,
    profile: &ClientBackchannelProfile,
) -> Result<(), CibaError> {
    match (
        profile.delivery_mode,
        params.client_notification_token.as_deref(),
    ) {
        (DeliveryMode::Ping, Some(token)) if !token.trim().is_empty() => Ok(()),
        (DeliveryMode::Ping, _) => Err(CibaError::InvalidRequest(
            "a ping-mode client must send a client_notification_token",
        )),
        (DeliveryMode::Poll, None) => Ok(()),
        (DeliveryMode::Poll, Some(_)) => Err(CibaError::InvalidRequest(
            "this client is registered for poll delivery and must not send a \
             client_notification_token",
        )),
    }
}

/// Parse and validate the RFC 9396 `authorization_details` document (#131 criterion 4).
///
/// Runs BEFORE the user lookup, for the same reason the shape checks do: a refusable request
/// must not cause a lookup that could be timed.
///
/// Unknown types are refused by DEFAULT. The document travels inside an issued token and
/// resource servers act on it, so a type nobody in this deployment has defined is an
/// authorization statement with no agreed meaning riding in a trusted credential.
fn parse_authorization_details(
    state: &OidcState,
    params: &BackchannelAuthParams,
) -> Result<Option<serde_json::Value>, CibaError> {
    let details = match params.authorization_details.as_deref() {
        None => None,
        Some(raw) => Some(
            serde_json::from_str::<serde_json::Value>(raw)
                .map_err(|_| CibaError::InvalidAuthorizationDetails)?,
        ),
    };
    validate_authorization_details(details.as_ref(), state.registered_rar_types())
        .map_err(|_| CibaError::InvalidAuthorizationDetails)?;
    Ok(details)
}

/// Authenticate the caller and gate it on the CIBA grant.
///
/// One function because it answers a single question -- "who is asking, and may they ask" --
/// and because every refusal it produces must happen before the request is examined or any
/// user is looked up.
async fn authenticated_caller(
    state: &OidcState,
    headers: &HeaderMap,
    params: &BackchannelAuthParams,
) -> Result<(ClientId, Scope), CibaError> {
    // Authenticate the client and recover its scope from the presented client_id: the
    // endpoint is global, exactly like the token endpoint's self-scoped auth.
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
        .map_err(|_| CibaError::InvalidClient { via_basic: false })?;
    let client_id =
        ClientId::parse_in_scope(&client.client_id, &scope).map_err(|_| CibaError::ServerError)?;

    // The CIBA grant is opt-in per client, read from the same registered grant list the
    // device grant is gated on.
    let record = state
        .store()
        .scoped(scope)
        .clients()
        .get(&client_id)
        .await
        .map_err(|_| CibaError::ServerError)?;
    if !grant_types_allow_ciba(&record.grant_types) {
        return Err(CibaError::UnauthorizedClient);
    }

    Ok((client_id, scope))
}

async fn backchannel_authenticate_inner(
    state: &OidcState,
    headers: &HeaderMap,
    params: &BackchannelAuthParams,
) -> Result<Response, CibaError> {
    let (client_id, scope) = authenticated_caller(state, headers, params).await?;

    let hint = validate_shape(params)?;

    let details = parse_authorization_details(state, params)?;

    // The REGISTERED delivery settings. A client this endpoint authenticated but which has
    // no row here is answered as `invalid_client`, exactly like an unauthenticated one.
    let profile = state
        .store()
        .scoped(scope)
        .backchannel_auth()
        .client_profile(&client_id)
        .await
        .map_err(|_| CibaError::ServerError)?
        .ok_or(CibaError::InvalidClient { via_basic: false })?;
    reconcile_delivery(params, &profile)?;

    let user = state
        .store()
        .scoped(scope)
        .users()
        .by_identifier(hint)
        .await
        .map_err(|_| CibaError::ServerError)?
        .ok_or(CibaError::UnknownUserId)?;

    let now = state.now();
    let interval = i32::try_from(state.device_poll_interval_secs()).unwrap_or(5);
    let requested = params
        .requested_expiry
        .and_then(|secs| u64::try_from(secs).ok())
        .map(Duration::from_secs);
    let lifetime = bounded_expiry(requested, Duration::from_secs(30), state.device_code_ttl());
    let expires_micros = epoch_micros(now.checked_add(lifetime).unwrap_or(now));

    // The client's notification token, sealed for storage. It is the ONE credential here
    // that cannot be reduced to a digest: it must be REPLAYED to the client's endpoint so the
    // client can authenticate the ping, and a digest cannot be replayed. Stored as bytes and
    // never logged; the column is write-once at INSERT (see migration 0147).
    let notification_token: Option<Vec<u8>> = params
        .client_notification_token
        .as_deref()
        .map(|t| t.as_bytes().to_vec());

    let id = BackchannelAuthRequestId::generate(state.env(), &scope);
    let (auth_req_id, digest) = mint_auth_req_id(state, &id);

    state
        .store()
        .scoped(scope)
        .backchannel_auth()
        .create(&NewBackchannelRequest {
            auth_req_id_digest: &digest,
            id: &id,
            client_id: &client_id.to_string(),
            delivery_mode: profile.delivery_mode,
            client_notification_url: profile.notification_endpoint.as_deref(),
            client_notification_token: notification_token.as_deref(),
            requested_scope: params
                .scope
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty()),
            authorization_details: details.as_ref(),
            binding_message: params
                .binding_message
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty()),
            subject: &user.id.to_string(),
            interval_secs: interval,
            expires_at_micros: expires_micros,
        })
        .await
        .map_err(|_| CibaError::ServerError)?;

    let body = json!({
        "auth_req_id": auth_req_id,
        "expires_in": lifetime.as_secs(),
        "interval": interval,
    })
    .to_string();
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        body,
    )
        .into_response())
}

/// Mint the wire `auth_req_id` and the digest that is stored for it.
///
/// Returns `(plaintext, digest)`. The plaintext leaves in the response and is never
/// persisted; only the digest is written, so a database dump yields nothing replayable.
fn mint_auth_req_id(state: &OidcState, id: &BackchannelAuthRequestId) -> (String, String) {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    // The SAME prefix/handle/delimiter/entropy shape the device grant uses, drawn from the
    // same seam. Deliberately not a second scheme: two wire-credential formats are two
    // things to get right, and the one nobody looks at is the one that drifts.
    let mut bytes = [0_u8; AUTH_REQ_ID_SECRET_BYTES];
    state.env().entropy().fill_bytes(&mut bytes);
    let plaintext = format!(
        "{AUTH_REQ_ID_PREFIX}{id}{}{}",
        crate::tokens::OPAQUE_ACCESS_TOKEN_DELIMITER,
        URL_SAFE_NO_PAD.encode(bytes)
    );
    let digest = hex_sha256(plaintext.as_bytes());
    (plaintext, digest)
}

/// The lowercase hex SHA-256 of `bytes`.
fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Epoch microseconds from a system time, via the application clock seam.
fn epoch_micros(at: std::time::SystemTime) -> i64 {
    at.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> BackchannelAuthParams {
        BackchannelAuthParams {
            client_id: None,
            client_secret: None,
            client_assertion: None,
            client_assertion_type: None,
            scope: None,
            login_hint: None,
            id_token_hint: None,
            binding_message: None,
            client_notification_token: None,
            requested_expiry: None,
            authorization_details: None,
        }
    }

    /// Exactly one hint, refused in BOTH directions.
    ///
    /// The two-hint case is the one worth having. Two hints that disagree have no defined
    /// winner, so an implementation that picked the first would authenticate a user the
    /// client did not unambiguously name -- and it would do so silently, which is the part
    /// that makes it a security bug rather than an ergonomic one.
    #[test]
    fn exactly_one_hint_is_required() {
        let mut none = params();
        assert!(matches!(
            single_hint(&none),
            Err(CibaError::InvalidRequest(_))
        ));

        none.login_hint = Some("ada@example.test".to_owned());
        assert_eq!(single_hint(&none), Ok("ada@example.test"));

        let mut both = params();
        both.login_hint = Some("ada@example.test".to_owned());
        both.id_token_hint = Some("eyJhbGciOiJub25lIn0.e30.".to_owned());
        assert!(matches!(
            single_hint(&both),
            Err(CibaError::InvalidRequest(_))
        ));
    }

    /// A blank hint counts as absent, not as a hint whose value is the empty string.
    ///
    /// `login_hint=` is a present-but-empty form field. Without the trim-and-filter it would
    /// count as one hint and then resolve nobody, turning a malformed request into an
    /// `unknown_user_id` -- which tells the client the wrong thing about what went wrong.
    #[test]
    fn a_blank_hint_is_treated_as_absent() {
        let mut blank = params();
        blank.login_hint = Some("   ".to_owned());
        assert!(matches!(
            single_hint(&blank),
            Err(CibaError::InvalidRequest(_))
        ));
    }

    /// The CIBA grant is opt-in, and is not matched by a prefix or a substring.
    #[test]
    fn the_ciba_grant_must_be_registered_exactly() {
        assert!(grant_types_allow_ciba(
            "authorization_code urn:openid:params:grant-type:ciba"
        ));
        assert!(grant_types_allow_ciba(CIBA_GRANT_TYPE));
        assert!(!grant_types_allow_ciba("authorization_code"));
        assert!(!grant_types_allow_ciba(""));
        // Not a substring match: a grant that merely CONTAINS the name is a different grant.
        assert!(!grant_types_allow_ciba(
            "urn:openid:params:grant-type:ciba-extended"
        ));
    }

    /// Every error renders its own status and code, and only the fault class is a 500.
    #[test]
    fn each_error_renders_its_own_status_and_code() {
        let cases = [
            (
                CibaError::InvalidClient { via_basic: false },
                StatusCode::UNAUTHORIZED,
                "invalid_client",
            ),
            (
                CibaError::UnauthorizedClient,
                StatusCode::FORBIDDEN,
                "unauthorized_client",
            ),
            (
                CibaError::InvalidRequest("why"),
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                CibaError::UnknownUserId,
                StatusCode::BAD_REQUEST,
                "unknown_user_id",
            ),
            (
                CibaError::ServerError,
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
            ),
        ];
        for (error, status, code) in cases {
            assert_eq!(error.status(), status, "{code}");
            assert_eq!(error.code(), code);
        }
    }

    fn profile(mode: DeliveryMode) -> ClientBackchannelProfile {
        ClientBackchannelProfile {
            delivery_mode: mode,
            notification_endpoint: match mode {
                DeliveryMode::Ping => Some("https://client.test/ciba".to_owned()),
                DeliveryMode::Poll => None,
            },
        }
    }

    /// The registered mode decides, and BOTH mismatches are refused (#131 criterion 2).
    ///
    /// Driven over the full (mode x token-present) table rather than the two happy cases,
    /// because the interesting cells are the mismatches and a hand-picked pair would cover
    /// only one of them.
    #[test]
    fn the_registered_mode_decides_and_both_mismatches_are_refused() {
        // Ping + token: the only shape that can actually be delivered.
        let mut p = params();
        p.client_notification_token = Some("nt-secret".to_owned());
        assert_eq!(reconcile_delivery(&p, &profile(DeliveryMode::Ping)), Ok(()));

        // Ping without a token: we would send an UNAUTHENTICATED notification, training the
        // client to accept pings from anyone who learns its endpoint.
        let bare = params();
        assert!(matches!(
            reconcile_delivery(&bare, &profile(DeliveryMode::Ping)),
            Err(CibaError::InvalidRequest(_))
        ));

        // Poll with no token: ordinary.
        assert_eq!(
            reconcile_delivery(&bare, &profile(DeliveryMode::Poll)),
            Ok(())
        );

        // Poll WITH a token: nothing would ever be sent, so we would be holding a bearer
        // credential for no reason -- refused rather than stored and ignored.
        assert!(matches!(
            reconcile_delivery(&p, &profile(DeliveryMode::Poll)),
            Err(CibaError::InvalidRequest(_))
        ));
    }

    /// A blank notification token does not satisfy ping.
    ///
    /// `client_notification_token=` is a present-but-empty form field. Without the trim it
    /// would count as a token, and the ping would carry an empty credential the client cannot
    /// distinguish from an attacker's.
    #[test]
    fn a_blank_notification_token_does_not_satisfy_ping() {
        let mut blank = params();
        blank.client_notification_token = Some("   ".to_owned());
        assert!(matches!(
            reconcile_delivery(&blank, &profile(DeliveryMode::Ping)),
            Err(CibaError::InvalidRequest(_))
        ));
    }
}
