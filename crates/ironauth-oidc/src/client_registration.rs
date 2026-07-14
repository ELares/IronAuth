// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dynamic Client Registration and configuration management (issue #30).
//!
//! This module serves RFC 7591 (dynamic client registration) and RFC 7592 (client
//! configuration management), with OpenID Connect Dynamic Client Registration 1.0
//! errata set 2 and RP Metadata Choices 1.0 layered on top. It is CLIENT
//! registration (an OAuth client registering itself), a distinct concept from the
//! human account registration in [`crate::register`]; the two never share a module
//! or a route (this one is mounted at `/connect/register`).
//!
//! # Where the abuse controls live (the issue #31 seam)
//!
//! Open self-service client registration is an abuse surface. This issue ships
//! ONLY the endpoint plus a plain default-off enable flag
//! (`oidc.registration_enabled`, surfaced as
//! [`OidcState::registration_enabled`](crate::OidcState::registration_enabled));
//! the real gating (initial access token policy chains, per-tenant quotas, and
//! quarantine) is owned by the abuse-controls work (issue #31). The clean seam #31
//! layers onto is the single `registration_enabled` gate here and the fact that
//! every request funnels through [`register`]: #31 can wrap the handler or add a
//! policy check ahead of the create without reshaping this module. Because the
//! safe posture is off, the default is UNMOUNTED and undiscoverable.
//!
//! # What is validated (RFC 7591 section 2)
//!
//! The metadata property set is validated with per-spec defaults applied when a
//! property is omitted, and UNRECOGNIZED properties are ignored (RFC 7591 section
//! 2, never an error). The spec defaults:
//!
//! - `token_endpoint_auth_method` defaults to `client_secret_basic`;
//! - `response_types` defaults to `["code"]`, `grant_types` to
//!   `["authorization_code"]` (the only flow this provider serves);
//! - `id_token_signed_response_alg` defaults to `RS256`.
//!
//! `token_endpoint_auth_method` and every algorithm value are validated against
//! the ACTUALLY IMPLEMENTED client-authentication suite (issue #25,
//! [`ClientAuthMethod::ALL`]): a method the suite does not honor (the inert
//! `client_secret_jwt`, or an unknown value) is rejected with
//! `invalid_client_metadata`, never stored as a client that could never
//! authenticate.
//!
//! `redirect_uris` are validated as RFC 8252 targets: for a `web` client, https
//! only; for a `native` client, https OR an http loopback IP literal OR a
//! reverse-domain private-use scheme. Dangerous schemes are rejected. `jwks` and
//! `jwks_uri` are mutually exclusive, and a `jwks_uri` is fetched THROUGH the
//! SSRF-hardened fetcher (issue #25's [`ClientKeyResolver`](crate::ClientKeyResolver)),
//! so a private-address destination is rejected structurally.
//!
//! # RP Metadata Choices negotiation
//!
//! `id_token_signed_response_alg` may be supplied as an ARRAY of acceptable values
//! (RP Metadata Choices 1.0), either under that name or under the plural
//! `id_token_signed_response_alg_values`. The OP selects the best mutual option:
//! it PREFERS `EdDSA` when the RP offers it, falls back to `RS256`, and otherwise
//! takes the first offered value it can represent. The negotiated value is recorded
//! on the client and echoed in the registration response.
//!
//! # Credentials at rest (never plaintext)
//!
//! The generated `client_secret` and `registration_access_token` are stored ONLY
//! as their SHA-256 hashes; each plaintext is returned exactly once (the secret at
//! registration, the token at registration and again, freshly rotated, on every
//! successful update) and never persisted. Every value the OP mints (the client
//! id, the secret, the registration access token) is drawn from the environment
//! entropy seam.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_env::Env;
use ironauth_jose::JwsAlgorithm;
use ironauth_store::{
    ActorRef, CorrelationId, DynamicClientRecord, DynamicClientUpdate, NewDynamicClient, Scope,
    ServiceId, StoreError, redirect_uri_is_registrable,
};
use serde_json::{Value, json};

use crate::client_auth::{ClientAuthMethod, generate_secret, hash_secret};
use crate::state::OidcState;
use crate::util::{client_service_actor, epoch_micros};
use crate::wellknown::{not_found, parse_scope};

/// Bytes of entropy in a registration access token: 32 bytes is 256 bits, drawn
/// from the entropy seam and base64url-encoded (URL-safe, no padding) so the token
/// is safe in an `Authorization: Bearer` header and in the response body.
const REGISTRATION_TOKEN_BYTES: usize = 32;

/// The spec-default `id_token_signed_response_alg` when the client expresses no
/// preference (OIDC Core section 2 / Dynamic Client Registration).
const DEFAULT_ID_TOKEN_ALG: &str = "RS256";

/// The spec-default `token_endpoint_auth_method` when omitted (RFC 7591 section 2).
const DEFAULT_AUTH_METHOD: &str = "client_secret_basic";

/// `POST {issuer}/connect/register`: register a client from an RFC 7591 metadata
/// document, returning the created client and its credentials (201 Created).
pub async fn register(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let Some(scope) = enabled_scope(&state, &tenant_id, &environment_id).await else {
        return not_found();
    };

    let Ok(metadata) = serde_json::from_slice::<Value>(&body) else {
        return metadata_error("the request body must be a JSON object");
    };
    let Some(metadata) = metadata.as_object() else {
        return metadata_error("the request body must be a JSON object");
    };

    let validated = match validate_metadata(&state, metadata, None).await {
        Ok(validated) => validated,
        Err(error) => return error.into_response(),
    };

    // Mint the credentials from the entropy seam. A confidential client gets a
    // secret; every DCR client gets a registration access token. Only the hashes
    // are stored; the plaintext is returned once here.
    let secret = validated
        .auth_method
        .needs_secret()
        .then(|| generate_secret(state.env()));
    let secret_hash = secret.as_deref().map(hash_secret);
    let registration_token = generate_registration_token(state.env());
    let registration_token_hash = hash_secret(&registration_token);

    let issuer = state.issuer_for(&scope);
    let registration_uri_base = format!("{issuer}/connect/register");
    let actor = ActorRef::service(ServiceId::generate(state.env()));

    let params = NewDynamicClient {
        display_name: &validated.display_name,
        auth_method: validated.auth_method.as_str(),
        secret_hash: secret_hash.as_deref(),
        redirect_uris: &validated.redirect_uris,
        application_type: &validated.application_type,
        id_token_signed_response_alg: &validated.id_token_signed_response_alg,
        jwks: validated.jwks.as_deref(),
        jwks_uri: validated.jwks_uri.as_deref(),
        token_endpoint_auth_signing_alg: validated.token_endpoint_auth_signing_alg.as_deref(),
        registration_access_token_hash: &registration_token_hash,
        registration_uri_base: &registration_uri_base,
    };

    let registration = match state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .clients()
        .register_dynamic(state.env(), params)
        .await
    {
        Ok(registration) => registration,
        Err(StoreError::InvalidRedirectUri) => {
            return redirect_error("a redirect_uri is not a registrable target");
        }
        Err(StoreError::Conflict) => {
            return metadata_error("the client key configuration is invalid");
        }
        Err(_) => return server_error(),
    };

    let issued_at = epoch_micros(state.now()) / 1_000_000;
    let mut body = base_metadata(
        &registration.id.to_string(),
        issued_at,
        &validated,
        &registration.registration_client_uri,
    );
    if let Some(secret) = &secret {
        body.insert("client_secret".to_owned(), json!(secret));
        // 0 means the secret does not expire (RFC 7591 section 3.2.1).
        body.insert("client_secret_expires_at".to_owned(), json!(0));
    }
    body.insert(
        "registration_access_token".to_owned(),
        json!(registration_token),
    );

    credential_response(StatusCode::CREATED, &Value::Object(body))
}

/// `GET {registration_client_uri}`: read a dynamically registered client's current
/// configuration (RFC 7592 section 2.1). Authenticated by the registration access
/// token.
pub async fn read(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some((_scope, record)) =
        authenticate(&state, &tenant_id, &environment_id, &client_id, &headers).await
    else {
        return unauthorized();
    };

    let issued_at = record.created_at_unix_micros / 1_000_000;
    let uri = record.registration_client_uri.clone().unwrap_or_default();
    let body = read_metadata(&record, issued_at, &uri);
    credential_response(StatusCode::OK, &Value::Object(body))
}

/// `PUT {registration_client_uri}`: replace a dynamically registered client's
/// configuration (RFC 7592 section 2.2), ROTATING the registration access token.
/// The old token is rejected on the next call. Authenticated by the current token.
pub async fn update(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some((scope, record)) =
        authenticate(&state, &tenant_id, &environment_id, &client_id, &headers).await
    else {
        return unauthorized();
    };

    let Ok(metadata) = serde_json::from_slice::<Value>(&body) else {
        return metadata_error("the request body must be a JSON object");
    };
    let Some(metadata) = metadata.as_object() else {
        return metadata_error("the request body must be a JSON object");
    };

    let validated = match validate_metadata(&state, metadata, Some(&record)).await {
        Ok(validated) => validated,
        Err(error) => return error.into_response(),
    };

    // Rotate the registration access token on every successful update: mint a fresh
    // one, store only its new hash, and hand back the plaintext. The superseded
    // token's hash no longer matches, so it stops working immediately.
    let new_token = generate_registration_token(state.env());
    let new_token_hash = hash_secret(&new_token);
    let actor = client_service_actor(&record.id);

    let store_update = DynamicClientUpdate {
        display_name: &validated.display_name,
        auth_method: validated.auth_method.as_str(),
        redirect_uris: &validated.redirect_uris,
        application_type: &validated.application_type,
        id_token_signed_response_alg: &validated.id_token_signed_response_alg,
        jwks: validated.jwks.as_deref(),
        jwks_uri: validated.jwks_uri.as_deref(),
        token_endpoint_auth_signing_alg: validated.token_endpoint_auth_signing_alg.as_deref(),
        registration_access_token_hash: &new_token_hash,
    };

    match state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .clients()
        .update_dynamic(state.env(), &record.id, store_update)
        .await
    {
        Ok(()) => {}
        Err(StoreError::InvalidRedirectUri) => {
            return redirect_error("a redirect_uri is not a registrable target");
        }
        Err(StoreError::NotFound) => return unauthorized(),
        Err(StoreError::Conflict) => {
            return metadata_error("the client key configuration is invalid");
        }
        Err(_) => return server_error(),
    }

    let issued_at = record.created_at_unix_micros / 1_000_000;
    let uri = record.registration_client_uri.clone().unwrap_or_default();
    let mut body = base_metadata(&record.id.to_string(), issued_at, &validated, &uri);
    body.insert("registration_access_token".to_owned(), json!(new_token));
    credential_response(StatusCode::OK, &Value::Object(body))
}

/// `DELETE {registration_client_uri}`: delete a dynamically registered client (RFC
/// 7592 section 2.3), returning 204 No Content. Authenticated by the token.
pub async fn delete(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some((scope, record)) =
        authenticate(&state, &tenant_id, &environment_id, &client_id, &headers).await
    else {
        return unauthorized();
    };

    let actor = client_service_actor(&record.id);
    match state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .clients()
        .delete(state.env(), &record.id)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        // The client authenticated a moment ago; a not-found here is a concurrent
        // delete, reported as the uniform unauthorized (no existence oracle).
        Err(StoreError::NotFound) => unauthorized(),
        Err(_) => server_error(),
    }
}

/// Resolve the `(tenant, environment)` scope for a registration request, returning
/// `None` (a uniform 404) when the endpoint is disabled, the scope is malformed, or
/// the environment is unprovisioned or cross-tenant.
async fn enabled_scope(state: &OidcState, tenant_id: &str, environment_id: &str) -> Option<Scope> {
    if !state.registration_enabled() {
        return None;
    }
    let scope = parse_scope(tenant_id, environment_id)?;
    // Require a provisioned environment, exactly as discovery and the JWKS surface
    // do: a cross-tenant scope loads zero rows under row-level security and yields
    // no entry, so registration cannot be aimed at another tenant's environment.
    state.issuer_entry(&scope).await?;
    Some(scope)
}

/// Authenticate an RFC 7592 request: resolve the scope and DCR client, then compare
/// the presented registration access token's hash against the stored hash in
/// constant time. Returns the scope and the record on success, or `None` for ANY
/// failure (disabled, malformed, absent, not a DCR client, missing or wrong token)
/// so the surface is never an oracle. The caller maps `None` to a uniform 401.
async fn authenticate(
    state: &OidcState,
    tenant_id: &str,
    environment_id: &str,
    client_id: &str,
    headers: &HeaderMap,
) -> Option<(Scope, DynamicClientRecord)> {
    let scope = enabled_scope(state, tenant_id, environment_id).await?;
    let presented = bearer_token(headers)?;
    let id = state
        .store()
        .scoped(scope)
        .clients()
        .parse_id(client_id)
        .ok()?;
    let record = state
        .store()
        .scoped(scope)
        .clients()
        .dynamic_registration(&id)
        .await
        .ok()?;
    let stored = record.registration_access_token_hash.as_deref()?;
    if constant_time_eq(hash_secret(&presented).as_bytes(), stored.as_bytes()) {
        Some((scope, record))
    } else {
        None
    }
}

/// A client's validated registration metadata, ready to persist.
struct ValidatedMetadata {
    display_name: String,
    auth_method: ClientAuthMethod,
    redirect_uris: Vec<String>,
    application_type: String,
    id_token_signed_response_alg: String,
    jwks: Option<String>,
    jwks_uri: Option<String>,
    token_endpoint_auth_signing_alg: Option<String>,
}

/// Validate an RFC 7591 metadata document, applying per-spec defaults, ignoring
/// unrecognized properties, negotiating the ID token algorithm, and (for a
/// `jwks_uri`) fetching through the SSRF-hardened fetcher. `existing` is the record
/// being updated (RFC 7592), so the auth-method transition rules apply; `None` for
/// a fresh registration.
async fn validate_metadata(
    state: &OidcState,
    metadata: &serde_json::Map<String, Value>,
    existing: Option<&DynamicClientRecord>,
) -> Result<ValidatedMetadata, RegistrationError> {
    let application_type = match metadata.get("application_type") {
        None => "web".to_owned(),
        Some(Value::String(value)) if value == "web" || value == "native" => value.clone(),
        Some(_) => {
            return Err(RegistrationError::metadata(
                "application_type must be \"web\" or \"native\"",
            ));
        }
    };

    // response_types / grant_types: this provider serves only the authorization
    // code flow, so a request that pins any other value is rejected (RFC 7591
    // consistency), while omission takes the spec defaults.
    check_only(metadata, "response_types", "code")?;
    check_only(metadata, "grant_types", "authorization_code")?;

    let auth_method = validate_auth_method(metadata)?;

    let redirect_uris = validate_redirect_uris(metadata, &application_type)?;

    // On an RFC 7592 update, switching to a secret-based method requires a secret
    // the client does not have (an update never mints one), so refuse the
    // transition and let the RP re-register instead of silently creating a client
    // that can never authenticate.
    if let Some(existing) = existing {
        let had_secret = matches!(
            ClientAuthMethod::parse(&existing.auth_method),
            Some(ClientAuthMethod::Basic | ClientAuthMethod::Post)
        );
        if auth_method.needs_secret() && !had_secret {
            return Err(RegistrationError::metadata(
                "cannot switch to a secret-based token_endpoint_auth_method on update",
            ));
        }
    }

    let id_token_signed_response_alg = negotiate_id_token_alg(metadata)?;
    let token_endpoint_auth_signing_alg = validate_signing_alg(metadata)?;
    let (jwks, jwks_uri) = validate_client_keys(state, metadata, auth_method).await?;

    let display_name = metadata
        .get("client_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("Dynamically Registered Client")
        .to_owned();

    Ok(ValidatedMetadata {
        display_name,
        auth_method,
        redirect_uris,
        application_type,
        id_token_signed_response_alg,
        jwks,
        jwks_uri,
        token_endpoint_auth_signing_alg,
    })
}

/// Validate `token_endpoint_auth_method` against the ACTUALLY IMPLEMENTED suite
/// (issue #25). The default is `client_secret_basic`. A method the suite does not
/// advertise (the inert `client_secret_jwt`, or an unknown string) is rejected: the
/// provider never stores a client registered for a method it cannot honor.
fn validate_auth_method(
    metadata: &serde_json::Map<String, Value>,
) -> Result<ClientAuthMethod, RegistrationError> {
    let raw = match metadata.get("token_endpoint_auth_method") {
        None => DEFAULT_AUTH_METHOD,
        Some(Value::String(value)) => value.as_str(),
        Some(_) => {
            return Err(RegistrationError::metadata(
                "token_endpoint_auth_method must be a string",
            ));
        }
    };
    match ClientAuthMethod::parse(raw) {
        // Only a method the suite ADVERTISES is registrable: client_secret_jwt is
        // recognized but inert (issue #25), so it is not in ALL and is refused here.
        Some(method) if ClientAuthMethod::ALL.contains(&method) => Ok(method),
        _ => Err(RegistrationError::metadata(
            "token_endpoint_auth_method is not supported by this provider",
        )),
    }
}

/// Validate `redirect_uris` as RFC 8252 targets under the client's application
/// type. `redirect_uris` is required (the only supported flow is redirect based),
/// every entry must be registrable, and for a `web` client every entry must be
/// https (loopback and private-use schemes are native-only).
fn validate_redirect_uris(
    metadata: &serde_json::Map<String, Value>,
    application_type: &str,
) -> Result<Vec<String>, RegistrationError> {
    let Some(value) = metadata.get("redirect_uris") else {
        return Err(RegistrationError::redirect(
            "redirect_uris is required and must be a non-empty array",
        ));
    };
    let Some(array) = value.as_array() else {
        return Err(RegistrationError::redirect(
            "redirect_uris must be an array",
        ));
    };
    if array.is_empty() {
        return Err(RegistrationError::redirect(
            "redirect_uris must not be empty",
        ));
    }
    let mut uris = Vec::with_capacity(array.len());
    for entry in array {
        let Some(uri) = entry.as_str() else {
            return Err(RegistrationError::redirect(
                "every redirect_uri must be a string",
            ));
        };
        if !redirect_allowed(uri, application_type) {
            return Err(RegistrationError::redirect(
                "a redirect_uri is not a valid target for this application_type",
            ));
        }
        uris.push(uri.to_owned());
    }
    Ok(uris)
}

/// Whether `uri` is an allowed redirect target for `application_type`. Both types
/// require an RFC 8252 registrable target (which rejects dangerous schemes,
/// fragments, and non-ASCII authorities); a `web` client additionally requires the
/// https scheme, so an http loopback or a private-use scheme is native-only.
fn redirect_allowed(uri: &str, application_type: &str) -> bool {
    if !redirect_uri_is_registrable(uri) {
        return false;
    }
    if application_type == "web" {
        return uri
            .split_once(':')
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"));
    }
    // Native: any registrable target (https, http loopback IP literal, or a
    // reverse-domain private-use scheme).
    true
}

/// Negotiate `id_token_signed_response_alg` (RP Metadata Choices 1.0). The RP may
/// offer a single value or an array of acceptable values (under the singular name
/// or the plural `id_token_signed_response_alg_values`). The OP prefers `EdDSA`,
/// then `RS256`, then the first representable offered value; an offered set with no
/// representable algorithm is rejected. Omission takes the `RS256` default.
fn negotiate_id_token_alg(
    metadata: &serde_json::Map<String, Value>,
) -> Result<String, RegistrationError> {
    let candidates = id_token_alg_candidates(metadata)?;
    let Some(candidates) = candidates else {
        return Ok(DEFAULT_ID_TOKEN_ALG.to_owned());
    };
    let supported: Vec<JwsAlgorithm> = candidates
        .iter()
        .filter_map(|name| JwsAlgorithm::from_jose_name(name))
        .collect();
    if supported.is_empty() {
        return Err(RegistrationError::metadata(
            "no supported id_token_signed_response_alg was offered",
        ));
    }
    // Prefer EdDSA when the RP offers it, else RS256, else the first offered value
    // this provider can represent.
    let chosen = if supported.contains(&JwsAlgorithm::EdDsa) {
        JwsAlgorithm::EdDsa
    } else if supported.contains(&JwsAlgorithm::Rs256) {
        JwsAlgorithm::Rs256
    } else {
        supported[0]
    };
    Ok(chosen.as_jose_name().to_owned())
}

/// The candidate `id_token_signed_response_alg` values from the metadata: the
/// plural `_values` array (RP Metadata Choices) if present, otherwise the singular
/// value (a string, or an array some deployments use). `None` when the client
/// expressed no preference.
fn id_token_alg_candidates(
    metadata: &serde_json::Map<String, Value>,
) -> Result<Option<Vec<String>>, RegistrationError> {
    if let Some(value) = metadata.get("id_token_signed_response_alg_values") {
        return string_array(value).map(Some).ok_or_else(|| {
            RegistrationError::metadata(
                "id_token_signed_response_alg_values must be an array of strings",
            )
        });
    }
    match metadata.get("id_token_signed_response_alg") {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(vec![value.clone()])),
        Some(value @ Value::Array(_)) => string_array(value).map(Some).ok_or_else(|| {
            RegistrationError::metadata(
                "id_token_signed_response_alg must be a string or array of strings",
            )
        }),
        Some(_) => Err(RegistrationError::metadata(
            "id_token_signed_response_alg must be a string or array of strings",
        )),
    }
}

/// Validate `token_endpoint_auth_signing_alg` (the pinned `private_key_jwt`
/// assertion algorithm, issue #25). It must be a representable JWS algorithm; an
/// unrepresentable one (for example ES512) is rejected. `None` when omitted.
fn validate_signing_alg(
    metadata: &serde_json::Map<String, Value>,
) -> Result<Option<String>, RegistrationError> {
    match metadata.get("token_endpoint_auth_signing_alg") {
        None => Ok(None),
        Some(Value::String(value)) if JwsAlgorithm::from_jose_name(value).is_some() => {
            Ok(Some(value.clone()))
        }
        Some(_) => Err(RegistrationError::metadata(
            "token_endpoint_auth_signing_alg is not a supported algorithm",
        )),
    }
}

/// Validate the `jwks` / `jwks_uri` pair. They are MUTUALLY EXCLUSIVE. A
/// `private_key_jwt` client MUST supply exactly one usable source; other methods
/// ignore any key material (it has no effect on their authentication). An inline
/// `jwks` must name at least one representable key; a `jwks_uri` is fetched THROUGH
/// the SSRF-hardened fetcher and must yield at least one key, so a private-address
/// destination is rejected structurally (issue #25 path reuse).
async fn validate_client_keys(
    state: &OidcState,
    metadata: &serde_json::Map<String, Value>,
    auth_method: ClientAuthMethod,
) -> Result<(Option<String>, Option<String>), RegistrationError> {
    let jwks_value = metadata.get("jwks").filter(|value| !value.is_null());
    let jwks_uri = metadata
        .get("jwks_uri")
        .and_then(Value::as_str)
        .map(str::to_owned);

    if jwks_value.is_some() && jwks_uri.is_some() {
        return Err(RegistrationError::metadata(
            "jwks and jwks_uri are mutually exclusive",
        ));
    }

    // Only private_key_jwt consumes registered keys; for any other method they are
    // an unrecognized-for-this-method property, so they are ignored (RFC 7591).
    if auth_method != ClientAuthMethod::PrivateKeyJwt {
        return Ok((None, None));
    }

    if let Some(jwks_value) = jwks_value {
        let Some(object) = jwks_value.as_object() else {
            return Err(RegistrationError::metadata("jwks must be a JWK Set object"));
        };
        let serialized = Value::Object(object.clone()).to_string();
        if ironauth_jose::trusted_keys_from_jwks(serialized.as_bytes()).is_empty() {
            return Err(RegistrationError::metadata("jwks names no usable key"));
        }
        return Ok((Some(serialized), None));
    }

    if let Some(jwks_uri) = jwks_uri {
        // Fetch through the SSRF-hardened resolver (issue #25). An internal or
        // private-address destination is blocked and yields an empty key set; a
        // non-https or unreachable URL likewise yields none. Any of these is a
        // uniform rejection, so the endpoint reveals nothing about internal hosts.
        let Some(resolver) = state.client_key_resolver() else {
            return Err(RegistrationError::metadata(
                "jwks_uri registration is not available on this deployment",
            ));
        };
        let keys = resolver.resolve(state.now(), &jwks_uri).await;
        if keys.is_empty() {
            return Err(RegistrationError::metadata(
                "jwks_uri did not yield a usable key set",
            ));
        }
        return Ok((None, Some(jwks_uri)));
    }

    // private_key_jwt with neither source: a keyless client would authenticate
    // nothing. Reject at registration rather than store an inert client.
    Err(RegistrationError::metadata(
        "private_key_jwt requires jwks or jwks_uri",
    ))
}

/// Reject a metadata property that pins any value other than `only` (used for the
/// single-value `response_types`/`grant_types` this provider supports). An omitted
/// property is fine (the default applies); a present one must contain `only` and
/// nothing else.
fn check_only(
    metadata: &serde_json::Map<String, Value>,
    key: &str,
    only: &str,
) -> Result<(), RegistrationError> {
    let Some(value) = metadata.get(key) else {
        return Ok(());
    };
    let Some(values) = string_array(value) else {
        return Err(RegistrationError::metadata_owned(format!(
            "{key} must be an array of strings"
        )));
    };
    if values.is_empty() || values.iter().any(|entry| entry != only) {
        return Err(RegistrationError::metadata_owned(format!(
            "{key} supports only [\"{only}\"]"
        )));
    }
    Ok(())
}

/// A JSON value as a `Vec<String>` if it is an array whose every element is a
/// string, else `None`.
fn string_array(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|entry| entry.as_str().map(str::to_owned))
        .collect()
}

/// Whether the method mints and stores a client secret (`client_secret_basic` /
/// `client_secret_post`).
impl ClientAuthMethod {
    fn needs_secret(self) -> bool {
        matches!(self, ClientAuthMethod::Basic | ClientAuthMethod::Post)
    }
}

/// Generate a registration access token: 256 bits from the entropy seam, URL-safe
/// base64 (no padding). Only its hash is stored; this plaintext is returned once.
fn generate_registration_token(env: &Env) -> String {
    let mut bytes = [0_u8; REGISTRATION_TOKEN_BYTES];
    env.entropy().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Extract a `Bearer` token from the `Authorization` header (case-insensitive
/// scheme), or `None`.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_owned())
}

/// Build the shared client-metadata portion of a registration response from the
/// validated metadata (used by the register and update responses).
fn base_metadata(
    client_id: &str,
    issued_at: i64,
    validated: &ValidatedMetadata,
    registration_client_uri: &str,
) -> serde_json::Map<String, Value> {
    metadata_object(
        client_id,
        issued_at,
        &validated.display_name,
        validated.auth_method.as_str(),
        &validated.redirect_uris,
        &validated.application_type,
        &validated.id_token_signed_response_alg,
        validated.jwks.as_deref(),
        validated.jwks_uri.as_deref(),
        validated.token_endpoint_auth_signing_alg.as_deref(),
        registration_client_uri,
    )
}

/// Build the client-metadata portion of an RFC 7592 read response from the stored
/// record.
fn read_metadata(
    record: &DynamicClientRecord,
    issued_at: i64,
    registration_client_uri: &str,
) -> serde_json::Map<String, Value> {
    metadata_object(
        &record.id.to_string(),
        issued_at,
        &record.display_name,
        &record.auth_method,
        &record.redirect_uris,
        record.application_type.as_deref().unwrap_or("web"),
        record
            .id_token_signed_response_alg
            .as_deref()
            .unwrap_or(DEFAULT_ID_TOKEN_ALG),
        record.jwks.as_deref(),
        record.jwks_uri.as_deref(),
        record.token_endpoint_auth_signing_alg.as_deref(),
        registration_client_uri,
    )
}

/// The shared response object builder for the register, update, and read
/// responses. Never includes a credential (the caller adds the secret and/or the
/// registration access token where applicable).
#[allow(clippy::too_many_arguments)]
fn metadata_object(
    client_id: &str,
    issued_at: i64,
    display_name: &str,
    auth_method: &str,
    redirect_uris: &[String],
    application_type: &str,
    id_token_signed_response_alg: &str,
    jwks: Option<&str>,
    jwks_uri: Option<&str>,
    token_endpoint_auth_signing_alg: Option<&str>,
    registration_client_uri: &str,
) -> serde_json::Map<String, Value> {
    let mut object = serde_json::Map::new();
    object.insert("client_id".to_owned(), json!(client_id));
    object.insert("client_id_issued_at".to_owned(), json!(issued_at));
    object.insert("client_name".to_owned(), json!(display_name));
    object.insert("redirect_uris".to_owned(), json!(redirect_uris));
    object.insert("token_endpoint_auth_method".to_owned(), json!(auth_method));
    object.insert("grant_types".to_owned(), json!(["authorization_code"]));
    object.insert("response_types".to_owned(), json!(["code"]));
    object.insert("application_type".to_owned(), json!(application_type));
    object.insert(
        "id_token_signed_response_alg".to_owned(),
        json!(id_token_signed_response_alg),
    );
    if let Some(jwks_uri) = jwks_uri {
        object.insert("jwks_uri".to_owned(), json!(jwks_uri));
    }
    if let Some(jwks) = jwks {
        if let Ok(value) = serde_json::from_str::<Value>(jwks) {
            object.insert("jwks".to_owned(), value);
        }
    }
    if let Some(signing_alg) = token_endpoint_auth_signing_alg {
        object.insert(
            "token_endpoint_auth_signing_alg".to_owned(),
            json!(signing_alg),
        );
    }
    object.insert(
        "registration_client_uri".to_owned(),
        json!(registration_client_uri),
    );
    object
}

/// A validation failure, mapped to the RFC 7591 error object.
#[derive(Debug)]
enum RegistrationError {
    /// A metadata property is missing, malformed, or unsupported.
    InvalidClientMetadata(String),
    /// A `redirect_uri` is not a valid registrable target.
    InvalidRedirectUri(String),
}

impl RegistrationError {
    fn metadata(message: &'static str) -> Self {
        RegistrationError::InvalidClientMetadata(message.to_owned())
    }

    fn metadata_owned(message: String) -> Self {
        RegistrationError::InvalidClientMetadata(message)
    }

    fn redirect(message: &'static str) -> Self {
        RegistrationError::InvalidRedirectUri(message.to_owned())
    }
}

impl IntoResponse for RegistrationError {
    fn into_response(self) -> Response {
        match self {
            RegistrationError::InvalidClientMetadata(description) => {
                error_body("invalid_client_metadata", &description)
            }
            RegistrationError::InvalidRedirectUri(description) => {
                error_body("invalid_redirect_uri", &description)
            }
        }
    }
}

/// A 400 `invalid_client_metadata` error response.
fn metadata_error(description: &str) -> Response {
    error_body("invalid_client_metadata", description)
}

/// A 400 `invalid_redirect_uri` error response.
fn redirect_error(description: &str) -> Response {
    error_body("invalid_redirect_uri", description)
}

/// Build a 400 RFC 7591 error object with a `no-store` cache directive.
fn error_body(code: &str, description: &str) -> Response {
    let body = json!({ "error": code, "error_description": description }).to_string();
    (
        StatusCode::BAD_REQUEST,
        [
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        body,
    )
        .into_response()
}

/// A uniform 401 for an unauthenticated RFC 7592 request, with the RFC 6750
/// `WWW-Authenticate: Bearer` challenge and no oracle for which check failed.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (
                header::WWW_AUTHENTICATE,
                "Bearer error=\"invalid_token\"".to_owned(),
            ),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        "",
    )
        .into_response()
}

/// A 500 for an unexpected persistence fault, with no detail.
fn server_error() -> Response {
    let body = json!({ "error": "server_error" }).to_string();
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(header::CONTENT_TYPE, "application/json".to_owned())],
        body,
    )
        .into_response()
}

/// A success response carrying credentials: the JSON body, `Cache-Control:
/// no-store`, and `Pragma: no-cache`, so a response containing a secret or token is
/// never cached.
fn credential_response(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (header::CACHE_CONTROL, "no-store".to_owned()),
            (header::PRAGMA, "no-cache".to_owned()),
        ],
        body.to_string(),
    )
        .into_response()
}

/// Compare two byte strings in time independent of where they first differ. Both
/// operands here are fixed-length SHA-256 hex, so equal length is the normal path.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(json: &str) -> serde_json::Map<String, Value> {
        serde_json::from_str(json).expect("json object")
    }

    #[test]
    fn omitted_metadata_takes_the_spec_defaults() {
        let m = meta(r#"{"redirect_uris":["https://rp.example/cb"]}"#);
        assert_eq!(
            validate_auth_method(&m).expect("method"),
            ClientAuthMethod::Basic
        );
        assert_eq!(negotiate_id_token_alg(&m).expect("alg"), "RS256");
        // response_types / grant_types omitted is accepted (defaults apply).
        check_only(&m, "response_types", "code").expect("default response_types");
        check_only(&m, "grant_types", "authorization_code").expect("default grant_types");
    }

    #[test]
    fn client_secret_jwt_and_unknown_methods_are_rejected() {
        for method in ["client_secret_jwt", "tls_client_auth", "made_up"] {
            let m = meta(&format!(r#"{{"token_endpoint_auth_method":"{method}"}}"#));
            assert!(
                validate_auth_method(&m).is_err(),
                "{method} must be rejected"
            );
        }
        // The four advertised methods are accepted.
        for method in [
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "none",
        ] {
            let m = meta(&format!(r#"{{"token_endpoint_auth_method":"{method}"}}"#));
            assert!(validate_auth_method(&m).is_ok(), "{method} is supported");
        }
    }

    #[test]
    fn metadata_choices_prefer_eddsa_then_rs256() {
        // EdDSA offered alongside RS256: EdDSA wins.
        let m = meta(r#"{"id_token_signed_response_alg":["RS256","EdDSA"]}"#);
        assert_eq!(negotiate_id_token_alg(&m).expect("alg"), "EdDSA");
        // The plural RP Metadata Choices name works too.
        let m = meta(r#"{"id_token_signed_response_alg_values":["ES256","EdDSA"]}"#);
        assert_eq!(negotiate_id_token_alg(&m).expect("alg"), "EdDSA");
        // No EdDSA, RS256 present: RS256 wins over ES256.
        let m = meta(r#"{"id_token_signed_response_alg":["ES256","RS256"]}"#);
        assert_eq!(negotiate_id_token_alg(&m).expect("alg"), "RS256");
        // Neither EdDSA nor RS256: the first representable offered value.
        let m = meta(r#"{"id_token_signed_response_alg":["ES256","ES384"]}"#);
        assert_eq!(negotiate_id_token_alg(&m).expect("alg"), "ES256");
        // A single string value.
        let m = meta(r#"{"id_token_signed_response_alg":"RS512"}"#);
        assert_eq!(negotiate_id_token_alg(&m).expect("alg"), "RS512");
        // An offered set with nothing representable (ES512 is unrepresentable) is
        // rejected.
        let m = meta(r#"{"id_token_signed_response_alg":["ES512"]}"#);
        assert!(negotiate_id_token_alg(&m).is_err());
    }

    #[test]
    fn web_requires_https_native_allows_loopback_and_private_use() {
        // Web: https only.
        assert!(redirect_allowed("https://rp.example/cb", "web"));
        assert!(!redirect_allowed("http://127.0.0.1/cb", "web"));
        assert!(!redirect_allowed("com.example.app:/cb", "web"));
        // Native: https, http loopback IP literal, and reverse-domain private-use.
        assert!(redirect_allowed("https://rp.example/cb", "native"));
        assert!(redirect_allowed("http://127.0.0.1:52000/cb", "native"));
        assert!(redirect_allowed("http://[::1]/cb", "native"));
        assert!(redirect_allowed(
            "com.example.app:/oauth2redirect",
            "native"
        ));
        // Dangerous schemes are rejected for both types.
        for uri in [
            "javascript:alert(1)",
            "data:text/html,x",
            "http://evil.example/cb",
        ] {
            assert!(!redirect_allowed(uri, "native"), "{uri} rejected (native)");
            assert!(!redirect_allowed(uri, "web"), "{uri} rejected (web)");
        }
    }

    #[test]
    fn response_and_grant_types_must_match_the_supported_flow() {
        let ok = meta(r#"{"response_types":["code"],"grant_types":["authorization_code"]}"#);
        check_only(&ok, "response_types", "code").expect("code ok");
        check_only(&ok, "grant_types", "authorization_code").expect("authorization_code ok");

        let bad = meta(r#"{"response_types":["token"]}"#);
        assert!(check_only(&bad, "response_types", "code").is_err());
        let bad = meta(r#"{"grant_types":["client_credentials"]}"#);
        assert!(check_only(&bad, "grant_types", "authorization_code").is_err());
    }

    #[test]
    fn a_registration_token_is_url_safe_and_from_the_seam() {
        let (env, _) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 7);
        let token = generate_registration_token(&env);
        let decoded = URL_SAFE_NO_PAD.decode(&token).expect("url-safe base64");
        assert_eq!(decoded.len(), REGISTRATION_TOKEN_BYTES);
        assert!(
            token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "url-safe alphabet: {token}"
        );
    }

    #[test]
    fn constant_time_eq_matches_only_identical_equal_length_inputs() {
        assert!(constant_time_eq(b"abcd", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abce"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn bearer_token_parses_case_insensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer tok-123".parse().unwrap());
        assert_eq!(bearer_token(&headers).as_deref(), Some("tok-123"));
        headers.insert(header::AUTHORIZATION, "bEaReR  spaced ".parse().unwrap());
        assert_eq!(bearer_token(&headers).as_deref(), Some("spaced"));
        headers.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
    }
}
