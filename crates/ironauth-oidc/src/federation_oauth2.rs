// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OAuth 2.0 (non-OIDC) federated login path (issue #74), for an upstream like GitHub
//! that issues NO ID token.
//!
//! GitHub is a plain OAuth 2.0 code grant: the token endpoint returns an ACCESS TOKEN, not
//! an ID token, so there is no signed identity to validate. The identity is instead read
//! from the provider's PROFILE endpoint over TLS with the access token, and because the
//! profile may omit a usable email, the PRIMARY VERIFIED email is resolved from the
//! provider's email endpoint (the documented GitHub quirk handler). The identity is keyed on
//! the STABLE numeric GitHub `id` (namespaced by the connector's `identity_issuer`), never
//! the mutable `login` or email.
//!
//! # Design decision (flagged): the `oauth2` protocol variant
//!
//! GitHub does not fit the OIDC framework's ID-token spine, so rather than bolt it on as a
//! quirk that fakes a JWKS and bypasses ID-token validation, it is modeled as a first-class
//! [`Protocol::Oauth2`](ironauth_connector::Protocol::Oauth2) connector with its own
//! [`OAuth2Endpoints`](ironauth_connector::OAuth2Endpoints). The identity comes from the
//! profile response over the hardened fetch path; the honest model keeps the security-
//! critical OIDC ID-token validation from ever running on a protocol that has no ID token.
//!
//! Every outbound call here (token exchange, profile, email) rides the ONE SSRF-hardened
//! `ironauth_fetch::Fetcher`, so a profile or email URL that resolves to an internal address
//! is blocked on the wire exactly like every other federation fetch.

use std::time::SystemTime;

use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::response::Response;
use ironauth_connector::{ConnectorError, ConnectorRuntimeConfig, OAuth2Endpoints};
use ironauth_fetch::{FetchPurpose, FetchRequest};
use ironauth_store::Scope;

use crate::federation::{
    FederationRuntime, FinalizeLogin, VerifiedUpstreamIdentity, classify_upstream_status,
    federation_callback_url, finalize_federated_login,
};
use crate::interaction;
use crate::state::OidcState;
use crate::util::percent_encode_query;

/// The inputs the OAuth 2.0 callback needs, threaded from the dispatching federation callback
/// (issue #74). Bundled to keep the argument count readable.
pub(crate) struct Oauth2Callback<'a> {
    /// The OIDC application state.
    pub state: &'a OidcState,
    /// The tenant/environment scope.
    pub scope: Scope,
    /// The installed federation runtime (hardened fetcher and health registry).
    pub runtime: &'a FederationRuntime,
    /// The connector's health-registry key (its immutable id as a string).
    pub connector_key: &'a str,
    /// The connector's per-environment slug.
    pub connector_slug: &'a str,
    /// The route tenant id (for the redirect URI).
    pub tenant_id: &'a str,
    /// The route environment id (for the redirect URI).
    pub environment_id: &'a str,
    /// The connector-definition fingerprint for the per-connector health record.
    pub fingerprint: i64,
    /// The connector's OAuth 2.0 endpoint set.
    pub endpoints: &'a OAuth2Endpoints,
    /// The connector's secret-free runtime config (claim mapping and quirks).
    pub definition: &'a ConnectorRuntimeConfig,
    /// The connector's unsealed static client secret.
    pub client_secret: &'a [u8],
    /// The authorization code returned to the callback.
    pub code: &'a str,
    /// The inbound request headers (for the session cookie binding).
    pub headers: &'a HeaderMap,
    /// The pending LOCAL authorization request to resume.
    pub return_to: &'a str,
    /// The callback instant from the clock seam.
    pub now: SystemTime,
    /// The callback instant in epoch microseconds.
    pub now_micros: i64,
}

/// Complete an OAuth 2.0 (non-OIDC) federated login (issue #74): exchange the code for an
/// access token, read the profile, resolve the primary verified email, and finalize through
/// the shared provisioning path. Any upstream failure fails the login WITHOUT provisioning a
/// user and is recorded against the connector's health (issue #76).
pub(crate) async fn oauth2_callback(cb: Oauth2Callback<'_>) -> Response {
    let redirect_uri =
        federation_callback_url(cb.state, cb.tenant_id, cb.environment_id, cb.connector_slug);
    let allow_http = cb.runtime.allow_http();

    // The static client secret authenticates the exchange (GitHub uses no signed assertion).
    let Ok(client_secret) = std::str::from_utf8(cb.client_secret) else {
        return interaction::server_error_page();
    };

    let access_token =
        match exchange_code_for_access_token(&cb, &redirect_uri, client_secret, allow_http).await {
            Ok(token) => token,
            Err(error) => {
                cb.runtime.health().record_failure(
                    cb.now,
                    cb.connector_key,
                    cb.fingerprint,
                    &error,
                );
                return interaction::server_error_page();
            }
        };

    let identity = match resolve_identity(&cb, &access_token, allow_http).await {
        Ok(identity) => identity,
        Err(error) => {
            cb.runtime
                .health()
                .record_failure(cb.now, cb.connector_key, cb.fingerprint, &error);
            return interaction::server_error_page();
        }
    };

    // Finalize through the SHARED path: claim mapping (fail-closed), provisioning keyed on the
    // stable `(identity_issuer, id)` composite, the honest federated session, and the resume.
    finalize_federated_login(FinalizeLogin {
        state: cb.state,
        scope: cb.scope,
        runtime: cb.runtime,
        connector_slug: cb.connector_slug,
        connector_key: cb.connector_key,
        fingerprint: cb.fingerprint,
        issuer: &cb.endpoints.identity_issuer,
        definition: cb.definition,
        identity: &identity,
        headers: cb.headers,
        return_to: cb.return_to,
        now: cb.now,
        now_micros: cb.now_micros,
    })
    .await
}

/// Exchange the authorization code at the OAuth 2.0 token endpoint and return the access token.
/// The request asks for a JSON response (GitHub otherwise form-encodes) and rides the
/// hardened fetcher through [`FetchPurpose::FederationToken`].
async fn exchange_code_for_access_token(
    cb: &Oauth2Callback<'_>,
    redirect_uri: &str,
    client_secret: &str,
    allow_http: bool,
) -> Result<String, ConnectorError> {
    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}",
        percent_encode_query(cb.code),
        percent_encode_query(redirect_uri),
        percent_encode_query(&cb.definition.client_id),
        percent_encode_query(client_secret),
    );
    let mut request = FetchRequest::new(
        FetchPurpose::FederationToken,
        Method::POST,
        cb.endpoints.token_endpoint.clone(),
    )
    .header(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    )
    .header(header::ACCEPT, HeaderValue::from_static("application/json"))
    .body(form.into_bytes());
    if allow_http {
        request = request.allow_plaintext_http();
    }
    let response = cb
        .runtime
        .fetcher()
        .fetch(request)
        .await
        .map_err(|err| ConnectorError::UpstreamUnavailable(err.to_string()))?;
    if !response.status().is_success() {
        return Err(classify_upstream_status(
            response.status(),
            "the token endpoint",
        ));
    }
    let body: serde_json::Value = serde_json::from_slice(response.body()).map_err(|_| {
        ConnectorError::UpstreamProtocol("the token response is not JSON".to_owned())
    })?;
    body.get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            ConnectorError::UpstreamProtocol(
                "the token response carried no access_token".to_owned(),
            )
        })
}

/// Read the profile and resolve the primary verified email, building the verified upstream
/// identity (issue #74). The identity is keyed on the stable numeric `id`.
async fn resolve_identity(
    cb: &Oauth2Callback<'_>,
    access_token: &str,
    allow_http: bool,
) -> Result<VerifiedUpstreamIdentity, ConnectorError> {
    let profile = fetch_json(
        cb,
        &cb.endpoints.profile_endpoint,
        access_token,
        allow_http,
        "the profile endpoint",
    )
    .await?;
    let profile = profile.as_object().ok_or_else(|| {
        ConnectorError::UpstreamProtocol("the profile response is not a JSON object".to_owned())
    })?;

    // The STABLE numeric id is the subject (never the mutable login or email). GitHub returns
    // it as a JSON number; it is rendered as a string for the issuer-namespaced identity key.
    let subject = profile
        .get("id")
        .and_then(json_id_to_string)
        .ok_or_else(|| {
            ConnectorError::UpstreamProtocol("the profile carried no stable numeric id".to_owned())
        })?;
    let login = profile.get("login").and_then(|v| v.as_str());
    let name = profile
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    // Resolve the email: prefer the primary VERIFIED email from the email endpoint (the
    // authoritative, verified source), since the profile email may be absent or unverified.
    // Fall back to a non-null profile email only when the connector configures no email
    // endpoint.
    let email = match &cb.endpoints.email_endpoint {
        Some(email_endpoint) => {
            let emails = fetch_json(
                cb,
                email_endpoint,
                access_token,
                allow_http,
                "the email endpoint",
            )
            .await?;
            resolve_primary_verified_email(&emails).ok_or_else(|| {
                ConnectorError::UpstreamProtocol(
                    "no primary verified email was available from the email endpoint".to_owned(),
                )
            })?
        }
        None => profile
            .get("email")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                ConnectorError::UpstreamProtocol("the profile carried no usable email".to_owned())
            })?,
    };

    // Assemble the synthetic claim set the declarative claim mapping resolves against: the
    // stable id as `sub`, the resolved email, and the optional login and name.
    let mut claims = serde_json::Map::new();
    claims.insert("sub".to_owned(), serde_json::Value::String(subject.clone()));
    claims.insert("email".to_owned(), serde_json::Value::String(email.clone()));
    if let Some(login) = login {
        claims.insert(
            "login".to_owned(),
            serde_json::Value::String(login.to_owned()),
        );
    }
    if let Some(name) = name {
        claims.insert(
            "name".to_owned(),
            serde_json::Value::String(name.to_owned()),
        );
    }

    Ok(VerifiedUpstreamIdentity {
        subject,
        email: Some(email),
        upstream_amr: Vec::new(),
        upstream_acr: None,
        auth_time_secs: None,
        claims,
    })
}

/// GET a JSON document from an OAuth 2.0 upstream endpoint with the bearer access token, riding
/// the hardened fetcher through [`FetchPurpose::FederationUserinfo`]. A `User-Agent` is sent
/// because some providers (GitHub) reject a request without one.
async fn fetch_json(
    cb: &Oauth2Callback<'_>,
    url: &str,
    access_token: &str,
    allow_http: bool,
    context: &str,
) -> Result<serde_json::Value, ConnectorError> {
    let authorization = HeaderValue::try_from(format!("Bearer {access_token}"))
        .map_err(|_| ConnectorError::Config("the access token is not a valid header".to_owned()))?;
    let mut request = FetchRequest::new(
        FetchPurpose::FederationUserinfo,
        Method::GET,
        url.to_owned(),
    )
    .header(header::AUTHORIZATION, authorization)
    .header(header::ACCEPT, HeaderValue::from_static("application/json"))
    .header(header::USER_AGENT, HeaderValue::from_static("IronAuth"));
    if allow_http {
        request = request.allow_plaintext_http();
    }
    let response = cb
        .runtime
        .fetcher()
        .fetch(request)
        .await
        .map_err(|err| ConnectorError::UpstreamUnavailable(err.to_string()))?;
    if !response.status().is_success() {
        return Err(classify_upstream_status(response.status(), context));
    }
    serde_json::from_slice(response.body())
        .map_err(|_| ConnectorError::UpstreamProtocol(format!("{context} response is not JSON")))
}

/// Render a JSON `id` (a number, or a string of digits) as a stable subject string.
fn json_id_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Resolve the PRIMARY VERIFIED email from a GitHub-style `/user/emails` array (issue #74):
/// the entry that is both `primary` and `verified`, else the first `verified` entry, else
/// [`None`]. A non-verified email is NEVER selected (the login has no honest verified email).
///
/// This is the documented GitHub email-resolution quirk handler, kept pure so it is directly
/// unit-testable.
#[must_use]
pub fn resolve_primary_verified_email(emails: &serde_json::Value) -> Option<String> {
    let array = emails.as_array()?;
    let mut first_verified: Option<String> = None;
    for entry in array {
        let object = entry.as_object()?;
        let verified = object.get("verified").and_then(serde_json::Value::as_bool) == Some(true);
        if !verified {
            continue;
        }
        let Some(email) = object.get("email").and_then(|v| v.as_str()) else {
            continue;
        };
        let primary = object.get("primary").and_then(serde_json::Value::as_bool) == Some(true);
        if primary {
            return Some(email.to_owned());
        }
        if first_verified.is_none() {
            first_verified = Some(email.to_owned());
        }
    }
    first_verified
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_primary_verified_email_is_resolved() {
        let emails = serde_json::json!([
            { "email": "old@example.test", "primary": false, "verified": true },
            { "email": "primary@example.test", "primary": true, "verified": true },
            { "email": "unverified@example.test", "primary": false, "verified": false },
        ]);
        assert_eq!(
            resolve_primary_verified_email(&emails).as_deref(),
            Some("primary@example.test")
        );
    }

    #[test]
    fn a_verified_non_primary_is_used_when_no_verified_primary_exists() {
        let emails = serde_json::json!([
            { "email": "primary@example.test", "primary": true, "verified": false },
            { "email": "verified@example.test", "primary": false, "verified": true },
        ]);
        assert_eq!(
            resolve_primary_verified_email(&emails).as_deref(),
            Some("verified@example.test")
        );
    }

    #[test]
    fn an_unverified_only_set_resolves_no_email() {
        let emails = serde_json::json!([
            { "email": "primary@example.test", "primary": true, "verified": false },
        ]);
        assert_eq!(resolve_primary_verified_email(&emails), None);
    }

    #[test]
    fn a_non_array_resolves_no_email() {
        assert_eq!(resolve_primary_verified_email(&serde_json::json!({})), None);
    }

    #[test]
    fn a_numeric_id_renders_as_a_string_subject() {
        assert_eq!(
            json_id_to_string(&serde_json::json!(1_234_567_u64)).as_deref(),
            Some("1234567")
        );
        assert_eq!(json_id_to_string(&serde_json::json!(null)), None);
    }
}
