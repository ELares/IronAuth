//! Starting a SAML sign-in: issue an `AuthnRequest` and send the browser to the identity
//! provider (issue #139).
//!
//! # What this closes
//!
//! Until now the assertion consumer service could only ever be reached IdP-initiated. Nothing
//! issued an `AuthnRequest`, so no outstanding request could exist, so a response naming one was
//! always `UnknownRequest` and only a connection with `allow_unsolicited = true` could get
//! anywhere -- exactly the mode #139 requires be off by default, and the one migration 0198
//! calls "the weaker defence".
//!
//! The outstanding request is the strong one, and this is where it comes from. The row is
//! written BEFORE the browser is sent anywhere, because a request the identity provider answers
//! and this deployment never recorded is a response that will be refused.
//!
//! # Signed by default, with no switch to turn it off
//!
//! #139 says `AuthnRequest`s are "signed by default". There is no per-connection toggle here and
//! that is deliberate: the signature costs one RSA operation on a redirect, an identity provider
//! that does not verify it ignores it, and a toggle would be a column whose OFF position is
//! strictly worse and which somebody would eventually set. What a connection can lack is a KEY,
//! and a connection with no key cannot start a flow -- it is told so, rather than falling back to
//! an unsigned request nobody asked for.
//!
//! # What the outstanding request does NOT prove
//!
//! It proves a response answers a request THIS DEPLOYMENT issued and has not spent. It does not
//! prove the browser presenting the response is the one the request was issued to, because this
//! endpoint is unauthenticated and sets no cookie: anybody can mint a request, answer it at the
//! identity provider as themselves, and auto-submit the result into somebody else's browser.
//! Closing that needs a browser binding, it lands with sign-in -- which is when a session first
//! depends on it -- and the cookie must be `SameSite=None; Secure`, because the response comes
//! back on a cross-site POST and a `Lax` one would not be sent.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse as _;
use axum::response::Response;
use ironauth_jose::{JwsAlgorithm, SigningKey};
use ironauth_saml::authn_request::{self, Request};
use ironauth_store::SamlConnectionId;
use serde::Deserialize;

use crate::interaction;
use crate::state::OidcState;
use crate::util::epoch_micros;
use crate::wellknown::parse_scope;

/// How long an outstanding request stays answerable.
///
/// FIVE MINUTES, which bounds how long a captured `AuthnRequest` is worth replaying and how long
/// a user may sit on the identity provider's login page. The ACS enforces it through the store's
/// own expiry predicate, so a longer window here is a longer window there.
///
/// NOT A COLUMN, unlike the assertion window. `clock_skew_secs` and `max_assertion_age_secs`
/// bound a document somebody ELSE wrote and so have to accommodate their clock; this bounds one
/// we wrote and hold the other end of, where there is nothing to accommodate.
const REQUEST_TTL_SECS: i64 = 300;

/// The largest `RelayState` migration 0198's column will hold.
///
/// THE COLUMN'S OWN BOUND, restated here because this is where a value is admitted. 0198 checks
/// `octet_length(relay_state) <= 1024`, so a longer one is a constraint violation at the insert
/// -- and on this endpoint that is a 500 for an unauthenticated caller who chose the length.
/// Refusing to record it is not a loss: an unrecorded return location lands the user on the
/// default page, which is what happens for a `return_to` that fails to parse anyway.
const MAX_RELAY_STATE_BYTES: usize = 1024;

/// The query this endpoint accepts.
#[derive(Deserialize)]
pub struct StartQuery {
    /// Where to return to after the sign-in completes.
    ///
    /// RECORDED, NEVER ECHOED. It is written into the outstanding-request row and comes back out
    /// of the store at the ACS; the copy that travels through the identity provider as
    /// `RelayState` is a convenience for the browser and is discarded on the way back. That is
    /// what stops the return location being something the round trip could change.
    return_to: Option<String>,
}

/// `GET /t/{tenant}/e/{environment}/saml/start/{connection}`: begin a SAML sign-in.
///
/// # Why a GET
///
/// It is a navigation, not a submission: the browser arrives here from a link or a redirect and
/// leaves with a `Location`. Nothing is authenticated, nothing is mutated on the caller's behalf,
/// and the one row written is a nonce this deployment issues to itself -- so the properties a
/// POST would buy do not apply, and requiring one would make the ordinary "sign in with SSO"
/// link impossible.
pub async fn start_get(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, connection)): Path<(String, String, String)>,
    Query(query): Query<StartQuery>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    let Ok(connection_id) = SamlConnectionId::parse_in_scope(&connection, &scope) else {
        return not_found();
    };

    let read = state.store().scoped(scope);
    let connection = match read.saml_connections().find_active(&connection_id).await {
        Ok(Some(connection)) => connection,
        Ok(None) => return not_found(),
        Err(_) => return server_error(),
    };
    let key = match read.saml_connections().active_sp_key(&connection_id).await {
        Ok(Some(key)) => key,
        // A CONNECTION WITH NO KEY CANNOT START A FLOW, and says so rather than sending an
        // unsigned request. The operator's next step is provisioning one and re-uploading their
        // metadata, which is a different action from anything else on this page.
        Ok(None) => {
            return refused(
                StatusCode::CONFLICT,
                "this connection has no signing key yet; provision one and upload the updated \
                 metadata to your identity provider",
            );
        }
        Err(_) => return server_error(),
    };
    let Ok(signing_key) = SigningKey::rsa_from_pkcs1_der(
        Some(key.id.to_string()),
        JwsAlgorithm::Rs256,
        key.material.expose(),
    ) else {
        // THE STORED KEY DID NOT LOAD, which is a row this deployment wrote and cannot use. It
        // is not the caller's fault and there is nothing they can do, so it is a 500 rather than
        // an explanation.
        return server_error();
    };

    // THE RETURN LOCATION IS VALIDATED BEFORE IT IS RECORDED, not when it is used, so a value
    // that could never be honoured is never written.
    //
    // THE VALIDATED VALUE IS THE ONE RECORDED, and an earlier version recorded the raw one.
    // `parse_resume` TRIMS before it checks, so a `return_to` wrapped in whitespace passed the
    // check while the untrimmed string went into the row and onto the wire -- validating one
    // string and using another, which is the shape every validation bypass has.
    //
    // AND IT IS BOUNDED HERE, because migration 0198 caps `relay_state` at 1024 bytes and a
    // longer value that parses is a database CHECK violation -- which this endpoint would
    // answer as a 500 on an unauthenticated GET, a fault a caller can trigger at will. The
    // bound is the column's, named once so the two cannot drift.
    let return_to = query
        .return_to
        .as_deref()
        .and_then(|value| interaction::parse_resume(Some(value)).map(|resume| resume.return_to))
        .filter(|value| value.len() <= MAX_RELAY_STATE_BYTES);

    let now_micros = epoch_micros(state.now());
    let request_id = format!("_{}", ironauth_store::CorrelationId::generate(state.env()));
    let issue_instant = rfc3339_utc(now_micros / 1_000_000);

    let xml = match authn_request::build(&Request {
        id: &request_id,
        issue_instant: &issue_instant,
        destination: &connection.idp_sso_url,
        issuer: &connection.sp_entity_id,
        assertion_consumer_service_url: &connection.acs_url,
        name_id_format: &connection.nameid_format,
    }) {
        Ok(xml) => xml,
        Err(error) => {
            tracing::warn!(
                target: "ironauth.saml",
                reason = %error,
                "a SAML connection could not be turned into an AuthnRequest",
            );
            return refused(
                StatusCode::CONFLICT,
                "this connection's configuration cannot be expressed as a SAML request",
            );
        }
    };

    // RECORDED BEFORE THE BROWSER IS SENT, and the order is the whole point: an `AuthnRequest`
    // the identity provider answers and this deployment never wrote down is a response the ACS
    // refuses as `UnknownRequest`. Writing after the redirect would be writing after the race.
    if read
        .saml_replay()
        .issue_request(
            &connection_id,
            &request_id,
            return_to.as_deref(),
            now_micros,
            now_micros + REQUEST_TTL_SECS * 1_000_000,
        )
        .await
        .is_err()
    {
        return server_error();
    }

    // NO RELAYSTATE ON THE WIRE, and its absence is the deliberate part. OASIS Bindings 3.4.3
    // says a `RelayState` MUST NOT exceed 80 bytes, and every value this endpoint could send is
    // an `/authorize?client_id=...` resume path that exceeds it before the query begins -- so
    // sending one would violate the binding on every request, and hand the identity provider a
    // return path that is this deployment's business.
    //
    // NOTHING IS LOST BY OMITTING IT. The return location is in the outstanding-request row,
    // which is where the ACS reads it from; the copy that travels through the browser was only
    // ever a convenience, and one the ACS deliberately discards.
    let Ok(redirect) = authn_request::redirect(&xml, None, &signing_key) else {
        return server_error();
    };

    // THE SEPARATOR DEPENDS ON THE CONFIGURED URL. An `idp_sso_url` may already carry a query --
    // ADFS deployments commonly do -- and appending `?` to one that does produces a URL the
    // identity provider reads as a single malformed parameter.
    let separator = if connection.idp_sso_url.contains('?') {
        '&'
    } else {
        '?'
    };
    let location = format!("{}{separator}{}", connection.idp_sso_url, redirect.query);
    (
        StatusCode::SEE_OTHER,
        [
            (axum::http::header::LOCATION, location),
            (axum::http::header::CACHE_CONTROL, "no-store".to_owned()),
        ],
    )
        .into_response()
}

/// `seconds` since the epoch as the `xsd:dateTime` SAML writes.
///
/// SPELLED OUT RATHER THAN PULLED IN. A date library on this path would be a dependency for one
/// format string, and the civil-from-days algorithm is short, exact, and has no locale, no
/// leap-second table and no parsing.
fn rfc3339_utc(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// An outcome page carrying `reason`, which is always a sentence written in this file.
fn refused(status: StatusCode, reason: &'static str) -> Response {
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Sign-in unavailable</title>\
         <p>This sign-in could not be started.</p><p>{reason}</p>"
    );
    (
        status,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        axum::response::Html(body),
    )
        .into_response()
}

/// A uniform not-found for an unreadable scope, an unparsable id, or a connection not serving.
fn not_found() -> Response {
    refused(StatusCode::NOT_FOUND, "no SAML connection is served here")
}

/// A generic failure that never says what broke.
fn server_error() -> Response {
    refused(
        StatusCode::INTERNAL_SERVER_ERROR,
        "this sign-in could not be started; try again",
    )
}

#[cfg(test)]
mod tests {
    use super::rfc3339_utc;

    #[test]
    fn the_issue_instant_is_the_datetime_saml_reads() {
        // THE FORMAT IS PART OF THE PROTOCOL: an identity provider parses this as an
        // `xsd:dateTime`, and a request it cannot read is a sign-in that never starts. Pinned at
        // a realistic instant, because a fixture at the epoch would leave the year, month and
        // day arithmetic exercised only at its degenerate values.
        assert_eq!(rfc3339_utc(1_767_225_600), "2026-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_767_225_599), "2025-12-31T23:59:59Z");
        // A LEAP DAY, which is where a civil-from-days implementation goes wrong if it is going
        // to: 2024 is a leap year, 1900 was not, 2000 was.
        assert_eq!(rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z");
    }
}
