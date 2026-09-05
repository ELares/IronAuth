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
//! # What the outstanding request does not prove on its own, and the cookie that closes it
//!
//! The row proves a response answers a request THIS DEPLOYMENT issued and has not spent. It does
//! NOT prove the browser presenting the response is the one the request was issued to: this
//! endpoint is unauthenticated, so anybody can mint a request, answer it at the identity
//! provider as themselves, capture the response, and auto-submit it into somebody else's
//! browser. Before sign-in that bought nothing, because the assertion consumer minted no
//! session; it does now, and the result would be a victim signed into the ATTACKER'S account.
//!
//! SO THIS ENDPOINT SETS A BINDING COOKIE, whose SHA-256 goes on the request row and which the
//! assertion consumer compares. `SameSite=None; Secure` is load-bearing rather than a
//! relaxation: the response arrives on a cross-site POST from the identity provider, and a `Lax`
//! cookie is simply not sent on one -- so a `Lax` binding would refuse every real login while
//! stopping nothing. What keeps that safe is that the cookie is not an authenticator: it carries
//! a nonce that means nothing except beside the one request whose digest it matches, it is
//! `HttpOnly`, and it dies with the request's own five-minute TTL.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse as _;
use axum::response::Response;
use ironauth_jose::{JwsAlgorithm, SigningKey};
use ironauth_saml::authn_request::{self, Redirect, Request};
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

/// The browser-binding cookie's name for one outstanding request (issue #139).
///
/// ONE COOKIE PER FLOW, NOT ONE PER HOST, and an earlier version used a single fixed name.
/// `__Host-` forbids a `Domain` and pins `Path=/`, so a fixed name is exactly ONE storage slot
/// per host: a second sign-in started anywhere on the deployment -- another tab, another
/// connection, another tenant -- overwrote the first flow's nonce. The first response then
/// arrived, spent its outstanding request and burned its assertion id in the store BEFORE the
/// transport compared cookies, and was refused with both already consumed. The user could not
/// retry: their request was gone. Two tabs is not an attack, it is Tuesday.
///
/// THE REQUEST ID IS IN THE NAME rather than the value, so the consumer can ask for the ONE
/// cookie belonging to the request the response names instead of guessing among several. Each
/// carries the request's own five-minute `Max-Age`, so the jar drains by itself.
///
/// SHARED WITH THE ASSERTION CONSUMER, which is the only other reader, so the two cannot drift
/// into setting one name and checking another -- a divergence that would refuse every solicited
/// login and read, from the outside, exactly like a broken identity provider.
pub(crate) fn binding_cookie_name(request_id: &str) -> String {
    format!("__Host-ironauth_saml_bind_{request_id}")
}

/// The largest `RelayState` migration 0198's column will hold.
///
/// A SECOND COPY OF THE COLUMN'S BOUND, and calling it "named once so the two cannot drift"
/// -- as an earlier version of the comment at the filter site did -- was false: this literal and
/// 0198's `octet_length(relay_state) <= 1024` are independent, and the migration is frozen by
/// checksum, so only this one can move. Nothing links them and nothing can: a test that read the
/// migration text would be asserting a claim about another file rather than a behaviour.
///
/// WHAT KEEPS THEM TOGETHER IS THE DIRECTION OF FAILURE. If this shrinks, a return location is
/// dropped that the column would have held -- a user lands on the default page. If it grows past
/// the column, the insert fails and an unauthenticated caller who chose the length gets a 500.
/// Only the second is a fault, and it is the one the suite drives, at a length over BOTH.
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
    let (signing_key, _stored) = match signing_key_for(&read, &connection_id).await {
        Ok(loaded) => loaded,
        // THE OPERATOR'S NEXT STEP IS PROVISIONING A KEY and re-uploading their metadata, which
        // is a different action from anything else on this page.
        Err(KeyUnavailable::NotProvisioned) => {
            return refused(
                StatusCode::CONFLICT,
                "this connection has no signing key yet; provision one and upload the updated \
                 metadata to your identity provider",
            );
        }
        // NOT THE CALLER'S FAULT AND NOTHING THEY CAN DO, so it is a 500 rather than an
        // explanation.
        Err(KeyUnavailable::Unusable) => return server_error(),
    };

    // THE RETURN LOCATION IS VALIDATED BEFORE IT IS RECORDED, not when it is used. That does not
    // make every recorded value honourable -- `parse_resume` proves the shape and the scope, not
    // that the client exists -- but it does mean a value of the wrong SHAPE or the wrong TENANT
    // is never written, which are the two a use site could not detect for itself.
    //
    // THE VALIDATED VALUE IS THE ONE RECORDED, and an earlier version recorded the raw one.
    // `parse_resume` TRIMS before it checks, so a `return_to` wrapped in whitespace passed the
    // check while the untrimmed string went into the row and onto the wire -- validating one
    // string and using another, which is the shape every validation bypass has.
    //
    // AND IT IS BOUNDED HERE, because migration 0198 caps `relay_state` at 1024 bytes and a
    // longer value that parses is a database CHECK violation -- which this endpoint would
    // answer as a 500 on an unauthenticated GET, a fault a caller can trigger at will. The
    // bound is the column's; see the constant for why the two copies cannot be linked.
    // AND THE RESUME'S SCOPE MUST BE THIS ROUTE'S. `parse_resume` RECOVERS a scope by decoding
    // it out of the client id's bytes; it performs no existence check and knows nothing about
    // where it was called from, so every well-formed `cli_` from every tenant parses. The
    // unscoped interaction routes can stop there because they DERIVE their scope from the
    // resume; this one is path-scoped, and the path-scoped sites that compare are `federation`,
    // `flow`, `flow::orchestration`, `flow::consent` and `webauthn`. The census is not a clean
    // majority and saying so is more useful than a tidy number: `flow::signup_fields` and
    // `broker_overlay` are path-scoped and do NOT compare, which is either two more instances of
    // this defect or two places where the recovered scope is never acted on. Neither is this
    // change's to settle, and both are why the argument here rests on what the comparison BUYS
    // rather than on how many neighbours have it.
    //
    // WHAT IT BUYS is narrower than "a value that could never be honoured is never written":
    // `parse_resume` performs no existence check, so a well-formed client id for a client that
    // does not exist still passes, in this scope or any other. What the comparison removes is
    // the CROSS-TENANT case -- a row of this tenant's recording another tenant's authorization
    // path -- which is the half that is a boundary violation rather than a dangling link.
    let return_to = query
        .return_to
        .as_deref()
        .and_then(|value| interaction::parse_resume(Some(value)))
        .filter(|resume| resume.scope == scope)
        .map(|resume| resume.return_to)
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

    // NO RELAYSTATE ON THE WIRE, and its absence is the deliberate part. OASIS Bindings 3.4.3
    // says a `RelayState` MUST NOT exceed 80 bytes, and the SHORTEST value this endpoint could
    // send is already 89: `parse_resume` requires the literal `/authorize?` (11) plus
    // `client_id=` (10) plus a scoped client id, which is `cli_` and 64 base64url characters
    // (68). An earlier version of this comment said the path "exceeds it before the query
    // begins", which is wrong -- `/authorize?` is 11 bytes -- and reached the right conclusion
    // by leaving out the id that does the exceeding. Every real value is longer still.
    //
    // AND THE LENGTH IS NOT THE ONLY REASON: sending one hands the identity provider a return
    // path that is this deployment's business.
    //
    // NOTHING IS LOST BY OMITTING IT. The return location is in the outstanding-request row,
    // which is where the ACS reads it from; the copy that travels through the browser was only
    // ever a convenience, and one the ACS deliberately discards.
    let Ok(redirect) = authn_request::redirect(&xml, None, &signing_key) else {
        return server_error();
    };

    // THE REDIRECT IS BUILT BEFORE THE ROW IS WRITTEN, which is not the same as sending it
    // first. `idp_sso_url` is constrained by 0196 to non-empty and 2048 bytes and nothing else,
    // so it may hold an LF, a CR or a DEL -- `escape` turns the first two into numeric
    // references for the DOCUMENT, and none of the three can appear in a `Location` header
    // value. Assembling the header after the insert meant a connection with such a URL wrote a
    // row it could never answer and returned a 500, once per attempt, forever.
    let Ok(location) =
        axum::http::HeaderValue::from_str(&redirect_location(&connection, &redirect))
    else {
        tracing::warn!(
            target: "ironauth.saml",
            "a SAML connection's idp_sso_url cannot be sent as a Location header",
        );
        return refused(
            StatusCode::CONFLICT,
            "this connection's identity provider URL cannot be used as a redirect target",
        );
    };

    // AND ONLY THEN IS THE REQUEST RECORDED, which is the order that matters against the
    // network: an `AuthnRequest` the identity provider answers and this deployment never wrote
    // down is a response the ACS refuses as `UnknownRequest`. Nothing between here and the
    // response can fail.
    // THE BINDING NONCE IS MINTED BEFORE THE ROW IS WRITTEN, so a row can never exist with a
    // digest whose nonce was never sent: the cookie and the column are set from one value in one
    // response, and a failure to write the row returns before either reaches the browser.
    let (nonce, digest) = mint_binding(&state);

    if read
        .saml_replay()
        .issue_request(
            &connection_id,
            &request_id,
            return_to.as_deref(),
            Some(&digest),
            now_micros,
            now_micros + REQUEST_TTL_SECS * 1_000_000,
        )
        .await
        .is_err()
    {
        return server_error();
    }

    started(location, &request_id, &nonce)
}

/// The redirect that starts a flow: the identity provider's URL and the binding cookie.
///
/// SPLIT OUT SO `start_get` STAYS READABLE, and because the three headers are one decision --
/// where the browser goes, that the answer is never cached, and the binding it must carry back.
fn started(location: axum::http::HeaderValue, request_id: &str, nonce: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            (axum::http::header::LOCATION, location),
            (
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            ),
            (
                axum::http::header::SET_COOKIE,
                binding_cookie(request_id, nonce)
                    .parse()
                    .unwrap_or_else(|_| {
                        axum::http::HeaderValue::from_static("__Host-ironauth_saml_bind_x=")
                    }),
            ),
        ],
    )
        .into_response()
}

/// A fresh binding nonce and the digest that goes on the request row.
///
/// 32 BYTES FROM THE ENTROPY SEAM, which is the same source every other unguessable value in
/// this crate comes from, and base64url so the value is cookie-safe without escaping.
fn mint_binding(state: &OidcState) -> (String, Vec<u8>) {
    let mut nonce_bytes = [0_u8; 32];
    state.env().entropy().fill_bytes(&mut nonce_bytes);
    let nonce = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes)
    };
    let digest = {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(nonce.as_bytes()).to_vec()
    };
    (nonce, digest)
}

/// The browser-binding cookie carrying `nonce`.
///
/// EVERY ATTRIBUTE IS DOING SOMETHING.
///
/// `__Host-` fixes the cookie to this exact origin with `Path=/` and no `Domain`, so a sibling
/// subdomain -- a customer-controlled one, in a deployment that has any -- cannot write a
/// binding this deployment would then accept.
///
/// `SameSite=None` is what makes it ARRIVE. The identity provider's auto-submitting form is a
/// cross-site POST, and a `Lax` cookie is not sent on one; a `Lax` binding would refuse every
/// genuine login and stop nothing. `Secure` is mandatory alongside it and is required by
/// `__Host-` anyway.
///
/// `HttpOnly` keeps script from reading the nonce, and `Max-Age` matches the request's own TTL
/// so a cookie cannot outlive the row it is the key to.
fn binding_cookie(request_id: &str, nonce: &str) -> String {
    format!(
        "{}={nonce}; Path=/; Max-Age={REQUEST_TTL_SECS}; Secure; HttpOnly; SameSite=None",
        binding_cookie_name(request_id)
    )
}

/// Why a connection's signing key could not be loaded.
///
/// AN OUTCOME RATHER THAN A RENDERED PAGE, WHICH IS A CORRECTION. An earlier version returned the
/// `Response` itself, and its doc argued that keeping every sentence in one place was the point.
/// The sentences were written for the START route, so once the metadata route shared this step a
/// failed metadata fetch answered "Sign-in unavailable" and advised re-uploading the metadata the
/// operator was at that moment trying to fetch. The shared step decides WHICH outcome; each route
/// says what that outcome means where it is.
pub(crate) enum KeyUnavailable {
    /// No key is provisioned for this connection. The operator can act on this.
    NotProvisioned,
    /// The key could not be produced: the read failed, or the row named an algorithm this build
    /// does not know, or its material did not load. THREE CAUSES, NOT THE TWO AN EARLIER VERSION
    /// of this doc listed -- it omitted the store read, which is the one that is not the
    /// operator's doing at all. They collapse to one variant because they collapse to one
    /// answer: there is nothing the caller can do about any of them, and saying which would
    /// describe this deployment's internals to an unauthenticated fetch.
    Unusable,
}

/// Load the key this connection signs with, or why it cannot be.
///
/// SPLIT OUT BECAUSE IT IS THE ONE STEP WITH THREE OUTCOMES -- a key, a connection that has none
/// yet, and a row this build cannot load -- and because both routes that need a key need the same
/// three.
pub(crate) async fn signing_key_for(
    read: &ironauth_store::ScopedStore<'_>,
    connection_id: &SamlConnectionId,
) -> Result<(SigningKey, ironauth_store::SamlSpKey), KeyUnavailable> {
    let key = match read.saml_connections().active_sp_key(connection_id).await {
        Ok(Some(key)) => key,
        // A CONNECTION WITH NO KEY CANNOT START A FLOW, and says so rather than sending an
        // unsigned request.
        Ok(None) => return Err(KeyUnavailable::NotProvisioned),
        Err(_) => return Err(KeyUnavailable::Unusable),
    };
    // THE ALGORITHM COMES FROM THE ROW, and an earlier version hardcoded `Rs256` here while
    // `redirect` derived `SigAlg` from the key -- which made "SigAlg comes from the key" a
    // tautology and left the `algorithm` column reading, as before, nothing at all. The column
    // is the operator-visible fact; this is where it becomes the key's.
    let Some(algorithm) = jws_algorithm_for(&key.algorithm) else {
        // A ROW NAMING AN ALGORITHM THIS BUILD CANNOT LOAD. The column's CHECK admits one value
        // today, so this is schema drift rather than configuration.
        return Err(KeyUnavailable::Unusable);
    };
    let Ok(signing_key) =
        SigningKey::rsa_from_pkcs1_der(Some(key.id.to_string()), algorithm, key.material.expose())
    else {
        // THE STORED KEY DID NOT LOAD, which is a row this deployment wrote and cannot use.
        return Err(KeyUnavailable::Unusable);
    };

    // THE ROW COMES BACK WITH THE KEY, so a caller needing a fact about the key -- its creation
    // instant, its id -- reads no second time. Two reads are two answers to "which key does this
    // connection sign with", and a rotation between them publishes a mismatched pair.
    Ok((signing_key, key))
}

/// The absolute URL to send the browser to.
///
/// THE SEPARATOR DEPENDS ON THE CONFIGURED URL. An `idp_sso_url` may already carry a query --
/// ADFS deployments commonly do -- and appending `?` to one that does produces a URL the
/// identity provider reads as a single malformed parameter.
fn redirect_location(connection: &ironauth_store::SamlConnection, redirect: &Redirect) -> String {
    let separator = if connection.idp_sso_url.contains('?') {
        '&'
    } else {
        '?'
    };
    format!("{}{separator}{}", connection.idp_sso_url, redirect.query)
}

/// The JOSE algorithm a stored `algorithm` fragment names, if this build has one for it.
///
/// THE TRANSLATION IS EXPLICIT AND TOTAL, rather than a parse or a default: the column holds
/// XML-Signature's spelling (`rsa-sha256`) because that is what an operator sees in their
/// identity provider, and this crate signs by JOSE name. A row naming something this build has
/// no signer for answers `None` and is refused.
///
/// WHAT THAT PREVENTS is not a mismatched announcement -- `redirect` derives `SigAlg` from the
/// key it is handed, so the URI and the signature cannot disagree. It is a row this build cannot
/// honour being treated as one it can: without the lookup the loader would have to assume an
/// algorithm, and assuming RSA for a row that says something else signs with a key the operator
/// did not configure for the purpose.
///
/// READING THE COLUMN IS NOT YET DISTINGUISHABLE FROM A CONSTANT, and that is worth admitting
/// rather than claiming as coverage: 0199's CHECK admits `rsa-sha256` and nothing else, so no
/// row can disagree with the literal, and replacing `key.algorithm` here with `"rsa-sha256"`
/// passes every test. The unit test below measures the MAPPING, which is the half that can be
/// wrong today. The half that cannot be measured until a second algorithm exists is that the
/// caller passes the row -- and it is written this way now so that adding one is a migration and
/// TWO match arms: this one, and `ironauth-saml`'s `SigAlg` mapping, which turns the JOSE name
/// back into the XML-Signature URI that goes on the wire. Naming both is the point; an earlier
/// version said "a match arm, not a hunt for a hardcode" and left the second site unmentioned,
/// which is the hunt it was claiming to have prevented.
fn jws_algorithm_for(algorithm: &str) -> Option<JwsAlgorithm> {
    match algorithm {
        "rsa-sha256" => Some(JwsAlgorithm::Rs256),
        _ => None,
    }
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
    fn the_algorithm_column_maps_to_one_jose_name_and_nothing_else() {
        use super::jws_algorithm_for;
        use ironauth_jose::JwsAlgorithm;

        // THE HALF THAT CAN BE WRONG TODAY. The column is single-valued by CHECK, so no
        // integration test can tell a read from a constant; what it CAN tell is whether the one
        // value maps to the right signer, and whether anything else is refused rather than
        // defaulted. A default here would sign with RSA whatever the row said.
        assert_eq!(jws_algorithm_for("rsa-sha256"), Some(JwsAlgorithm::Rs256));
        for unknown in [
            "",
            "rsa-sha1",
            "RSA-SHA256",
            "ecdsa-sha256",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        ] {
            assert_eq!(
                jws_algorithm_for(unknown),
                None,
                "{unknown} was accepted as an algorithm"
            );
        }
    }

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
