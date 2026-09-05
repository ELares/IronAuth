//! The SAML HTTP POST binding: the endpoint an identity provider posts a response to (#139).
//!
//! # What this is, and what [`crate::saml_acs`] is
//!
//! `saml_acs` is the PROTOCOL: verify a response against the connection's pinned certificates,
//! check every condition, spend the outstanding request and admit the assertion id, in that
//! order. It takes bytes and a connection row and touches no HTTP. This module is the
//! TRANSPORT around it: which connection a request is for, how the bytes arrive, and what the
//! poster is told afterwards. WHO THE `NameID` NAMES LOCALLY IS NOT ITS JOB -- that sentence
//! survived from a version that resolved identities, and the section below says why it no
//! longer does.
//!
//! Splitting them is not tidiness. The protocol half is the part with the CVEs in it, and it is
//! testable with no server at all -- which is how it came to have twenty-three tests against a
//! real database before any route existed.
//!
//! # The connection is named by the URL, never by the document
//!
//! The path carries the `smc_` connection id, so the response is checked against the trust
//! anchors, audience and recipient of the connection the IDENTITY PROVIDER WAS TOLD TO POST TO.
//! The obvious alternative -- one endpoint per environment, resolving the connection from the
//! response's `Issuer` -- lets the document choose which trust anchors it is checked against,
//! which is CVE-2026-9090 moved up one layer: an attacker with a signature valid for ANY
//! connection in the environment picks the one whose audience and certificates suit them.
//!
//! It also means the ACS URL an operator pastes into Okta is per connection, which is what SP
//! metadata generation will emit, and what the `acs_url` column already holds.
//!
//! # This endpoint signs somebody in, and it took four objections to earn the right
//!
//! AN EARLIER VERSION OF THIS SECTION SAID THE OPPOSITE, and the sentence "this endpoint does
//! not sign anybody in, and that is the point of this change" was true of the change it was
//! written for. It is not true now: the handoff at the end of `acs_post` establishes a session.
//! The four objections that took the FIRST attempt apart are kept below because each is a
//! constraint the current one satisfies, and [`crate::saml_signin`] answers them one by one.
//! Read them as the specification they became rather than as a list of reasons not to.
//!
//! 1. IT CROSSED ORGANIZATIONS. A `SamlConnection` carries an `organization_id`, and migration
//!    0196 says why: "a trust anchor that reached two organizations would let one customer's
//!    identity provider assert another customer's users." The identifier seam resolves per
//!    ENVIRONMENT, so any identity provider with a key pinned anywhere in the environment could
//!    have minted a session for any account in it.
//! 2. IT BYPASSED THE CRATE'S OWN ANTI-TAKEOVER GATE. `account_linking` returns `AutoLink` from
//!    exactly one arm of an exhaustive match, requiring an environment posture that is off by
//!    default, a server-verified local address, an upstream that asserts verification, and a
//!    connector marked trusted. The federated OIDC callback consults it on every login. Minting
//!    a session on "a verified identifier exists" answers a question that module already owns,
//!    and answers it differently.
//! 3. THE POPULATION IT NAMED COULD NOT USE IT. Requiring a VERIFIED identifier is right, and
//!    the SCIM inbound server in this same milestone deliberately writes `verified: false` --
//!    "a provisioning system asserts that a person exists in its directory", which is not the
//!    same as proving the address. So it would have signed in exactly none of the accounts it
//!    existed to serve.
//! 4. ITS ONLY REACHABLE MODE WAS THE ONE #139 REQUIRES OFF. Nothing in production issues a SAML
//!    `AuthnRequest` yet, so no outstanding request can exist, so a solicited response is always
//!    `UnknownRequest` and only `allow_unsolicited = true` could ever succeed.
//!
//! WHAT STILL BELONGS TO THIS MODULE is the binding itself: a response arrives, is verified
//! against the right connection, and is either consumed or refused with a typed reason. That is
//! the surface #139 asks for when it says failures must "surface as typed connection-test
//! failures ... so the test-connection flow can render actionable messages", and it is what an
//! operator points Okta at to find out whether their certificate and audience are right. What
//! happens AFTER a response is consumed is `saml_signin`'s, and the split is the same one this
//! section opens with: protocol, transport, then identity.
//!
//! # There is no CSRF check here, deliberately
//!
//! Most browser-facing POSTs in this crate begin with a same-origin check. This one must not:
//! the HTTP POST binding IS a cross-site form submission, auto-submitted by a page the identity
//! provider served, so a same-origin check would refuse every real response.
//!
//! WHAT MAKES THAT SAFE TODAY IS THAT NOTHING IS AUTHENTICATED HERE. A cross-site POST reaches a
//! signature check, a set of conditions, and a one-time spend, and then a page. The moment this
//! endpoint mints a session, that argument stops being sufficient on its own: the assertion-id
//! replay cache stops one assertion being re-used, and it does not stop somebody auto-submitting
//! a FRESH assertion for their OWN account into a victim's browser.
//!
//! THE OUTSTANDING REQUEST IS HALF OF THAT DEFENCE and an earlier version of this sentence
//! called it the whole of it. The row proves a response answers a request this deployment issued
//! and has not spent; it does not prove the browser presenting it is the one the request was
//! issued to, and the start endpoint is unauthenticated, so an attacker can mint their own.
//!
//! THE OTHER HALF IS THE BROWSER BINDING, AND IT IS HERE NOW. Two earlier versions of this
//! paragraph said it "lands with sign-in"; sign-in landed without it. `saml_start` now sets a
//! `SameSite=None; Secure; HttpOnly` `__Host-` cookie carrying a nonce, records its SHA-256 on
//! the request row, and [`binding_matches`] below compares them. `SameSite=None` is what makes
//! the cookie ARRIVE on this cross-site POST; a `Lax` one would refuse every genuine login and
//! stop nothing.
//!
//! # What the binding closes, and the one it does not
//!
//! IT CLOSES THE CAPTURED-RESPONSE ATTACK: an attacker who starts a flow in THEIR OWN browser,
//! authenticates at the identity provider as themselves and auto-submits the response into
//! somebody else's browser now fails, because the nonce is in the attacker's cookie jar and not
//! the victim's.
//!
//! IT DOES NOT CLOSE THE ATTACKER-INITIATED FLOW, and that is worth stating plainly rather than
//! leaving a reader to infer that "login CSRF is handled". An attacker who CONTROLS A CONNECTION
//! -- their own tenant, pointing `idp_sso_url` at a server they run and pinning a certificate
//! they hold -- can top-level-navigate a victim's browser to that connection's START endpoint.
//! The binding is then planted in the VICTIM'S jar, their own server answers immediately with an
//! assertion naming the attacker, the cookie matches because it is the same browser, and the
//! victim is signed into the attacker's account. The binding cannot see this: every fact it
//! checks is true. What would close it is a first-party-initiation requirement on the start
//! endpoint or a confirmation interstitial, and BOTH cost a legitimate flow -- a "sign in with
//! SSO" link on a partner page or in an email is a cross-site navigation. Choosing which to pay
//! is an operator-visible trade, so it is named here rather than decided quietly.
//!
//! IT ALSO DOES NOT COVER AN UNSOLICITED RESPONSE, which answers no request and so has no row to
//! carry a digest. That is inherent -- there is no earlier moment at which this deployment met
//! that browser -- and it is why unsolicited responses are off by default and why #139 asks for
//! the risk to be documented where an operator turns them on.

use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use base64::Engine as _;
use ironauth_saml::Limits;
use ironauth_store::SamlConnectionId;
use serde::Deserialize;
use std::time::SystemTime;

use crate::saml_acs::{Acs, AcsError, consume};
use crate::state::OidcState;
use crate::util::epoch_micros;
use crate::wellknown::parse_scope;

/// The largest `SAMLResponse` form field this endpoint will decode.
///
/// APPLIED TO THE ENCODED FORM, BEFORE DECODING, because that is the work being bounded: a
/// megabyte of base64 costs a megabyte of decode before `ironauth-saml`'s own limits ever see a
/// byte. Signed enterprise responses with a certificate and a handful of attributes run to a few
/// tens of kilobytes, so this is roughly an order of magnitude of headroom over the real ones and
/// still small enough that the decode is uninteresting.
const MAX_ENCODED_RESPONSE: usize = 512 * 1024;

/// The deployment clock in the unit `ironauth-saml` reads it in.
///
/// A NAMED SEAM WITH ITS OWN TEST, because this is the module's only unit conversion and the
/// harness cannot exercise it: the test environment's clock is frozen at the Unix epoch, so
/// micros and seconds are the same number there and deleting the division left every route test
/// green. On a real clock the same mistake passes ~1.8e15 as a second count, which puts every
/// window tens of millions of years in the future and refuses every genuine response as expired.
/// The unit test below is where that is measured.
fn unix_seconds(now: SystemTime) -> i64 {
    epoch_micros(now) / 1_000_000
}

/// The HTTP POST binding's form.
#[derive(Deserialize)]
pub struct AcsForm {
    /// The base64 `<samlp:Response>`, as OASIS Bindings 3.5.4 requires.
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    /// The `RelayState` the identity provider echoed back.
    ///
    /// READ AND THROWN AWAY, and named here so that is visible rather than accidental.
    /// `RelayState` is a binding parameter that travels through the browser, so this value is
    /// whatever the last party to touch it wanted; it is where a service provider puts the URL
    /// to return to, which makes honouring the posted one an open redirect with extra steps.
    /// [`consume`] reads the `RelayState` this deployment RECORDED when it issued the request,
    /// and that is the ONLY value a `Location` is ever built from. TWO EARLIER VERSIONS OF THIS
    /// PARAGRAPH said "nothing redirects on this build -- there is no `Location` on any path",
    /// which was true of the build they were written for and false the moment sign-in landed in
    /// the same commit. An accepted response now answers 303 with a `Location`; this field is
    /// still read and thrown away, and that is the property worth stating.
    #[serde(rename = "RelayState")]
    _relay_state: Option<String>,
}

/// `POST /t/{tenant}/e/{environment}/saml/acs/{connection}`: consume a SAML response.
///
/// # What a refusal leaves behind
///
/// THIS MODULE MAKES SEVEN REFUSALS AND THEY DIVIDE IN THREE, which two earlier versions of
/// this paragraph got wrong in turn -- first "there are three ... all reached before the store",
/// then six. BEFORE THE STORE IS ADDRESSED: an unreadable scope, an oversized field, an
/// undecodable body, and an unreadable connection id -- four, and none writes anything anywhere.
/// AFTER, HAVING ONLY READ: a connection that is absent or inactive, and a store fault reading
/// the connection or its certificates; their only statements were SELECTs.
///
/// AND ONE THAT REFUSES AFTER A WRITE, which is the seventh and the reason the split is no
/// longer two. A response whose browser binding does not match has already spent its outstanding
/// request and burned its assertion id inside [`consume`], because those are what prove it is a
/// genuine unreplayed answer at all. The spend is deliberate rather than regrettable: a
/// single-use request that survived being presented in the wrong browser would hand an attacker
/// a retry.
///
/// NOT NOTHING FOR EVERY REFUSAL [`consume`] MAKES, and an earlier version of this paragraph
/// said so. `consume`'s property is narrower and its own doc states it correctly: nothing is
/// spent until every STATELESS check has passed. Past that point it performs two writes in two
/// transactions, so a response that spends its outstanding request and then loses the
/// assertion-id race comes back [`AcsError::Replayed`] -- a refusal, with the request already
/// spent. That is the deliberate order (the alternative burns a replay slot a losing response
/// never used) and it means "a refusal writes nothing" is false at the seam below this one.
pub async fn acs_post(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, connection)): Path<(String, String, String)>,
    // THE HEADERS COME BEFORE THE FORM because axum consumes the body last: a body extractor
    // has to be the final argument, and putting `HeaderMap` after it does not compile.
    headers: axum::http::HeaderMap,
    Form(form): Form<AcsForm>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    if form.saml_response.len() > MAX_ENCODED_RESPONSE {
        return refused(
            StatusCode::PAYLOAD_TOO_LARGE,
            "the response is too large to read",
        );
    }
    // STANDARD BASE64 WITH PADDING, which is what OASIS Bindings 3.5.4 specifies for this field
    // -- not the URL-safe alphabet the rest of this crate uses for its own tokens.
    //
    // ONLY CR AND LF ARE STRIPPED, because line wrapping is the whole reason to strip anything:
    // identity providers wrap the field and a conformant decoder rejects the break. An earlier
    // version used `is_ascii_whitespace`, which also matches SPACE -- and by the time this runs,
    // a space is ambiguous. `application/x-www-form-urlencoded` decodes `+` to a space, and `+`
    // is base64 character 62, so a poster who failed to percent-encode their field arrives here
    // with spaces where their data had `+`. Deleting them SILENTLY REPAIRS the field into a
    // shorter string that, whenever the count is a multiple of four, still decodes -- to bytes
    // the identity provider never signed. The operator is then told the signature is wrong, on
    // the one endpoint whose job is telling them whether their certificate is right. Leaving
    // SPACE in place makes the same input answer "not valid base64", which names the real fault.
    let packed: String = form
        .saml_response
        .chars()
        .filter(|character| !matches!(character, '\r' | '\n'))
        .collect();
    let Ok(response) = base64::engine::general_purpose::STANDARD.decode(packed) else {
        return refused(StatusCode::BAD_REQUEST, "the response is not valid base64");
    };

    // A MALFORMED ID AND AN UNKNOWN ONE ANSWER IDENTICALLY, and so does an inactive connection.
    // THE PARSE SITS HERE, BELOW THE BODY GATES, and an earlier version had it above them --
    // which made that sentence false: an undecodable body posted at `not-an-id` answered 404
    // while the same body at a well-formed id naming no connection answered 400, so the pair
    // told an enumerator whether a string parses as an in-scope `smc_` id. That much is
    // computable offline and the leak was worth little, but a written property that is false
    // for most bodies is worth less than none. Below the gates, every body class gets one
    // answer for both.
    let Ok(connection_id) = SamlConnectionId::parse_in_scope(&connection, &scope) else {
        return not_found();
    };

    let read = state.store().scoped(scope);
    // A STORE FAULT IS NOT AN ABSENT CONNECTION, and an earlier version collapsed the two into
    // one 404 under the heading "the fail-closed direction". Failing closed is about whether
    // anybody is admitted, and both answers admit nobody; what differs is what the operator
    // does next. "No connection is served here" sends them to delete and re-create a connection
    // that is fine, while the very next read one line below already answered a transient fault
    // with "try again". Two answers to one class of fault, ten milliseconds apart.
    let connection = match read.saml_connections().find_active(&connection_id).await {
        Ok(Some(connection)) => connection,
        Ok(None) => return not_found(),
        Err(_) => return server_error(),
    };
    let Ok(certificates) = read.saml_connections().certificates(&connection_id).await else {
        return server_error();
    };

    let acs = Acs {
        connection: &connection,
        certificates: &certificates,
        now_unix_secs: unix_seconds(state.now()),
        limits: &Limits::default(),
    };
    let consumed = match consume(&read.saml_replay(), &acs, &response).await {
        Ok(consumed) => consumed,
        Err(error) => return refused_by(&error),
    };

    // THE BROWSER BINDING, CHECKED BEFORE ANYBODY IS SIGNED IN. The request is already spent by
    // this point and deliberately stays spent: a response presented in the wrong browser has
    // burned the sign-in it was answering, which is the correct outcome for a single-use
    // request and denies an attacker a retry.
    if !binding_matches(
        &headers,
        consumed.accepted.in_response_to.as_deref(),
        consumed.browser_binding_sha256.as_deref(),
    ) {
        tracing::warn!(
            target: "ironauth.saml",
            connection = %connection.id,
            "a SAML response was presented in a browser other than the one its sign-in started in",
        );
        return refused(
            StatusCode::BAD_REQUEST,
            "this response does not belong to a sign-in started in this browser",
        );
    }

    // AND NOW SOMEBODY IS SIGNED IN, which is what the paragraphs above were waiting for. The
    // transport half ends here: which connection, which bytes, whether they verified and whether
    // they came back to the browser that started are this module's questions, and who the
    // `NameID` names locally is `saml_signin`'s.
    crate::saml_signin::sign_in(&state, scope, &connection, &consumed, &headers).await
}

/// Whether the request's recorded binding matches the cookie this POST carried.
///
/// # A missing digest is not a failure, and that is the one subtle part
///
/// `expected` is [`None`] for exactly two shapes, and neither can be checked: an UNSOLICITED
/// response, which answers no request and so has no row to have recorded one, and a request
/// issued before migration 0200 added the column, which drains inside its own five-minute TTL.
/// Refusing those would break every opted-in unsolicited connection and every login in flight
/// across a deploy, so [`None`] passes.
///
/// WHAT KEEPS THAT FROM BEING THE BYPASS IT LOOKS LIKE is that a caller cannot reach this arm by
/// choice. `expected` comes from the row the response's own `InResponseTo` just spent, so a
/// solicited response gets that row's digest or gets refused as `UnknownRequest` before this is
/// called; there is no input that turns a bound request into an unbound one. The reachable
/// no-binding case is a connection whose operator opted into unsolicited responses, which is the
/// documented trade #139 asks for.
///
/// # Constant time, because the comparison is against a secret's digest
///
/// A digest comparison that returns early leaks a prefix, and the value being probed is the one
/// thing standing between a captured assertion and a forced sign-in.
fn binding_matches(
    headers: &axum::http::HeaderMap,
    request_id: Option<&str>,
    expected: Option<&[u8]>,
) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    // THE COOKIE IS NAMED FOR THE REQUEST THE RESPONSE ANSWERS, so a browser with several flows
    // in flight is asked for the right one rather than for whichever overwrote the others. A
    // recorded binding with no request id cannot happen -- the digest comes off the row that
    // `InResponseTo` just spent -- but the pair is passed together so the impossible case is
    // refused rather than assumed.
    let Some(request_id) = request_id else {
        return false;
    };
    let Some(nonce) = cookie_value(headers, &crate::saml_start::binding_cookie_name(request_id))
    else {
        return false;
    };
    let actual = {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(nonce.as_bytes())
    };
    if actual.len() != expected.len() {
        return false;
    }
    actual
        .iter()
        .zip(expected)
        .fold(0_u8, |differences, (left, right)| {
            differences | (left ^ right)
        })
        == 0
}

/// The value of `name` in this request's `Cookie` header.
///
/// SPLIT ON `;` AND THEN ONCE ON `=`, because a cookie VALUE may contain `=` (base64url does not
/// pad, but a future value might) while a NAME may not. Whitespace around a pair is what the
/// header grammar puts between them.
fn cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|header| header.split(';'))
        .find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key.trim() == name).then(|| value.trim().to_owned())
        })
}

/// The no-store headers every response THIS HANDLER BUILDS carries.
///
/// NOT EVERY RESPONSE ON THE PATH, which an earlier version claimed: a POST with no
/// `SAMLResponse` field is refused by the `Form` extractor before this module runs, and that
/// 422 carries no `Cache-Control` at all. Nothing here can reach it, so the honest scope of the
/// sentence is the handler rather than the route.
fn no_store() -> [(axum::http::header::HeaderName, &'static str); 1] {
    [(axum::http::header::CACHE_CONTROL, "no-store")]
}

/// Render an [`AcsError`] for whoever posted the response.
///
/// # The typed reason does not go in the page
///
/// #139 asks for failures that "surface as typed connection-test failures ... so the
/// test-connection flow can render actionable messages", and an earlier version of this function
/// read that as licence to render [`AcsError`]'s `Display` to the browser. It is not: some of
/// those sentences quote THIS DEPLOYMENT'S configuration back -- `WrongNameIdFormat` names the
/// format the connection is set to, and `AllCertificatesUnusable` counts its pinned rows -- and
/// the browser reading them belongs to whoever posted, who on this endpoint is anybody.
///
/// THE TYPE IS THE DELIVERABLE, NOT THE PAGE. `AcsError` is a public enum with a variant per
/// fixable cause, for the connection-test flow #140 owns to render to an authenticated operator
/// -- a reader entitled to their own configuration. THAT FLOW IS NOT BUILT, and saying so
/// belongs here rather than in a sentence that reads as though the detail already reaches
/// somebody: today the variant reaches a Rust caller and nothing else, and the page carries the
/// coarse class. What this function decides is only that the page is not the place.
fn refused_by(error: &AcsError) -> Response {
    // THE TYPED REASON GOES TO THE LOG, which is the only place it can go today: the page is
    // read by whoever posted, and the connection-test flow that will render it to an
    // authenticated operator is not built. Without this the variant reached a `match` and was
    // dropped on the stack -- so `NoTrustAnchor`, whose whole purpose is to tell an operator
    // they have pinned nothing rather than blaming their identity provider, was recoverable
    // from nowhere at all.
    //
    // `Display` RATHER THAN `Debug`, because `AcsError::Store` wraps a database error whose
    // `Debug` carries connection detail; every `Display` in that enum is a sentence written to
    // be read.
    tracing::warn!(
        target: "ironauth.saml",
        reason = %error,
        "a SAML response was refused",
    );
    let (status, reason) = match error {
        AcsError::NoConnection => return not_found(),
        AcsError::Store(_) => return server_error(),
        // NOT IMPLEMENTED, and saying so is safe: it describes this build, which an operator
        // discovers from the release notes anyway, and it is the one class where "try again"
        // would be a lie.
        AcsError::EncryptionRequired | AcsError::EncryptedAttributes { .. } => (
            StatusCode::NOT_IMPLEMENTED,
            "this server cannot yet read an encrypted assertion",
        ),
        AcsError::Signature(_)
        | AcsError::NoTrustAnchor
        | AcsError::AllCertificatesUnusable { .. } => (
            StatusCode::BAD_REQUEST,
            "the response was not signed by a certificate this connection trusts",
        ),
        AcsError::UnknownRequest | AcsError::Replayed | AcsError::UnsolicitedRefused => (
            StatusCode::BAD_REQUEST,
            "the response does not answer a sign-in this server started",
        ),
        AcsError::Condition(_) | AcsError::Attributes(_) | AcsError::WrongNameIdFormat { .. } => (
            StatusCode::BAD_REQUEST,
            "the response is not one this connection accepts",
        ),
    };
    refused(status, reason)
}

/// An outcome page carrying `reason`.
///
/// `reason` IS A `&'static str` AND THAT IS LOAD-BEARING. An earlier version took an arbitrary
/// string, because it rendered [`AcsError`]'s `Display` -- which quotes the document and this
/// deployment's configuration -- and escaped it on the way out. Both halves are gone: the page
/// carries one of a fixed set of sentences written in this file, so there is no untrusted text
/// on this path to escape, and an escaping helper kept "in case" would be a defence nothing
/// reaches and nothing measures. The TYPE is what stops document text arriving here.
fn refused(status: StatusCode, reason: &'static str) -> Response {
    use axum::response::IntoResponse;

    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Response refused</title>\
         <p>This response was refused.</p><p>{reason}</p>"
    );
    (status, no_store(), axum::response::Html(body)).into_response()
}

/// A uniform not-found for an unreadable scope, an unparsable id, or a connection that is not
/// serving.
fn not_found() -> Response {
    refused(StatusCode::NOT_FOUND, "no SAML connection is served here")
}

/// A generic failure that never says what broke.
fn server_error() -> Response {
    refused(
        StatusCode::INTERNAL_SERVER_ERROR,
        "this response could not be processed; try again",
    )
}

#[cfg(test)]
mod tests {
    use super::unix_seconds;
    use std::time::{Duration, SystemTime};

    #[test]
    fn the_clock_reaches_the_protocol_in_seconds() {
        // THE ONE UNIT CONVERSION IN THIS MODULE, and the integration suite cannot see it: the
        // harness clock is frozen at the Unix epoch, where micros and seconds are the same
        // number, so deleting the division left all eight route tests green. On a real clock
        // that mistake hands `check` a second count about 1.8e15 -- tens of millions of years
        // ahead -- and every genuine enterprise response is refused as expired, which is a total
        // outage behind a green suite.
        let instant = SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_225_600);
        assert_eq!(unix_seconds(instant), 1_767_225_600);

        // AND IT TRUNCATES TOWARD THE PAST rather than rounding, which is the safe direction for
        // a `NotOnOrAfter`: an instant 999_999 microseconds into a second is still that second,
        // so a bound is never treated as having passed before it has.
        let mid = SystemTime::UNIX_EPOCH + Duration::from_micros(1_767_225_600_999_999);
        assert_eq!(unix_seconds(mid), 1_767_225_600);
    }
}
