//! The SAML HTTP POST binding: the endpoint an identity provider posts a response to (#139).
//!
//! # What this is, and what [`crate::saml_acs`] is
//!
//! `saml_acs` is the PROTOCOL: verify a response against the connection's pinned certificates,
//! check every condition, spend the outstanding request and admit the assertion id, in that
//! order. It takes bytes and a connection row and touches no HTTP. This module is the
//! TRANSPORT around it: which connection a request is for, how the bytes arrive, who the
//! `NameID` names locally, and what the browser is told afterwards.
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
//! # This endpoint does not sign anybody in, and that is the point of this change
//!
//! An earlier version of this module did: it resolved the `NameID` through the email identifier
//! seam and minted a session. Review took it apart on four independent grounds, and each one is
//! worth writing down, because they are the shape of the work that comes next rather than
//! details to patch.
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
//! WHAT THIS SHIPS INSTEAD is the binding itself: a response arrives, is verified against the
//! right connection, and is either consumed or refused with a typed reason. That is the surface
//! #139 asks for when it says failures must "surface as typed connection-test failures ... so
//! the test-connection flow can render actionable messages", and it is what an operator points
//! Okta at to find out whether their certificate and audience are right.
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
//! a FRESH assertion for their OWN account into a victim's browser. The defence for that is
//! the outstanding request -- which is why `AuthnRequest` issuance is the piece that has to land
//! before sign-in does, and not after.

use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use base64::Engine as _;
use ironauth_saml::Limits;
use ironauth_store::SamlConnectionId;
use serde::Deserialize;

use crate::saml_acs::{Acs, AcsError, Consumed, consume};
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
    /// and that is the only one that reaches a redirect.
    #[serde(rename = "RelayState")]
    _relay_state: Option<String>,
}

/// `POST /t/{tenant}/e/{environment}/saml/acs/{connection}`: consume a SAML response.
///
/// # What a refusal leaves behind
///
/// NOTHING IN THE STORE, which is [`consume`]'s own property and the reason this endpoint can be
/// this thin: every stateless check runs and passes before the outstanding request is spent or
/// the assertion id recorded. What a refusal DOES leave is a page, and the two refusals this
/// module adds on its own account -- an unreadable connection id and an undecodable body -- are
/// reached before the store is touched at all.
pub async fn acs_post(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, connection)): Path<(String, String, String)>,
    Form(form): Form<AcsForm>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    // A MALFORMED ID AND AN UNKNOWN ONE ANSWER IDENTICALLY, and so does an inactive connection,
    // because the difference is only interesting to somebody enumerating which connections a
    // deployment has. An operator testing their own connection is looking at the id they just
    // pasted, and gets the same answer either way.
    let Ok(connection_id) = SamlConnectionId::parse_in_scope(&connection, &scope) else {
        return not_found();
    };

    if form.saml_response.len() > MAX_ENCODED_RESPONSE {
        return refused(
            StatusCode::PAYLOAD_TOO_LARGE,
            "the response is too large to read",
        );
    }
    // STANDARD BASE64 WITH PADDING, which is what OASIS Bindings 3.5.4 specifies for this field
    // -- not the URL-safe alphabet the rest of this crate uses for its own tokens. Whitespace is
    // stripped first because identity providers line-wrap the field and a conformant decoder
    // rejects the newline.
    let packed: String = form
        .saml_response
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let Ok(response) = base64::engine::general_purpose::STANDARD.decode(packed) else {
        return refused(StatusCode::BAD_REQUEST, "the response is not valid base64");
    };

    let read = state.store().scoped(scope);
    let Ok(Some(connection)) = read.saml_connections().find_active(&connection_id).await else {
        // A STORE FAULT LANDS HERE TOO, and that is the fail-closed direction: unable to read
        // which certificates to trust, this endpoint signs nobody in.
        return not_found();
    };
    let Ok(certificates) = read.saml_connections().certificates(&connection_id).await else {
        return server_error();
    };

    let acs = Acs {
        connection: &connection,
        certificates: &certificates,
        now_unix_secs: epoch_micros(state.now()) / 1_000_000,
        limits: &Limits::default(),
    };
    let consumed = match consume(&read.saml_replay(), &acs, &response).await {
        Ok(consumed) => consumed,
        Err(error) => return refused_by(&error),
    };

    accepted(&consumed)
}

/// What an accepted response answers with.
///
/// NO SESSION, NO COOKIE, NO REDIRECT -- see the module doc for why that is this change's
/// deliverable rather than a gap in it. The page is the same for every accepted response: it
/// does not name the subject, the connection, or anything the poster did not already put in the
/// document, because the party reading it is whoever posted, and nobody here has been
/// authenticated as anyone.
fn accepted(consumed: &Consumed) -> Response {
    use axum::response::IntoResponse;

    // THE RECORDED RELAYSTATE IS READ AND NOT ACTED ON. Reading it here rather than ignoring the
    // field keeps the redirect-to-be anchored on the value `consume` returns from the store,
    // so the day sign-in lands, the thing a redirect is built from is already the recorded value
    // and not the posted one. An assertion rather than a branch, because there is no behaviour
    // to gate yet.
    debug_assert!(
        consumed
            .relay_state
            .as_ref()
            .is_none_or(|value| !value.is_empty()),
        "consume folds an empty RelayState to None"
    );
    (
        StatusCode::OK,
        no_store(),
        axum::response::Html(
            "<!doctype html><meta charset=\"utf-8\"><title>Response accepted</title>\
             <p>The response was accepted, so this connection's certificate, audience and \
             recipient are configured correctly.</p>\
             <p>Signing in through SAML is not enabled on this build.</p>",
        ),
    )
        .into_response()
}

/// The no-store headers every response on this path carries.
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
/// fixable cause; the connection-test flow #140 owns calls `examine` and renders it to an
/// authenticated operator, which is a reader who is entitled to their own configuration. Here
/// the page carries only the coarse class, and the status carries the rest.
fn refused_by(error: &AcsError) -> Response {
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

/// An outcome page carrying `reason`, which is always an operator-facing sentence.
fn refused(status: StatusCode, reason: &str) -> Response {
    use axum::response::IntoResponse;

    // ESCAPED, because some of these sentences quote the document: `WrongNameIdFormat` carries
    // the `Format` the assertion named, and a signed assertion is still a place a hostile string
    // can be written. Only a certificate the operator pinned can put text here, but "the
    // attacker had to be the identity provider" is not a reason to render markup.
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Sign-in failed</title>\
         <p>This sign-in could not be completed.</p><p>{}</p>",
        escape(reason)
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
        "this sign-in could not be completed; try again",
    )
}

/// The five characters that matter in an HTML text node or a quoted attribute.
fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for character in raw.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}
