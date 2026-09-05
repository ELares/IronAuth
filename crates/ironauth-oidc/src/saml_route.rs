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
//! # There is no CSRF check here, deliberately
//!
//! Every other browser POST in this crate begins with a same-origin check. This one must not:
//! the HTTP POST binding IS a cross-site form submission, auto-submitted by a page the identity
//! provider served. A same-origin check here would refuse every real sign-in.
//!
//! What stands in its place is the signature and the outstanding request. A response nobody
//! could sign is refused at `verify`; a response that names no request is refused unless the
//! connection opted in; and the request it names can be spent exactly once. That is a stronger
//! guarantee than an origin header, and it is the reason the binding is safe without one.

use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use base64::Engine as _;
use ironauth_saml::Limits;
use ironauth_store::{IdentifierType, SamlConnectionId, Scope};
use serde::Deserialize;

use crate::authn::AuthenticationEvent;
use crate::interaction;
use crate::saml_acs::{Acs, AcsError, Consumed, consume};
use crate::state::OidcState;
use crate::util::epoch_micros;
use crate::wellknown::parse_scope;

/// The `NameID` `Format` this build can resolve to a local account.
///
/// ONE FORMAT, STATED RATHER THAN ASSUMED. A `NameID` in the `emailAddress` format is an email
/// address, so it resolves through the same identifier seam every other login uses. `persistent`
/// and `transient` are opaque strings that mean nothing to the identifier table: binding one to
/// an account needs a stored mapping, which is what the account-link work adds. A connection
/// configured for either gets told so rather than being silently refused as "unknown user".
const RESOLVABLE_NAMEID_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

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
/// # The order here is the same argument as the module it wraps
///
/// Nothing about the browser is touched -- no session, no cookie, no redirect -- until
/// [`consume`] has returned a [`Consumed`]. A response that fails any check leaves this endpoint
/// having written nothing and having said nothing about who might have signed in.
pub async fn acs_post(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, connection)): Path<(String, String, String)>,
    headers: HeaderMap,
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

    sign_in(
        &state,
        scope,
        &consumed,
        &connection.nameid_format,
        &headers,
    )
    .await
}

/// Turn a consumed assertion into a session, or say why it could not be one.
async fn sign_in(
    state: &OidcState,
    scope: Scope,
    consumed: &Consumed,
    nameid_format: &str,
    headers: &HeaderMap,
) -> Response {
    // WHAT THE CONNECTION SAYS THE NAME MEANS, not what this response's own `Format` said.
    // `consume` has already refused any document whose `Format` disagrees with the column, so
    // the two are equal here; reading the COLUMN is the habit that stays correct if that check
    // ever moves.
    if nameid_format.trim() != RESOLVABLE_NAMEID_FORMAT {
        return refused(
            StatusCode::NOT_IMPLEMENTED,
            "this connection's NameID format cannot yet be resolved to an account; configure the \
             connection for the emailAddress format",
        );
    }

    let Ok(resolutions) = state
        .store()
        .scoped(scope)
        .user_identifiers()
        .resolve(IdentifierType::Email, &consumed.accepted.name_id)
        .await
    else {
        return server_error();
    };
    // A VERIFIED IDENTIFIER, and only a verified one. An unverified row is somebody who typed
    // that address and never proved it, so signing the assertion's subject into it would let an
    // identity provider claim an account its user does not own. The identity provider vouches
    // for the address it asserts, but not for a local row nobody proved.
    let Some(subject) = resolutions
        .into_iter()
        .find(|resolution| resolution.verified)
        .map(|resolution| resolution.user_id)
    else {
        return refused(
            StatusCode::FORBIDDEN,
            "no account in this environment is provisioned for that identity",
        );
    };

    // THE UPSTREAM RAN THE FACTORS, NOT THIS DEPLOYMENT, which is exactly what
    // `AuthenticationEvent::federated` records: `AuthMethod::Federated` contributes no `amr` of
    // its own, so nothing here claims IronAuth verified a password or a passkey. The identity
    // provider's own `AuthnContextClassRef` is the SAML analogue of an upstream `acr` and is not
    // read yet -- `Accepted` does not carry it -- so this passes none rather than inventing one.
    let event = AuthenticationEvent::federated(epoch_micros(state.now()), &[], None);
    let actor = interaction::user_actor(&subject);
    match interaction::establish_session(state, scope, &subject.to_string(), &event, actor, headers)
        .await
    {
        Ok(cookies) => interaction::attach_session_cookies(landing(consumed), &cookies),
        // THE CENTRAL LIFECYCLE FENCE REFUSED: blocked, disabled, waitlisted, pending. Answered
        // exactly like an unprovisioned identity, so a valid assertion for a suspended account
        // is not an account-state oracle for whoever posted it.
        Err(interaction::EstablishSessionError::NotAuthenticatable) => refused(
            StatusCode::FORBIDDEN,
            "no account in this environment is provisioned for that identity",
        ),
        Err(interaction::EstablishSessionError::Store) => server_error(),
    }
}

/// Where the browser goes once the session exists.
///
/// THE RECORDED RELAYSTATE OR NOWHERE. The value came out of the request row this deployment
/// wrote, and it is still put through [`interaction::parse_resume`] -- the same open-redirect
/// defence every other resume goes through -- because "we wrote it" is a weaker claim than it
/// sounds once a future writer takes it from an operator-supplied field. Anything that does not
/// parse as a local `/authorize?` resume lands on a page instead of redirecting anywhere.
fn landing(consumed: &Consumed) -> Response {
    use axum::response::IntoResponse;

    if let Some(resume) = interaction::parse_resume(consumed.relay_state.as_deref()) {
        return (
            StatusCode::SEE_OTHER,
            [(axum::http::header::LOCATION, resume.return_to)],
            no_store(),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        no_store(),
        axum::response::Html(
            "<!doctype html><meta charset=\"utf-8\"><title>Signed in</title>\
             <p>You are signed in.</p>",
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
/// # Why this says as much as it does
///
/// #139 asks for typed failures an operator can act on, because a SAML integration that answers
/// "invalid response" costs days. Every variant here sits BEHIND the signature check -- reaching
/// any of them means the document was signed by a certificate the operator pinned -- so what is
/// being described is the identity provider's own document, not an attacker's guess. The two
/// that sit in front of it, [`AcsError::Signature`] and the trust-anchor pair, say only which
/// side of the pinning is wrong.
fn refused_by(error: &AcsError) -> Response {
    let status = match error {
        AcsError::NoConnection => StatusCode::NOT_FOUND,
        AcsError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        AcsError::EncryptionRequired | AcsError::EncryptedAttributes { .. } => {
            StatusCode::NOT_IMPLEMENTED
        }
        _ => StatusCode::BAD_REQUEST,
    };
    // A STORE FAULT NEVER SPEAKS. `AcsError::Store` wraps a database error whose message is
    // about this deployment's internals, and the browser it would reach belongs to whoever
    // posted the response.
    if matches!(error, AcsError::Store(_)) {
        return server_error();
    }
    refused(status, &error.to_string())
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
