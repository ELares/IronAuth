//! Serving the SP metadata document an operator uploads to their identity provider (issue #139).
//!
//! # Why this endpoint exists at all
//!
//! `AuthnRequest` issuance signs every request with a key provisioned per connection, and nothing
//! published the public half -- so an identity provider configured to VERIFY those signatures had
//! nothing to verify against, and the only providers that worked were the ones that did not
//! check. The metadata document is how the far side gets the key, and how an operator gets the
//! two strings they would otherwise transcribe: the entity id this deployment presents to them
//! and the URL their responses go to.
//!
//! # It is public, and that is the point
//!
//! No authentication, and the document names a certificate, an entity id and an ACS URL. All
//! three are PUBLIC BY CONSTRUCTION: a certificate carries a public key, the entity id is what
//! this deployment announces in every request it sends, and the ACS URL is where an identity
//! provider posts -- it is in the `Recipient` of every assertion. Metadata is meant to be
//! fetched; every SAML deployment in the world serves one over plain HTTPS.
//!
//! WHAT IT DOES NOT REVEAL is which connections exist: the id is in the path, so a caller learns
//! only about a connection whose id they already had. An unknown id, a malformed one and one from
//! another scope answer identically.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use ironauth_saml::metadata::{self, Descriptor};
use ironauth_store::SamlConnectionId;

use crate::saml_start::{KeyUnavailable, signing_key_for};
use crate::state::OidcState;
use crate::wellknown::parse_scope;

/// How long the published certificate is valid for.
///
/// FIVE YEARS FROM THE KEY'S OWN CREATION, not from now. The document is regenerated on every
/// request, and a validity window anchored to the REQUEST would move every time it was fetched --
/// so two operators fetching on different days would upload certificates that differ, and an
/// identity provider comparing them would see a rotation that never happened. Anchoring to the
/// key means the same key always produces the same certificate.
///
/// THE LENGTH IS NOT A SECURITY BOUND, and it is worth saying so: `anchors` on the inbound side
/// deliberately ignores certificate expiry, and most identity providers do the same for a
/// metadata signing certificate, because what is trusted is the key an operator uploaded rather
/// than a chain. Five years is long enough not to be a surprise and short enough that a provider
/// which DOES enforce it prompts a rotation before the key is ancient.
const CERTIFICATE_VALIDITY_SECS: i64 = 5 * 365 * 24 * 60 * 60;

/// `GET /t/{tenant}/e/{environment}/saml/metadata/{connection}`: the SP metadata document.
pub async fn metadata_get(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, connection)): Path<(String, String, String)>,
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
    // ONE READ OF THE KEY ROW. An earlier version called the shared loader and then read the
    // row AGAIN for its creation instant -- two reads in two transactions, so a rotation landing
    // between them would publish one key's certificate with the other key's validity window,
    // which is exactly the drift the shared loader exists to prevent. The loader now hands back
    // the row it used.
    //
    // ONE READ OF THE KEY, NOT ONE READ IN THE HANDLER: the connection row above is a second
    // read in a second transaction. That one is not the same hazard -- the entity id and ACS URL
    // it carries are not derived from the key -- but a previous version of this comment said
    // "ONE READ" without the qualifier and pointed at a paragraph it had itself deleted.
    let (key, stored) = match signing_key_for(&read, &connection_id).await {
        Ok(loaded) => loaded,
        // THE SENTENCES ARE THIS ROUTE'S OWN, and an earlier version had none: it surfaced the
        // start route's rendered page, so fetching metadata for a keyless connection answered
        // "Sign-in unavailable" and advised uploading the very document being fetched. There is
        // no metadata to publish without a key, because the certificate IS the metadata's point.
        Err(KeyUnavailable::NotProvisioned) => {
            return refused(
                StatusCode::CONFLICT,
                "this connection has no signing key yet, so there is no certificate to publish; \
                 provision one and fetch this document again",
            );
        }
        Err(KeyUnavailable::Unusable) => return server_error(),
    };

    let not_before = stored.created_at_unix_micros / 1_000_000;
    let document = match metadata::entity_descriptor(&Descriptor {
        entity_id: &connection.sp_entity_id,
        assertion_consumer_service_url: &connection.acs_url,
        name_id_format: &connection.nameid_format,
        key: &key,
        not_before_unix_secs: not_before,
        not_after_unix_secs: not_before + CERTIFICATE_VALIDITY_SECS,
    }) {
        Ok(document) => document,
        Err(error) => {
            tracing::warn!(
                target: "ironauth.saml",
                reason = %error,
                "a SAML connection could not be turned into a metadata document",
            );
            return refused(
                StatusCode::CONFLICT,
                "this connection's configuration cannot be expressed as SAML metadata",
            );
        }
    };

    // `application/samlmetadata+xml` IS THE TYPE OASIS REGISTERED WITH IANA FOR SAML METADATA,
    // and it is what makes a browser offer to save the document rather than try to render it --
    // which is what an operator wants, because the next step is uploading the file. A provider
    // fetching it programmatically accepts either. AN EARLIER VERSION OF THIS COMMENT ATTACHED A
    // SECTION NUMBER TO THE CLAIM and the section it named says something else; the registration
    // is the citable fact, so it is the one stated.
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/samlmetadata+xml"),
            ),
            // CACHEABLE, BRIEFLY, AS JWKS IN THIS CRATE ALREADY IS. Two earlier versions of
            // this comment got the comparison wrong and each was checkable: the first said this
            // endpoint was alone in being cacheable, and its correction gave JWKS an hour.
            // `JwksCacheWindow` admits 300..=900 and defaults to 600 (`issuer.rs`), and a
            // config outside that range refuses the process at load -- so no configuration of
            // this build serves an hour, and an operator at the floor gets the SAME window from
            // both endpoints.
            //
            // THE BOUND IS THE CONFIG RANGE, NOT A PINNED FIGURE. A third version of this
            // comment said "`issuer_http.rs` pins the served value at 600", which was wrong
            // twice over: that is a TEST file, not source, and it asserts 600 against a window
            // its own fixture built from a literal, so it pins neither the default nor anything
            // served. The JWKS handlers serve `state.registry.cache().max_age_secs()`, which
            // tracks configuration -- which is what makes the "operator at the floor" sentence
            // beside it true, and what "pins at 600" would have made false.
            //
            // The document changes only when the connection or its key does, it contains no
            // secret, and a provider refreshing on a schedule should not make this deployment
            // re-sign a certificate on every poll. FIVE MINUTES AS A CONSTANT RATHER THAN A
            // KNOB, because there is nothing for an operator to trade off yet: SP key rotation
            // does not exist (migration 0199 grants no UPDATE; it waits for #141), so no
            // rotation can be waiting on a cache to drain. Until one can, the shortest window
            // this crate already treats as acceptable for a public document is the conservative
            // choice, and it costs a provider one fetch per five minutes.
            (
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("public, max-age=300"),
            ),
        ],
        document,
    )
        .into_response()
}

/// An outcome page carrying `reason`, which is always a sentence written in this file.
fn refused(status: StatusCode, reason: &'static str) -> Response {
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Metadata unavailable</title>\
         <p>This connection's metadata could not be produced.</p><p>{reason}</p>"
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
        "this metadata could not be produced; try again",
    )
}
