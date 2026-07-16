// SPDX-License-Identifier: MIT OR Apache-2.0

//! The WebAuthn Related Origin Requests well-known document (issue #67).
//!
//! `GET /.well-known/webauthn` serves the JSON `{"origins": [...]}` document that
//! WebAuthn Level 3 defines for related origin requests: the list of origins
//! permitted to run a ceremony against this deployment's RP ID. A browser that
//! supports the feature (Chrome 128+, Safari 18+) fetches this document from
//! `https://{rp_id}/.well-known/webauthn` when a ceremony is invoked from an origin
//! that is not a registrable-suffix of the RP ID, and accepts the ceremony only if
//! the origin is listed here.
//!
//! The document is GENERATED from live per-environment configuration at request
//! time (never a baked static asset), so an operator adding a related origin is
//! reflected without a code redeploy. It carries the same cache discipline as the
//! discovery and JWKS surfaces (an explicit `Cache-Control` plus a strong `ETag`
//! with `304` on a matching `If-None-Match`), served as `application/json`.
//!
//! An unconfigured deployment (WebAuthn disabled, or no related origins declared)
//! has no document to serve and returns a uniform `404`, so the well-known path
//! discloses nothing on a domain that does not use the feature.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;

use crate::state::OidcState;
use crate::wellknown::{cacheable_response, not_found};

/// The `Cache-Control` max-age for the related-origins document, in seconds. Five
/// minutes: long enough that a browser fetching it mid-ceremony does not re-hit the
/// origin repeatedly, short enough that a related-origin change propagates quickly.
/// The strong `ETag` still lets a client revalidate cheaply with `If-None-Match`.
const WELL_KNOWN_WEBAUTHN_MAX_AGE_SECS: u64 = 300;

/// `GET /.well-known/webauthn`: the related-origins document, or a uniform `404`
/// when the feature is not configured for this deployment.
pub(crate) async fn related_origins(
    State(state): State<OidcState>,
    headers: HeaderMap,
) -> Response {
    let Some(body) = state.webauthn_related_origins_document() else {
        return not_found();
    };
    cacheable_response(
        &headers,
        "application/json",
        WELL_KNOWN_WEBAUTHN_MAX_AGE_SECS,
        &body,
    )
}
