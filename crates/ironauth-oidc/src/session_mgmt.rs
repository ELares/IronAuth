// SPDX-License-Identifier: MIT OR Apache-2.0

//! OIDC Session Management 1.0 and Front-Channel Logout 1.0, behind default-off
//! flags (issue #39).
//!
//! # Why these ship flagged, and honestly documented
//!
//! Both iframe logout specs are functionally degraded under 2026 third-party-cookie
//! partitioning: the OP iframe cannot read the OP session cookie in a third-party
//! context, and OIDC Session Management 1.0 section 5.1 warns that a blocked poll can
//! return `changed` forever and drive an infinite re-authentication loop. IronAuth
//! implements them ONLY for certification completeness (the Session OP and
//! Front-Channel OP profiles), never as a recommended mechanism, and steers
//! integrators to back-channel logout (issue #34), which is the authoritative
//! propagation path. Every surface here is gated by an environment flag AND a
//! per-client opt-in, so neither can turn on globally by accident; with the flags off
//! nothing is mounted and discovery advertises nothing.
//!
//! # `session_state`, and why it cannot leak the session id
//!
//! An authorization response carries `session_state` (OIDC Session Management 1.0
//! section 4.2) so the RP's `check_session_iframe` poll can detect a change without a
//! full redirect. It is a one-way keyed digest, NEVER the session id:
//!
//! - [`op_browser_state`] maps the SSO session id to the OP browser state (`opbs`)
//!   through a peppered SHA-256, so the value the browser holds is preimage-resistant:
//!   it is stable per session, changes when the session changes, and cannot be
//!   inverted to the session id or to another session's `opbs`.
//! - [`session_state`] then hashes `client_id`, the RP `origin`, that `opbs`, and a
//!   per-response `salt` (OIDC Session Management 1.0 section 4.2), appending the salt
//!   so the iframe can recompute. The result is stable per (client, origin, session,
//!   salt), differs per client and per origin, and changes when the session changes,
//!   while revealing neither the session id nor the `opbs`.
//!
//! # Front-Channel Logout targeting
//!
//! On logout the OP loads, in a hidden iframe, each participating RP's registered
//! `frontchannel_logout_uri` (issue #39 store columns). When the client registered
//! `frontchannel_logout_session_required`, [`frontchannel_logout_iframe_url`] appends
//! `iss` and the RP's OWN per-(client, session) `sid` (issue #32), so an RP learns
//! which of ITS sessions to clear and never sees another client's `sid`.

use axum::extract::State;
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};

use crate::pages;
use crate::state::OidcState;
use crate::util::append_query;

/// The domain-separating pepper mixed into the OP browser-state digest, so the
/// `opbs` a browser holds is not a bare hash of a value an attacker could grind. It
/// provides domain separation, not secrecy: the one-wayness of SHA-256 is what hides
/// the session id, independent of this constant.
const OP_BROWSER_STATE_PEPPER: &str = "ironauth.session_management.v1.opbs";

/// The OP browser state (`opbs`) for one SSO session: a peppered, one-way SHA-256
/// digest of the per-environment `issuer` and the session id, URL-safe base64 with no
/// padding.
///
/// This is the value the check-session iframe compares against, NEVER the session id
/// itself. It is:
///
/// - preimage-resistant, so it cannot be inverted to the session id (SHA-256);
/// - keyed by the `issuer`, so an `opbs` from one environment cannot be replayed as
///   another's;
/// - stable for the lifetime of the session, and different for a different session,
///   so `session_state` is stable per session and changes when the session changes.
#[must_use]
pub fn op_browser_state(issuer: &str, session_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(OP_BROWSER_STATE_PEPPER.as_bytes());
    hasher.update(b"\x00");
    hasher.update(issuer.as_bytes());
    hasher.update(b"\x00");
    hasher.update(session_id.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// The `session_state` value for an authorization response (OIDC Session Management
/// 1.0 section 4.2): `base64url(sha256(client_id + " " + origin + " " + opbs + " " +
/// salt)) + "." + salt`.
///
/// `opbs` is the OP browser state from [`op_browser_state`] (a one-way digest of the
/// session id), so `session_state` never carries the session id or the `opbs` in the
/// clear; the RP's iframe recomputes it from the trailing `salt` and its own `opbs`
/// cookie. The value is deterministic in its inputs, so it is stable per (client,
/// origin, session, salt) and differs when any of client, origin, or session (hence
/// `opbs`) changes.
#[must_use]
pub fn session_state(client_id: &str, origin: &str, opbs: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{client_id} {origin} {opbs} {salt}").as_bytes());
    let digest = URL_SAFE_NO_PAD.encode(hasher.finalize());
    format!("{digest}.{salt}")
}

/// The origin (scheme, host, and optional port) of an `http`/`https` redirect URI,
/// for use as the RP `origin` in [`session_state`] and as a `frame-src` source. A URI
/// with no recognized origin (a native custom scheme) yields its scheme-and-authority
/// prefix up to the first path/query/fragment separator, matching how the RP would
/// serialize its own origin.
#[must_use]
pub fn origin_of(uri: &str) -> String {
    for scheme in ["https://", "http://"] {
        if let Some(rest) = uri.strip_prefix(scheme) {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
            return format!("{scheme}{authority}");
        }
    }
    // A non-http scheme has no web origin; return the scheme-and-authority prefix so a
    // CSP source is at least as tight as the registered value.
    uri.split(['/', '?', '#']).next().unwrap_or(uri).to_owned()
}

/// Compute the `session_state` for an authorization response (issue #39), drawing a
/// fresh per-response `salt` from the environment entropy seam (never a raw RNG, so a
/// `FixedEntropy` test is deterministic). `issuer` keys the OP browser state, `origin`
/// is the RP origin derived from the validated `redirect_uri`, and `session_id` is the
/// SSO session the response authenticates. The session id never appears in the result
/// (it is folded through the one-way [`op_browser_state`]).
#[must_use]
pub fn authorization_session_state(
    state: &OidcState,
    issuer: &str,
    client_id: &str,
    redirect_uri: &str,
    session_id: &str,
) -> String {
    let mut salt_bytes = [0u8; 16];
    state.env().entropy().fill_bytes(&mut salt_bytes);
    let salt = URL_SAFE_NO_PAD.encode(salt_bytes);
    let opbs = op_browser_state(issuer, session_id);
    let origin = origin_of(redirect_uri);
    session_state(client_id, &origin, &opbs, &salt)
}

/// One relying party participating in a front-channel logout: its registered
/// `frontchannel_logout_uri`, its OWN per-(client, session) `sid`, and whether it
/// registered `frontchannel_logout_session_required`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontChannelParticipant {
    /// The RP's registered `frontchannel_logout_uri` (an `https` URL).
    pub uri: String,
    /// The RP's OWN `sid` for the session being ended (issue #32). Only ever this
    /// client's `sid`, never another client's.
    pub sid: String,
    /// Whether `iss` and `sid` must be appended (`frontchannel_logout_session_required`).
    pub session_required: bool,
}

/// The iframe `src` URL for one participating RP (OIDC Front-Channel Logout 1.0
/// section 2 and 3).
///
/// When the client registered `frontchannel_logout_session_required`, `iss` (the
/// per-environment issuer) and the RP's OWN `sid` are appended as query parameters, so
/// the RP can identify WHICH of its sessions to clear. Otherwise the registered URI is
/// returned unchanged. The `sid` is always the participant's own; this function never
/// receives, and never emits, another client's `sid`.
#[must_use]
pub fn frontchannel_logout_iframe_url(
    participant: &FrontChannelParticipant,
    issuer: &str,
) -> String {
    if participant.session_required {
        append_query(
            &participant.uri,
            &[("iss", Some(issuer)), ("sid", Some(&participant.sid))],
        )
    } else {
        participant.uri.clone()
    }
}

/// `GET /connect/check_session` (OIDC Session Management 1.0): the OP
/// `check_session_iframe`.
///
/// Served ONLY when session management is enabled for the deployment; the route is
/// otherwise not mounted (see [`crate::oidc_router`]). It is the ONE page deliberately
/// exempt from the platform anti-clickjacking posture: an RP must embed it
/// cross-origin, so [`pages::check_session_iframe_response`] omits
/// `frame-ancestors 'none'` and `X-Frame-Options`. Its inline script validates the
/// message and replies ONLY to the sender's exact `origin` (never `*`), and folds that
/// `origin` into the recomputed `session_state`, so a wrong-origin poller learns
/// nothing.
#[allow(clippy::unused_async)]
pub async fn check_session(State(_state): State<OidcState>) -> Response {
    pages::check_session_iframe_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISS: &str = "https://issuer.test/t/tnt/e/env";
    const SES_A: &str = "ses_tnt_env_aaaaaaaaaaaaaaaa";
    const SES_B: &str = "ses_tnt_env_bbbbbbbbbbbbbbbb";

    #[test]
    fn op_browser_state_is_not_the_session_id_and_does_not_contain_it() {
        let opbs = op_browser_state(ISS, SES_A);
        assert_ne!(opbs, SES_A, "opbs must not equal the session id");
        assert!(
            !opbs.contains(SES_A),
            "opbs must not embed the session id: {opbs}"
        );
        // A short fixed-width digest, not a growing blob.
        assert_eq!(opbs.len(), 43, "SHA-256 url-safe-no-pad is 43 chars");
    }

    #[test]
    fn op_browser_state_is_stable_per_session_and_changes_across_sessions() {
        assert_eq!(
            op_browser_state(ISS, SES_A),
            op_browser_state(ISS, SES_A),
            "stable for the same session"
        );
        assert_ne!(
            op_browser_state(ISS, SES_A),
            op_browser_state(ISS, SES_B),
            "changes when the session changes"
        );
    }

    #[test]
    fn op_browser_state_is_keyed_by_issuer() {
        assert_ne!(
            op_browser_state(ISS, SES_A),
            op_browser_state("https://other.test/t/tnt/e/env", SES_A),
            "an opbs from one issuer cannot be replayed as another's"
        );
    }

    #[test]
    fn session_state_does_not_leak_the_session_id_or_the_opbs() {
        let opbs = op_browser_state(ISS, SES_A);
        let ss = session_state("client-1", "https://rp.test", &opbs, "salt123");
        assert!(
            !ss.contains(SES_A),
            "session_state must not embed session id"
        );
        assert_ne!(ss, SES_A);
        // The salt is exposed by design (so the RP can recompute), but the opbs digest
        // is NOT: only the trailing ".salt" is cleartext.
        let (hash_part, salt_part) = ss.split_once('.').expect("hash.salt shape");
        assert_eq!(salt_part, "salt123");
        assert!(
            !hash_part.contains(&opbs),
            "the opbs must not appear in the hash part"
        );
    }

    #[test]
    fn session_state_is_stable_per_client_origin_session_and_salt() {
        let opbs = op_browser_state(ISS, SES_A);
        assert_eq!(
            session_state("client-1", "https://rp.test", &opbs, "s"),
            session_state("client-1", "https://rp.test", &opbs, "s"),
            "deterministic in its inputs"
        );
    }

    #[test]
    fn session_state_changes_with_client_origin_and_session() {
        let opbs_a = op_browser_state(ISS, SES_A);
        let opbs_b = op_browser_state(ISS, SES_B);
        let base = session_state("client-1", "https://rp.test", &opbs_a, "s");
        assert_ne!(
            base,
            session_state("client-2", "https://rp.test", &opbs_a, "s"),
            "differs per client"
        );
        assert_ne!(
            base,
            session_state("client-1", "https://evil.test", &opbs_a, "s"),
            "differs per origin"
        );
        assert_ne!(
            base,
            session_state("client-1", "https://rp.test", &opbs_b, "s"),
            "changes when the session (opbs) changes"
        );
    }

    #[test]
    fn origin_of_extracts_the_scheme_host_and_port() {
        assert_eq!(
            origin_of("https://rp.test/frontchannel?x=1"),
            "https://rp.test"
        );
        assert_eq!(origin_of("https://rp.test:8443/a"), "https://rp.test:8443");
        assert_eq!(
            origin_of("http://127.0.0.1:9000/cb"),
            "http://127.0.0.1:9000"
        );
    }

    #[test]
    fn frontchannel_url_appends_iss_and_own_sid_only_when_session_required() {
        let with_session = FrontChannelParticipant {
            uri: "https://rp.test/fc".to_owned(),
            sid: "sid-own".to_owned(),
            session_required: true,
        };
        let url = frontchannel_logout_iframe_url(&with_session, ISS);
        assert!(url.starts_with("https://rp.test/fc?"), "{url}");
        assert!(url.contains("iss="), "carries iss: {url}");
        assert!(url.contains("sid=sid-own"), "carries its OWN sid: {url}");

        let without_session = FrontChannelParticipant {
            uri: "https://rp.test/fc".to_owned(),
            sid: "sid-own".to_owned(),
            session_required: false,
        };
        let url = frontchannel_logout_iframe_url(&without_session, ISS);
        assert_eq!(
            url, "https://rp.test/fc",
            "no iss/sid when session_required is false"
        );
        assert!(!url.contains("sid="), "never leaks a sid when not required");
    }
}
