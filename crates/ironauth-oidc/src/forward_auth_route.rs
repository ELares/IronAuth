// SPDX-License-Identifier: MIT OR Apache-2.0

//! The forward-auth check endpoint (issue #154 criteria 1 and 2).
//!
//! A reverse proxy calls this before serving a request, and the answer decides whether the
//! original request proceeds. `crate::forward_auth` already holds the decision logic and
//! the header discipline; this is the HTTP shell around it, and the shell is where the
//! mistakes that matter live.
//!
//! # What the shell is responsible for
//!
//! **Reading the ORIGINAL request, not this one.** The check request is addressed to the
//! authenticator: its method is whatever the proxy chose, its path is this endpoint, and
//! authorizing those would authorize the wrong thing every time. The original request is in
//! headers whose names differ per proxy, which is what [`Dialect`] exists for.
//!
//! **Refusing to read them from an untrusted hop.** Those headers are ordinary request
//! headers, so a client that can reach this endpoint directly can set them. `Dialect::describe`
//! refuses when the hop is untrusted, and the trust decision comes from `[proxy]`, resolved
//! once at boot.
//!
//! **Answering in the shape the caller can act on.** An allow carries the trusted identity
//! headers; a deny carries none; a step-up is a 401 with the RFC 9470 challenge rather than
//! a 403, because the caller CAN do something about it.
//!
//! # Absent unless enabled
//!
//! With no `[forward_auth]` section the route answers a uniform 404. A deployment that did
//! not ask for this surface does not advertise one, and the 404 is indistinguishable from
//! the route not existing.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;

use crate::forward_auth::{DialectError, Identity};
use crate::forward_auth::{ProxyHop, trusted_header_names};
use crate::rules::Action;
use crate::state::OidcState;
use crate::wellknown::parse_scope;

/// The header carrying names the proxy MUST delete from the forwarded request.
///
/// Advisory to the proxy and diagnostic to the operator. `crate::forward_auth` removed these
/// from its own view so no rule could be evaluated against a forged one, but whether the
/// client's header reaches the upstream depends on the proxy, which this server does not
/// configure. A client sending `Remote-User` is either a misconfigured proxy or an attempt
/// to forge an identity, and an operator wants to know which without reproducing it.
pub const MUST_DELETE_HEADER: &str = "x-ironauth-must-delete";

/// Answer a proxy's forward-auth check.
///
/// Accepts ANY method: under `ext_authz` the check request carries the original request's
/// method as its own, so constraining this route to `GET` would make every non-GET request
/// unauthorizable on that dialect.
pub async fn check(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let Some(runtime) = state.forward_auth() else {
        return status(StatusCode::NOT_FOUND);
    };
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return status(StatusCode::NOT_FOUND);
    };

    let pairs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();

    let hop = if state.proxy_hop_trusted() {
        ProxyHop::Trusted
    } else {
        ProxyHop::Untrusted
    };

    // The check request's own path is this endpoint's, which is exactly what must NOT be
    // authorized. It is passed because `ext_authz` is the dialect where the check request
    // IS the original one; every other dialect ignores it and reads its headers.
    let (facts, must_delete) = match runtime.dialect().describe(
        hop,
        method.as_str(),
        &format!("/t/{tenant_id}/e/{environment_id}/forward-auth"),
        &pairs,
    ) {
        Ok(described) => described,
        // A REFUSAL, NOT A FALLBACK. Every arm here means the original request could not be
        // established, and admitting a request whose target is unknown is the one answer
        // that cannot be right.
        Err(DialectError::UntrustedHop) => return status(StatusCode::FORBIDDEN),
        Err(_) => return status(StatusCode::BAD_REQUEST),
    };

    // GROUPS AND ROLES ARE EMPTY, and that is safe only because
    // `forward_auth_rules::rule_from_config` refuses any rule that reads them. If that
    // refusal is ever relaxed without an identity source behind it, a `deny` rule keyed on
    // a group stops biting and nothing here would notice.
    let identity = crate::interaction::resolve_session(&state, scope, &headers)
        .await
        .map(|session| Identity {
            user: session.subject,
            groups: Vec::new(),
            roles: Vec::new(),
            email: None,
            name: None,
        });

    let outcome = runtime.forward_auth().evaluate(facts, identity.as_ref());

    let mut response = match outcome.decision.action {
        Action::Allow => status(StatusCode::OK),
        Action::Deny => status(StatusCode::FORBIDDEN),
        // RFC 9470: the caller can reach a stronger authentication, so this is a challenge
        // rather than a refusal. A 403 would tell them to stop trying.
        Action::StepUp { ref acr } => {
            let mut response = status(StatusCode::UNAUTHORIZED);
            if let Ok(value) = axum::http::HeaderValue::from_str(&format!(
                "Bearer error=\"insufficient_user_authentication\", acr_values=\"{acr}\""
            )) {
                response
                    .headers_mut()
                    .insert(axum::http::header::WWW_AUTHENTICATE, value);
            }
            response
        }
    };

    // ONLY ON AN ALLOW. `ForwardAuthOutcome` already guarantees `upstream_headers` is empty
    // otherwise; copying unconditionally would depend on that invariant holding forever
    // rather than on this decision being made here.
    if matches!(outcome.decision.action, Action::Allow) {
        for (name, value) in &outcome.upstream_headers {
            if let (Ok(name), Ok(value)) = (
                axum::http::HeaderName::from_bytes(name.as_bytes()),
                axum::http::HeaderValue::from_str(value),
            ) {
                response.headers_mut().insert(name, value);
            }
        }
    }

    if !must_delete.is_empty() {
        if let Ok(value) = axum::http::HeaderValue::from_str(&must_delete.join(", ")) {
            response.headers_mut().insert(
                axum::http::HeaderName::from_static(MUST_DELETE_HEADER),
                value,
            );
        }
    }

    response
}

/// An empty response with `code`.
fn status(code: StatusCode) -> Response {
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = code;
    response
}

/// The trusted header names, re-exported so an operator configuring a proxy has one list.
#[must_use]
pub fn trusted_headers() -> Vec<&'static str> {
    trusted_header_names().collect()
}
