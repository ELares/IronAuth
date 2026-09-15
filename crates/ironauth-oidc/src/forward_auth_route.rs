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

use crate::forward_auth::{DialectError, ForwardAuthOutcome, Identity};
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

    let hop = hop_from_headers(&headers);

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

    render(&outcome, &must_delete)
}

/// Whether THIS request arrived through the configured trusted-proxy chain.
///
/// PER REQUEST, AND FAIL CLOSED. This was `state.proxy_hop_trusted()`, a boot-time boolean
/// meaning "this deployment honours forwarding headers at all". That is a different question
/// from "did this request arrive through the chain", and answering the second with the first
/// treats a client that reached the endpoint directly as though it had come through the
/// proxy. It could then state the original request itself, which is the entire thing the hop
/// check exists to stop.
///
/// The verdict is stamped per request by the server's middleware, which REPLACES any value a
/// client sent, exactly as it does for the resolved peer IP. Anything other than the honored
/// value, the header being absent included, is untrusted: a deployment that has not wired
/// the middleware refuses rather than admits.
fn hop_from_headers(headers: &HeaderMap) -> ProxyHop {
    if headers
        .get(ironauth_config::FORWARD_DECISION_HEADER)
        .and_then(|value| value.to_str().ok())
        == Some(ironauth_config::FORWARD_DECISION_HONORED)
    {
        ProxyHop::Trusted
    } else {
        ProxyHop::Untrusted
    }
}

/// Turn a decision into the response a proxy acts on.
fn render(outcome: &ForwardAuthOutcome, must_delete: &[String]) -> Response {
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

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use crate::rules::Decision;

    use super::*;

    fn outcome(action: Action, upstream: Vec<(String, String)>) -> ForwardAuthOutcome {
        ForwardAuthOutcome {
            decision: Decision {
                action,
                matched: Some("a rule".to_owned()),
            },
            upstream_headers: upstream,
            must_delete: Vec::new(),
            identity_rejected: None,
        }
    }

    /// ONLY the stamped value means trusted (issue #154).
    ///
    /// The table drives what an ATTACKER sends, because this is the check that decides
    /// whether the request is allowed to describe some other request. A client reaching the
    /// endpoint directly sends no stamped header, or sends one it made up; both must be
    /// untrusted, and the absent case must be untrusted too so a deployment that has not
    /// wired the middleware refuses rather than admits.
    #[test]
    fn only_the_stamped_honored_value_is_a_trusted_hop() {
        let mut trusted = HeaderMap::new();
        trusted.insert(
            axum::http::HeaderName::from_static(ironauth_config::FORWARD_DECISION_HEADER),
            HeaderValue::from_static(ironauth_config::FORWARD_DECISION_HONORED),
        );
        assert_eq!(hop_from_headers(&trusted), ProxyHop::Trusted);

        for forged in [
            "",
            "direct",
            "failed-closed",
            "HONORED",
            "honored ",
            "true",
            "1",
        ] {
            let mut headers = HeaderMap::new();
            if let Ok(value) = HeaderValue::from_str(forged) {
                headers.insert(
                    axum::http::HeaderName::from_static(ironauth_config::FORWARD_DECISION_HEADER),
                    value,
                );
            }
            assert_eq!(
                hop_from_headers(&headers),
                ProxyHop::Untrusted,
                "a client-supplied `{forged}` must not read as a trusted hop"
            );
        }

        assert_eq!(
            hop_from_headers(&HeaderMap::new()),
            ProxyHop::Untrusted,
            "absent is untrusted: an unwired deployment must refuse, not admit"
        );
    }

    /// Each action renders the status a proxy can act on.
    ///
    /// The step-up case is the one worth pinning: RFC 9470 makes it a 401 CHALLENGE, and a
    /// 403 would tell a caller who can reach a stronger authentication to stop trying.
    #[test]
    fn each_action_renders_its_own_status_and_challenge() {
        assert_eq!(
            render(&outcome(Action::Allow, Vec::new()), &[]).status(),
            StatusCode::OK
        );
        assert_eq!(
            render(&outcome(Action::Deny, Vec::new()), &[]).status(),
            StatusCode::FORBIDDEN
        );

        let stepped = render(
            &outcome(
                Action::StepUp {
                    acr: "urn:example:mfa".to_owned(),
                },
                Vec::new(),
            ),
            &[],
        );
        assert_eq!(stepped.status(), StatusCode::UNAUTHORIZED);
        let challenge = stepped
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .expect("a step-up carries a challenge")
            .to_str()
            .expect("the challenge is ASCII");
        assert!(
            challenge.contains("insufficient_user_authentication"),
            "RFC 9470 names the error; got {challenge}"
        );
        assert!(
            challenge.contains("urn:example:mfa"),
            "the challenge must name the acr the caller has to reach; got {challenge}"
        );
    }

    /// IDENTITY HEADERS ON AN ALLOW AND NOWHERE ELSE.
    ///
    /// The contrast is the assertion: the same upstream headers are handed to all three
    /// actions, and only the allow may emit them. A refusal that still carried `Remote-User`
    /// would hand the upstream an identity for a request it was told to refuse.
    #[test]
    fn upstream_identity_headers_are_emitted_only_on_an_allow() {
        let upstream = vec![("remote-user".to_owned(), "usr_1".to_owned())];

        let allowed = render(&outcome(Action::Allow, upstream.clone()), &[]);
        assert_eq!(
            allowed
                .headers()
                .get("remote-user")
                .and_then(|v| v.to_str().ok()),
            Some("usr_1")
        );

        for refused in [
            Action::Deny,
            Action::StepUp {
                acr: "urn:example:mfa".to_owned(),
            },
        ] {
            let response = render(&outcome(refused, upstream.clone()), &[]);
            assert!(
                response.headers().get("remote-user").is_none(),
                "a refusal must not hand the upstream an identity"
            );
        }
    }

    /// The must-delete instruction reaches the proxy, and is absent when there is nothing
    /// to delete rather than being an empty header nobody can act on.
    #[test]
    fn the_must_delete_instruction_is_present_only_when_there_is_one() {
        let forged = vec!["remote-user".to_owned(), "remote-groups".to_owned()];
        let response = render(&outcome(Action::Deny, Vec::new()), &forged);
        assert_eq!(
            response
                .headers()
                .get(MUST_DELETE_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("remote-user, remote-groups")
        );

        let clean = render(&outcome(Action::Deny, Vec::new()), &[]);
        assert!(clean.headers().get(MUST_DELETE_HEADER).is_none());
    }
}
