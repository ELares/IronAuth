// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CIBA approval page (issue #131 criterion 1).
//!
//! CIBA's whole shape is that the thing asking is NOT the thing approving: a client calls
//! `/backchannel_authenticate` naming a user, and that user approves somewhere else entirely.
//! The store has had both halves of this since the feature landed -- `pending_for_subject` is
//! documented as "the requests awaiting THIS subject's decision (#131 criterion 1)" and
//! `decide` records the answer -- and nothing exposed either of them over HTTP. So a request
//! could be created, could be polled, could expire, and could never be approved by a human at
//! all. Measured before this module existed: the OIDC router had no route reaching
//! `backchannel_auth()` except the client-facing ones.
//!
//! # The cross-device posture, which is the same one the device page documents
//!
//! A person approving here did not start the flow, so every mitigation is about letting them
//! recognise a request they did NOT begin:
//!
//! - the `binding_message` is rendered prominently, and the page says what to do when it does
//!   not match the other device. That message is the only thing tying this screen to the one
//!   the person is actually looking at;
//! - approval is explicit and per request. Each pending request gets its own form, so a
//!   mis-click cannot approve a different request than the one whose message was just read;
//! - the listing is SUBJECT-BOUND in the store's own query, so handing this page another
//!   user's request id renders nothing;
//! - a decision is refused unless it is same-origin, exactly like the other interaction pages;
//! - every refusal answers the same way. "Already decided", "expired", "not yours" and "never
//!   existed" are one message, so the page is not an oracle for which requests exist.
//!
//! # Why an unauthenticated visitor is told rather than redirected
//!
//! [`crate::interaction`] validates `return_to` against a single allowed prefix, the local
//! authorization path. Sending someone here from `/login` would mean widening that allowlist,
//! which is an open-redirect surface change to make an ergonomics improvement. The page says
//! "sign in first" instead.

use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use ironauth_store::{
    BackchannelApprovalLinkage, BackchannelAuthRequestId, CorrelationId, GrantId, Scope,
};
use serde::Deserialize;

use crate::interaction;
use crate::pages::{self, PendingBackchannelItem};
use crate::state::OidcState;
use crate::util::epoch_micros;
use crate::wellknown::parse_scope;

/// The one answer every refusal about a request gets.
///
/// Deliberately identical for "already decided", "expired", "belongs to someone else" and
/// "never existed": a person can act on none of those distinctions, and an attacker holding a
/// guessed id could act on all of them.
const NOT_ACTIONABLE: &str =
    "That request is no longer waiting for a decision. If your other device is still waiting, \
     start again there.";

/// The approval form: which request, and what was decided.
#[derive(Deserialize)]
pub struct ApprovalForm {
    /// The request's logical id, from the hidden field on its own form.
    request_id: String,
    /// `allow` or `deny`. Anything else is treated as neither and refused.
    decision: String,
}

/// `GET /t/{tenant}/e/{environment}/backchannel`: what is waiting for this person.
pub async fn backchannel_get(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    let Some(session) = interaction::resolve_session(&state, scope, &headers).await else {
        return sign_in_first();
    };

    let now = epoch_micros(state.now());
    let Ok(pending) = state
        .store()
        .scoped(scope)
        .backchannel_auth()
        .pending_for_subject(&session.subject, now)
        .await
    else {
        return server_error();
    };

    render(&state, scope, &pending).await
}

/// `POST /t/{tenant}/e/{environment}/backchannel`: record one decision.
pub async fn backchannel_post(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<ApprovalForm>,
) -> Response {
    // SAME-ORIGIN FIRST, before anything is read or looked up. A cross-site POST that got as
    // far as resolving a request id would be a CSRF that silently approves a sign-in.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    let Some(session) = interaction::resolve_session(&state, scope, &headers).await else {
        return sign_in_first();
    };

    // NEITHER value is trusted. An unknown decision is refused rather than defaulted: a
    // default of "deny" would be safe and would still mean a mangled form silently threw away
    // an approval the person made, and a default of "allow" needs no argument.
    let approved = match form.decision.as_str() {
        "allow" => true,
        "deny" => false,
        _ => return notice(StatusCode::BAD_REQUEST, "Approve a sign-in", NOT_ACTIONABLE),
    };
    let Ok(request_id) = BackchannelAuthRequestId::parse_in_scope(&form.request_id, &scope) else {
        // A malformed id is answered exactly like a live one belonging to someone else.
        return notice(StatusCode::OK, "Approve a sign-in", NOT_ACTIONABLE);
    };

    // A GRANT PER APPROVAL, minted here because `decide` refuses an approval without one:
    // the tokens need a revocation spine, and discovering that at redemption strands an
    // approval the person already gave. A denial gets none, because there is nothing to hang
    // off a refusal.
    let grant = approved.then(|| GrantId::generate(state.env(), &scope));
    let now = epoch_micros(state.now());

    // THE DECISION IS ANNOUNCED (issue #131 criterion 1). CIBA's shape is that the thing
    // asking is not the thing approving, so "who said yes to this, and when" is recoverable
    // from nothing else: the client only ever learns that its poll started succeeding. The
    // DENIAL is announced too, and is the half a fraud team most wants -- it issues nothing,
    // so it would otherwise leave no trace at all.
    let event_id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject_id = session.subject.clone();
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        "backchannel_request.decided",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        now / 1000,
        &serde_json::json!({ "request_id": request_id.to_string(), "approved": approved }),
    );
    let decision_event = envelope
        .as_ref()
        .map(|envelope| ironauth_store::DomainEvent {
            id: &event_id,
            // The SUBJECT is the person who decided, which is the whole point of the record.
            subject: &subject_id,
            envelope,
        });
    let decided = state
        .store()
        .scoped(scope)
        .backchannel_auth()
        .decide_with_event(
            state.env(),
            &request_id,
            &session.subject,
            approved,
            BackchannelApprovalLinkage {
                grant_id: grant.as_ref(),
                consent_ref: None,
                // FROZEN FROM THE APPROVING SESSION, which is the point: the ID token's `amr`
                // and `auth_time` must describe how the person who APPROVED authenticated, not
                // how the client that asked did.
                auth_methods: Some(session.auth_methods.as_str()),
                auth_time_micros: Some(session.auth_time_unix_micros),
            },
            now,
            decision_event.as_ref(),
        )
        .await;

    match decided {
        Ok(true) if approved => notice(
            StatusCode::OK,
            "Approved",
            "You approved the sign-in. Your other device can continue.",
        ),
        Ok(true) => notice(
            StatusCode::OK,
            "Denied",
            "You denied the sign-in. Nothing was issued.",
        ),
        // `Ok(false)` is every refusal ABOUT the request, and the store deliberately does not
        // say which. `Err` includes a caller mistake this module should not make; both answer
        // the same, because neither is something the person can act on differently.
        Ok(false) | Err(_) => notice(StatusCode::OK, "Approve a sign-in", NOT_ACTIONABLE),
    }
}

/// Render the pending list, naming each client.
async fn render(
    state: &OidcState,
    scope: Scope,
    pending: &[ironauth_store::PendingBackchannelRequest],
) -> Response {
    let action = approval_path(&scope);
    let mut names: Vec<String> = Vec::with_capacity(pending.len());
    for request in pending {
        // A client that cannot be read falls back to its id rather than dropping the request
        // from the page: a request the person cannot see is one they cannot approve, and the
        // display name is decoration next to the binding message.
        let name = match ironauth_store::ClientId::parse_in_scope(&request.client_id, &scope) {
            Ok(id) => match state.store().scoped(scope).clients().get(&id).await {
                Ok(client) => client.display_name,
                Err(_) => request.client_id.clone(),
            },
            Err(_) => request.client_id.clone(),
        };
        names.push(name);
    }

    let scopes: Vec<Vec<&str>> = pending
        .iter()
        .map(|request| {
            request
                .requested_scope
                .as_deref()
                .map(|scope| scope.split_whitespace().collect())
                .unwrap_or_default()
        })
        .collect();

    // The id is rendered as its own string and re-parsed on the POST, so the round trip goes
    // through exactly the parser that decides whether it is addressable in this scope.
    let request_ids: Vec<String> = pending.iter().map(|r| r.id.to_string()).collect();

    let items: Vec<PendingBackchannelItem<'_>> = pending
        .iter()
        .enumerate()
        .map(|(index, request)| PendingBackchannelItem {
            request_id: request_ids[index].as_str(),
            client_name: names[index].as_str(),
            scopes: scopes[index].as_slice(),
            binding_message: request.binding_message.as_deref(),
        })
        .collect();

    pages::secure_html(
        StatusCode::OK,
        pages::backchannel_approve_page(&action, &items),
    )
}

/// This page's own scope-routed path, which is the decision form's action.
fn approval_path(scope: &Scope) -> String {
    format!(
        "/t/{}/e/{}/backchannel",
        scope.tenant(),
        scope.environment()
    )
}

fn notice(status: StatusCode, title: &str, message: &str) -> Response {
    pages::secure_html(status, pages::notice_page(title, message))
}

fn not_found() -> Response {
    notice(
        StatusCode::NOT_FOUND,
        "Not found",
        "This page is not available.",
    )
}

fn sign_in_first() -> Response {
    notice(
        StatusCode::UNAUTHORIZED,
        "Sign in first",
        "Sign in, then open this page again to see what is waiting for your approval.",
    )
}

fn server_error() -> Response {
    notice(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong",
        "Try again in a moment.",
    )
}
