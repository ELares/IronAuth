// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authenticated hosted mailbox ceremony. Identity comes from the live cookie;
//! the only continuation is an in-scope authorization request for a registered
//! callback. No mailbox, code or invitation capability is placed in the URL.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;

use crate::{interaction, pages, state::OidcState};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PageQuery {
    return_to: String,
}

fn notice(status: StatusCode, message: &str) -> Response {
    pages::secure_html(status, pages::notice_page("Verify your email", message))
}

pub(crate) async fn page(
    State(state): State<OidcState>,
    Path((tenant, environment)): Path<(String, String)>,
    headers: HeaderMap,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    if state.recipient_verification_transport().is_none() {
        return notice(
            StatusCode::SERVICE_UNAVAILABLE,
            "Email verification is not available on this server yet. Return to your application and contact its administrator.",
        );
    }
    let Ok(Query(query)) = query else {
        return notice(
            StatusCode::BAD_REQUEST,
            "Open email verification from your application's invitation page.",
        );
    };
    if query.return_to.len() > 8192 {
        return notice(
            StatusCode::BAD_REQUEST,
            "The application link is invalid. Open your invitation again.",
        );
    }
    let Some(scope) = crate::wellknown::parse_scope(&tenant, &environment) else {
        return notice(StatusCode::NOT_FOUND, "This verification link is invalid.");
    };
    if interaction::registered_form_origin(&state, Some(&query.return_to), Some(scope))
        .await
        .is_none()
    {
        return notice(
            StatusCode::BAD_REQUEST,
            "The application link is invalid. Open your invitation again.",
        );
    }
    let subject = match crate::account::recipient_page_subject(
        &state,
        &tenant,
        &environment,
        &headers,
    )
    .await
    {
        Ok((_, subject)) => subject,
        Err(_) => {
            let return_to = pages::escape_html(&query.return_to);
            let body = format!(
                "<h1>Sign in again to verify your email</h1><p>For your account's protection, verification requires a recent sign-in. Return to the application, sign in, then reopen email verification.</p><p><a href=\"{return_to}\">Return to application</a></p>"
            );
            return pages::secure_html(StatusCode::UNAUTHORIZED, shell(&body));
        }
    };
    let Ok(user) = state.store().scoped(scope).users().get(&subject).await else {
        return notice(
            StatusCode::SERVICE_UNAVAILABLE,
            "We could not load your account. Try again shortly.",
        );
    };
    if !ironauth_store::recipient_verification::valid_recipient_email(&user.identifier) {
        return notice(
            StatusCode::CONFLICT,
            "Your sign-in identifier is not an email address. Contact your administrator to set up mailbox verification for this account.",
        );
    }
    let verified = match state
        .store()
        .scoped(scope)
        .recipient_verification()
        .current(&subject, &user.identifier)
        .await
    {
        Ok(current) => current.is_some(),
        Err(_) => {
            return notice(
                StatusCode::SERVICE_UNAVAILABLE,
                "We could not check your email verification. Try again shortly.",
            );
        }
    };
    let nonce = crate::login::passkey_nonce(&state);
    let base = format!("/t/{tenant}/e/{environment}/account/email-verification");
    let body = format!(
        r#"<div id="verification" data-base="{base}" data-key="{key}" data-verified="{verified}">
<h1>Verify your email</h1>
<p>Confirm this mailbox belongs to you before continuing to your invitation.</p>
<label for="recipient-email">Signed-in account</label><input id="recipient-email" type="email" value="{email}" readonly autocomplete="email">
<p id="verification-status" role="status" aria-live="polite" tabindex="-1"></p>
<div id="verification-actions">
<form id="send-form"><button id="send-code" type="submit">Send verification code</button></form>
<form id="verify-form" hidden><label for="verification-code">Eight-digit code</label>
<input id="verification-code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{{8}}" maxlength="8" required aria-describedby="code-help">
<p id="code-help">Use the latest code from IronAuth. It expires in five minutes.</p><button id="verify-code" type="submit">Verify email</button></form>
<button id="cancel-verification" class="secondary" type="button">Cancel verification</button>
</div>
<p><a id="return-application" href="{return_to}">Return to application</a></p>
<noscript><p>Enable JavaScript to send and verify your code, then reopen this page.</p></noscript>
</div><script nonce="{nonce}">{script}</script>"#,
        base = pages::escape_html(&base),
        key = pages::escape_html(&format!("recipient-verification:{subject}")),
        email = pages::escape_html(&user.identifier),
        return_to = pages::escape_html(&query.return_to),
        nonce = pages::escape_html(&nonce),
        script = include_str!("recipient_page.js"),
    );
    pages::login_html(StatusCode::OK, shell(&body), &nonce)
}

fn shell(body: &str) -> String {
    pages::document_styled(
        "Verify your email",
        body,
        "en",
        "page",
        "ltr",
        None,
        None,
        None,
    )
}
