// SPDX-License-Identifier: MIT OR Apache-2.0

//! The caller's optional readable name, never an identity or email assertion.
use super::{Account, authenticate, json_response, server_error, unauthenticated};
use crate::{interaction, state::OidcState};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use ironauth_store::{CorrelationId, StoreError};
use serde::Deserialize;
use serde_json::{Value, json};

/// A single-field update. No caller-provided subject, scope or claim bag is accepted.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileInput {
    expected_name: String,
    name: String,
}

/// Read only the signed-in person's display label, not their other stored claims.
pub async fn get(
    State(state): State<OidcState>,
    Path((tenant, environment)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let account = match authenticate(&state, &tenant, &environment, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    match read_name(&state, &account).await {
        Ok(name) => json_response(StatusCode::OK, json!({ "name": name })),
        Err(response) => response,
    }
}

async fn read_name(state: &OidcState, account: &Account) -> Result<String, Response> {
    let wire = state
        .store()
        .scoped(account.scope)
        .users()
        .claims_for_subject(&account.subject_str)
        .await
        .map_err(|_| server_error())?
        .ok_or_else(unauthenticated)?;
    let value: Value = serde_json::from_str(&wire).map_err(|_| server_error())?;
    let object = value.as_object().ok_or_else(server_error)?;
    match object.get("name") {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(name)) => Ok(name.clone()),
        _ => Err(server_error()),
    }
}

/// Compare and set the optional label under the user's row lock.
pub async fn post(
    State(state): State<OidcState>,
    Path((tenant, environment)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<ProfileInput>,
) -> Response {
    if !headers.contains_key(header::ORIGIN)
        || !interaction::same_origin_ok(&headers, state.self_origin().as_deref())
    {
        return json_response(StatusCode::FORBIDDEN, json!({"error":"origin_required"}));
    }
    let account = match authenticate(&state, &tenant, &environment, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    let outcome = state
        .store()
        .scoped(account.scope)
        .acting(
            interaction::user_actor(&account.subject),
            CorrelationId::generate(state.env()),
        )
        .users()
        .set_own_display_name(
            state.env(),
            &account.subject,
            &input.expected_name,
            &input.name,
        )
        .await;
    match outcome {
        Ok(()) => json_response(StatusCode::OK, json!({"name":input.name})),
        Err(StoreError::Invalid) => json_response(
            StatusCode::BAD_REQUEST,
            json!({"error":"invalid_name","error_description":"Use up to 80 characters without control characters or surrounding spaces. Leave it blank to remove your display name."}),
        ),
        Err(StoreError::Conflict) => json_response(
            StatusCode::CONFLICT,
            json!({"error":"profile_changed","error_description":"Your name changed in another session. Read the current name before saving again."}),
        ),
        Err(StoreError::NotFound) => unauthenticated(),
        Err(_) => server_error(),
    }
}

/// Optional hosted continuation. It must be a registered in-scope authorization
/// request, never an arbitrary application URL.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageQuery {
    return_to: Option<String>,
}

/// Hosted account settings for both newly registered and existing people.
pub async fn page(
    State(state): State<OidcState>,
    Path((tenant, environment)): Path<(String, String)>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<PageQuery>,
) -> Response {
    let Ok(account) = authenticate(&state, &tenant, &environment, &headers).await else {
        return crate::pages::secure_html(
            StatusCode::UNAUTHORIZED,
            crate::pages::notice_page(
                "Sign in to edit your name",
                "Return to your application and sign in, then reopen account settings. Your name has not changed.",
            ),
        );
    };
    if let Some(target) = &query.return_to {
        let allowed = target.len() <= 8192
            && interaction::registered_form_origin(&state, Some(target), Some(account.scope))
                .await
                .is_some();
        if !allowed {
            return interaction::invalid_link_page();
        }
    }
    let Ok(name) = read_name(&state, &account).await else {
        return crate::pages::secure_html(
            StatusCode::SERVICE_UNAVAILABLE,
            crate::pages::notice_page(
                "Name unavailable",
                "We could not load your name. Reload this page to try again.",
            ),
        );
    };
    let nonce = crate::login::passkey_nonce(&state);
    let back = query.return_to.as_ref().map_or_else(String::new, |target| {
        format!(
            "<p><a id=\"profile-return\" href=\"{}\">Continue to application</a></p>",
            crate::pages::escape_html(target)
        )
    });
    let base = format!("/t/{tenant}/e/{environment}/account/profile");
    let body = format!(
        r#"<section id="account-profile" data-base="{base}" data-key="{key}">
<h1>Your display name</h1><p class="page-description">Choose how apps recognize you. This is optional and does not change how you sign in or verify your email.</p>
<form id="profile-form"><label for="profile-name">Display name</label>
<input id="profile-name" name="name" value="{name}" autocomplete="name" aria-describedby="profile-help">
<p id="profile-help">Up to 80 characters. Leave blank to remove it. Apps receive this name only when you allow profile access.</p>
<p id="profile-status" role="status" aria-live="polite" tabindex="-1"></p>
<div class="actions"><button id="profile-save" type="submit">Save name</button>
<button id="profile-reload" class="secondary" type="button">Reload saved name</button></div></form>{back}
<noscript><p>Enable JavaScript to edit your display name.</p></noscript></section>
<script nonce="{nonce}">{script}</script>"#,
        base = crate::pages::escape_html(&base),
        key = crate::pages::escape_html(&format!("profile:{}", account.subject)),
        name = crate::pages::escape_html(&name),
        nonce = crate::pages::escape_html(&nonce),
        script = include_str!("profile.js")
    );
    let html = crate::pages::document_styled(
        "Your display name",
        &body,
        "en",
        "page",
        "ltr",
        state.environment_banner(&account.scope).await,
        None,
        None,
    );
    let response = crate::pages::login_html(StatusCode::OK, html, &nonce);
    interaction::with_registered_form_navigation(
        &state,
        query.return_to.as_deref(),
        Some(account.scope),
        response,
    )
    .await
}
