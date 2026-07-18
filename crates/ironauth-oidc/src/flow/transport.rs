// SPDX-License-Identifier: MIT OR Apache-2.0

//! The two transports (issue #84, FORK C): a thin shim over the ONE shared engine
//! ([`super::drive`] / [`super::create_login_flow`]). The state machine, node rendering,
//! message ids, error shaping, and anti enumeration recipe are ONE type, ONE state
//! machine, ONE code path (the found vs unknown equality holds WITHIN a transport; the
//! transport tag, `ui.action`, and browser hidden node differ by design); the transports
//! differ in EXACTLY two mechanical places:
//!
//! 1. submission ingestion: the browser decodes `application/x-www-form-urlencoded` and
//!    runs the [`same_origin_ok`](crate::interaction::same_origin_ok) CSRF check; the API
//!    decodes `application/json` and matches a per flow submit token;
//! 2. continuation: the browser sets the session cookie on a 303 redirect; the API returns
//!    a 200 JSON envelope (and sets the cookie for a client that holds cookies).
//!
//! Every route answers a uniform 404 when `flows.enabled` is off (FORK D), so a deployment
//! that does not use the flow API discloses nothing and the bootstrap pages are untouched.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use ironauth_store::FlowId;
use serde::Deserialize;
use serde_json::{Value, json};

use super::model::{Flow, Journey, Transport};
use super::{
    Continuation, FLOW_CONTRACT_HEADER, FlowError, Submission, TransportAuth, create_login_flow,
    drive, message::Message,
};
use crate::interaction;
use crate::pages;
use crate::state::OidcState;
use crate::wellknown::parse_scope;

/// The browser transport path (GET creates and renders, POST submits): scope routed under
/// the per environment issuer path so the flow runs under the right row level security
/// scope. The `{journey}` is the journey to start (only `login` in PR1).
pub const FLOW_BROWSER_PATH: &str = "/t/{tenant_id}/e/{environment_id}/flow/{journey}";

/// The API transport creation path: POST a JSON body to create a flow and receive the flow
/// object plus the first submit token.
pub const FLOW_CREATE_API_PATH: &str = "/t/{tenant_id}/e/{environment_id}/flow/api/{journey}";

/// The API transport submission path: POST a JSON body with the flow id, the submit token,
/// and the node values.
pub const FLOW_API_SUBMIT_PATH: &str =
    "/t/{tenant_id}/e/{environment_id}/flow/api/{journey}/submit";

/// Stamp the flow contract version response header (issue #84, FORK B) onto a response.
fn with_contract_header(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::HeaderName::from_static(FLOW_CONTRACT_HEADER),
        HeaderValue::from_static("1"),
    );
    response
}

/// The uniform 404 when the flow API is disabled (FORK D): a plain not found with no body,
/// so a deployment that does not use the flow API discloses nothing.
fn disabled_not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// Render a typed flow error as JSON (the API transport). The body carries the numeric
/// message id so a client keys its copy on the number; [`FlowError::Store`] is the neutral
/// server error with no client facing id.
fn error_json(error: FlowError) -> Response {
    let body = match error.message_id() {
        Some(id) => {
            let message = Message::of(id);
            json!({ "error": { "id": message.id, "text": message.text } })
        }
        None => json!({ "error": { "text": "server_error" } }),
    };
    with_contract_header((error.status(), Json(body)).into_response())
}

/// Render a typed flow error as a hardened HTML notice (the browser transport).
fn error_html(error: FlowError) -> Response {
    let text = match error.message_id() {
        Some(id) => Message::of(id).text,
        None => "The request could not be processed.".to_owned(),
    };
    with_contract_header(pages::secure_html(
        error.status(),
        pages::notice_page("Sign in", &text),
    ))
}

/// The API create request body: the journey to start plus the optional resume target and
/// transient payload.
#[derive(Debug, Deserialize)]
pub struct ApiCreateBody {
    /// The resume target to complete back to, or absent.
    #[serde(default)]
    return_to: Option<String>,
    /// Arbitrary client context carried through the flow (never persisted on the identity).
    #[serde(default)]
    transient_payload: Option<Value>,
}

/// The API submit request body: the flow id, the submit token, the node values, and the
/// optional transient payload.
#[derive(Debug, Deserialize)]
pub struct ApiSubmitBody {
    /// The flow id to advance.
    id: String,
    /// The per flow submit token (the API CSRF handle), matched against the row.
    submit_token: String,
    /// The submitted node values keyed by node name.
    #[serde(default)]
    nodes: std::collections::BTreeMap<String, Value>,
    /// Arbitrary client context (never persisted on the identity).
    #[serde(default)]
    transient_payload: Option<Value>,
}

/// The browser GET query: the optional resume target seeded at creation.
#[derive(Debug, Deserialize)]
pub struct BrowserCreateQuery {
    /// The resume target to complete back to, or absent.
    #[serde(default)]
    return_to: Option<String>,
}

/// The browser POST form: the flow id (a hidden field), the node values, and the optional
/// transient payload.
#[derive(Debug, Deserialize)]
pub struct BrowserSubmitForm {
    /// The flow id carried back from the hidden field.
    #[serde(default)]
    flow: String,
    /// The identifier field.
    #[serde(default)]
    identifier: Option<String>,
    /// The password field.
    #[serde(default)]
    password: Option<String>,
    /// The transient payload as a JSON string, or absent.
    #[serde(default)]
    transient_payload: Option<String>,
}

// -------------------------------------------------------------------------------------
// API transport (application/json + submit token).
// -------------------------------------------------------------------------------------

/// `POST /t/{tenant}/e/{env}/flow/api/{journey}` (issue #84): create a flow and return the
/// flow object plus the first submit token as a 200 JSON envelope.
pub async fn flow_api_create(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, journey)): Path<(String, String, String)>,
    Json(body): Json<ApiCreateBody>,
) -> Response {
    if !state.flows_enabled() {
        return disabled_not_found();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return error_json(FlowError::NotFound);
    };
    // PR1 ships the login journey only; any other journey is a typed not found.
    if Journey::parse(&journey) != Some(Journey::Login) {
        return error_json(FlowError::NotFound);
    }
    match create_login_flow(
        &state,
        scope,
        Transport::Api,
        body.return_to.as_deref(),
        body.transient_payload.as_ref(),
    )
    .await
    {
        Ok((_id, submit_token, flow)) => api_flow_envelope(StatusCode::OK, &flow, &submit_token),
        Err(error) => error_json(error),
    }
}

/// `POST /t/{tenant}/e/{env}/flow/api/{journey}/submit` (issue #84): advance a flow. Returns
/// the next flow state plus a rotated submit token, or a completion envelope with the
/// session cookie on success.
pub async fn flow_api_submit(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, _journey)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(body): Json<ApiSubmitBody>,
) -> Response {
    if !state.flows_enabled() {
        return disabled_not_found();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return error_json(FlowError::NotFound);
    };
    let Ok(flow_id) = FlowId::parse_in_scope(&body.id, &scope) else {
        return error_json(FlowError::NotFound);
    };
    let transient_payload = match body.transient_payload {
        Some(Value::Null) | None => None,
        Some(value) => Some(value),
    };
    let submission = Submission {
        node_values: body.nodes,
        transient_payload,
    };
    let auth = TransportAuth::Api {
        presented_submit_token: body.submit_token,
    };
    match drive(
        &state,
        scope,
        &flow_id,
        Transport::Api,
        auth,
        submission,
        &headers,
    )
    .await
    {
        Ok(Continuation::Render { flow, submit_token }) => {
            api_flow_envelope(StatusCode::OK, &flow, &submit_token)
        }
        Ok(Continuation::Complete { session, return_to }) => {
            let body = json!({
                "state": "completed",
                "continue_with": { "redirect_to": return_to },
            });
            let response = with_contract_header((StatusCode::OK, Json(body)).into_response());
            interaction::attach_session_cookies(response, &session)
        }
        Err(error) => error_json(error),
    }
}

/// Build the API JSON envelope: the flow object plus the current submit token, with the
/// contract header.
fn api_flow_envelope(status: StatusCode, flow: &Flow, submit_token: &str) -> Response {
    let body = json!({ "flow": flow, "submit_token": submit_token });
    with_contract_header((status, Json(body)).into_response())
}

// -------------------------------------------------------------------------------------
// Browser transport (form urlencoded + same origin + cookie/redirect).
// -------------------------------------------------------------------------------------

/// `GET /t/{tenant}/e/{env}/flow/{journey}` (issue #84): create a flow and render its HTML
/// form. The flow id rides a hidden field so the POST carries it back.
pub async fn flow_browser_get(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, journey)): Path<(String, String, String)>,
    Query(query): Query<BrowserCreateQuery>,
) -> Response {
    if !state.flows_enabled() {
        return disabled_not_found();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return error_html(FlowError::NotFound);
    };
    if Journey::parse(&journey) != Some(Journey::Login) {
        return error_html(FlowError::NotFound);
    }
    match create_login_flow(
        &state,
        scope,
        Transport::Browser,
        query.return_to.as_deref(),
        None,
    )
    .await
    {
        Ok((_id, _submit_token, flow)) => {
            with_contract_header(pages::secure_html(StatusCode::OK, render_flow_html(&flow)))
        }
        Err(error) => error_html(error),
    }
}

/// `POST /t/{tenant}/e/{env}/flow/{journey}` (issue #84): submit the browser form. Runs the
/// same origin CSRF gate, then the SAME engine; re-renders the HTML form on a validation or
/// authentication failure, or 303 redirects setting the session cookie on completion.
pub async fn flow_browser_post(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, _journey)): Path<(String, String, String)>,
    headers: HeaderMap,
    Form(form): Form<BrowserSubmitForm>,
) -> Response {
    if !state.flows_enabled() {
        return disabled_not_found();
    }
    // The browser CSRF IO edge: the same origin gate (issue #196) BEFORE any state change,
    // exactly as the bootstrap login POST does.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return with_contract_header(interaction::forbidden_page());
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return error_html(FlowError::NotFound);
    };
    let Ok(flow_id) = FlowId::parse_in_scope(&form.flow, &scope) else {
        return error_html(FlowError::NotFound);
    };
    let transient_payload = match form.transient_payload.as_deref() {
        None => None,
        Some(raw) => match serde_json::from_str::<Value>(raw) {
            Ok(Value::Null) => None,
            Ok(value) => Some(value),
            Err(_) => return error_html(FlowError::MalformedTransientPayload),
        },
    };
    let mut node_values = std::collections::BTreeMap::new();
    if let Some(identifier) = form.identifier {
        node_values.insert("identifier".to_owned(), Value::String(identifier));
    }
    if let Some(password) = form.password {
        node_values.insert("password".to_owned(), Value::String(password));
    }
    let submission = Submission {
        node_values,
        transient_payload,
    };
    match drive(
        &state,
        scope,
        &flow_id,
        Transport::Browser,
        TransportAuth::Browser,
        submission,
        &headers,
    )
    .await
    {
        Ok(Continuation::Render { flow, .. }) => {
            with_contract_header(pages::secure_html(StatusCode::OK, render_flow_html(&flow)))
        }
        Ok(Continuation::Complete { session, return_to }) => {
            if let Some(target) = return_to {
                with_contract_header(interaction::redirect_setting_cookie(&target, &session))
            } else {
                // No resume target: render a hardened success notice with the session cookie.
                let notice = pages::secure_html(
                    StatusCode::OK,
                    pages::notice_page(
                        "Signed in",
                        &Message::of(super::message::LOGIN_SUCCESS).text,
                    ),
                );
                with_contract_header(interaction::attach_session_cookies(notice, &session))
            }
        }
        Err(error) => error_html(error),
    }
}

/// Render a flow object to a minimal, hardened HTML form (the browser transport). The
/// hardening (CSP, framing, referrer) is applied by [`pages::secure_html`] at the call
/// site; this builds only the body. Every value is HTML escaped.
fn render_flow_html(flow: &Flow) -> String {
    let mut body = String::new();
    body.push_str("<h1>");
    body.push_str(&escape(&Message::of(super::message::LOGIN_TITLE).text));
    body.push_str("</h1>");
    // Flow level messages.
    for message in &flow.ui.messages {
        body.push_str("<p class=\"message\">");
        body.push_str(&escape(&message.text));
        body.push_str("</p>");
    }
    body.push_str("<form method=\"post\" action=\"");
    body.push_str(&escape(&flow.ui.action));
    body.push_str("\">");
    for node in &flow.ui.nodes {
        render_node_html(&mut body, node);
    }
    body.push_str("</form>");
    body
}

/// Render one node into the form body.
fn render_node_html(body: &mut String, node: &super::model::Node) {
    use super::model::{InputType, NodeAttributes};
    match &node.attributes {
        NodeAttributes::Input {
            name,
            input_type,
            value,
            required,
            ..
        } => {
            let type_attr = match input_type {
                InputType::Text => "text",
                InputType::Password => "password",
                InputType::Email => "email",
                InputType::Tel => "tel",
                InputType::Hidden => "hidden",
                InputType::Checkbox => "checkbox",
                InputType::Submit => "submit",
            };
            if let Some(label) = &node.label {
                if !matches!(input_type, InputType::Hidden | InputType::Submit) {
                    body.push_str("<label>");
                    body.push_str(&escape(&label.text));
                    body.push(' ');
                }
            }
            body.push_str("<input type=\"");
            body.push_str(type_attr);
            body.push_str("\" name=\"");
            body.push_str(&escape(name));
            body.push('"');
            if let Some(value) = value {
                body.push_str(" value=\"");
                body.push_str(&escape(value));
                body.push('"');
            }
            if *required {
                body.push_str(" required");
            }
            body.push('>');
            if node.label.is_some() && !matches!(input_type, InputType::Hidden | InputType::Submit)
            {
                body.push_str("</label>");
            }
            for message in &node.messages {
                body.push_str("<span class=\"error\">");
                body.push_str(&escape(&message.text));
                body.push_str("</span>");
            }
        }
        NodeAttributes::Text { message } => {
            body.push_str("<p>");
            body.push_str(&escape(&message.text));
            body.push_str("</p>");
        }
    }
}

/// Minimal HTML escaping for the values interpolated into the flow form.
fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
}
