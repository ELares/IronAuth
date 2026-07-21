// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment, per-client signup form management (issue #87, PR 1).
//!
//! The management surface for the signup-form-as-data definitions: set (create or overwrite),
//! get, and delete a form keyed on the authorize `client_id`. A signup form is a DATA-plane
//! scoped resource (`signup_forms`), reachable by the operator OR by a management key scoped to
//! exactly this environment (the same authorization as the environment reads), exactly like
//! locales and connectors.
//!
//! Every write is FAIL-FAST validated against the scope's ACTIVE trait schema before it is stored
//! (the store keeps only the validated result): a field's `trait_pointer` must resolve to an
//! existing trait, that trait must be a RENDERABLE input type, and every rule in `rules` may only
//! TIGHTEN the trait's constraint (a widening rule is rejected). A duplicate order or a duplicate
//! trait pointer within a form is likewise rejected. Every violation is a loud 400 naming the
//! offending trait pointer and keyword, never a value, so a rejection carries no trait PII;
//! nothing is stored. This is PR 1: the config model, storage, and write validation only. The
//! schema-to-node flow generation that RENDERS a form is PR 2.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{
    ClientId, CorrelationId, NewSignupForm, Scope, SignupFormConfig, SignupFormError,
    SignupFormField, SignupFormId, SignupStep, TraitSchema, validate_signup_form,
};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{SetSignupFormRequest, SignupFormFieldView, SignupFormView};

/// Resolve and authorize the `(tenant, environment)` scope from the path (issue #87). The
/// operator passes; a management key must be scoped to exactly this environment (otherwise the
/// LOUD wrong-scope error). A malformed tenant or environment id is the uniform not-found.
fn resolve_scope(
    state: &AdminState,
    principal: &Principal,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(Scope, ironauth_store::ActorRef), ApiError> {
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(tenant_id)?;
    let environment = state
        .store()
        .management()
        .environments(tenant)
        .parse_id(environment_id)?;
    let actor = principal.require_environment(tenant, environment)?;
    Ok((Scope::new(tenant, environment), actor))
}

/// Normalize the `{client_id}` path parameter to a validated, in-scope client id, or the uniform
/// not-found for a malformed or cross-scope id (a form can be keyed only on a client id that
/// belongs to this scope, so anything else names no installable form and is a uniform not-found).
fn parse_client_id(raw: &str, scope: Scope) -> Result<String, ApiError> {
    ClientId::parse_in_scope(raw, &scope)
        .map(|id| id.to_string())
        .map_err(|_| ApiError::NotFound)
}

/// Convert a submitted field view into the store's typed field (issue #87). The `step` string
/// must be one of the two known steps, else a loud 400 (an unknown step names no journey step).
fn field_from_view(view: &SignupFormFieldView) -> Result<SignupFormField, ApiError> {
    let step = match view.step.as_str() {
        "signup" => SignupStep::Signup,
        "later_login" => SignupStep::LaterLogin,
        other => {
            return Err(ApiError::BadRequest(format!(
                "signup form field step {other:?} is not one of \"signup\" or \"later_login\""
            )));
        }
    };
    Ok(SignupFormField {
        trait_pointer: view.trait_pointer.clone(),
        required: view.required,
        order: view.order,
        step,
        rules: view.rules.clone(),
        label_message_id: view.label_message_id,
    })
}

/// Map a fail-fast validation error to a precise, operator-safe 400. Every message names a trait
/// pointer, a keyword, or an order, never a trait value.
fn bad_request(error: &SignupFormError) -> ApiError {
    ApiError::BadRequest(error.to_string())
}

/// Build the typed config from the request, FAIL-FAST validating it against the scope's active
/// trait schema. Stores only a valid form. When there is no active schema a form referencing any
/// trait is rejected (there is nothing to validate against); an empty form is permitted.
async fn validated_config(
    state: &AdminState,
    scope: Scope,
    request: &SetSignupFormRequest,
) -> Result<SignupFormConfig, ApiError> {
    let mut fields = Vec::with_capacity(request.fields.len());
    for view in &request.fields {
        fields.push(field_from_view(view)?);
    }
    let config = SignupFormConfig { fields };
    let active = state.store().scoped(scope).trait_schemas().active().await?;
    match active {
        Some(version) => {
            // A stored schema is well-formed on write; a compile fault here is a real persistence
            // corruption, surfaced as an internal error rather than a client fault.
            let schema =
                TraitSchema::compile(&version.schema_json).map_err(|_| ApiError::Internal)?;
            validate_signup_form(&config, &schema).map_err(|error| bad_request(&error))?;
        }
        None if !config.fields.is_empty() => {
            return Err(ApiError::BadRequest(
                "the environment has no active trait schema, so a signup form field cannot \
                 reference a trait"
                    .to_string(),
            ));
        }
        None => {}
    }
    Ok(config)
}

/// Build the API view of a signup form from its stored field list.
fn view_of(client_id: String, fields_json: &str) -> Result<SignupFormView, ApiError> {
    let config = SignupFormConfig::from_fields_json(fields_json).map_err(|_| ApiError::Internal)?;
    let fields = config
        .fields
        .into_iter()
        .map(|field| SignupFormFieldView {
            trait_pointer: field.trait_pointer,
            required: field.required,
            order: field.order,
            step: match field.step {
                SignupStep::Signup => "signup".to_string(),
                SignupStep::LaterLogin => "later_login".to_string(),
            },
            rules: field.rules,
            label_message_id: field.label_message_id,
        })
        .collect();
    Ok(SignupFormView { client_id, fields })
}

/// Set (create or overwrite) a per-environment, per-client signup form.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/signup-form",
    operation_id = "setSignupForm",
    tag = "signup-forms",
    request_body = SetSignupFormRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier the form governs")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Set", body = SignupFormView),
        (status = 400, description = "A nonexistent or type-incompatible trait, a widening rule, or a duplicate field", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found or malformed client id", body = ErrorBody)
    )
)]
pub async fn set_signup_form(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    // A signup form write changes WHICH identity traits a signup collects and validates, a
    // security-relevant config surface, so it demands fresh privilege exactly like the other
    // environment-scoped management writes (locales, connectors).
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let client_id = parse_client_id(&client_id, scope)?;

    // The environment must exist (a clean 404 rather than a foreign-key error).
    state
        .store()
        .management()
        .environments(scope.tenant())
        .get(&scope.environment())
        .await?;

    let request: SetSignupFormRequest = parse_json(&body)?;
    // Store ONLY the validated result: a nonexistent / type-incompatible trait, a widening rule,
    // or a duplicate field is a loud 400 and nothing is written.
    let config = validated_config(&state, scope, &request).await?;
    let fields_json = config.to_fields_json().map_err(|_| ApiError::Internal)?;

    let created_at_micros = state.now_unix_micros();
    let id = SignupFormId::generate(state.env(), &scope);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .signup_forms()
        .set(
            state.env(),
            &id,
            created_at_micros,
            NewSignupForm {
                client_id: &client_id,
                fields_json: &fields_json,
            },
        )
        .await?;

    let view = view_of(client_id, &fields_json)?;
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Get a per-environment, per-client signup form.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/signup-form",
    operation_id = "getSignupForm",
    tag = "signup-forms",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier the form governs")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The signup form", body = SignupFormView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_signup_form(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let client_id = parse_client_id(&client_id, scope)?;
    let record = state
        .store()
        .scoped(scope)
        .signup_forms()
        .get(&client_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let view = view_of(record.client_id, &record.fields_json)?;
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Delete a per-environment, per-client signup form.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/signup-form",
    operation_id = "deleteSignupForm",
    tag = "signup-forms",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier the form governs")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn delete_signup_form(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let client_id = parse_client_id(&client_id, scope)?;
    // Resolve the stored id by client (a uniform not-found when absent), then delete by id so the
    // audit row names the immutable signup form id.
    let record = state
        .store()
        .scoped(scope)
        .signup_forms()
        .get(&client_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let id = SignupFormId::parse_in_scope(&record.id, &scope).map_err(|_| ApiError::NotFound)?;
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .signup_forms()
        .delete(state.env(), &id)
        .await?;
    Ok(no_content())
}

#[cfg(test)]
mod tests {
    use super::field_from_view;
    use crate::error::ApiError;
    use crate::views::SignupFormFieldView;
    use serde_json::json;

    fn view(step: &str) -> SignupFormFieldView {
        SignupFormFieldView {
            trait_pointer: "/email".to_string(),
            required: true,
            order: 0,
            step: step.to_string(),
            rules: json!({}),
            label_message_id: 1070,
        }
    }

    #[test]
    fn a_known_step_converts_and_an_unknown_step_is_rejected() {
        assert!(field_from_view(&view("signup")).is_ok());
        assert!(field_from_view(&view("later_login")).is_ok());
        match field_from_view(&view("whenever")) {
            Err(ApiError::BadRequest(message)) => {
                assert!(message.contains("whenever"), "{message}");
            }
            other => panic!("expected a 400 for an unknown step, got {other:?}"),
        }
    }
}
