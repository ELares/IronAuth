// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment locale bundle management (issue #86, PR 2).
//!
//! The management surface for the per-environment localization bundles: set (create or
//! overwrite), get, and delete a bundle keyed on its BCP47 tag. A locale bundle is a DATA-plane
//! scoped resource (`locale_bundles`), reachable by the operator OR by a management key scoped
//! to exactly this environment (the same authorization as environment reads), exactly like
//! organizations.
//!
//! Every write is STRICTLY validated before it is stored (the store keeps only the validated
//! result): every entry key must be a REGISTERED numeric message id (the flow message
//! registry), and every `{placeholder}` in an entry string must be one that id DECLARES in its
//! `context_keys`. So a translator cannot invent an interpolation that leaks unintended context,
//! and a reworded English default never silently breaks an override. A violation is a loud 400
//! naming the offending entry; nothing is stored. A bundle string is PLAIN TEXT, escaped on
//! render exactly like the compiled default, never markup.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_oidc::flow::LanguageTag;
use ironauth_oidc::flow::message::{MessageId, spec_for};
use ironauth_store::{CorrelationId, LocaleBundleId, NewLocaleBundle, Scope};
use std::collections::BTreeMap;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{LocaleBundleView, SetLocaleRequest};

/// Resolve and authorize the `(tenant, environment)` scope from the path (issue #86). The
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

/// Normalize the `{locale}` path parameter to a validated BCP47 tag, or the uniform not-found
/// for a malformed tag (a malformed tag can name no installed locale, so it is indistinguishable
/// from an absent one).
fn parse_locale(raw: &str) -> Result<String, ApiError> {
    LanguageTag::parse(raw)
        .map(|tag| tag.as_str().to_owned())
        .ok_or(ApiError::NotFound)
}

/// Extract the `{placeholder}` names referenced by a bundle string, in order of appearance. A
/// lone `{` with no closing `}` is ignored (it references nothing), so an unbalanced brace is
/// never a spurious placeholder.
fn placeholders(template: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        rest = &rest[open + 1..];
        if let Some(close) = rest.find('}') {
            let name = &rest[..close];
            if !name.is_empty() {
                names.push(name.to_owned());
            }
            rest = &rest[close + 1..];
        } else {
            break;
        }
    }
    names
}

/// The largest a single localized string may be. A UI label, title, or error line is short; this
/// bound (generous for any real translation) keeps a management key holder from storing a huge
/// string that then inflates the cost of every subsequent flow render for the environment.
const MAX_LOCALE_STRING_BYTES: usize = 4096;

/// Strictly validate a set request (issue #86): every entry key must be a REGISTERED numeric
/// message id, every entry string is bounded by [`MAX_LOCALE_STRING_BYTES`], and every
/// `{placeholder}` in an entry string must be one that id declares in its `context_keys`. On
/// success returns the validated entries serialized as the JSON object the store persists verbatim
/// (a decode/encode fault is an internal error, not a client fault). The entry COUNT is bounded
/// intrinsically: a duplicate key cannot exist in the map and every key must be a registered id,
/// so at most the registry size of entries can validate.
fn validate_and_serialize(request: &SetLocaleRequest) -> Result<String, ApiError> {
    for (key, value) in &request.entries {
        let id: u32 = key.parse().map_err(|_| {
            ApiError::BadRequest(format!(
                "locale entry key {key:?} is not a numeric message id"
            ))
        })?;
        if value.len() > MAX_LOCALE_STRING_BYTES {
            return Err(ApiError::BadRequest(format!(
                "locale entry for message {key} is {} bytes, over the {MAX_LOCALE_STRING_BYTES} \
                 byte limit",
                value.len()
            )));
        }
        let spec = spec_for(MessageId(id)).ok_or_else(|| {
            ApiError::BadRequest(format!(
                "locale entry key {key:?} is not a registered message id"
            ))
        })?;
        for placeholder in placeholders(value) {
            if !spec.context_keys.contains(&placeholder.as_str()) {
                return Err(ApiError::BadRequest(format!(
                    "locale entry for message {key} references placeholder {{{placeholder}}}, \
                     which message {key} does not declare"
                )));
            }
        }
    }
    serde_json::to_string(&request.entries).map_err(|_| ApiError::Internal)
}

/// Build the API view of a stored locale bundle.
fn view_of(
    locale: String,
    is_env_default: bool,
    entries_json: &str,
) -> Result<LocaleBundleView, ApiError> {
    let entries: BTreeMap<String, String> =
        serde_json::from_str(entries_json).map_err(|_| ApiError::Internal)?;
    Ok(LocaleBundleView {
        locale,
        is_env_default,
        entries,
    })
}

/// Set (create or overwrite) a per-environment locale bundle.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/locales/{locale}",
    operation_id = "setLocale",
    tag = "locales",
    request_body = SetLocaleRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("locale" = String, Path, description = "The BCP47 language tag (for example fr or fr-CA)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Set", body = LocaleBundleView),
        (status = 400, description = "Unregistered message id or undeclared placeholder", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found or malformed locale tag", body = ErrorBody)
    )
)]
pub async fn set_locale(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, locale)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    // A locale write rewrites the plain text of the auth pages (login, recovery, error copy), a
    // social engineering surface, so it demands fresh privilege exactly like the other environment
    // scoped management writes (organizations, connectors).
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let locale = parse_locale(&locale)?;

    // The environment must exist (a clean 404 rather than a foreign-key error).
    state
        .store()
        .management()
        .environments(scope.tenant())
        .get(&scope.environment())
        .await?;

    let request: SetLocaleRequest = parse_json(&body)?;
    // Store ONLY the validated result: an unregistered id or an undeclared placeholder is a loud
    // 400 and nothing is written.
    let entries_json = validate_and_serialize(&request)?;

    let created_at_micros = state.now_unix_micros();
    let id = LocaleBundleId::generate(state.env(), &scope);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .locale_bundles()
        .set(
            state.env(),
            &id,
            created_at_micros,
            NewLocaleBundle {
                locale: &locale,
                is_env_default: request.is_env_default,
                entries_json: &entries_json,
            },
        )
        .await?;

    let view = view_of(locale, request.is_env_default, &entries_json)?;
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Get a per-environment locale bundle by tag.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/locales/{locale}",
    operation_id = "getLocale",
    tag = "locales",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("locale" = String, Path, description = "The BCP47 language tag (for example fr or fr-CA)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The locale bundle", body = LocaleBundleView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_locale(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, locale)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let locale = parse_locale(&locale)?;
    let record = state
        .store()
        .scoped(scope)
        .locale_bundles()
        .get(&locale)
        .await?
        .ok_or(ApiError::NotFound)?;
    let view = view_of(record.locale, record.is_env_default, &record.entries_json)?;
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Delete a per-environment locale bundle by tag.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/locales/{locale}",
    operation_id = "deleteLocale",
    tag = "locales",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("locale" = String, Path, description = "The BCP47 language tag (for example fr or fr-CA)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn delete_locale(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, locale)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let locale = parse_locale(&locale)?;
    // Resolve the stored id by tag (a uniform not-found when absent), then delete by id so the
    // audit row names the immutable bundle id.
    let record = state
        .store()
        .scoped(scope)
        .locale_bundles()
        .get(&locale)
        .await?
        .ok_or(ApiError::NotFound)?;
    let id = LocaleBundleId::parse_in_scope(&record.id, &scope).map_err(|_| ApiError::NotFound)?;
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .locale_bundles()
        .delete(state.env(), &id)
        .await?;
    Ok(no_content())
}

#[cfg(test)]
mod tests {
    use super::{parse_locale, placeholders, validate_and_serialize};
    use crate::error::ApiError;
    use crate::views::SetLocaleRequest;
    use ironauth_oidc::flow::message::{
        FEDERATION_CONTINUE_LABEL, LOGIN_TITLE, MessageId, RECOVERY_ACK,
    };
    use std::collections::BTreeMap;

    fn id(message: MessageId) -> String {
        message.0.to_string()
    }

    fn request(entries: Vec<(String, &str)>) -> SetLocaleRequest {
        let map: BTreeMap<String, String> = entries
            .into_iter()
            .map(|(k, v)| (k, v.to_owned()))
            .collect();
        SetLocaleRequest {
            entries: map,
            is_env_default: false,
        }
    }

    #[test]
    fn placeholders_extracts_declared_names_and_ignores_unbalanced_braces() {
        assert_eq!(placeholders("Continuer avec {provider}"), vec!["provider"]);
        assert_eq!(placeholders("plain text"), Vec::<String>::new());
        assert_eq!(placeholders("a {one} b {two} c"), vec!["one", "two"]);
        // An unbalanced brace references nothing.
        assert_eq!(placeholders("dangling {open"), Vec::<String>::new());
        // An empty placeholder is not a name.
        assert_eq!(placeholders("empty {}"), Vec::<String>::new());
    }

    #[test]
    fn a_plain_registered_entry_validates() {
        let request = request(vec![
            (id(LOGIN_TITLE), "Se connecter"),
            (id(RECOVERY_ACK), "Si un compte existe..."),
        ]);
        let json = validate_and_serialize(&request).expect("valid");
        assert!(json.contains("Se connecter"));
    }

    #[test]
    fn a_declared_placeholder_validates_but_an_undeclared_one_is_rejected() {
        // federation.continue.label declares {provider}, so it is allowed.
        let ok = request(vec![(
            id(FEDERATION_CONTINUE_LABEL),
            "Continuer avec {provider}",
        )]);
        assert!(validate_and_serialize(&ok).is_ok());

        // login.title declares NO context keys, so any placeholder is rejected (a translator
        // cannot invent an interpolation that leaks unintended context).
        let bad = request(vec![(id(LOGIN_TITLE), "Bonjour {provider}")]);
        match validate_and_serialize(&bad) {
            Err(ApiError::BadRequest(message)) => {
                assert!(message.contains("provider"), "{message}");
            }
            other => panic!("expected a 400 for an undeclared placeholder, got {other:?}"),
        }
    }

    #[test]
    fn a_non_numeric_or_unregistered_key_is_rejected() {
        // A non-numeric key.
        assert!(matches!(
            validate_and_serialize(&request(vec![("not_a_number".to_owned(), "x")])),
            Err(ApiError::BadRequest(_))
        ));
        // A numeric but unregistered id.
        assert!(matches!(
            validate_and_serialize(&request(vec![("9999999".to_owned(), "x")])),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn an_oversize_entry_string_is_rejected() {
        // A string over the byte cap is a loud 400, so a management key holder cannot store a huge
        // string that inflates every subsequent flow render for the environment.
        let big = "a".repeat(super::MAX_LOCALE_STRING_BYTES + 1);
        match validate_and_serialize(&request(vec![(id(LOGIN_TITLE), big.as_str())])) {
            Err(ApiError::BadRequest(message)) => {
                assert!(message.contains("limit"), "{message}");
            }
            other => panic!("expected a 400 for an oversize entry, got {other:?}"),
        }
        // A string exactly at the cap is accepted.
        let at_cap = "a".repeat(super::MAX_LOCALE_STRING_BYTES);
        assert!(validate_and_serialize(&request(vec![(id(LOGIN_TITLE), at_cap.as_str())])).is_ok());
    }

    #[test]
    fn parse_locale_normalizes_and_rejects_a_malformed_tag() {
        assert_eq!(parse_locale("FR-CA").expect("valid"), "fr-ca");
        assert!(matches!(
            parse_locale("\"><script>"),
            Err(ApiError::NotFound)
        ));
    }
}
