// SPDX-License-Identifier: MIT OR Apache-2.0

//! Creating a customer organization's SAML upstream (issue #140 criterion 1).
//!
//! # The granting path this surface exists to be
//!
//! `saml_connections` has been read on the sign-in path since #139 -- `saml_signin`,
//! `saml_acs` and the portal's renewal and single-sign-on panels all resolve it -- and until
//! now NOTHING in the product wrote a row. A workspace scan found zero non-test callers of
//! `saml_connections().create`: the table was reachable only through a config snapshot
//! restore. #140's first criterion is a customer's IT admin completing SSO setup with no
//! vendor-side action, and there was no vendor-side action either.
//!
//! # The deployment owns the path; the caller owns the host
//!
//! `saml_acs` verifies an assertion's `Recipient` against the STORED `acs_url`, and
//! `saml_metadata` publishes that same stored value to the identity provider. The route is
//! mounted at `/t/{tenant}/e/{environment}/saml/acs/{connection}`, so a stored URL whose path
//! is anything else describes a connection that can never complete a sign-in -- the provider
//! posts where it was told, and nothing answers.
//!
//! Nothing enforced that, because nothing wrote the column. So this endpoint does not accept
//! an `acs_url`. It accepts a `public_base_url` and appends the canonical path to the id it
//! just minted. That is the same division `portal_links` already makes: it returns a
//! `url_path` because "the issuer base for the DATA plane is not necessarily where a human's
//! browser goes", so the caller supplies the host and IronAuth supplies the path. One
//! derivation reaches four consumers -- the ACS route, the assertion check, the metadata
//! document, and the portal page that prints it for the admin to paste.
//!
//! # Why a confined credential may do this
//!
//! Unlike `project_grants`, this does NOT refuse a confined credential. An organization's own
//! delegated administrator creating that organization's SSO connection is the product, and
//! `resolve_live_org` already bounds which organization they may name.
//!
//! It is worth being explicit that this widens what such a credential can do: an identity
//! provider is a way to authenticate AS a member, so a compromised organization-scoped
//! management credential can now add an upstream it controls rather than only edit
//! configuration. That is inherent to self-service SSO.
//!
//! THE CONTROLS THAT ALWAYS APPLY are the audit row and the organization bound: every create
//! is attributed to the organization it names, and `resolve_live_org` is what decides which
//! organization a confined credential may name. `require_fresh_privilege` is also called, but
//! it is NOT a control this module may lean on: `sudo::require_fresh_privilege` returns `Ok`
//! immediately when sudo mode is off, so on a deployment that has not turned it on it is
//! inert. An earlier version of this paragraph offered it as a compensating control without
//! that condition, which reads as a guarantee the default configuration does not provide.
//!
//! # The tuning knobs are the schema's defaults
//!
//! Clock skew, assertion age, `NameID` format, encryption requirement and unsolicited
//! responses are not on this request. Migration 0196 gives each a default and a CHECK, and
//! the values
//! here mirror them exactly rather than offering a second opinion. A connection needing
//! different ones is a follow-up that can add them without changing what this call means.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{CorrelationId, IdempotencyWrite, NewSamlConnection, StoreError};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::{EnvironmentAccess, resolve_live_org, resolve_scope};
use crate::response::json;
use crate::state::AdminState;

/// The longest `public_base_url` this accepts.
///
/// A HOSTNAME IS 253 BYTES AT MOST, plus a scheme and a port. The bound matters beyond
/// tidiness because the two values this endpoint DERIVES are bounded by migration 0196 at
/// 1024 and 2048 bytes: without a bound here, a long base makes the derived `sp_entity_id`
/// violate its CHECK, and the caller's over-long input comes back as a 500 from a constraint
/// rather than a 400 naming the field. With this bound the derived values cannot approach
/// either ceiling.
const MAX_BASE_URL_BYTES: usize = 267;

/// What migration 0196's CHECKs allow, mirrored so an over-long field is a 400 naming it
/// rather than a 500 from a constraint violation the caller cannot see.
const MAX_DISPLAY_NAME_BYTES: usize = 252;
/// See [`MAX_DISPLAY_NAME_BYTES`].
const MAX_IDP_ENTITY_ID_BYTES: usize = 1024;
/// See [`MAX_DISPLAY_NAME_BYTES`].
const MAX_IDP_SSO_URL_BYTES: usize = 2048;

/// The defaults migration 0196 gives, restated where the writer can see them.
const DEFAULT_CLOCK_SKEW_SECS: i32 = 30;
/// See [`DEFAULT_CLOCK_SKEW_SECS`].
const DEFAULT_MAX_ASSERTION_AGE_SECS: i32 = 300;
/// See [`DEFAULT_CLOCK_SKEW_SECS`].
const DEFAULT_NAMEID_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

/// A SAML connection to create.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSamlConnectionRequest {
    /// The operator-facing label, as it appears in the portal and the console.
    pub display_name: String,
    /// What the identity provider calls itself. An assertion's `Issuer` must equal this.
    pub idp_entity_id: String,
    /// Where an `AuthnRequest` is sent.
    pub idp_sso_url: String,
    /// The scheme and host this deployment is reached at, with no path.
    ///
    /// The HOST only: IronAuth appends the ACS and metadata paths itself, because those are
    /// its own routes and a caller cannot know the connection id in advance.
    pub public_base_url: String,
}

/// A created SAML connection, including the two values to paste into a provider's console.
#[derive(Debug, Serialize, ToSchema)]
pub struct SamlConnectionView {
    /// The `smc_` identifier.
    pub id: String,
    /// The organization whose people sign in through this provider.
    pub organization_id: String,
    /// The operator-facing label.
    pub display_name: String,
    /// What the identity provider calls itself.
    pub idp_entity_id: String,
    /// What this deployment calls itself to that provider.
    pub sp_entity_id: String,
    /// Where the provider posts its assertion.
    pub acs_url: String,
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/saml-connections",
    operation_id = "createSamlConnection",
    tag = "organizations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("Idempotency-Key" = String, Header, description = "Required; replays return the original response")
    ),
    request_body = CreateSamlConnectionRequest,
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created. The ACS URL and SP entity id are this deployment's own, derived from the new connection id", body = SamlConnectionView),
        (status = 400, description = "A field is missing, or the base URL is not an absolute http(s) origin", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or fresh privilege is required", body = ErrorBody),
        (status = 404, description = "The organization is not a live row of this scope", body = ErrorBody),
        (status = 409, description = "A live connection of this scope already announces that identity provider entity id", body = ErrorBody)
    )
)]
pub async fn create_saml_connection(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;

    let request: CreateSamlConnectionRequest = parse_json(&body)?;
    let base = origin_of(&request.public_base_url)?;
    check_field_bounds(&request)?;

    let id = ironauth_store::SamlConnectionId::generate(state.env(), &scope);
    // DERIVED FROM THE ID JUST MINTED, which is why the caller cannot supply them: the paths
    // name the connection, and the connection did not exist when the request was written.
    let acs_url = format!(
        "{base}/t/{tenant}/e/{environment}/saml/acs/{id}",
        tenant = scope.tenant(),
        environment = scope.environment(),
    );
    let sp_entity_id = format!(
        "{base}/t/{tenant}/e/{environment}/saml/metadata/{id}",
        tenant = scope.tenant(),
        environment = scope.environment(),
    );

    let view = SamlConnectionView {
        id: id.to_string(),
        organization_id: org_id.to_string(),
        display_name: request.display_name.clone(),
        idp_entity_id: request.idp_entity_id.clone(),
        sp_entity_id: sp_entity_id.clone(),
        acs_url: acs_url.clone(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;

    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 201,
        response_body: &body_string,
    };
    let pending = saml_connection_event(&state, scope, &view);
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .saml_connections()
        .create(
            state.env(),
            NewSamlConnection {
                id: &id,
                organization_id: &org_id,
                display_name: &request.display_name,
                idp_entity_id: &request.idp_entity_id,
                idp_sso_url: &request.idp_sso_url,
                sp_entity_id: &sp_entity_id,
                acs_url: &acs_url,
                allow_unsolicited: false,
                clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
                max_assertion_age_secs: DEFAULT_MAX_ASSERTION_AGE_SECS,
                nameid_format: DEFAULT_NAMEID_FORMAT,
                attribute_mapping: &serde_json::json!({}),
                require_encrypted_assertion: false,
            },
            Some(write),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "a live connection of this scope already announces that identity provider entity id"
                .to_owned(),
        )),
        Err(StoreError::NotFound) => Err(ApiError::NotFound),
        Err(_) => Err(ApiError::Internal),
    }
}

/// Refuse an empty or over-long text field before it reaches the column's CHECK.
///
/// Split out of the handler so that function stays inside the crate's line bound. The limits
/// mirror migration 0196 exactly, so a caller's over-long value is a 400 naming the field
/// rather than a 500 from a constraint they cannot see.
fn check_field_bounds(request: &CreateSamlConnectionRequest) -> Result<(), ApiError> {
    for (field, value, limit) in [
        (
            "display_name",
            &request.display_name,
            MAX_DISPLAY_NAME_BYTES,
        ),
        (
            "idp_entity_id",
            &request.idp_entity_id,
            MAX_IDP_ENTITY_ID_BYTES,
        ),
        ("idp_sso_url", &request.idp_sso_url, MAX_IDP_SSO_URL_BYTES),
    ] {
        if value.trim().is_empty() {
            return Err(ApiError::BadRequest(format!("{field} must not be empty")));
        }
        if value.len() > limit {
            return Err(ApiError::BadRequest(format!(
                "{field} must be at most {limit} bytes"
            )));
        }
    }
    Ok(())
}

/// The scheme-and-host prefix of `raw`, with no trailing slash and no path.
///
/// A PATH IN THE BASE WOULD SILENTLY MOVE THE ACS. The caller supplies a host so IronAuth can
/// append its own routes; accepting `https://auth.example/sso` would store an ACS URL at
/// `/sso/t/.../saml/acs/...`, which nothing serves, and the failure would arrive as a
/// provider posting into a 404 long after the call returned 201.
fn origin_of(raw: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim().trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .ok_or_else(|| {
            ApiError::BadRequest("public_base_url must be an http or https URL".to_owned())
        })?;
    if rest.is_empty() {
        return Err(ApiError::BadRequest(
            "public_base_url must name a host".to_owned(),
        ));
    }
    if trimmed.len() > MAX_BASE_URL_BYTES {
        return Err(ApiError::BadRequest(format!(
            "public_base_url must be at most {MAX_BASE_URL_BYTES} bytes"
        )));
    }
    // AN ALLOWLIST, NOT A DENYLIST OF THE ONE CHARACTER I THOUGHT OF. The first version
    // refused `/` and nothing else, so a query, a fragment, userinfo or a space all passed
    // and every one of them MOVES the derived ACS URL: `https://auth.example?x=1` becomes
    // `https://auth.example?x=1/t/.../saml/acs/...`, where the path this deployment serves
    // has been swallowed into a query string. A host is a narrow grammar and stating it
    // positively is the only way to be sure nothing else is in it.
    let (host, port) = rest
        .split_once(':')
        .map_or((rest, None), |(h, p)| (h, Some(p)));
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !host.starts_with('-')
        && !host.starts_with('.')
        && !host.ends_with('-');
    let port_ok = match port {
        None => true,
        Some(digits) => {
            !digits.is_empty() && digits.len() <= 5 && digits.bytes().all(|b| b.is_ascii_digit())
        }
    };
    if !host_ok || !port_ok {
        return Err(ApiError::BadRequest(
            "public_base_url must be a scheme and host, optionally with a port, and nothing \
             else -- no path, query, fragment, credentials or whitespace"
                .to_owned(),
        ));
    }
    Ok(trimmed.to_owned())
}

/// The `saml_connection.created` announcement, built in the same transaction as the write.
fn saml_connection_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    view: &SamlConnectionView,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let payload = serde_json::json!({
        "saml_connection_id": view.id,
        "organization_id": view.organization_id,
        "idp_entity_id": view.idp_entity_id,
        "sp_entity_id": view.sp_entity_id,
    });
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "saml_connection.created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &payload,
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject: view.id.clone(),
        envelope,
    })
}
