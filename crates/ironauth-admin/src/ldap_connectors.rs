// SPDX-License-Identifier: MIT OR Apache-2.0

//! The LDAP/AD connector management surface, and per-connector sync health (issue #142).
//!
//! # Why the health half is here rather than in a metrics exporter
//!
//! #142's isolation criterion has two halves: one unreachable server degrades only its own
//! connector, and an operator can SEE which one. The first shipped with the scheduler. The second
//! was a warning in a log line, which nothing can be alerted on and no console can render. These
//! routes are that second half: `GET .../ldap-connectors/health` answers "which of my directories
//! is broken right now" in one request.
//!
//! # The bind secret can only name a secret in the connector namespace
//!
//! This is the one rule here that is a security boundary rather than a shape check, and it is the
//! same one the outbound SCIM surface enforces for the same reason. A connector NAMES an
//! `environment_secrets` row and the sweep sends that value to `host` as a bind password. The
//! secret store is otherwise write-only on this plane -- no endpoint returns a secret -- so a
//! connector that could name ANY secret turns it into a read oracle: point one at the database
//! password, at a directory you control, and the sweep delivers it on the next tick. A prefix
//! rather than an allowlist because operators name their own secrets; what it buys is that a
//! connector can only reach a secret somebody deliberately put in the connector namespace.
//!
//! ENFORCED AT THE READ AS WELL AS AT THE WRITE, which is the half that makes it a bound rather
//! than a bound on one door. This POST is the only door the API offers, but a direct store call,
//! a config import, a snapshot restore, or a row written before the rule existed all reach the
//! table without passing it -- so `ldap_boot::StoreSourceFactory::open` checks the prefix again
//! before opening the secret, exactly as the outbound SCIM scheduler does.
//!
//! # Nothing here returns a secret, and there is nothing to return
//!
//! The connector row holds a secret NAME, so there is no plaintext for any response to leak --
//! a property of the model rather than of care taken in this file. The shapes differ: the create
//! and its idempotency replay return two fields (the handle and the label), while the listing
//! renders the row. Named here because the safety argument is about the ROW holding no secret,
//! not about the three responses being alike -- a create later extended to echo the full row
//! inherits the same guarantee for the same reason.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, LdapAbsencePolicy, LdapConnectorId, LdapTlsMode,
    NewLdapConnector, OrganizationId, Scope, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::org_context::{EnvironmentAccess, resolve_live_org, resolve_scope};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// The namespace a connector's bind secret must live in.
///
/// See the module header: without it, configuring a connector reads any secret in the
/// environment. The outbound SCIM surface uses `scim_push_` for the identical hazard.
pub const BIND_SECRET_PREFIX: &str = "ldap_bind_";

/// The longest operator-facing label the row accepts, matching 0212's CHECK.
const MAX_LABEL_BYTES: usize = 200;
/// The longest DN or filter the row accepts, matching 0212's CHECKs.
const MAX_DN_BYTES: usize = 1024;
/// The longest filter, matching 0212.
const MAX_FILTER_BYTES: usize = 4096;
/// The deepest nested-group walk 0212 permits.
const MAX_GROUP_DEPTH: i32 = 64;

/// One connector, as the management surface renders it.
///
/// THE SECRET NAME IS HERE AND THE SECRET IS NOT, because the row holds only the name.
#[derive(Debug, Serialize, ToSchema)]
pub struct LdapConnectorView {
    /// The non-secret `ldc_` handle. Every other operation names the connector by this.
    pub id: String,
    /// The organization whose users this directory populates.
    pub organization_id: String,
    /// The operator-facing label.
    pub display_name: String,
    /// The directory host.
    pub host: String,
    /// The directory port.
    pub port: u16,
    /// `ldaps`, `starttls` or `plaintext`.
    pub tls_mode: String,
    /// The DN the sweep binds as.
    pub bind_dn: String,
    /// The NAME of the environment secret holding the bind password.
    pub bind_secret_name: String,
    /// Where users live.
    pub user_base_dn: String,
    /// Where groups live, empty when the connector syncs users only.
    pub group_base_dn: String,
    /// Which entries under the user base are users.
    pub user_filter: String,
    /// Which entries under the group base are groups, empty with no group base.
    pub group_filter: String,
    /// How directory attributes become identity.
    #[schema(value_type = Object)]
    pub attribute_mapping: serde_json::Value,
    /// `deactivate` or `delete`.
    pub absence_policy: String,
    /// How deep nested groups resolve.
    pub max_group_depth: i32,
    /// Whether the sweep serves this connector.
    pub active: bool,
    /// When it was configured, in milliseconds since the epoch.
    pub created_at_unix_ms: i64,
}

/// A page of connectors.
#[derive(Debug, Serialize, ToSchema)]
pub struct LdapConnectorListView {
    /// This organization's connectors.
    pub items: Vec<LdapConnectorView>,
    /// The cursor for the next page, absent on the last one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// One connector's sync health.
#[derive(Debug, Serialize, ToSchema)]
pub struct LdapHealthView {
    /// The connector this describes.
    pub connector_id: String,
    /// Whether it needs attention. FALSE for a connector that binds fine and fails to apply
    /// every principal, which reports a successful outcome.
    pub healthy: bool,
    /// `planned`, `unreachable`, `failed`, `timed_out` or `skipped`.
    pub outcome: String,
    /// The KIND of failure, absent on a successful pass.
    ///
    /// NEVER the directory's own message: it can carry a DN, which names a person and their
    /// place in an organization. The full text is in the log.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// When the last pass reached this connector, in milliseconds since the epoch.
    pub last_run_at_unix_ms: i64,
    /// How long that pass took.
    pub duration_ms: i64,
    /// Passes in a row that did not produce a plan.
    pub consecutive_failures: i32,
    /// The last pass that DID produce a plan.
    ///
    /// Present so a reader can tell how STALE the view of the directory is, not merely that the
    /// last attempt failed. A connector down for a day and one down for a minute report the same
    /// outcome and different values here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_at_unix_ms: Option<i64>,
    /// Accounts created on the last pass.
    pub provisioned: i32,
    /// Arrivals that already had an account.
    pub already_present: i32,
    /// Accounts disabled.
    pub deactivated: i32,
    /// Accounts removed.
    pub deleted: i32,
    /// Per-principal failures inside an otherwise successful pass.
    pub apply_failures: i32,
}

/// Every connector's health in one organization.
#[derive(Debug, Serialize, ToSchema)]
pub struct LdapHealthListView {
    /// One entry per connector a pass has reached, most recent first.
    pub items: Vec<LdapHealthView>,
    /// How many of them need attention.
    ///
    /// COUNTED HERE rather than left to the caller, because "is anything wrong" is the question
    /// an alert asks and a caller computing it from the list would each write the predicate
    /// again.
    pub unhealthy: usize,
}

/// What a create names.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateLdapConnectorRequest {
    /// The operator-facing label.
    pub display_name: String,
    /// The directory host.
    pub host: String,
    /// The directory port.
    pub port: u16,
    /// `ldaps` (default), `starttls` or `plaintext`.
    #[serde(default)]
    pub tls_mode: Option<String>,
    /// The DN to bind as.
    pub bind_dn: String,
    /// The environment secret holding the bind password. Must begin with `ldap_bind_`.
    pub bind_secret_name: String,
    /// Where users live.
    pub user_base_dn: String,
    /// Where groups live. Omit for a connector that syncs users only.
    #[serde(default)]
    pub group_base_dn: Option<String>,
    /// Which entries under the user base are users.
    pub user_filter: String,
    /// Which entries under the group base are groups. Required with a group base.
    #[serde(default)]
    pub group_filter: Option<String>,
    /// How directory attributes become identity.
    #[schema(value_type = Object)]
    pub attribute_mapping: serde_json::Value,
    /// `deactivate` (default) or `delete`.
    #[serde(default)]
    pub absence_policy: Option<String>,
    /// How deep nested groups resolve. Defaults to the column default.
    #[serde(default)]
    pub max_group_depth: Option<i32>,
}

/// The 201 of a create.
#[derive(Debug, Serialize, ToSchema)]
pub struct LdapConnectorCreated {
    /// The non-secret handle.
    pub id: String,
    /// The operator-facing label.
    pub display_name: String,
}

/// What a pause or resume names.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetLdapConnectorActiveRequest {
    /// Whether the sweep should serve this connector.
    pub active: bool,
}

fn view(connector: &ironauth_store::LdapConnector) -> LdapConnectorView {
    LdapConnectorView {
        id: connector.id.to_string(),
        organization_id: connector.organization_id.to_string(),
        display_name: connector.display_name.clone(),
        host: connector.host.clone(),
        port: connector.port,
        tls_mode: connector.tls_mode.as_str().to_owned(),
        bind_dn: connector.bind_dn.clone(),
        bind_secret_name: connector.bind_secret_name.clone(),
        user_base_dn: connector.user_base_dn.clone(),
        group_base_dn: connector.group_base_dn.clone(),
        user_filter: connector.user_filter.clone(),
        group_filter: connector.group_filter.clone(),
        attribute_mapping: connector.attribute_mapping.clone(),
        absence_policy: connector.absence_policy.as_str().to_owned(),
        max_group_depth: connector.max_group_depth,
        active: connector.active,
        created_at_unix_ms: crate::scim_connections::micros_to_millis(
            connector.created_at_unix_micros,
        ),
    }
}

fn health_view(record: &ironauth_store::LdapRunRecord) -> LdapHealthView {
    LdapHealthView {
        connector_id: record.connector_id.clone(),
        healthy: record.is_healthy(),
        outcome: record.outcome.as_str().to_owned(),
        error: record.error.clone(),
        last_run_at_unix_ms: crate::scim_connections::micros_to_millis(
            record.started_at_unix_micros,
        ),
        duration_ms: record.duration_ms,
        consecutive_failures: record.consecutive_failures,
        last_success_at_unix_ms: record
            .last_success_at_unix_micros
            .map(crate::scim_connections::micros_to_millis),
        provisioned: record.provisioned,
        already_present: record.already_present,
        deactivated: record.deactivated,
        deleted: record.deleted,
        apply_failures: record.apply_failures,
    }
}

/// A bounded, non-empty field, refused HERE rather than by the column's CHECK.
///
/// A CHECK violation is SQLSTATE 23514, which falls through to a 500: a 500 caused by a request
/// body. Same figures and same unit (bytes) as 0212.
fn bounded(value: &str, field: &str, ceiling: usize) -> Result<String, ApiError> {
    // ONE PREFIX FOR BOTH HALVES. `require_non_empty` emits its own wording, so delegating the
    // empty case would give one field two error shapes and a caller matching on
    // `invalid_<field>` would miss half of them.
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "invalid_{field}: {field} must not be empty"
        )));
    }
    if trimmed.len() > ceiling {
        return Err(ApiError::BadRequest(format!(
            "invalid_{field}: {field} must be at most {ceiling} bytes"
        )));
    }
    Ok(trimmed.to_owned())
}

/// The bind secret name, held to the connector namespace.
fn check_bind_secret_name(value: &str) -> Result<String, ApiError> {
    let value = require_non_empty(value, "bind_secret_name")?;
    if !ironauth_store::esv::name_is_valid(&value) {
        return Err(ApiError::BadRequest(format!(
            "invalid_bind_secret_name: bind_secret_name must be at most {} ASCII letters, \
             digits, underscore, dot or hyphen, which is what an environment secret name may be",
            ironauth_store::esv::MAX_NAME_LEN
        )));
    }
    if !value.starts_with(BIND_SECRET_PREFIX) {
        return Err(ApiError::BadRequest(format!(
            "invalid_bind_secret_name: bind_secret_name must begin with {BIND_SECRET_PREFIX:?}. \
             The sweep sends the named secret to `host` as a bind password, so a connector that \
             could name any secret would make the write-only secret store readable by anyone who \
             can configure one"
        )));
    }
    Ok(value)
}

/// `ldaps` by default, and the insecure choice has to be a value somebody typed.
fn check_tls_mode(value: Option<&str>) -> Result<LdapTlsMode, ApiError> {
    match value {
        None => Ok(LdapTlsMode::Ldaps),
        Some(raw) => LdapTlsMode::parse(raw).ok_or_else(|| {
            ApiError::BadRequest(
                "invalid_tls_mode: tls_mode must be \"ldaps\", \"starttls\" or \"plaintext\""
                    .to_owned(),
            )
        }),
    }
}

/// `deactivate` by default, because the irreversible choice has to be asked for.
fn check_absence_policy(value: Option<&str>) -> Result<LdapAbsencePolicy, ApiError> {
    match value {
        None => Ok(LdapAbsencePolicy::Deactivate),
        Some(raw) => LdapAbsencePolicy::parse(raw).ok_or_else(|| {
            ApiError::BadRequest(
                "invalid_absence_policy: absence_policy must be \"deactivate\" or \"delete\""
                    .to_owned(),
            )
        }),
    }
}

/// The mapping is a JSON object, which is what the mapper reads.
fn check_attribute_mapping(value: serde_json::Value) -> Result<serde_json::Value, ApiError> {
    if !value.is_object() {
        return Err(ApiError::BadRequest(
            "invalid_attribute_mapping: attribute_mapping must be a JSON object of \
             {canonical field: source attribute}"
                .to_owned(),
        ));
    }
    Ok(value)
}

/// The group base and its filter travel together, exactly as 0213's CHECK requires.
///
/// REFUSED HERE for the same reason as every other bound: the constraint would otherwise arrive
/// as a 500. And the pairing is not arbitrary -- a base says where to look and the filter says
/// what counts, so a base with no filter is half a configuration.
fn check_group_pair(
    base: Option<&str>,
    filter: Option<&str>,
) -> Result<(String, String), ApiError> {
    let base = base.unwrap_or_default().to_owned();
    let filter = filter.unwrap_or_default().to_owned();
    if base.trim().is_empty() {
        // USERS ONLY. The filter is meaningless without a base, so a stray one is dropped rather
        // than stored where nothing reads it.
        return Ok((base, String::new()));
    }
    if base.len() > MAX_DN_BYTES {
        return Err(ApiError::BadRequest(format!(
            "invalid_group_base_dn: group_base_dn must be at most {MAX_DN_BYTES} bytes"
        )));
    }
    if filter.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "invalid_group_filter: group_filter is required when group_base_dn is set, because a \
             base says where to look and the filter says what counts"
                .to_owned(),
        ));
    }
    if filter.len() > MAX_FILTER_BYTES {
        return Err(ApiError::BadRequest(format!(
            "invalid_group_filter: group_filter must be at most {MAX_FILTER_BYTES} bytes"
        )));
    }
    Ok((base, filter))
}

/// The nested-group depth, held to 0212's range.
fn check_depth(value: Option<i32>) -> Result<i32, ApiError> {
    let depth = value.unwrap_or(10);
    if !(0..=MAX_GROUP_DEPTH).contains(&depth) {
        return Err(ApiError::BadRequest(format!(
            "invalid_max_group_depth: max_group_depth must be between 0 and {MAX_GROUP_DEPTH}. \
             Zero resolves no nesting at all, which is a real choice; above a few dozen the \
             recursion is a cycle the detector should have caught"
        )));
    }
    Ok(depth)
}

/// `GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/ldap-connectors`
///
/// # Errors
///
/// [`ApiError::Forbidden`] on the wrong plane, scope or permission; [`ApiError::NotFound`] if
/// the organization does not exist here; [`ApiError::BadRequest`] on a malformed cursor or
/// limit; [`ApiError::Internal`] on a store failure.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/ldap-connectors",
    operation_id = "listLdapConnectors",
    tag = "ldap",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("limit" = Option<i64>, Query, description = "Maximum connectors to return"),
        ("cursor" = Option<String>, Query, description = "Opaque cursor from a previous page"),
    ),
    responses(
        (status = 200, description = "This organization's directory connectors", body = LdapConnectorListView),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such organization", body = ErrorBody)
    )
)]
pub async fn list_ldap_connectors(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`. A listing carries no
    // credential, so it is a strictly smaller capability than pointing a connector somewhere.
    principal.require_permission(ManagementPermission::Read)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let connectors = state
        .store()
        .scoped(scope)
        .ldap_connectors()
        .list_for_org(&org_id, page.fetch_limit(), page.after())
        .await
        .map_err(|_| ApiError::Internal)?;
    let (connectors, next_cursor) = page.finish(connectors, |connector| {
        (connector.created_at_unix_micros, connector.id.to_string())
    });
    let body = serde_json::to_string(&LdapConnectorListView {
        items: connectors.iter().map(view).collect(),
        next_cursor,
    })
    .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// `GET .../ldap-connectors/health`
///
/// # Errors
///
/// [`ApiError::Forbidden`] on the wrong plane, scope or permission; [`ApiError::NotFound`] if
/// the organization does not exist here; [`ApiError::Internal`] on a store failure. NOT
/// `BadRequest`: this route takes no query and no body, which its `responses(...)` and the
/// generated spec both already say.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/ldap-connectors/health",
    operation_id = "listLdapConnectorHealth",
    tag = "ldap",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
    ),
    responses(
        (status = 200, description = "How each directory's last sync went", body = LdapHealthListView),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such organization", body = ErrorBody)
    )
)]
pub async fn list_ldap_connector_health(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`. Health names no
    // secret and no host; it is strictly smaller than the writes below.
    principal.require_permission(ManagementPermission::Read)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;

    // SCOPED TO THIS ORGANIZATION, which the health table cannot do on its own: it is keyed by
    // connector and carries no organization column, deliberately, because health belongs to the
    // connector rather than to the org. So the org's connectors are read first and the health
    // rows filtered to them. Without this an operator delegated one organization would read
    // every directory in the environment -- host names and failure states included.
    // THE CAP IS THE STORE'S, stated rather than left to be discovered: `list_for_org` clamps to
    // `MANAGEMENT_LIST_HARD_CAP + 1`, so an organization past ~1000 connectors would have the
    // tail of its health silently omitted and `unhealthy` would under-count. No deployment is
    // near that, and the honest fix when one is is a cursor on this route rather than a bigger
    // number here.
    let mine: std::collections::BTreeSet<String> = state
        .store()
        .scoped(scope)
        .ldap_connectors()
        .list_for_org(&org_id, i64::from(u32::MAX), None)
        .await
        .map_err(|_| ApiError::Internal)?
        .iter()
        .map(|connector| connector.id.to_string())
        .collect();
    let health = state
        .store()
        .scoped(scope)
        .ldap_sync_runs()
        .in_scope()
        .await
        .map_err(|_| ApiError::Internal)?;
    let items: Vec<LdapHealthView> = health
        .iter()
        .filter(|record| mine.contains(&record.connector_id))
        .map(health_view)
        .collect();
    let unhealthy = items.iter().filter(|item| !item.healthy).count();
    let body = serde_json::to_string(&LdapHealthListView { items, unhealthy })
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// The `ldap_connector.created` envelope, its id, and its subject.
///
/// Split out of the handler because adding it there took `create_ldap_connector` to 113 lines
/// against the crate's hundred-line clippy ceiling -- which a targeted `cargo test` does not
/// see and only the lint does.
///
/// It names the HOST and the TLS MODE beside the ids, because the question a consumer asks
/// about a directory connector is "where is this organization's identity data now read from,
/// and is that connection protected". Neither the bind DN nor the secret name travels: no
/// receiver can resolve either, and naming an environment secret on the wire only says which
/// one to attack.
fn created_envelope(
    state: &AdminState,
    scope: Scope,
    id: &LdapConnectorId,
    organization_id: &OrganizationId,
    host: &str,
    tls_mode: LdapTlsMode,
) -> (String, String, Option<serde_json::Value>) {
    let event_id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        "ldap_connector.created",
        &scope.tenant().to_string(),
        &subject,
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "ldap_connector_id": subject,
            "organization_id": organization_id.to_string(),
            "host": host,
            "tls_mode": tls_mode.as_str(),
        }),
    );
    (event_id, subject, envelope)
}

/// `POST .../ldap-connectors`
///
/// # Errors
///
/// [`ApiError::BadRequest`] on any invalid field, including a bind secret outside the connector
/// namespace; [`ApiError::Forbidden`] on the wrong plane, scope or permission;
/// [`ApiError::NotFound`] if the organization does not exist here; [`ApiError::Conflict`] if the
/// handle is already used; [`ApiError::Internal`] on a store failure.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/ldap-connectors",
    operation_id = "createLdapConnector",
    tag = "ldap",
    request_body = CreateLdapConnectorRequest,
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replays return the original response."),
    ),
    responses(
        (status = 201, description = "The connector was configured", body = LdapConnectorCreated),
        (status = 400, description = "Invalid configuration", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such organization", body = ErrorBody),
        (status = 409, description = "The handle is already used", body = ErrorBody)
    )
)]
pub async fn create_ldap_connector(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`. Sharper here
    // than for a plain configuration write: the sweep sends the named secret to a HOST the same
    // principal chose, so a caller who could do this with `management.read` could read the
    // write-only secret store.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // BEFORE THE ORGANIZATION RESOLVES, like every sibling: a retry whose organization has since
    // been deleted returns the original response rather than a 404 for work that succeeded.
    let idem_key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &idem_key, &fingerprint).await?
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

    let request: CreateLdapConnectorRequest = parse_json(&body)?;
    let display_name = bounded(&request.display_name, "display_name", MAX_LABEL_BYTES)?;
    let host = bounded(&request.host, "host", 255)?;
    if request.port == 0 {
        return Err(ApiError::BadRequest(
            "invalid_port: port must be between 1 and 65535".to_owned(),
        ));
    }
    let tls_mode = check_tls_mode(request.tls_mode.as_deref())?;
    let bind_dn = bounded(&request.bind_dn, "bind_dn", MAX_DN_BYTES)?;
    let bind_secret_name = check_bind_secret_name(&request.bind_secret_name)?;
    let user_base_dn = bounded(&request.user_base_dn, "user_base_dn", MAX_DN_BYTES)?;
    let user_filter = bounded(&request.user_filter, "user_filter", MAX_FILTER_BYTES)?;
    let (group_base_dn, group_filter) = check_group_pair(
        request.group_base_dn.as_deref(),
        request.group_filter.as_deref(),
    )?;
    let attribute_mapping = check_attribute_mapping(request.attribute_mapping)?;
    let absence_policy = check_absence_policy(request.absence_policy.as_deref())?;
    let max_group_depth = check_depth(request.max_group_depth)?;

    let id = LdapConnectorId::generate(state.env(), &scope);
    // BUILT BEFORE THE WRITE, because the idempotency record stores it in the same transaction:
    // a replay must return the ORIGINAL bytes, so they have to exist by the time the row does.
    let created = LdapConnectorCreated {
        id: id.to_string(),
        display_name: display_name.clone(),
    };
    let stored_body = serde_json::to_string(&created).map_err(|_| ApiError::Internal)?;
    // The domain event (issue #108), built by the helper below so this handler stays under the
    // crate's hundred-line ceiling.
    let (event_id, subject, envelope) =
        created_envelope(&state, scope, &id, &org_id, &host, tls_mode);
    let created_event = envelope
        .as_ref()
        .map(|envelope| ironauth_store::DomainEvent {
            id: &event_id,
            subject: &subject,
            envelope,
        });
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        // ATTRIBUTED TO THE ORGANIZATION, so the org whose directory is being read sees this on
        // its own audit stream.
        .in_organization(org_id)
        .ldap_connectors()
        .create(
            state.env(),
            NewLdapConnector {
                id: &id,
                organization_id: &org_id,
                display_name: &display_name,
                host: &host,
                port: request.port,
                tls_mode,
                bind_dn: &bind_dn,
                bind_secret_name: &bind_secret_name,
                user_base_dn: &user_base_dn,
                group_base_dn: &group_base_dn,
                user_filter: &user_filter,
                group_filter: &group_filter,
                attribute_mapping: &attribute_mapping,
                absence_policy,
                max_group_depth,
            },
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &idem_key,
                request_fingerprint: &fingerprint,
                response_status: 201,
                response_body: &stored_body,
            }),
            created_event.as_ref(),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, stored_body)),
        Err(StoreError::Conflict) => Err(ApiError::Conflict("connector_exists".to_owned())),
        Err(StoreError::NotFound) => Err(ApiError::NotFound),
        // THE RACE THE RECORD EXISTS TO CLOSE: two requests carrying one key arrive together,
        // both pass `replay_if_stored`, and the loser meets the winner's primary key. Its whole
        // transaction rolls back, so no second connector exists, and it then returns the
        // winner's committed 201 -- the id that was minted, which is what the caller wants.
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &idem_key, &fingerprint)
                .await
        }
        // EVERYTHING ELSE IS A 500. Mapping a bare database error onto a 400 naming a field is
        // how a revoked grant or a full disk tells a caller their input was wrong.
        Err(_) => Err(ApiError::Internal),
    }
}

/// `PUT .../ldap-connectors/{connector_id}/active`
///
/// # Errors
///
/// [`ApiError::Forbidden`] on the wrong plane, scope or permission; [`ApiError::NotFound`] if no
/// such connector belongs to this organization; [`ApiError::BadRequest`] on a malformed body;
/// [`ApiError::Internal`] on a store failure.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/ldap-connectors/{connector_id}/active",
    operation_id = "setLdapConnectorActive",
    tag = "ldap",
    request_body = SetLdapConnectorActiveRequest,
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("connector_id" = String, Path, description = "Connector identifier"),
    ),
    responses(
        (status = 204, description = "The connector was paused or resumed"),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such connector", body = ErrorBody)
    )
)]
pub async fn set_ldap_connector_active(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, connector_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`. Sharper here
    // than for a plain configuration write: the sweep sends the named secret to a HOST the same
    // principal chose, so a caller who could do this with `management.read` could read the
    // write-only secret store.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
    let request: SetLdapConnectorActiveRequest = parse_json(&body)?;
    // PARSED IN SCOPE. An id from another scope is a 404 rather than a refusal that admits the
    // connector exists somewhere.
    let id =
        LdapConnectorId::parse_in_scope(&connector_id, &scope).map_err(|_| ApiError::NotFound)?;
    // ONE event with a boolean rather than two types: a consumer's question is "is this
    // organization's directory still being read", and two types would make that a join.
    let event_id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        "ldap_connector.active_changed",
        &scope.tenant().to_string(),
        &subject,
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "ldap_connector_id": subject,
            "organization_id": org_id.to_string(),
            "active": request.active,
        }),
    );
    let active_event = envelope
        .as_ref()
        .map(|envelope| ironauth_store::DomainEvent {
            id: &event_id,
            subject: &subject,
            envelope,
        });
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .in_organization(org_id)
        .ldap_connectors()
        .set_active(
            state.env(),
            &org_id,
            &id,
            request.active,
            active_event.as_ref(),
        )
        .await
        .map_err(|error| match error {
            StoreError::NotFound => ApiError::NotFound,
            _ => ApiError::Internal,
        })?;
    Ok(no_content())
}

/// `DELETE .../ldap-connectors/{connector_id}`
///
/// # Errors
///
/// [`ApiError::Forbidden`] on the wrong plane, scope or permission; [`ApiError::NotFound`] if no
/// such connector belongs to this organization; [`ApiError::Internal`] on a store failure. NOT
/// `BadRequest`: this route takes no body.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/ldap-connectors/{connector_id}",
    operation_id = "deleteLdapConnector",
    tag = "ldap",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("connector_id" = String, Path, description = "Connector identifier"),
    ),
    responses(
        (status = 204, description = "The connector was removed"),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such connector", body = ErrorBody)
    )
)]
pub async fn delete_ldap_connector(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, connector_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`. Sharper here
    // than for a plain configuration write: the sweep sends the named secret to a HOST the same
    // principal chose, so a caller who could do this with `management.read` could read the
    // write-only secret store.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
    let id =
        LdapConnectorId::parse_in_scope(&connector_id, &scope).map_err(|_| ApiError::NotFound)?;
    // THE SNAPSHOT AND THE HEALTH ROW GO WITH IT, by the cascade 0214 and 0215 declare. A set of
    // directory identifiers whose connector has been removed is PII nothing will ever read
    // again, and health describing a directory nobody syncs is noise in the listing.
    let event_id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        "ldap_connector.deleted",
        &scope.tenant().to_string(),
        &subject,
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "ldap_connector_id": subject,
            "organization_id": org_id.to_string(),
        }),
    );
    let deleted_event = envelope
        .as_ref()
        .map(|envelope| ironauth_store::DomainEvent {
            id: &event_id,
            subject: &subject,
            envelope,
        });
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .in_organization(org_id)
        .ldap_connectors()
        .delete(state.env(), &org_id, &id, deleted_event.as_ref())
        .await
        .map_err(|error| match error {
            StoreError::NotFound => ApiError::NotFound,
            _ => ApiError::Internal,
        })?;
    Ok(no_content())
}
