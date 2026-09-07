// SPDX-License-Identifier: MIT OR Apache-2.0

//! The people an organization's operational notifications reach (issue #141).
//!
//! A contact is a routing destination, not a principal: it authenticates nothing, holds no
//! session and grants no access. #141's premise is that "the person who set up SSO is rarely the
//! person watching the vendor's status page", so a certificate approaching expiry, a SCIM token
//! nearing its lead time or a connection degrading each need to reach somebody who will act, and
//! those are usually different people. The category is what routes them.
//!
//! # Create and remove, and why there is no update
//!
//! The surface is create, list and remove. There is deliberately no PATCH, and the schema cannot
//! express one: 0207 grants the control plane `UPDATE (updated_at, deleted_at)` and nothing
//! wider, so no route could edit a name, an address or a category however this layer were
//! written. That is the design rather than an omission. The row survives its removal so an
//! `org_contact.*` audit entry keeps a referent -- "who was told about the certificate that then
//! expired" is answerable only while it does -- and an in-place edit would make that entry
//! resolve to the CURRENT address rather than the one actually notified, destroying the property
//! the tombstone exists for. Correcting a contact is therefore remove-then-add, which leaves both
//! facts in the trail and is what an operator wants to be able to reconstruct.
//!
//! # The organization is a predicate, not context
//!
//! Row-level security fences `(tenant, environment)` and nothing finer, so inside one environment
//! the `organization_id` is the only thing keeping one organization's contacts out of another's.
//! Both identifiers are caller-supplied, and the two are related only by the row -- so a removal
//! keyed on the contact alone would let a caller holding one organization's handle silence any
//! other organization's notifications. This layer passes the path's organization into every store
//! call and relies on it carrying the value as a statement predicate, which is what
//! [`ironauth_store::ActingOrgContactRepo::remove_with_event`] does.
//!
//! # What the events do not carry
//!
//! Neither `org_contact.added` nor `org_contact.removed` carries the name or the address. 0207
//! seals both columns so that whoever can read the table cannot thereby learn who a customer's
//! staff are; an event carrying the address in the clear would hand it to every consumer and to
//! the outbox row it sits in, undoing the seal by a route that never touches the table. The
//! category travels, because it names nobody and routing is why a consumer subscribes.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, NewOrgContact, OrgContact, OrgContactId, OrganizationId, Scope, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::ApiError;
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::org_context::{EnvironmentAccess, resolve_live_org, resolve_scope};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// One operational contact, as returned by the management API (issue #141).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrgContactView {
    /// The contact identifier (`oct_...`, embeds its scope).
    pub id: String,
    /// The organization whose notifications this person receives (`org_...`).
    pub organization_id: String,
    /// Who they are. Sealed at rest; opened for this response.
    pub display_name: String,
    /// Where the notification goes. Sealed at rest; opened for this response.
    pub email: String,
    /// Which kind of notification they want: `technical`, `security` or `billing`.
    pub category: String,
    /// When the contact was added, epoch milliseconds.
    pub created_at_unix_ms: i64,
}

impl OrgContactView {
    fn from_record(record: OrgContact) -> Self {
        Self {
            id: record.id.to_string(),
            organization_id: record.organization_id.to_string(),
            display_name: record.display_name,
            email: record.email,
            category: record.category,
            created_at_unix_ms: record.created_at_unix_micros / 1000,
        }
    }
}

/// A page of contacts (issue #141).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrgContactList {
    /// The contacts on this page, oldest first.
    pub items: Vec<OrgContactView>,
    /// The cursor for the next page, or null when this is the last one.
    pub next_cursor: Option<String>,
}

/// The body of a create request (issue #141).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateOrgContactRequest {
    /// Who they are.
    pub display_name: String,
    /// Where the notification goes.
    pub email: String,
    /// Which kind of notification they want: `technical`, `security` or `billing`.
    pub category: String,
}

/// Add a person to an organization's operational notification list.
///
/// # Errors
///
/// `400` if the body, the address, the name or the category is malformed; `403` if the
/// credential lacks `management.write_organizations`; `404` if the scope or organization is not
/// addressable; `409` if this organization already lists that address on that category.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/contacts",
    operation_id = "createOrganizationContact",
    tag = "organizations",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("Idempotency-Key" = String, Header, description = "Required replay key"),
    ),
    request_body = CreateOrgContactRequest,
    responses(
        (status = 201, description = "The contact was added", body = OrgContactView),
        (status = 400, description = "Malformed request", body = crate::error::ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = crate::error::ErrorBody),
        (status = 403, description = "Insufficient permission", body = crate::error::ErrorBody),
        (status = 404, description = "Unknown scope or organization", body = crate::error::ErrorBody),
        (status = 409, description = "Already listed on that category", body = crate::error::ErrorBody),
    ),
    security(("bearer" = []))
)]
pub async fn create_org_contact(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_organizations`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    // Replay BEFORE the organization precondition, so a genuine replay returns the original
    // response even if the organization was disabled meanwhile.
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

    let request: CreateOrgContactRequest = parse_json(&body)?;
    let display_name = require_non_empty(&request.display_name, "display_name")?;
    let email = require_non_empty(&request.email, "email")?;
    let category = require_non_empty(&request.category, "category")?;

    let created_at_micros = state.now_unix_micros();
    let contact_id = OrgContactId::generate(state.env(), &scope);
    let view = OrgContactView {
        id: contact_id.to_string(),
        organization_id: org_id.to_string(),
        display_name: display_name.clone(),
        email: email.clone(),
        category: category.clone(),
        created_at_unix_ms: created_at_micros / 1000,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;

    let write = ironauth_store::IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 201,
        response_body: &body_string,
    };
    let pending = org_contact_event(
        &state,
        scope,
        &contact_id,
        &org_id,
        &category,
        "org_contact.added",
    );
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .org_contacts()
        .add_with_event(
            state.env(),
            NewOrgContact {
                id: &contact_id,
                organization_id: &org_id,
                display_name: &display_name,
                email: &email,
                category: &category,
                // The SAME value the 201 body reports, so the create response and every later
                // listing agree about when this contact was added.
                created_at_micros,
            },
            Some(write),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(json(StatusCode::CREATED, body_string))
}

/// List the people an organization's operational notifications reach.
///
/// # Errors
///
/// `403` if the credential lacks `management.read`; `404` if the scope or organization is not
/// addressable.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/contacts",
    operation_id = "listOrganizationContacts",
    tag = "organizations",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("limit" = Option<u32>, Query, description = "Maximum contacts to return"),
        ("cursor" = Option<String>, Query, description = "Cursor from a previous page"),
    ),
    responses(
        (status = 200, description = "The organization's live contacts", body = OrgContactList),
        (status = 401, description = "Missing or invalid credential", body = crate::error::ErrorBody),
        (status = 403, description = "Insufficient permission", body = crate::error::ErrorBody),
        (status = 404, description = "Unknown scope or organization", body = crate::error::ErrorBody),
    ),
    security(("bearer" = []))
)]
pub async fn list_org_contacts(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
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
    // `list_for_organization` filters on organization_id, so a sibling organization's contacts
    // can never appear on this page.
    let rows = state
        .store()
        .scoped(scope)
        .org_contacts()
        .list_for_organization(&org_id, page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = OrgContactList {
        items: rows.into_iter().map(OrgContactView::from_record).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Take a person off an organization's operational notification list.
///
/// # Errors
///
/// `403` if the credential lacks `management.write_organizations`; `404` if the scope, the
/// organization or the contact is not addressable from here.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/contacts/{contact_id}",
    operation_id = "deleteOrganizationContact",
    tag = "organizations",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("contact_id" = String, Path, description = "Contact identifier"),
    ),
    responses(
        (status = 204, description = "The contact is off the list"),
        (status = 401, description = "Missing or invalid credential", body = crate::error::ErrorBody),
        (status = 403, description = "Insufficient permission", body = crate::error::ErrorBody),
        (status = 404, description = "Unknown scope, organization or contact", body = crate::error::ErrorBody),
    ),
    security(("bearer" = []))
)]
pub async fn delete_org_contact(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, contact_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_organizations`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
    let id = parse_contact_id(scope, &contact_id)?;

    // THE CATEGORY FOR THE EVENT IS READ BEFORE THE REMOVAL, because after it the row is a
    // tombstone the live listing no longer returns. A contact this caller cannot address is
    // absent from it, so this yields `None` and the removal below answers the uniform
    // not-found -- the read is not what decides the outcome.
    //
    // A POINT LOOKUP, NOT A PAGE. Reading the category out of `list_for_organization` looked
    // equivalent and was not: that listing is paged, so a contact past the first page yielded
    // `None` and its removal announced NOTHING while still tombstoning the row and writing its
    // audit entry -- a consumer counting `org_contact.removed` would have undercounted, silently.
    // The point lookup also opens no seal, which matters here more than anywhere: a row whose
    // ciphertext will not open is exactly the row an operator most needs to remove, and routing
    // the removal through a listing that opens every seal made the remedy fail on the thing it
    // was meant to remedy.
    let category = state
        .store()
        .scoped(scope)
        .org_contacts()
        .live_category(&org_id, &id)
        .await?;

    let pending = category.as_ref().and_then(|category| {
        org_contact_event(&state, scope, &id, &org_id, category, "org_contact.removed")
    });
    // The organization rides into the UPDATE as a predicate: a contact of a sibling organization
    // matches no row and is the uniform not-found.
    let removed = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .org_contacts()
        .remove_with_event(
            state.env(),
            &org_id,
            &id,
            state.now_unix_micros(),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    // A REPEAT IS 204, NOT 404. `remove_with_event` answers `Ok(false)` for a contact that is
    // already off the list, and DELETE is idempotent: the caller's goal -- this person is not
    // notified -- holds either way. A contact that never existed in this organization is a
    // different fact and is `NotFound` from the store, which is the 404.
    let _ = removed;
    Ok(no_content())
}

/// Parse an untrusted contact id in scope, under the uniform not-found.
///
/// A MALFORMED ID AND A FOREIGN ONE ARE THE SAME ANSWER. Distinguishing them would make this an
/// existence oracle over another scope's contacts.
fn parse_contact_id(scope: Scope, raw: &str) -> Result<OrgContactId, ApiError> {
    OrgContactId::parse_in_scope(raw, &scope).map_err(|_| ApiError::from(StoreError::NotFound))
}

/// Build the pending domain event for a contact write (issue #141).
///
/// NO NAME AND NO ADDRESS IN THE PAYLOAD. See this module's header: the columns are sealed so a
/// reader of the table cannot learn who a customer's staff are, and an event carrying them in the
/// clear would hand them to every consumer by a route that never touches the table.
fn org_contact_event(
    state: &AdminState,
    scope: Scope,
    contact_id: &OrgContactId,
    organization_id: &OrganizationId,
    category: &str,
    event_type: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = contact_id.to_string();
    let payload = serde_json::json!({
        "org_contact_id": subject,
        "organization_id": organization_id.to_string(),
        "category": category,
    });
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &payload,
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}
