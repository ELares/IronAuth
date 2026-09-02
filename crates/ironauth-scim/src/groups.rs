// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SCIM 2.0 `/Groups` resource handlers (issue #135, RFC 7643 section 4.2).
//!
//! # A SCIM group IS an organization group
//!
//! Not a parallel table. `org_groups` already exists, already carries role bindings, and is
//! already what a token's group claim is computed from, so a SCIM group living beside it would
//! be a second answer to "what groups is this person in" -- and the two would disagree the
//! first time anybody used the admin API. Group push therefore writes the SAME rows an
//! operator writes by hand, and a group pushed by Okta grants exactly what an
//! operator-created one does.
//!
//! # displayName is mutable, the slug is not
//!
//! `org_groups.slug` is the stable name a token claim carries, and the schema makes it
//! immutable. SCIM's `displayName` is a label an identity provider renames freely. So the slug
//! is DERIVED from the display name at creation and never again: a renamed group keeps its
//! claim value, which is what anything consuming that claim needs.
//!
//! # Membership goes through the organization membership, not straight to the user
//!
//! `org_group_members` binds a MEMBERSHIP to a group rather than a user, and that indirection
//! is the authorization boundary doing its job: a person can only be put in a group of an
//! organization they belong to, because there is no membership to bind otherwise. A SCIM
//! member add resolves the user, checks the credential's organization, and binds the
//! membership it finds -- the same three steps `/Users` takes, for the same reason.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{
    CorrelationId, NewOrgGroup, NewOrgGroupMember, OrgGroupId, OrgGroupMemberId, OrgGroupRecord,
    OrgMembershipId, UserId,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::server::{Authenticated, ScimState, scim_error, scim_json};
use crate::users::{ListQuery, addressed_user, epoch_micros, not_found, store_failure};

/// The SCIM core group schema URN (RFC 7643 section 4.2).
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
/// The SCIM `PatchOp` message URN (RFC 7644 section 3.5.2).
const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/// The nesting depth a SCIM-created group may reach.
///
/// ONE, because this surface creates only flat groups: RFC 7643 models nesting through a
/// member whose `type` is `Group`, which this slice does not serve, so every group it creates
/// has no parent. The store still wants the bound, and passing the deployment's configured
/// maximum would advertise a depth nothing here can produce.
const SCIM_GROUP_DEPTH: u32 = 1;

/// A SCIM group resource as far as this surface reads it.
#[derive(Debug, Deserialize)]
struct ScimGroup {
    #[serde(rename = "displayName", default)]
    display_name: String,
    #[serde(default)]
    members: Vec<ScimMember>,
}

/// One entry of a group's `members` array. For a user member, `value` is the user id.
#[derive(Debug, Clone, Deserialize)]
struct ScimMember {
    #[serde(default)]
    value: String,
}

/// The slug an organization group gets for a SCIM `displayName`.
///
/// `org_groups.slug` is `^[a-z0-9][a-z0-9._-]{0,62}$` and case sensitive by design, so this
/// folds case, maps every character outside the charset to `-`, collapses runs, and trims to
/// fit. It returns [`None`] when nothing usable survives, which is a 400 rather than a group
/// whose stable name is a row of dashes.
fn slug_for(display_name: &str) -> Option<String> {
    let mut slug = String::with_capacity(display_name.len());
    for character in display_name.to_lowercase().chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            slug.push(character);
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    // The charset allows the three punctuation characters anywhere EXCEPT first, so both ends
    // are trimmed rather than only the leading one; and the trim runs again after truncation,
    // because cutting at 63 can leave a trailing separator that was interior before.
    let trimmed: String = slug
        .trim_matches(['-', '.', '_'])
        .chars()
        .take(63)
        .collect();
    let trimmed = trimmed.trim_end_matches(['-', '.', '_']).to_owned();
    (!trimmed.is_empty() && trimmed.starts_with(|c: char| c.is_ascii_alphanumeric()))
        .then_some(trimmed)
}

/// Resolve the addressed group, or the uniform 404.
///
/// `get_in_org` is the whole check: it takes the credential's organization and refuses a group
/// of any other, so a group id from another organization is indistinguishable from one that
/// never existed. The same shape `/Users` uses, for the same reason.
async fn addressed_group(
    state: &ScimState,
    auth: &Authenticated,
    raw_id: &str,
) -> Result<OrgGroupRecord, Response> {
    let scoped = state.store().scoped(auth.scope);
    let group_id = scoped
        .org_groups()
        .parse_id(raw_id)
        .map_err(|_| not_found())?;
    scoped
        .org_groups()
        .get_in_org(&auth.connection.organization_id, &group_id)
        .await
        .map_err(|_| not_found())
}

/// The organization membership binding `user` into this credential's organization.
async fn membership_of(
    state: &ScimState,
    auth: &Authenticated,
    user: &UserId,
) -> Result<OrgMembershipId, Response> {
    let memberships = state
        .store()
        .scoped(auth.scope)
        .org_memberships()
        .list_for_user(user)
        .await
        .map_err(|error| store_failure(&error))?;
    memberships
        .into_iter()
        .find(|membership| membership.organization_id == auth.connection.organization_id)
        .map(|membership| membership.id)
        .ok_or_else(not_found)
}

/// Render a stored group as a SCIM group resource.
async fn group_resource(
    state: &ScimState,
    auth: &Authenticated,
    record: &OrgGroupRecord,
) -> Result<Value, Response> {
    let scoped = state.store().scoped(auth.scope);
    let bindings = scoped
        .org_group_members()
        .list_for_group(
            &auth.connection.organization_id,
            &record.id,
            i64::try_from(state.limits().scan_bound()).unwrap_or(i64::MAX),
            None,
        )
        .await
        .map_err(|error| store_failure(&error))?;
    let mut members = Vec::with_capacity(bindings.len());
    for binding in &bindings {
        // A binding names a MEMBERSHIP; SCIM wants the person. A membership removed since
        // renders as no member rather than as an error: the two rows are not written
        // together, and a dangling one must not make the group unreadable.
        let Ok(membership) = scoped.org_memberships().get(&binding.membership_id).await else {
            continue;
        };
        members.push(json!({
            "value": membership.user_id.to_string(),
            "$ref": format!("/scim/v2/Users/{}", membership.user_id),
            "type": "User",
        }));
    }
    Ok(json!({
        "schemas": [GROUP_SCHEMA],
        "id": record.id.to_string(),
        "displayName": record.display_name,
        "members": members,
        "meta": {
            "resourceType": "Group",
            "location": format!("/scim/v2/Groups/{}", record.id),
        },
    }))
}

/// `POST /scim/v2/Groups`.
pub(crate) async fn create_group(
    State(state): State<ScimState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let auth = match state.authenticate(&headers).await {
        Ok(auth) => auth,
        Err(refusal) => return refusal.response(),
    };
    let Ok(parsed) = serde_json::from_str::<ScimGroup>(&body) else {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "the request body is not a SCIM group resource",
        );
    };
    let Some(slug) = slug_for(&parsed.display_name) else {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "displayName must contain at least one ASCII letter or digit",
        );
    };
    let env = state.env().clone();
    let group_id = OrgGroupId::generate(&env, &auth.scope);
    if let Err(error) = state
        .store()
        .management()
        .acting(auth.actor, CorrelationId::generate(&env))
        .org_groups(auth.scope)
        .create(
            &env,
            NewOrgGroup {
                id: &group_id,
                organization_id: &auth.connection.organization_id,
                // FLAT: RFC 7643 nests through a member whose type is Group, which this slice
                // does not serve, so a SCIM-created group never has a parent.
                parent_id: None,
                slug: &slug,
                display_name: &parsed.display_name,
                metadata: None,
            },
            epoch_micros(&state),
            SCIM_GROUP_DEPTH,
            None,
        )
        .await
    {
        // A slug collision is the interesting one. RFC 7643 section 4.2 already treats
        // displayName as a group's name, so 409 is the right answer, but two display names
        // differing only in punctuation fold onto ONE slug: the detail says so rather than
        // leaving an operator to wonder why a visibly different name conflicted.
        if matches!(error, ironauth_store::StoreError::Conflict) {
            return scim_error(
                StatusCode::CONFLICT,
                Some("uniqueness"),
                "a group with this displayName already exists, or one whose displayName \
                 differs from it only in punctuation or case",
            );
        }
        return store_failure(&error);
    }
    if let Err(response) = set_members(&state, &auth, &group_id, &parsed.members, true).await {
        return response;
    }
    match rendered_group(&state, &auth, &group_id.to_string()).await {
        Ok(body) => (
            StatusCode::CREATED,
            [
                (header::CONTENT_TYPE, crate::server::SCIM_CONTENT_TYPE),
                (header::LOCATION, "/scim/v2/Groups"),
            ],
            body.to_string(),
        )
            .into_response(),
        Err(response) => response,
    }
}

/// Re-read and render a group, so a response reflects what was stored rather than what was
/// asked for.
async fn rendered_group(
    state: &ScimState,
    auth: &Authenticated,
    raw_id: &str,
) -> Result<Value, Response> {
    let record = addressed_group(state, auth, raw_id).await?;
    group_resource(state, auth, &record).await
}

/// Bring a group's membership to `wanted`.
///
/// `replace` distinguishes the two callers. A create and a PUT declare the WHOLE member set,
/// so anybody not named is removed; a PATCH `add` names only additions, so nothing is removed.
/// Getting that backwards in either direction is a silent deprovisioning or a silent grant,
/// which is why it is a parameter rather than two nearly identical functions that could drift.
async fn set_members(
    state: &ScimState,
    auth: &Authenticated,
    group: &OrgGroupId,
    wanted: &[ScimMember],
    replace: bool,
) -> Result<(), Response> {
    let env = state.env().clone();
    let scoped = state.store().scoped(auth.scope);
    let existing = scoped
        .org_group_members()
        .list_for_group(
            &auth.connection.organization_id,
            group,
            i64::try_from(state.limits().scan_bound()).unwrap_or(i64::MAX),
            None,
        )
        .await
        .map_err(|error| store_failure(&error))?;
    let acting = state
        .store()
        .management()
        .acting(auth.actor, CorrelationId::generate(&env));

    let mut keep = Vec::with_capacity(wanted.len());
    for member in wanted {
        // EVERY member id goes through the same gate a direct /Users request would: the user
        // must hold a membership in THIS credential's organization. Without it, group push
        // would be a way to name a user of another organization and have the server resolve
        // it -- the criterion-5 failure through a door that is not /Users.
        let user = addressed_user(state, auth, &member.value).await?;
        let membership = membership_of(state, auth, &user).await?;
        if existing
            .iter()
            .any(|binding| binding.membership_id == membership)
        {
            keep.push(membership);
            continue;
        }
        let binding_id = OrgGroupMemberId::generate(&env, &auth.scope);
        acting
            .org_group_members(auth.scope)
            .add(
                &env,
                NewOrgGroupMember {
                    id: &binding_id,
                    organization_id: &auth.connection.organization_id,
                    group_id: group,
                    membership_id: &membership,
                },
                epoch_micros(state),
                None,
            )
            .await
            .map_err(|error| store_failure(&error))?;
        keep.push(membership);
    }
    if !replace {
        return Ok(());
    }
    for binding in &existing {
        if keep.contains(&binding.membership_id) {
            continue;
        }
        acting
            .org_group_members(auth.scope)
            .remove(&env, &auth.connection.organization_id, &binding.id)
            .await
            .map_err(|error| store_failure(&error))?;
    }
    Ok(())
}

/// Remove named members from a group, leaving the rest.
async fn drop_members(
    state: &ScimState,
    auth: &Authenticated,
    group: &OrgGroupId,
    unwanted: &[ScimMember],
) -> Result<(), Response> {
    let env = state.env().clone();
    let scoped = state.store().scoped(auth.scope);
    let existing = scoped
        .org_group_members()
        .list_for_group(
            &auth.connection.organization_id,
            group,
            i64::try_from(state.limits().scan_bound()).unwrap_or(i64::MAX),
            None,
        )
        .await
        .map_err(|error| store_failure(&error))?;
    let acting = state
        .store()
        .management()
        .acting(auth.actor, CorrelationId::generate(&env));
    for member in unwanted {
        let user = addressed_user(state, auth, &member.value).await?;
        let membership = membership_of(state, auth, &user).await?;
        for binding in existing
            .iter()
            .filter(|binding| binding.membership_id == membership)
        {
            acting
                .org_group_members(auth.scope)
                .remove(&env, &auth.connection.organization_id, &binding.id)
                .await
                .map_err(|error| store_failure(&error))?;
        }
    }
    Ok(())
}

/// `GET /scim/v2/Groups/{id}`.
pub(crate) async fn get_group(
    State(state): State<ScimState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
) -> Response {
    let auth = match state.authenticate(&headers).await {
        Ok(auth) => auth,
        Err(refusal) => return refusal.response(),
    };
    match rendered_group(&state, &auth, &raw_id).await {
        Ok(body) => scim_json(StatusCode::OK, &body),
        Err(response) => response,
    }
}

/// `PUT /scim/v2/Groups/{id}` (RFC 7644 section 3.5.1).
pub(crate) async fn replace_group(
    State(state): State<ScimState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
    body: String,
) -> Response {
    let auth = match state.authenticate(&headers).await {
        Ok(auth) => auth,
        Err(refusal) => return refusal.response(),
    };
    let record = match addressed_group(&state, &auth, &raw_id).await {
        Ok(record) => record,
        Err(response) => return response,
    };
    let Ok(parsed) = serde_json::from_str::<ScimGroup>(&body) else {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "the request body is not a SCIM group resource",
        );
    };
    let env = state.env().clone();
    if !parsed.display_name.is_empty() && parsed.display_name != record.display_name {
        // The SLUG does not move; see the module docs. Only the label does.
        if let Err(error) = state
            .store()
            .management()
            .acting(auth.actor, CorrelationId::generate(&env))
            .org_groups(auth.scope)
            .update(
                &env,
                &auth.connection.organization_id,
                &record.id,
                Some(parsed.display_name.as_str()),
                None,
            )
            .await
        {
            return store_failure(&error);
        }
    }
    // A PUT declares the WHOLE member set, so anybody absent from it leaves the group.
    if let Err(response) = set_members(&state, &auth, &record.id, &parsed.members, true).await {
        return response;
    }
    match rendered_group(&state, &auth, &raw_id).await {
        Ok(body) => scim_json(StatusCode::OK, &body),
        Err(response) => response,
    }
}

/// One operation in a group `PatchOp`.
#[derive(Debug, Deserialize)]
struct GroupPatchOperation {
    op: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    value: Option<Value>,
}

/// A group `PatchOp` request body.
#[derive(Debug, Deserialize)]
struct GroupPatchRequest {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(rename = "Operations", default)]
    operations: Vec<GroupPatchOperation>,
}

/// `PATCH /scim/v2/Groups/{id}` (RFC 7644 section 3.5.2).
///
/// # This is the operation group push is made of
///
/// Okta and Entra do not PUT a group to change its membership; they PATCH it, one add or
/// remove at a time, thousands of times during a sync. So all three shapes they send are
/// served: `add` with `path: "members"`, `remove` with `path: "members"` and a value array,
/// and the selector spelling `members[value eq "..."]` that drops a single person without
/// carrying a value at all.
pub(crate) async fn patch_group(
    State(state): State<ScimState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
    body: String,
) -> Response {
    let auth = match state.authenticate(&headers).await {
        Ok(auth) => auth,
        Err(refusal) => return refusal.response(),
    };
    let record = match addressed_group(&state, &auth, &raw_id).await {
        Ok(record) => record,
        Err(response) => return response,
    };
    let Ok(parsed) = serde_json::from_str::<GroupPatchRequest>(&body) else {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "the request body is not a SCIM PatchOp",
        );
    };
    if !parsed
        .schemas
        .iter()
        .any(|urn| urn.eq_ignore_ascii_case(PATCH_OP_SCHEMA))
    {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "a PatchOp must declare the PatchOp schema URN",
        );
    }
    if parsed.operations.is_empty() {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "a PatchOp must carry at least one operation",
        );
    }
    for operation in &parsed.operations {
        if let Err(response) = apply_group_operation(&state, &auth, &record, operation).await {
            return response;
        }
    }
    match rendered_group(&state, &auth, &raw_id).await {
        Ok(body) => scim_json(StatusCode::OK, &body),
        Err(response) => response,
    }
}

/// Rename a group's display label. The slug is untouched; see the module docs.
async fn rename(
    state: &ScimState,
    auth: &Authenticated,
    group: &OrgGroupId,
    label: &str,
) -> Result<(), Response> {
    let env = state.env().clone();
    state
        .store()
        .management()
        .acting(auth.actor, CorrelationId::generate(&env))
        .org_groups(auth.scope)
        .update(
            &env,
            &auth.connection.organization_id,
            group,
            Some(label),
            None,
        )
        .await
        .map_err(|error| store_failure(&error))
}

/// Apply one group PATCH operation.
async fn apply_group_operation(
    state: &ScimState,
    auth: &Authenticated,
    record: &OrgGroupRecord,
    operation: &GroupPatchOperation,
) -> Result<(), Response> {
    let op = operation.op.to_ascii_lowercase();
    // The path is PARSED, never matched as text: `members` and `members[value eq "x"]` are
    // told apart by the grammar rather than by a substring test, which would accept the
    // second as the first and empty the whole group instead of removing one person.
    let (attribute, selector) = match operation.path.as_deref() {
        Some(raw) => {
            let path = crate::parse_patch_path(raw).map_err(|_| {
                scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidPath"),
                    "the operation path is not a SCIM attribute path",
                )
            })?;
            (
                Some(path.attribute().to_ascii_lowercase()),
                path.selector().cloned(),
            )
        }
        None => (None, None),
    };
    match (op.as_str(), attribute.as_deref()) {
        ("add", Some("members")) => {
            let members = members_of(operation.value.as_ref())?;
            set_members(state, auth, &record.id, &members, false).await
        }
        ("replace", Some("members")) => {
            let members = members_of(operation.value.as_ref())?;
            set_members(state, auth, &record.id, &members, true).await
        }
        ("remove", Some("members")) => {
            // A single-person removal names the member in a SELECTOR and sends no value. A
            // handler that only read `value` would see an empty list and remove NOBODY while
            // answering 200 -- a deprovisioning that silently did not happen.
            if let Some(selector) = selector.as_ref() {
                let named = selected_member(selector).ok_or_else(|| {
                    scim_error(
                        StatusCode::BAD_REQUEST,
                        Some("invalidPath"),
                        "a members selector must compare value to a single member id",
                    )
                })?;
                return drop_members(state, auth, &record.id, &[named]).await;
            }
            let members = members_of(operation.value.as_ref())?;
            if members.is_empty() {
                // `remove` on the whole attribute with no value empties the group, which is
                // what RFC 7644 section 3.5.2.2 says. It is destructive, so it happens only
                // for that exact shape rather than as the fallback of a parse failure.
                return set_members(state, auth, &record.id, &[], true).await;
            }
            drop_members(state, auth, &record.id, &members).await
        }
        ("replace", Some("displayname")) => {
            let Some(Value::String(name)) = operation.value.as_ref() else {
                return Err(scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidValue"),
                    "displayName must be a string",
                ));
            };
            rename(state, auth, &record.id, name).await
        }
        // The no-path shape: a whole object whose members are the attributes to set.
        ("add" | "replace", None) => {
            let Some(Value::Object(fields)) = operation.value.as_ref() else {
                return Err(scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidValue"),
                    "an operation with no path must carry an object value",
                ));
            };
            for (name, value) in fields {
                match (name.to_ascii_lowercase().as_str(), value) {
                    ("displayname", Value::String(label)) => {
                        rename(state, auth, &record.id, label).await?;
                    }
                    ("members", Value::Array(_)) => {
                        let members = members_of(Some(value))?;
                        set_members(state, auth, &record.id, &members, op == "replace").await?;
                    }
                    // Anything else in a no-path object is ignored rather than refused: a
                    // client sends whole resources here, and failing would make every
                    // ordinary update a 400.
                    _ => {}
                }
            }
            Ok(())
        }
        (_, Some(other)) => Err(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidPath"),
            &format!("this surface does not serve the group attribute {other}"),
        )),
        _ => Err(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "op must be add, remove or replace",
        )),
    }
}

/// The member list an operation's value carries.
///
/// `Response` is a large error type, and boxing it here would mean unboxing it at every call
/// site to return it: these are request-handling paths that build at most one response per
/// request, so the size is paid once on a path that is already doing a database round trip.
#[allow(clippy::result_large_err)]
fn members_of(value: Option<&Value>) -> Result<Vec<ScimMember>, Response> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::Array(entries)) => entries
            .iter()
            .map(|entry| {
                serde_json::from_value::<ScimMember>(entry.clone()).map_err(|_| {
                    scim_error(
                        StatusCode::BAD_REQUEST,
                        Some("invalidValue"),
                        "each member must be an object carrying a value",
                    )
                })
            })
            .collect(),
        Some(_) => Err(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "members must be an array",
        )),
    }
}

/// The single member id a `members[value eq "..."]` selector names.
///
/// ONLY that exact shape. A selector comparing anything else, or with any operator other than
/// `eq`, names a SET rather than a member, and guessing which member it meant is how a remove
/// takes the wrong person out of a group.
fn selected_member(selector: &crate::Filter) -> Option<ScimMember> {
    let crate::Filter::Compare { path, op, value } = selector else {
        return None;
    };
    if *op != crate::CompareOp::Equal || !path.name.eq_ignore_ascii_case("value") {
        return None;
    }
    let crate::Value::String(id) = value else {
        return None;
    };
    Some(ScimMember { value: id.clone() })
}

/// `DELETE /scim/v2/Groups/{id}` (RFC 7644 section 3.6).
pub(crate) async fn delete_group(
    State(state): State<ScimState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
) -> Response {
    let auth = match state.authenticate(&headers).await {
        Ok(auth) => auth,
        Err(refusal) => return refusal.response(),
    };
    let record = match addressed_group(&state, &auth, &raw_id).await {
        Ok(record) => record,
        Err(response) => return response,
    };
    let env = state.env().clone();
    match state
        .store()
        .management()
        .acting(auth.actor, CorrelationId::generate(&env))
        .org_groups(auth.scope)
        .delete(&env, &auth.connection.organization_id, &record.id)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => store_failure(&error),
    }
}

/// `GET /scim/v2/Groups` (RFC 7644 section 3.4.2).
///
/// Groups are listed straight from the credential's organization, which is already the
/// boundary: `list_for_org` takes the organization and returns nothing for any other. The
/// filter is evaluated against the rendered resource exactly as `/Users` does, so
/// `displayName eq "Engineers"` selects by the same rules everything else in this crate
/// compares by.
pub(crate) async fn list_groups(
    State(state): State<ScimState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    let auth = match state.authenticate(&headers).await {
        Ok(auth) => auth,
        Err(refusal) => return refusal.response(),
    };
    let filter = match query.filter().map(crate::parse_filter).transpose() {
        Ok(filter) => filter,
        Err(error) => {
            let rendered = error.to_scim_error();
            return scim_error(
                StatusCode::BAD_REQUEST,
                Some(&rendered.scim_type),
                &rendered.detail,
            );
        }
    };
    // One row MORE than the bound, so reaching it is distinguishable from exactly filling it.
    let probe = i64::try_from(state.limits().scan_bound().saturating_add(1)).unwrap_or(i64::MAX);
    let groups = match state
        .store()
        .scoped(auth.scope)
        .org_groups()
        .list_for_org(&auth.connection.organization_id, probe, None)
        .await
    {
        Ok(groups) => groups,
        Err(error) => return store_failure(&error),
    };
    if groups.len() > state.limits().scan_bound() {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("tooMany"),
            "this organization has more groups than one request may examine; \
             narrow the request with a displayName filter",
        );
    }
    let mut matched = Vec::new();
    for group in &groups {
        let resource = match group_resource(&state, &auth, group).await {
            Ok(resource) => resource,
            Err(response) => return response,
        };
        if let Some(filter) = filter.as_ref()
            && !crate::filter_matches(filter, &resource)
        {
            continue;
        }
        matched.push(resource);
    }
    let total = matched.len();
    let start_index = query.start_index();
    let count = state.limits().clamp_count(query.count());
    let skip = usize::try_from(start_index - 1).unwrap_or(usize::MAX);
    let page: Vec<Value> = matched.into_iter().skip(skip).take(count).collect();
    scim_json(
        StatusCode::OK,
        &json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": total,
            "itemsPerPage": page.len(),
            "startIndex": start_index,
            "Resources": page,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The charset `org_groups_slug_valid` enforces. A slug this rejects is a 500 at creation
    /// rather than a bad name, so the slugifier is checked against the constraint itself.
    fn schema_accepts(slug: &str) -> bool {
        let mut chars = slug.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
            && slug.len() <= 63
            && slug
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    }

    #[test]
    fn every_display_name_with_a_usable_character_produces_a_slug_the_schema_accepts() {
        for name in [
            "Engineering",
            "Engineering Team",
            "  Sales & Marketing  ",
            "R&D (EMEA)",
            "\u{4e2d}\u{6587}team",
            "a",
            "UPPER CASE",
            "trailing punctuation ---",
            &"x".repeat(200),
            // A name whose 63rd character lands on a separator: truncation must not leave a
            // trailing one, which the constraint would refuse.
            &format!("{} tail", "y".repeat(62)),
        ] {
            let slug = slug_for(name).unwrap_or_else(|| panic!("{name:?} has a slug"));
            assert!(schema_accepts(&slug), "{name:?} produced {slug:?}");
        }
    }

    #[test]
    fn a_display_name_with_no_usable_character_has_no_slug() {
        // The control. Without it the test above passes on a slugifier returning "x" for
        // everything, and every group in an organization would collide on one stable name.
        for name in ["", "   ", "---", "!!!", "\u{4e2d}\u{6587}"] {
            assert!(slug_for(name).is_none(), "{name:?} must have no slug");
        }
    }

    #[test]
    fn different_names_keep_different_slugs() {
        // The other control: a slugifier folding everything together would satisfy both tests
        // above and make every second group a 409.
        let names = ["Engineering", "Sales", "Engineering2", "eng.team"];
        for (index, left) in names.iter().enumerate() {
            for right in &names[index + 1..] {
                assert_ne!(slug_for(left), slug_for(right), "{left} vs {right}");
            }
        }
    }
}
