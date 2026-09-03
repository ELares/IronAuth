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
use crate::users::{
    ListQuery, addressed_user, epoch_micros, internal_error, not_found, store_failure,
};

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

/// Every live member binding of a group, or the `tooMany` refusal.
///
/// # Why this is a function rather than three call sites
///
/// The three places that read a group's members were each passing `scan_bound()` as a plain
/// limit with no probe and no refusal, so a group larger than the bound rendered a SHORT
/// `members` array inside a 200 -- exactly the silent truncation `ScimLimits::max_scan` exists
/// to prevent, and worse here than in a listing: `set_members` computes its REMOVALS from this
/// list, so a PUT against an over-large group both fails to remove people it should and tries
/// to re-add members it could not see.
///
/// One function, so a fourth caller cannot reintroduce it.
///
/// # This refuses a READ; growing a group past the bound is refused elsewhere
///
/// An earlier version of this comment claimed a group could not be grown past the bound
/// "because the write's own response renders the group". That is false: the render runs after
/// the writes have committed, so it refuses the RESPONSE and keeps the rows. A reviewer drove
/// it -- a `PATCH` adding three members at a bound of two answered `tooMany` with all three
/// members landed, and the organization's whole `GET /Groups` then failed permanently.
///
/// Growing a group past the bound is refused by [`resolve_members`] and [`set_members`], both
/// of which check the RESULTING size before writing anything. This function is the read-side
/// half, for a group that exceeds the bound anyway: one built through the admin API, or one
/// that fitted until the bound was lowered.
async fn member_bindings(
    state: &ScimState,
    auth: &Authenticated,
    group: &OrgGroupId,
) -> Result<Vec<ironauth_store::OrgGroupMemberRecord>, Response> {
    // One row MORE than the bound, so reaching it is distinguishable from exactly filling it.
    let probe = i64::try_from(state.limits().scan_bound().saturating_add(1)).unwrap_or(i64::MAX);
    let bindings = state
        .store()
        .scoped(auth.scope)
        .org_group_members()
        .list_for_group(&auth.connection.organization_id, group, probe, None)
        .await
        .map_err(|error| store_failure(&error))?;
    if bindings.len() > state.limits().scan_bound() {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            Some("tooMany"),
            "this group has more members than one request may examine",
        ));
    }
    Ok(bindings)
}

/// Render a stored group as a SCIM group resource.
///
/// # `with_members` is false for the LISTING, and that is a decision rather than a shortcut
///
/// RFC 7644 section 3.4.2 lets a provider return a subset of attributes in a list response,
/// and a listing that carried every group's full membership is O(groups x members) of work a
/// caller chooses the size of -- the same unbounded read `max_scan` exists to bound, multiplied
/// by the number of groups.
///
/// It also removes a failure a reviewer reached: with members rendered, ONE group over the
/// bound made the organization's entire `GET /Groups` answer `tooMany` permanently, because
/// the per-group refusal propagated out of the listing. A client cannot enumerate groups it
/// cannot see, so a single oversized group hid every other group in the organization.
///
/// A single-resource `GET /Groups/{id}` carries members, bounded, which is where a client
/// reads them.
async fn group_resource(
    state: &ScimState,
    auth: &Authenticated,
    record: &OrgGroupRecord,
    with_members: bool,
) -> Result<Value, Response> {
    let scoped = state.store().scoped(auth.scope);
    let bindings = if with_members {
        member_bindings(state, auth, &record.id).await?
    } else {
        Vec::new()
    };
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
    let mut body = json!({
        "schemas": [GROUP_SCHEMA],
        "id": record.id.to_string(),
        "displayName": record.display_name,
        "meta": {
            "resourceType": "Group",
            "location": format!("/scim/v2/Groups/{}", record.id),
        },
    });
    // OMITTED, not empty, when members were not read. An empty array is a positive claim that
    // the group has no members, which a provisioning client acts on by removing everybody;
    // an absent attribute is RFC 7644 section 3.4.2's "the provider returned a subset", which
    // is what actually happened.
    if with_members {
        body["members"] = Value::Array(members);
    }
    Ok(body)
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
    // BEFORE the group exists. A member this credential may not reach used to answer 404 with
    // the group already committed, and the retry then answered 409 forever on the display name.
    let members = match resolve_members(&state, &auth, &parsed.members).await {
        Ok(members) => members,
        Err(response) => return response,
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
        // displayName as a group's name, so 409 is the right answer -- but the slug folds
        // EVERY character outside `[a-z0-9._-]` to a separator, non-ASCII letters included, so
        // "team A" and "team B" collide and so do two names differing only in a CJK character.
        // The detail says that rather than leaving an operator to wonder why two visibly
        // different names conflicted.
        if matches!(error, ironauth_store::StoreError::Conflict) {
            return scim_error(
                StatusCode::CONFLICT,
                Some("uniqueness"),
                "a group with this displayName already exists, or one whose displayName \
                 reduces to the same stable name: every character outside \
                 [a-z0-9._-] folds to a separator, so two names can differ visibly \
                 and still collide",
            );
        }
        return store_failure(&error);
    }
    if let Err(response) = set_members(&state, &auth, &group_id, &members, true).await {
        return response;
    }
    match rendered_group(&state, &auth, &group_id.to_string()).await {
        Ok(body) => (
            StatusCode::CREATED,
            [
                (header::CONTENT_TYPE, crate::server::SCIM_CONTENT_TYPE),
                (
                    header::LOCATION,
                    format!("/scim/v2/Groups/{group_id}").as_str(),
                ),
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
    group_resource(state, auth, &record, true).await
}

/// Resolve every member id to a membership in this credential's organization, de-duplicated.
///
/// # Resolving BEFORE any write is the point
///
/// `POST /Groups` used to create the group and then apply its members, so a create naming a
/// member this credential may not reach -- somebody in another organization, or somebody not
/// provisioned yet -- answered 404 with the GROUP ALREADY COMMITTED. The retry then answered
/// 409 forever on the display name. A reviewer drove it with the most ordinary group push
/// there is. The gate is the same one `/Users` applies; what changed is that it runs first.
///
/// DE-DUPLICATED, because a payload naming one person twice is ordinary and used to be a 409:
/// `set_members` reads the existing bindings once, so the second copy was not yet in that list
/// and the insert hit the unique index.
async fn resolve_members(
    state: &ScimState,
    auth: &Authenticated,
    wanted: &[ScimMember],
) -> Result<Vec<ResolvedMember>, Response> {
    // BEFORE anything is written, and before the caller creates a group to put them in. A
    // request naming more members than one request may examine cannot be served, and finding
    // that out after the group exists is what left an orphan group behind whose every retry
    // was a 409.
    if wanted.len() > state.limits().scan_bound() {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            Some("tooMany"),
            "this request names more members than one request may examine",
        ));
    }
    let mut resolved: Vec<ResolvedMember> = Vec::with_capacity(wanted.len());
    for member in wanted {
        // EVERY member id goes through the same gate a direct /Users request would: the user
        // must hold a membership in THIS credential's organization. Without it, group push
        // would be a way to name a user of another organization and have the server resolve
        // it -- the criterion-5 failure through a door that is not /Users.
        let user = addressed_user(state, auth, &member.value).await?;
        let membership = membership_of(state, auth, &user).await?;
        let resolution = ResolvedMember { user, membership };
        if !resolved.contains(&resolution) {
            resolved.push(resolution);
        }
    }
    Ok(resolved)
}

/// What one `/Groups` write will do to a group's membership, decided before any of it happens.
///
/// Computed up front for one reason: the delta event has to ride the LAST write of the
/// operation. Each binding write is its own transaction, so a delta enqueued anywhere else
/// would announce a set change that a later failure left half done. Knowing the whole plan is
/// what makes "the last one" nameable, and what makes the announcement mean "all of this
/// happened".
struct MemberPlan {
    /// Members to bind, in request order.
    adding: Vec<ResolvedMember>,
    /// Bindings to remove, each paired with the person it binds. Always empty unless the
    /// request REPLACES the membership: a SCIM `add` operation names what to add and says
    /// nothing about the rest of the group.
    removing: Vec<(ResolvedMember, ironauth_store::OrgGroupMemberId)>,
}

impl MemberPlan {
    /// How many writes the plan performs. The delta rides the last of them.
    fn writes(&self) -> usize {
        self.adding.len() + self.removing.len()
    }
}

/// Decide [`MemberPlan`] from what the group holds and what the request asked for.
///
/// Returns the plan rather than a `Result`, and the scan-bound refusal lives at the caller: a
/// `Response` is a large error variant and threading one out of a pure decision function buys
/// nothing, since the caller is the only thing that can answer the request anyway.
async fn plan_members(
    state: &ScimState,
    auth: &Authenticated,
    existing: &[ironauth_store::OrgGroupMemberRecord],
    wanted: &[ResolvedMember],
    replace: bool,
) -> Result<MemberPlan, Response> {
    let adding: Vec<ResolvedMember> = wanted
        .iter()
        .copied()
        .filter(|member| {
            !existing
                .iter()
                .any(|binding| binding.membership_id == member.membership)
        })
        .collect();
    let mut removing = Vec::new();
    if replace {
        let departing: Vec<OrgMembershipId> = existing
            .iter()
            .filter(|binding| {
                !wanted
                    .iter()
                    .any(|member| member.membership == binding.membership_id)
            })
            .map(|binding| binding.membership_id)
            .collect();
        // THE PEOPLE, not just the bindings, and in ONE query. A removal delta names who LEFT,
        // and this is the only place that knows: the binding row records the membership and the
        // request named the members who STAY, so a departing person appears in neither.
        //
        // Asked once rather than per member, because the loop is bounded by the scan bound: a
        // replace that empties a full group would otherwise pay a thousand sequential round
        // trips before writing anything.
        let users = state
            .store()
            .scoped(auth.scope)
            .org_memberships()
            .users_for(&departing)
            .await
            .map_err(|error| store_failure(&error))?;
        for binding in existing {
            let Some((_, user)) = users
                .iter()
                .find(|(membership, _)| *membership == binding.membership_id)
            else {
                continue;
            };
            removing.push((
                ResolvedMember {
                    user: *user,
                    membership: binding.membership_id,
                },
                binding.id,
            ));
        }
    }
    Ok(MemberPlan { adding, removing })
}

/// A member this request named, resolved to both the person and the binding endpoint.
///
/// BOTH, because the two events this surface emits speak different vocabularies and each is
/// right for what it is about. `org_group.member_added` names the BINDING it created, so it
/// carries the membership; `org_group.membership_changed` is a delta a mirror applies to its
/// own copy of the group, and a mirror keys people by USER, which is what its arrays and the
/// organization twin's have always declared. Resolving both here means neither producer has to
/// go back to the database for the half it lacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResolvedMember {
    user: UserId,
    membership: OrgMembershipId,
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
    wanted: &[ResolvedMember],
    replace: bool,
) -> Result<(), Response> {
    let env = state.env().clone();
    let existing = member_bindings(state, auth, group).await?;
    let acting = state
        .store()
        .management()
        .acting(auth.actor, CorrelationId::generate(&env));
    let plan = plan_members(state, auth, &existing, wanted, replace).await?;
    // The RESULTING size, which `resolve_members` cannot know: an `add` of two members to a
    // group that already holds the bound takes it over. Checked before any write, so the
    // refusal leaves the group exactly as it was.
    let resulting = if replace {
        wanted.len()
    } else {
        existing.len() + plan.adding.len()
    };
    if resulting > state.limits().scan_bound() {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            Some("tooMany"),
            "this change would leave the group with more members than one request may examine",
        ));
    }
    let writes = plan.writes();
    // AN EARLY RETURN, NOT THE GUARANTEE, and the difference is worth stating because it reads
    // like one. Nothing-changed announces nothing because the delta only ever rides an actual
    // write: with zero writes there is nothing for it to ride, so deleting this line changes no
    // behaviour and a review measured that (25 tests green with it gone). It is here because a
    // `PUT` restating a group's current membership is the ordinary output of a sync sweep and
    // there is no reason to build an event nobody will send.
    if writes == 0 {
        return Ok(());
    }
    let organization = auth.connection.organization_id.to_string();
    let group_text = group.to_string();
    let Some(delta) = crate::events::group_membership_delta_event(
        state,
        auth.scope,
        &group_text,
        &organization,
        plan.adding
            .iter()
            .map(|member| member.user.to_string())
            .collect(),
        plan.removing
            .iter()
            .map(|(member, _)| member.user.to_string())
            .collect(),
    ) else {
        return Err(internal_error());
    };

    let mut written = 0_usize;
    for member in &plan.adding {
        written += 1;
        bind_member(
            state,
            auth,
            &acting,
            group,
            member,
            (written == writes).then(|| delta.borrowed()).as_ref(),
        )
        .await?;
    }
    for (member, binding_id) in &plan.removing {
        written += 1;
        let Some(per_member) = crate::events::group_member_event(
            state,
            auth.scope,
            crate::events::GROUP_MEMBER_REMOVED,
            &group_text,
            &organization,
            &member.membership.to_string(),
        ) else {
            return Err(internal_error());
        };
        acting
            .org_group_members(auth.scope)
            .remove_with_event(
                &env,
                &auth.connection.organization_id,
                binding_id,
                Some(&per_member.borrowed()),
                (written == writes).then(|| delta.borrowed()).as_ref(),
            )
            .await
            .map_err(|error| store_failure(&error))?;
    }
    Ok(())
}

/// Bind one member into a group, announcing it, and carrying `delta` when this is the last
/// write of the operation.
async fn bind_member(
    state: &ScimState,
    auth: &Authenticated,
    acting: &ironauth_store::ActingManagementStore<'_>,
    group: &OrgGroupId,
    member: &ResolvedMember,
    delta: Option<&ironauth_store::DomainEvent<'_>>,
) -> Result<(), Response> {
    let env = state.env().clone();
    let binding_id = OrgGroupMemberId::generate(&env, &auth.scope);
    let Some(per_member) = crate::events::group_member_event(
        state,
        auth.scope,
        crate::events::GROUP_MEMBER_ADDED,
        &group.to_string(),
        &auth.connection.organization_id.to_string(),
        &member.membership.to_string(),
    ) else {
        return Err(internal_error());
    };
    acting
        .org_group_members(auth.scope)
        .add_with_event(
            &env,
            NewOrgGroupMember {
                id: &binding_id,
                organization_id: &auth.connection.organization_id,
                group_id: group,
                membership_id: &member.membership,
                // ATTRIBUTED TO THIS CONNECTION (issue #136, criterion 6). It is what a revoke
                // of this credential tears down: a compromised identity provider must not leave
                // the people it pushed holding the roles their groups confer after an operator
                // has disarmed it.
                source_scim_connection_id: Some(&auth.connection.id),
            },
            epoch_micros(state),
            None,
            Some(&per_member.borrowed()),
            delta,
        )
        .await
        .map_err(|error| store_failure(&error))
}

/// Remove named members from a group, leaving the rest.
async fn drop_members(
    state: &ScimState,
    auth: &Authenticated,
    group: &OrgGroupId,
    unwanted: &[ResolvedMember],
) -> Result<(), Response> {
    let env = state.env().clone();
    let existing = member_bindings(state, auth, group).await?;
    let acting = state
        .store()
        .management()
        .acting(auth.actor, CorrelationId::generate(&env));
    // THE PLAN FIRST, for the reason `set_members` gives: each removal is its own transaction,
    // so the delta has to ride the last one to mean "all of this happened". A named member who
    // is not in the group contributes nothing -- RFC 7644 makes a remove of an absent member a
    // no-op rather than an error, and announcing one would be a delta claiming a change nobody
    // made.
    let removing: Vec<_> = unwanted
        .iter()
        .filter_map(|member| {
            existing
                .iter()
                .find(|binding| binding.membership_id == member.membership)
                .map(|binding| (*member, binding.id))
        })
        .collect();
    // The same early return as `set_members`, and the same note: it is an optimisation. RFC 7644
    // makes a remove of an absent member a no-op rather than an error, and the delta rides a
    // write, so an operation with nothing to remove announces nothing either way.
    if removing.is_empty() {
        return Ok(());
    }
    let organization = auth.connection.organization_id.to_string();
    let group_text = group.to_string();
    let Some(delta) = crate::events::group_membership_delta_event(
        state,
        auth.scope,
        &group_text,
        &organization,
        Vec::new(),
        removing
            .iter()
            .map(|(member, _)| member.user.to_string())
            .collect(),
    ) else {
        return Err(internal_error());
    };
    for (position, (member, binding_id)) in removing.iter().enumerate() {
        let Some(per_member) = crate::events::group_member_event(
            state,
            auth.scope,
            crate::events::GROUP_MEMBER_REMOVED,
            &group_text,
            &organization,
            &member.membership.to_string(),
        ) else {
            return Err(internal_error());
        };
        let last = position + 1 == removing.len();
        acting
            .org_group_members(auth.scope)
            .remove_with_event(
                &env,
                &auth.connection.organization_id,
                binding_id,
                Some(&per_member.borrowed()),
                last.then(|| delta.borrowed()).as_ref(),
            )
            .await
            .map_err(|error| store_failure(&error))?;
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
    // RESOLVED FIRST, before the rename below writes anything. A PUT naming a member this
    // credential cannot reach would otherwise answer 404 having already renamed the group, and
    // the client would have no way to tell that half of its request landed.
    let members = match resolve_members(&state, &auth, &parsed.members).await {
        Ok(members) => members,
        Err(response) => return response,
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
    if let Err(response) = set_members(&state, &auth, &record.id, &members, true).await {
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
    if let Err(response) = apply_group_operations(&state, &auth, &record, &parsed.operations).await
    {
        return response;
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

/// What one group PATCH operation asks this surface to change, with every member id already
/// resolved to a membership in this credential's organization.
#[derive(Debug)]
enum GroupChange {
    /// Change the display label. The slug does not move.
    Rename(String),
    /// Bring the membership to this set. `true` REPLACES (anybody absent leaves).
    Members(Vec<ResolvedMember>, bool),
    /// Remove these members, leaving the rest.
    Drop(Vec<ResolvedMember>),
}

/// A group `PatchOp` is ATOMIC: everything is validated and resolved, then applied.
///
/// The same RFC 7644 section 3.5.2 requirement the users handler implements, and it was
/// missing here: a reviewer sent `[add members(alice), replace externalId]`, got a 400 for the
/// unsupported second operation, and found alice already in the group.
///
/// Resolving in the PLAN pass is what makes it worth anything on this door. A group PATCH's
/// failures are mostly member ids -- a person in another organization, a person not
/// provisioned yet -- so a plan pass that only checked the operation SHAPE would still apply
/// the first operation before the second's member id was rejected.
async fn apply_group_operations(
    state: &ScimState,
    auth: &Authenticated,
    record: &OrgGroupRecord,
    operations: &[GroupPatchOperation],
) -> Result<(), Response> {
    let mut planned = Vec::new();
    for operation in operations {
        planned.extend(plan_group_operation(state, auth, operation).await?);
    }
    for change in &planned {
        match change {
            GroupChange::Rename(label) => rename(state, auth, &record.id, label).await?,
            GroupChange::Members(members, replace) => {
                set_members(state, auth, &record.id, members, *replace).await?;
            }
            GroupChange::Drop(members) => {
                drop_members(state, auth, &record.id, members).await?;
            }
        }
    }
    Ok(())
}

/// Reduce one group operation to the changes it asks for, resolving every member id.
async fn plan_group_operation(
    state: &ScimState,
    auth: &Authenticated,
    operation: &GroupPatchOperation,
) -> Result<Vec<GroupChange>, Response> {
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
            let members =
                resolve_members(state, auth, &members_of(operation.value.as_ref())?).await?;
            Ok(vec![GroupChange::Members(members, false)])
        }
        ("replace", Some("members")) => {
            let members =
                resolve_members(state, auth, &members_of(operation.value.as_ref())?).await?;
            Ok(vec![GroupChange::Members(members, true)])
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
                let members = resolve_members(state, auth, &[named]).await?;
                return Ok(vec![GroupChange::Drop(members)]);
            }
            let named = members_of(operation.value.as_ref())?;
            if named.is_empty() {
                // `remove` on the whole attribute with no value empties the group, which is
                // what RFC 7644 section 3.5.2.2 says. It is destructive, so it happens only
                // for that exact shape rather than as the fallback of a parse failure.
                return Ok(vec![GroupChange::Members(Vec::new(), true)]);
            }
            Ok(vec![GroupChange::Drop(
                resolve_members(state, auth, &named).await?,
            )])
        }
        ("replace", Some("displayname")) => {
            let Some(Value::String(name)) = operation.value.as_ref() else {
                return Err(scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidValue"),
                    "displayName must be a string",
                ));
            };
            Ok(vec![GroupChange::Rename(name.clone())])
        }
        // The no-path shape: a whole object whose members are the attributes to set.
        ("add" | "replace", None) => {
            plan_whole_object(state, auth, operation.value.as_ref(), op == "replace").await
        }
        // A pathless `remove` has nothing to remove. RFC 7644 section 3.5.2.2 gives `noTarget`
        // for exactly this, and answering "op must be add, remove or replace" -- which an
        // earlier version did -- names the one thing that was not wrong.
        ("remove", None) => Err(scim_error(
            StatusCode::BAD_REQUEST,
            Some("noTarget"),
            "a remove operation must name the attribute it removes",
        )),
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

/// Plan the no-path shape: a whole object whose members are the attributes to set.
///
/// Its own function only because the arm is the one that loops; the behaviour is unchanged.
async fn plan_whole_object(
    state: &ScimState,
    auth: &Authenticated,
    value: Option<&Value>,
    replace: bool,
) -> Result<Vec<GroupChange>, Response> {
    let Some(Value::Object(fields)) = value else {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "an operation with no path must carry an object value",
        ));
    };
    let mut changes = Vec::new();
    for (name, member) in fields {
        match (name.to_ascii_lowercase().as_str(), member) {
            ("displayname", Value::String(label)) => {
                changes.push(GroupChange::Rename(label.clone()));
            }
            ("members", Value::Array(_)) => {
                let named = members_of(Some(member))?;
                changes.push(GroupChange::Members(
                    resolve_members(state, auth, &named).await?,
                    replace,
                ));
            }
            // Anything else in a no-path object is ignored rather than refused: a client sends
            // whole resources here, and failing would make every ordinary update a 400.
            _ => {}
        }
    }
    Ok(changes)
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
        let resource = match group_resource(&state, &auth, group, false).await {
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
