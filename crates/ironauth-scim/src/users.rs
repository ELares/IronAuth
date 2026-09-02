// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SCIM 2.0 `/Users` resource handlers (issue #135, RFC 7644 section 3).
//!
//! # What decides whether a caller may touch a resource
//!
//! ONE predicate, applied identically on every path in this module: the addressed user holds a
//! live membership in the organization named by the CREDENTIAL. Nothing in the request
//! participates in that decision except the user id, and the user id is parsed inside the
//! credential's own scope before it is used for anything.
//!
//! That shape is the answer to the two CVEs the issue cites. Casdoor's CVE-2025-4210 was a
//! SCIM authorization gap and Zitadel's CVE-2026-32130 a SCIM auth bypass by URL encoding;
//! both are failures of the step where a server takes a caller-supplied identifier, decodes
//! it, and decides whether this caller may have it. Here there is exactly one such step, it
//! runs after axum has fully percent-decoded the path, and it consults only the credential.
//!
//! # Every refusal a caller is not entitled to distinguish is the SAME refusal
//!
//! A user in another organization, a user in another tenant, a soft-deleted user, a malformed
//! id and a user that never existed all answer `404` with one body. A caller that could tell
//! those apart would have an existence oracle over the whole environment, which is precisely
//! what the IDOR criterion forbids: "cannot read, create, or mutate any resource in org B via
//! any encoding, path traversal, filter, or bulk trick".
//!
//! # externalId is per CONNECTION, not per environment
//!
//! `users.external_id` is an environment-wide column owned by the admin API. A SCIM
//! `externalId` is the PROVISIONING SYSTEM's own key for a person, and two `IdP`s provisioning
//! the same environment will collide on it. So SCIM externalIds live in `scim_external_ids`
//! (migration 0184), keyed by connection, and this module never reads or writes the
//! environment-wide column.
//!
//! # What is NOT here yet
//!
//! The BOOT MOUNT. Groups ship beside this module in `groups.rs` and are mounted by
//! `scim_router` alongside these routes; what the binary does not yet do is serve that router.
//! Mounting it, behind its config flag and with `ScimLimits` plumbed from configuration, is
//! the next slice, and is deliberately done ONCE for the whole surface.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::identifier::IdentifierType;
use ironauth_store::{
    CorrelationId, NewMembership, NewUserIdentifier, OffboardingSchedule, OrgMembershipId,
    ScimExternalIdId, StoreError, UserAdminRecord, UserId, UserIdentifierId, UserState,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::resource::ScimUser;
use crate::server::{Authenticated, ScimState, scim_error, scim_json};

/// The SCIM core user schema URN (RFC 7643 section 4.1).
const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
/// The SCIM `PatchOp` message URN (RFC 7644 section 3.5.2).
const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/// The uniform not-found every unauthorized and every absent resource answers with.
///
/// A function rather than a constant so there is ONE body: a second literal somewhere in this
/// module is how the two cases start to differ, and a caller only needs them to differ by a
/// byte to have the oracle this exists to deny.
pub(crate) fn not_found() -> Response {
    scim_error(
        StatusCode::NOT_FOUND,
        None,
        "no such user is visible to this credential",
    )
}

/// Map a store failure onto a SCIM response.
///
/// [`StoreError::NotFound`] becomes the uniform 404 rather than anything more specific: the
/// store returns it for an out-of-scope id, which is exactly the case a caller must not be
/// able to tell from an absent one.
pub(crate) fn store_failure(error: &StoreError) -> Response {
    match error {
        StoreError::NotFound => not_found(),
        StoreError::Conflict => scim_error(
            StatusCode::CONFLICT,
            Some("uniqueness"),
            "a resource with this identifier already exists",
        ),
        _ => scim_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            "the request could not be completed",
        ),
    }
}

/// Resolve the addressed user, or the uniform 404.
///
/// The two checks are separate and BOTH are load bearing. `parse_id` binds the presented text
/// to the credential's scope, so an id minted in another tenant fails here without a query.
/// `exists` then binds it to the credential's organization, which is the check the scope alone
/// cannot make: two organizations inside one environment share a scope, so a scope-valid id is
/// still not necessarily this connection's business.
pub(crate) async fn addressed_user(
    state: &ScimState,
    auth: &Authenticated,
    raw_id: &str,
) -> Result<UserId, Response> {
    let scoped = state.store().scoped(auth.scope);
    let user_id = scoped.users().parse_id(raw_id).map_err(|_| not_found())?;
    let member = scoped
        .org_memberships()
        .exists(&auth.connection.organization_id, &user_id)
        .await
        .map_err(|error| store_failure(&error))?;
    if !member {
        return Err(not_found());
    }
    Ok(user_id)
}

/// Render a stored user as a SCIM user resource (RFC 7643 section 4.1).
///
/// `active` is what THIS ORGANIZATION says (migration 0185), not the account's own state. The
/// account's state is environment wide, so rendering it would report a person as inactive here
/// because a different organization deactivated them -- the read side of the cross-organization
/// leak the write side was fixed for.
fn user_resource(record: &UserAdminRecord, external_id: Option<&str>, active: bool) -> Value {
    let mut body = json!({
        "schemas": [USER_SCHEMA],
        "id": record.id.to_string(),
        "userName": record.identifier,
        "active": active,
        "meta": {
            "resourceType": "User",
            "location": format!("/scim/v2/Users/{}", record.id),
        },
    });
    // Emitted only when this CONNECTION has one. A connection that never sent an externalId
    // must not be shown another connection's key for the same person, which is the whole
    // reason the mapping is per connection.
    if let Some(external_id) = external_id {
        body["externalId"] = json!(external_id);
    }
    body
}

/// Read the `externalId` this connection knows a user by, or `None`.
///
/// A lookup failure is `None` rather than an error: the mapping is a rendering detail, and a
/// read that fails must not turn a successful provisioning call into a 500 the IdP will retry.
async fn external_id_of(state: &ScimState, auth: &Authenticated, user: &UserId) -> Option<String> {
    state
        .store()
        .scoped(auth.scope)
        .scim_external_ids()
        .external_id_for(&auth.connection.id, user)
        .await
        .ok()
        .flatten()
}

/// Fetch and render one user the caller is entitled to see.
async fn rendered_user(
    state: &ScimState,
    auth: &Authenticated,
    user: &UserId,
) -> Result<Value, Response> {
    let record = state
        .store()
        .scoped(auth.scope)
        .users()
        .get(user)
        .await
        .map_err(|error| store_failure(&error))?;
    let external_id = external_id_of(state, auth, user).await;
    let active = state
        .store()
        .scoped(auth.scope)
        .scim_activation()
        .is_active(&auth.connection.organization_id, user)
        .await
        .map_err(|error| store_failure(&error))?;
    Ok(user_resource(&record, external_id.as_deref(), active))
}

/// `GET /scim/v2/Users/{id}`.
pub(crate) async fn get_user(
    State(state): State<ScimState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
) -> Response {
    let auth = match state.authenticate(&headers).await {
        Ok(auth) => auth,
        Err(refusal) => return refusal.response(),
    };
    let user = match addressed_user(&state, &auth, &raw_id).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    match rendered_user(&state, &auth, &user).await {
        Ok(body) => scim_json(StatusCode::OK, &body),
        Err(response) => response,
    }
}

/// `POST /scim/v2/Users`.
///
/// # Why the duplicate check goes through the flexible-identifier seam
///
/// Criterion 6 is that a SCIM-created identifier is canonicalized IDENTICALLY to one created
/// through any other door, and that DUPLICATE DETECTION proves it. `user_identifiers` is that
/// seam: its `resolve` canonicalizes once at the boundary and its `add` refuses a
/// post-canonicalization collision through a partial unique index. So this handler does not
/// implement duplicate detection at all. It asks the seam, and the 409 a caller sees is the
/// same 409 the admin API's own create produces for the same person.
pub(crate) async fn create_user(
    State(state): State<ScimState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let auth = match state.authenticate(&headers).await {
        Ok(auth) => auth,
        Err(refusal) => return refusal.response(),
    };
    let Ok(parsed) = serde_json::from_str::<ScimUser>(&body) else {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "the request body is not a SCIM user resource",
        );
    };
    let canonical = parsed.canonical_identifier();
    // An all-invisible or whitespace-only userName canonicalizes to nothing. The seam refuses
    // to store that, and refusing it HERE names the reason rather than surfacing the seam's
    // generic failure.
    if canonical.is_empty() {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "userName is required and must contain at least one visible character",
        );
    }
    let kind = canonical.kind();
    let env = state.env().clone();
    let scope = auth.scope;
    let store = state.store();
    let user_id = match refuse_a_duplicate(&state, &auth, &parsed, kind).await {
        // A person this credential once held, brought back. Their account, identifier row and
        // externalId mapping all still exist, so there is nothing to create: the response is a
        // 201 naming the id they already had, which is what the client's stored reference
        // points at.
        Ok(Some(readmitted)) => {
            return match rendered_user(&state, &auth, &readmitted).await {
                Ok(body) => created(&readmitted, &body),
                Err(response) => response,
            };
        }
        Ok(None) => UserId::generate(&env, &scope),
        Err(response) => return response,
    };
    if let Err(response) = land_account(&state, &auth, &user_id, &parsed, kind).await {
        return response;
    }
    if let Some(external_id) = parsed.external_id.as_deref() {
        let mapping_id = ScimExternalIdId::generate(&env, &scope);
        if let Err(error) = store
            .scoped(scope)
            .scim_external_ids()
            .bind(&mapping_id, &auth.connection.id, external_id, &user_id)
            .await
        {
            return store_failure(&error);
        }
    }
    // `active: false` on a create is a real thing an identity provider sends for a staged
    // user, so it is applied rather than ignored: an account created disabled must not be able
    // to sign in between the create and the deactivate the client would otherwise have to send.
    if !parsed.active
        && let Err(error) = set_active(&state, &auth, &user_id, false).await
    {
        return error;
    }
    match rendered_user(&state, &auth, &user_id).await {
        Ok(body) => created(&user_id, &body),
        Err(response) => response,
    }
}

/// The 201 a create answers, for both a fresh person and a re-admitted one.
///
/// RFC 7644 section 3.3: the `Location` header SHALL carry the URI of the CREATED RESOURCE. A
/// constant naming the collection satisfies nothing, and Entra follows this header to read the
/// resource back. One function so the two create paths cannot answer differently.
fn created(user_id: &UserId, body: &Value) -> Response {
    (
        StatusCode::CREATED,
        [
            (header::CONTENT_TYPE, crate::server::SCIM_CONTENT_TYPE),
            (
                header::LOCATION,
                format!("/scim/v2/Users/{user_id}").as_str(),
            ),
        ],
        body.to_string(),
    )
        .into_response()
}

/// Refuse a create that would duplicate somebody this credential can already see.
///
/// Split out of [`create_user`] so the two conflict rules sit together and can be read against
/// each other: they are the same kind of decision made about two different namespaces.
async fn refuse_a_duplicate(
    state: &ScimState,
    auth: &Authenticated,
    parsed: &ScimUser,
    kind: IdentifierType,
) -> Result<Option<UserId>, Response> {
    let store = state.store();
    let scope = auth.scope;
    // Duplicate detection BEFORE the write, so a collision answers 409 without having created
    // an account. `add` refuses the same collision under the partial unique index, which is
    // what makes this a fast path rather than the check: two concurrent creates both pass here
    // and one loses there.
    //
    // UNCONDITIONAL, and NOT because the uniqueness mode is ignored. A create makes an ACCOUNT
    // row, and `users_identifier_bidx_unique` (migration 0028) is
    // `UNIQUE (tenant_id, environment_id, identifier_bidx)` -- one account per login handle per
    // ENVIRONMENT, whatever `UniquenessMode` is configured. That mode governs
    // `user_identifiers`, the additional identifiers an account may carry; it cannot make a
    // second account for a handle the environment already has.
    //
    // Round 1 read this as an existence oracle and asked for a mode-aware check. The oracle
    // reading is right and the mode-aware fix was wrong: its org-scoped arm let a create
    // proceed to `register_passwordless`, which then failed on that unique constraint, so the
    // caller learned the same fact through a 500 instead of a 409. What is actually required
    // is that the refusal a foreign handle produces be INDISTINGUISHABLE from the one a handle
    // held here produces, which it is: the same status, the same scimType, the same detail,
    // and nothing naming an organization or a person.
    //
    // A person this organization previously held is the one case that is not a conflict, and
    // `readmit` below is gated on a fact only this organization could have created.
    match store
        .scoped(scope)
        .user_identifiers()
        .resolve(kind, &parsed.user_name)
        .await
    {
        Ok(found) if !found.is_empty() => {
            {
                // A RE-ADMIT rather than a conflict, when the person this names is somebody
                // this credential once held and no longer does. DELETE removes the membership
                // but nothing releases the identifier row or this connection's externalId
                // mapping (0184 grants no DELETE there, deliberately), so without this every
                // route back was closed: a reviewer deleted a person and found the re-POST
                // answered 409 in all three spellings, PATCH answered 404, and an Okta rehire
                // was unrecoverable through SCIM.
                for resolution in &found {
                    if let Some(user) = readmit(state, auth, &resolution.user_id).await? {
                        return Ok(Some(user));
                    }
                }
                return Err(scim_error(
                    StatusCode::CONFLICT,
                    Some("uniqueness"),
                    "a user with this userName already exists",
                ));
            }
        }
        Ok(_) => {}
        Err(error) => return Err(store_failure(&error)),
    }
    // MAJOR: the externalId conflict is checked BEFORE anything is written. `bind` runs after
    // three committed writes, so a duplicate externalId used to answer 409 having already
    // created the account, its identifier row and its organization membership -- the client was
    // told nothing was created and the organization gained a member. The index below is still
    // the authority for a concurrent pair; this is what stops the ordinary retry.
    if let Some(external_id) = parsed.external_id.as_deref() {
        match store
            .scoped(scope)
            .scim_external_ids()
            .resolve(&auth.connection.id, external_id)
            .await
        {
            Ok(Some(known)) => {
                // The same re-admit, through the externalId door: this connection's own key
                // for somebody it once provisioned is exactly how an identity provider names a
                // rehire.
                if let Some(user) = readmit(state, auth, &known).await? {
                    return Ok(Some(user));
                }
                return Err(scim_error(
                    StatusCode::CONFLICT,
                    Some("uniqueness"),
                    "this connection has already provisioned a user with this externalId",
                ));
            }
            Ok(None) => {}
            Err(error) => return Err(store_failure(&error)),
        }
    }
    Ok(None)
}

/// Re-admit a person this credential once held, or [`None`] if they are still a live member.
///
/// Returns `Some(user)` only when the person is genuinely absent from this organization, which
/// is the case a create is entitled to fix. A person who IS still a member is a real duplicate
/// and the caller falls through to the 409.
///
/// # This is not a way to reach somebody else's user
///
/// The person was found either by an identifier this credential is allowed to create, or by
/// THIS connection's own externalId mapping. In both cases the credential has already
/// demonstrated it knows who they are, and the re-admit binds them into the credential's own
/// organization and nowhere else -- the same write an ordinary create makes.
async fn readmit(
    state: &ScimState,
    auth: &Authenticated,
    user: &UserId,
) -> Result<Option<UserId>, Response> {
    let env = state.env().clone();
    let scoped = state.store().scoped(auth.scope);
    // THE GATE, and it is the whole safety of this path. "Not currently a member" is NOT
    // enough: it is true of every user in the environment, so re-admitting on that alone lets
    // any credential pull another organization's live user into its own by POSTing their
    // handle. That is a cross-organization write, and an earlier version of this function had
    // it -- caught by the environment-wide duplicate test answering 201.
    //
    // The activation row is the right key because only THIS surface writes it, only for THIS
    // organization, and only when this organization deactivated or deleted the person. So an
    // absent row (which reads as active) means this organization never held them, and a
    // present false row means it did.
    if scoped
        .scim_activation()
        .is_active(&auth.connection.organization_id, user)
        .await
        .map_err(|error| store_failure(&error))?
    {
        return Ok(None);
    }
    let member = scoped
        .org_memberships()
        .exists(&auth.connection.organization_id, user)
        .await
        .map_err(|error| store_failure(&error))?;
    if member {
        return Ok(None);
    }
    let membership_id = OrgMembershipId::generate(&env, &auth.scope);
    scoped
        .acting(auth.actor, CorrelationId::generate(&env))
        .org_memberships()
        .create(
            &env,
            NewMembership {
                id: &membership_id,
                organization_id: &auth.connection.organization_id,
                user_id: user,
                metadata: None,
            },
            epoch_micros(state),
            None,
        )
        .await
        .map_err(|error| store_failure(&error))?;
    // A re-admitted person is ACTIVE. The activation row from their deactivation is still
    // there and still says false, and leaving it would make the create answer 201 with
    // `active: false` -- a person the client believes it just provisioned who cannot sign in.
    set_active(state, auth, user, true).await?;
    Ok(Some(*user))
}

/// Register the account, bind it into the credential's organization, and index its login
/// identifier.
///
/// # The order is forced, not chosen
///
/// The three writes are not independently meaningful -- an account with no identifier row
/// cannot be resolved by the seam that detects duplicates, and an account with no membership is
/// invisible to the very credential that just created it -- and the repository surface offers
/// no way to make them one transaction.
///
/// An earlier version wrote the identifier BEFORE the membership, reasoning that a partial
/// failure should leave an orphan account rather than a membership pointing at nothing. That
/// reasoning was fine and the order was still wrong: under
/// [`UniquenessMode::OrgScoped`], `ActingUserIdentifierRepo::add` calls `require_live_membership`
/// and refuses an identifier for somebody who is not yet a member. So on an org-scoped
/// deployment EVERY create failed with a 500, after `register_passwordless` had already
/// committed. A reviewer drove it: the surface worked in exactly one of the three configured
/// modes, and the mode-aware duplicate check above it could never be reached in the other two.
///
/// The membership therefore comes second and the identifier third. What a partial failure
/// leaves behind is now a member with no login identifier, which the next create of the same
/// person resolves as absent and retries.
async fn land_account(
    state: &ScimState,
    auth: &Authenticated,
    user_id: &UserId,
    parsed: &ScimUser,
    kind: IdentifierType,
) -> Result<(), Response> {
    let env = state.env().clone();
    let scope = auth.scope;
    let acting = state
        .store()
        .scoped(scope)
        .acting(auth.actor, CorrelationId::generate(&env));
    // A SCIM-provisioned account holds NO password. It is reached by whatever federated or
    // passwordless method the organization uses; minting one here would create a credential
    // nobody asked for and nobody can rotate.
    acting
        .users()
        .register_passwordless(&env, user_id, &parsed.user_name, None)
        .await
        .map_err(|error| store_failure(&error))?;
    let membership_id = OrgMembershipId::generate(&env, &scope);
    acting
        .org_memberships()
        .create(
            &env,
            NewMembership {
                id: &membership_id,
                organization_id: &auth.connection.organization_id,
                user_id,
                metadata: None,
            },
            epoch_micros(state),
            None,
        )
        .await
        .map_err(|error| store_failure(&error))?;
    let identifier_id = UserIdentifierId::generate(&env, &scope);
    let organization = auth.connection.organization_id.to_string();
    acting
        .user_identifiers()
        .add(
            &env,
            NewUserIdentifier {
                id: &identifier_id,
                user_id,
                identifier_type: kind,
                raw: &parsed.user_name,
                // NOT verified. A provisioning system asserts that a person exists in its
                // directory, which is not the same claim as "this address was proven to belong
                // to them", and marking it verified here would let an identity provider hand
                // out a verified email nobody checked.
                verified: false,
                mode: state.uniqueness_mode(),
                org: Some(&organization),
            },
            None,
        )
        .await
        .map_err(|error| store_failure(&error))?;
    Ok(())
}

/// The application clock as epoch microseconds.
pub(crate) fn epoch_micros(state: &ScimState) -> i64 {
    state
        .env()
        .clock()
        .now_utc()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_micros()).ok())
        .unwrap_or(0)
}

/// Set whether this credential's organization considers a person active.
///
/// # A SCIM deactivate must not reach another organization
///
/// The obvious implementation moves `users.state` to `Disabled`, and it is WRONG. That column
/// is a property of the PERSON in the whole environment, not of one organization's view of
/// them, so a token for organization B deactivating a shared person stops them signing in to
/// organization A -- a cross-organization write through a door that never names organization
/// A. A reviewer drove exactly that: Initech's token issued one `DELETE` and Globex's user
/// could no longer authenticate.
///
/// So `active` is recorded PER ORGANIZATION (migration 0185), which is what a SCIM resource
/// actually describes: a person as one organization sees them.
///
/// # The account state moves only when nothing else holds them active
///
/// A person deactivated by their LAST organization is genuinely offboarded, and leaving the
/// account enabled would be the opposite failure: an identity provider that deactivated
/// somebody would have left them able to sign in. So `users.state` moves exactly when no other
/// organization still considers them active, in both directions, and neither direction can
/// reach a person another organization holds.
///
/// # The membership STAYS, so reactivation works
///
/// Deactivating leaves the person a member and therefore addressable. Removing the membership
/// would make the reactivating PATCH -- which an identity provider sends by resource id after
/// a rehire or a sync blip -- answer the uniform 404, leaving the client with no way to undo
/// its own deactivation. `DELETE` is the operation that removes the membership.
async fn set_active(
    state: &ScimState,
    auth: &Authenticated,
    user: &UserId,
    active: bool,
) -> Result<(), Response> {
    let scoped = state.store().scoped(auth.scope);
    scoped
        .scim_activation()
        .set_active(
            &auth.connection.organization_id,
            user,
            active,
            epoch_micros(state),
        )
        .await
        .map_err(|error| store_failure(&error))?;
    reconcile_account_state(state, auth, user).await
}

/// Move the account's own lifecycle state to match what its organizations now say.
///
/// Called after every change to a membership or an activation, and it asks ONE question: does
/// any organization still consider this person active? The answer is computed from the whole
/// relation rather than tracked incrementally, so a sequence of deactivations and
/// reactivations in any order lands on the same state as the set of facts implies.
async fn reconcile_account_state(
    state: &ScimState,
    auth: &Authenticated,
    user: &UserId,
) -> Result<(), Response> {
    let env = state.env().clone();
    let scoped = state.store().scoped(auth.scope);
    let elsewhere = scoped
        .scim_activation()
        .active_elsewhere(&auth.connection.organization_id, user)
        .await
        .map_err(|error| store_failure(&error))?;
    let here = scoped
        .org_memberships()
        .exists(&auth.connection.organization_id, user)
        .await
        .map_err(|error| store_failure(&error))?
        && scoped
            .scim_activation()
            .is_active(&auth.connection.organization_id, user)
            .await
            .map_err(|error| store_failure(&error))?;
    let should_be_active = here || elsewhere;
    let record = scoped
        .users()
        .get(user)
        .await
        .map_err(|error| store_failure(&error))?;
    let target = if should_be_active {
        UserState::Active
    } else {
        UserState::Disabled
    };
    if record.state == target {
        return Ok(());
    }
    // REACTIVATION is narrower than deactivation, deliberately. Moving somebody out of
    // `Disabled` is fine, but a person sitting in `Blocked`, `Waitlisted` or
    // `ScheduledOffboarding` is there because an operator or another subsystem put them there,
    // and a provisioning client must not be able to lift that by sending `active: true`.
    if should_be_active && record.state != UserState::Disabled {
        return Ok(());
    }
    scoped
        .acting(auth.actor, CorrelationId::generate(&env))
        .users()
        .set_state(
            &env,
            user,
            target,
            OffboardingSchedule {
                at_unix_micros: None,
                wake_payload: None,
            },
            // NOT a hard kill. Ending live sessions is the deprovisioning CASCADE, which the
            // issue puts in another piece of work; doing half of it here would make the
            // cascade's own tests pass against a behaviour it does not own.
            false,
            None,
        )
        .await
        .map_err(|error| store_failure(&error))
}

/// `PUT /scim/v2/Users/{id}` (RFC 7644 section 3.5.1).
pub(crate) async fn replace_user(
    State(state): State<ScimState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
    body: String,
) -> Response {
    let auth = match state.authenticate(&headers).await {
        Ok(auth) => auth,
        Err(refusal) => return refusal.response(),
    };
    let user = match addressed_user(&state, &auth, &raw_id).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(parsed) = serde_json::from_str::<ScimUser>(&body) else {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "the request body is not a SCIM user resource",
        );
    };
    let record = match state.store().scoped(auth.scope).users().get(&user).await {
        Ok(record) => record,
        Err(error) => return store_failure(&error),
    };
    // A rename is REFUSED rather than half-applied. The identifier a user logs in with lives
    // on the account row, which this store gives no update path, so accepting a changed
    // userName would answer 200 and leave the old handle live: the IdP would believe the
    // rename happened. Compared on the CANONICAL form, so the ordinary case of an IdP
    // re-sending the same handle in a different spelling is not a rename.
    if parsed.canonical_identifier().as_str()
        != ironauth_store::identifier::canonicalize_identifier(
            identifier_kind(&record.identifier),
            &record.identifier,
        )
        .as_str()
    {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("mutability"),
            "userName cannot be changed through SCIM in this deployment",
        );
    }
    if let Err(response) = set_active(&state, &auth, &user, parsed.active).await {
        return response;
    }
    if let Err(response) =
        rebind_external_id(&state, &auth, &user, parsed.external_id.as_deref()).await
    {
        return response;
    }
    match rendered_user(&state, &auth, &user).await {
        Ok(body) => scim_json(StatusCode::OK, &body),
        Err(response) => response,
    }
}

/// The identifier kind a stored handle has, by the same shape rule the mapping uses.
fn identifier_kind(handle: &str) -> IdentifierType {
    if handle.contains('@') {
        IdentifierType::Email
    } else {
        IdentifierType::Username
    }
}

/// Point this connection's `externalId` for a user at a new value.
///
/// An absent value LEAVES the existing mapping. RFC 7644 makes PUT a replace, but a mapping
/// this connection cannot see is not a mapping it is replacing: dropping it on a body that
/// simply did not mention it would delete the other direction of a binding the IdP still
/// relies on to find the person again.
async fn rebind_external_id(
    state: &ScimState,
    auth: &Authenticated,
    user: &UserId,
    external_id: Option<&str>,
) -> Result<(), Response> {
    let Some(external_id) = external_id else {
        return Ok(());
    };
    let existing = external_id_of(state, auth, user).await;
    if existing.as_deref() == Some(external_id) {
        return Ok(());
    }
    if existing.is_some() {
        // The mapping table holds no UPDATE and no DELETE grant, deliberately: a provisioning
        // system that changes its own key for a person has, from this side, started calling
        // somebody by a name that already belongs to somebody else's row. Refusing is the
        // honest answer; silently keeping the old key and reporting success is not.
        return Err(scim_error(
            StatusCode::CONFLICT,
            Some("mutability"),
            "externalId is already bound for this user and cannot be repointed",
        ));
    }
    let env = state.env().clone();
    let mapping_id = ScimExternalIdId::generate(&env, &auth.scope);
    state
        .store()
        .scoped(auth.scope)
        .scim_external_ids()
        .bind(&mapping_id, &auth.connection.id, external_id, user)
        .await
        .map_err(|error| store_failure(&error))
}

/// One operation in a SCIM `PatchOp` (RFC 7644 section 3.5.2).
#[derive(Debug, Deserialize)]
struct PatchOperation {
    /// `add`, `remove` or `replace`, matched case-insensitively: Entra capitalizes it.
    op: String,
    /// The attribute path, absent for an operation whose value is a whole object.
    #[serde(default)]
    path: Option<String>,
    /// The value, absent for `remove`.
    #[serde(default)]
    value: Option<Value>,
}

/// A SCIM `PatchOp` request body.
#[derive(Debug, Deserialize)]
struct PatchRequest {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(rename = "Operations", default)]
    operations: Vec<PatchOperation>,
}

/// Read a SCIM boolean that may have arrived as a JSON boolean or as a STRING.
///
/// Entra sends `"value": "False"` for a deactivate. A parser that accepted only the JSON
/// boolean would answer 200 to that request and leave the account enabled, which is the
/// deactivate-did-not-happen failure this whole surface exists to make impossible.
fn scim_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(flag) => Some(*flag),
        Value::String(text) if text.eq_ignore_ascii_case("true") => Some(true),
        Value::String(text) if text.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

/// `PATCH /scim/v2/Users/{id}` (RFC 7644 section 3.5.2).
pub(crate) async fn patch_user(
    State(state): State<ScimState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
    body: String,
) -> Response {
    let auth = match state.authenticate(&headers).await {
        Ok(auth) => auth,
        Err(refusal) => return refusal.response(),
    };
    let user = match addressed_user(&state, &auth, &raw_id).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(parsed) = serde_json::from_str::<PatchRequest>(&body) else {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "the request body is not a SCIM PatchOp",
        );
    };
    // The schema URN is checked case-insensitively on the URN as a whole, because that is how
    // both dialects send it, and REQUIRED: a body with no schemas is not a PatchOp, and
    // treating it as one would apply operations from a document that never claimed to be this.
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
    if let Err(response) = apply_operations(&state, &auth, &user, &parsed.operations).await {
        return response;
    }
    match rendered_user(&state, &auth, &user).await {
        Ok(body) => scim_json(StatusCode::OK, &body),
        Err(response) => response,
    }
}

/// What one PATCH operation asks this surface to change.
///
/// The normalized form BOTH vendor dialects reduce to. Okta sends
/// `{"op":"replace","value":{"active":false}}` (no path, a whole object) and Entra sends
/// `{"op":"Replace","path":"active","value":"False"}` (a path, a stringly boolean); neither
/// shape survives past [`plan_operation`], so nothing downstream branches on the vendor.
#[derive(Debug)]
enum Change {
    /// Set whether this credential's organization considers the person active.
    Active(bool),
    /// Point this connection's `externalId` at a value.
    ExternalId(String),
}

/// `PATCH` is ATOMIC: everything is validated, then everything is applied.
///
/// RFC 7644 section 3.5.2 says a `PatchOp` "SHALL be treated as atomic. If a single operation
/// encounters an error condition, the original SCIM resource MUST be restored". A loop that
/// validated and applied one operation at a time violated that in a way a reviewer reached in
/// one request: `[replace active=false, replace nickName]` answered 400 for the unsupported
/// second operation and left the account deactivated by the first.
///
/// Two passes cannot give true rollback across the store, and this does not claim to: a
/// failure in the middle of the APPLY pass still leaves earlier changes in place. What it
/// removes is every reachable case, because the apply pass can only fail on a store error --
/// every malformed, unsupported or ill-typed operation is refused before anything is written.
async fn apply_operations(
    state: &ScimState,
    auth: &Authenticated,
    user: &UserId,
    operations: &[PatchOperation],
) -> Result<(), Response> {
    let mut planned = Vec::new();
    for operation in operations {
        planned.extend(plan_operation(operation)?);
    }
    for change in &planned {
        match change {
            Change::Active(active) => set_active(state, auth, user, *active).await?,
            Change::ExternalId(external_id) => {
                rebind_external_id(state, auth, user, Some(external_id.as_str())).await?;
            }
        }
    }
    Ok(())
}

/// Reduce one operation to the changes it asks for, refusing anything this surface cannot do.
///
/// The `Err` variant is a whole `Response`, which is large; boxing it would mean unboxing at
/// the one call site that returns it, on a request path already doing database round trips.
///
/// Returns an EMPTY list for an operation that is well formed and asks for nothing this
/// surface serves, which happens only inside a no-path object; a path naming an unserved
/// attribute is refused, because a client that named one specifically is owed an answer rather
/// than a silent success.
#[allow(clippy::result_large_err)]
fn plan_operation(operation: &PatchOperation) -> Result<Vec<Change>, Response> {
    let op = operation.op.to_ascii_lowercase();
    if op != "add" && op != "replace" && op != "remove" {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "op must be add, remove or replace",
        ));
    }
    // The path is PARSED, never matched as text. `parse_patch_path` is the same grammar the
    // filter uses, so `active` and `emails[type eq "work"].value` are told apart by the parser
    // rather than by a substring test that would accept the second as the first.
    let attribute = match operation.path.as_deref() {
        Some(raw) => {
            let path = crate::parse_patch_path(raw).map_err(|_| {
                scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidPath"),
                    "the operation path is not a SCIM attribute path",
                )
            })?;
            // A sub-attribute or a value selector addresses something inside a multi-valued
            // attribute, and this slice serves none. Refusing names that; applying the
            // operation to the parent attribute would silently do the wrong thing.
            if path.sub_attribute().is_some() || path.selector().is_some() {
                return Err(unsupported_attribute(path.attribute()));
            }
            Some(path.attribute().to_ascii_lowercase())
        }
        None => None,
    };
    match (op.as_str(), attribute.as_deref()) {
        // `remove` on an attribute this surface serves means "set it to its default".
        // Answering "this surface does not serve the attribute active" to that, which an
        // earlier version did, is a false sentence about a supported attribute.
        ("remove", Some("active")) => Ok(vec![Change::Active(true)]),
        (_, Some("active")) => {
            let Some(value) = operation.value.as_ref() else {
                return Err(scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidValue"),
                    "active must carry a boolean value",
                ));
            };
            let Some(active) = scim_bool(value) else {
                return Err(scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidValue"),
                    "active must be a boolean",
                ));
            };
            Ok(vec![Change::Active(active)])
        }
        (_, Some("externalid")) => {
            let Some(Value::String(external_id)) = operation.value.as_ref() else {
                return Err(scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidValue"),
                    "externalId must be a string",
                ));
            };
            Ok(vec![Change::ExternalId(external_id.clone())])
        }
        (_, Some(other)) => Err(unsupported_attribute(other)),
        // The no-path shape: a whole object whose members are the attributes to set.
        (_, None) => {
            let Some(Value::Object(members)) = operation.value.as_ref() else {
                return Err(scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidValue"),
                    "an operation with no path must carry an object value",
                ));
            };
            let mut changes = Vec::new();
            for (name, value) in members {
                match name.to_ascii_lowercase().as_str() {
                    "active" => {
                        let Some(active) = scim_bool(value) else {
                            return Err(scim_error(
                                StatusCode::BAD_REQUEST,
                                Some("invalidValue"),
                                "active must be a boolean",
                            ));
                        };
                        changes.push(Change::Active(active));
                    }
                    "externalid" => {
                        if let Value::String(external_id) = value {
                            changes.push(Change::ExternalId(external_id.clone()));
                        }
                    }
                    // An attribute this surface does not serve is IGNORED inside a no-path
                    // object, not refused. A client sends whole resources here, most of whose
                    // members are profile attributes, and failing would make every ordinary
                    // update a 400.
                    _ => {}
                }
            }
            Ok(changes)
        }
    }
}

/// The refusal for an attribute this slice does not serve.
fn unsupported_attribute(attribute: &str) -> Response {
    // The PARSED attribute name, never the caller's raw path. The filter parser next door
    // states the policy: "none carries the offending text, because echoing an attacker's input
    // back into a response body is how a parser becomes a reflection gadget." A reviewer got a
    // whole selector, script tags and a right-to-left override included, back verbatim. The
    // attribute name is bounded by the grammar and carries no quoted literal.
    let _ = attribute;
    scim_error(
        StatusCode::BAD_REQUEST,
        Some("invalidPath"),
        "this surface does not serve the attribute this operation names",
    )
}

/// `DELETE /scim/v2/Users/{id}` (RFC 7644 section 3.6).
///
/// # Unbind, and disable only what nothing else holds
///
/// The membership in the credential's organization is removed, and the ACCOUNT is disabled
/// only when that was the person's last live membership. It is never deleted. So an account
/// other organizations in this environment also hold stays exactly as reachable to them as
/// before, which an earlier version of this handler did not manage: it moved `users.state`
/// unconditionally, and one organization's DELETE stopped a shared person signing in
/// everywhere. See [`set_active`] for the rule and why both directions are conditioned on it.
pub(crate) async fn delete_user(
    State(state): State<ScimState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
) -> Response {
    let auth = match state.authenticate(&headers).await {
        Ok(auth) => auth,
        Err(refusal) => return refusal.response(),
    };
    let user = match addressed_user(&state, &auth, &raw_id).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    // DELETE and `active: false` are DIFFERENT acts here, and the difference is deliberate.
    // RFC 7644 section 3.6 deletes the RESOURCE, so this removes the membership and the person
    // stops being visible to this credential. A deactivate keeps the membership, because a
    // client reactivates by resource id and an unaddressable person could never be reactivated.
    let env = state.env().clone();
    let scoped = state.store().scoped(auth.scope);
    let memberships = match scoped.org_memberships().list_for_user(&user).await {
        Ok(memberships) => memberships,
        Err(error) => return store_failure(&error),
    };
    // The activation row is written FIRST and the membership removed second, so the account
    // reconciliation below sees this organization as no longer holding the person by both
    // measures. Writing it after the removal would leave a row for a membership that is gone.
    if let Err(error) = scoped
        .scim_activation()
        .set_active(
            &auth.connection.organization_id,
            &user,
            false,
            epoch_micros(&state),
        )
        .await
    {
        return store_failure(&error);
    }
    let acting = scoped.acting(auth.actor, CorrelationId::generate(&env));
    for membership in memberships
        .iter()
        .filter(|membership| membership.organization_id == auth.connection.organization_id)
    {
        if let Err(error) = acting.org_memberships().remove(&env, &membership.id).await {
            return store_failure(&error);
        }
    }
    if let Err(response) = reconcile_account_state(&state, &auth, &user).await {
        return response;
    }
    StatusCode::NO_CONTENT.into_response()
}

/// The query parameters `GET /scim/v2/Users` reads (RFC 7644 section 3.4.2).
///
/// # Every field is a STRING, and the numbers are parsed later
///
/// `Query<T>` is a `FromRequestParts` extractor, so it runs BEFORE the handler body and
/// therefore before authentication. With typed fields, `?count=abc` answered a plain-text
/// `400 Failed to deserialize query string` to a caller with no credential at all -- the one
/// response on this surface that is neither a SCIM error document nor the uniform 401, and an
/// answer an unauthenticated caller is not entitled to. Taking the raw strings makes the
/// extractor infallible, so the first thing every request meets is still `authenticate`.
#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    #[serde(default)]
    filter: Option<String>,
    #[serde(rename = "startIndex", default)]
    start_index: Option<String>,
    #[serde(default)]
    count: Option<String>,
}

impl ListQuery {
    /// The raw filter text, if the caller sent one.
    pub(crate) fn filter(&self) -> Option<&str> {
        self.filter.as_deref()
    }

    /// The 1-based index of the first resource to return (RFC 7644 section 3.4.2.4).
    ///
    /// Clamped up to 1 rather than refused: the RFC says a value less than 1 is interpreted as
    /// 1, and refusing would fail a client that sent 0 meaning "the beginning". An
    /// UNPARSEABLE value is also 1, for the reason in the struct docs: this runs after
    /// authentication and a refusal here would be a fourth answer shape for a caller who at
    /// worst mistyped a number.
    pub(crate) fn start_index(&self) -> i64 {
        self.start_index
            .as_deref()
            .and_then(|raw| raw.parse::<i64>().ok())
            .unwrap_or(1)
            .max(1)
    }

    /// The requested page size, for [`ScimLimits::clamp_count`] to bound.
    ///
    /// A NEGATIVE count becomes zero rather than wrapping: `usize::try_from` on a negative
    /// fails, and mapping that failure to the default page size would turn "give me nothing"
    /// into a full page. An unparseable value is `None`, which is the default page size --
    /// the same answer a caller who sent no count at all gets.
    pub(crate) fn count(&self) -> Option<usize> {
        let raw = self.count.as_deref()?;
        let parsed = raw.parse::<i64>().ok()?;
        Some(usize::try_from(parsed.max(0)).unwrap_or(0))
    }
}

/// `GET /scim/v2/Users` (RFC 7644 section 3.4.2).
///
/// # Three ways to answer, and the reason there are three
///
/// A provisioning client sends exactly two filters during an ordinary sync: `userName eq` to
/// find out whether a person already exists, and `externalId eq` to find the person it created
/// last time. Both are answered from an INDEX -- the flexible-identifier seam and this
/// connection's `externalId` mapping -- so the common path does one lookup regardless of how
/// large the organization is.
///
/// Anything else (an unfiltered listing, or a filter over an attribute with no index) is
/// answered by walking the credential's organization MEMBERSHIPS and evaluating the parsed
/// filter against each rendered resource. That walk is bounded by `max_scan`, and reaching
/// the bound answers `tooMany` rather than a short page. A short page here would be read by
/// the client as "these are all the members", and an Okta or Entra sync deprovisions everyone
/// it did not see.
///
/// # Every path ends at the SAME membership predicate
///
/// The indexed paths resolve a user id and then check membership, exactly as the
/// single-resource path does. So a `userName eq` for somebody in another organization returns
/// an empty list rather than that person: the index is a way to find a candidate, never a way
/// around the boundary.
pub(crate) async fn list_users(
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
    let start_index = query.start_index();
    let count = state.limits().clamp_count(query.count());
    let matched = match collect_matches(&state, &auth, filter.as_ref()).await {
        Ok(matched) => matched,
        Err(response) => return response,
    };
    let total = matched.len();
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

/// Every resource in this credential's organization that satisfies `filter`.
async fn collect_matches(
    state: &ScimState,
    auth: &Authenticated,
    filter: Option<&crate::Filter>,
) -> Result<Vec<Value>, Response> {
    if let Some(filter) = filter
        && let Some(candidate) = indexed_candidate(state, auth, filter).await?
    {
        // The index found at most one user. It still has to pass the SAME membership check the
        // single-resource path applies, and the filter is still evaluated against the rendered
        // resource rather than assumed: the index answers "who has this handle", which is not
        // the same question as "does this resource satisfy this filter".
        let member = state
            .store()
            .scoped(auth.scope)
            .org_memberships()
            .exists(&auth.connection.organization_id, &candidate)
            .await
            .map_err(|error| store_failure(&error))?;
        if !member {
            return Ok(Vec::new());
        }
        // NO post-hoc filter re-check. The index answered the same question the filter asks,
        // and the two do not agree on what "equal" means: the identifier seam canonicalizes
        // (NFKC, case fold, whitespace and zero-width stripping) while the evaluator's string
        // comparison only lowercases. A reviewer found the consequence -- a user stored as
        // `admin` made `POST "ad min"` a 409 and `filter=userName eq "ad min"` an empty list,
        // so a client sending that spelling could neither find the person nor create them.
        // Re-checking here would be asking a weaker comparison to second-guess a stronger one.
        return Ok(vec![rendered_user(state, auth, &candidate).await?]);
    }
    scan_members(state, auth, filter).await
}

/// The single user an indexed filter names, or `None` when the filter is not one this can
/// answer from an index.
///
/// `Ok(None)` covers BOTH "not an indexed filter" and "indexed, and the value resolves to
/// nobody". Collapsing them is safe because the caller falls back to the bounded scan, which
/// returns the empty list for a value nobody has; keeping them apart would only add a path.
async fn indexed_candidate(
    state: &ScimState,
    auth: &Authenticated,
    filter: &crate::Filter,
) -> Result<Option<UserId>, Response> {
    let crate::Filter::Compare { path, op, value } = filter else {
        return Ok(None);
    };
    // ONLY `eq`, and only on a bare attribute. `co`, `sw` and a sub-attribute are not
    // answerable from an equality index, and treating them as though they were would return a
    // single exact match for a filter that asks for a set.
    if *op != crate::CompareOp::Equal || path.sub.is_some() {
        return Ok(None);
    }
    let crate::Value::String(wanted) = value else {
        return Ok(None);
    };
    let scoped = state.store().scoped(auth.scope);
    if path.name.eq_ignore_ascii_case("userName") {
        let kind = identifier_kind(wanted);
        let found = scoped
            .user_identifiers()
            .resolve(kind, wanted)
            .await
            .map_err(|error| store_failure(&error))?;
        // AMBIGUOUS resolves to nothing here, deliberately. Under a non-unique uniqueness
        // mode one handle can name several people, and answering with the first would hand a
        // provisioning client a person it did not ask for. The scan is the correct answer to
        // an ambiguous handle, and returning `None` falls through to it.
        return Ok(match found.as_slice() {
            [single] => Some(single.user_id),
            _ => None,
        });
    }
    if path.name.eq_ignore_ascii_case("externalId") {
        return scoped
            .scim_external_ids()
            .resolve(&auth.connection.id, wanted)
            .await
            .map_err(|error| store_failure(&error));
    }
    Ok(None)
}

/// Walk the organization's memberships, rendering and filtering each, up to `max_scan`.
async fn scan_members(
    state: &ScimState,
    auth: &Authenticated,
    filter: Option<&crate::Filter>,
) -> Result<Vec<Value>, Response> {
    let scoped = state.store().scoped(auth.scope);
    // One row MORE than the bound, so reaching it is distinguishable from exactly filling it.
    // Asking for exactly `max_scan` and getting `max_scan` back cannot tell a full page from
    // the last page, and guessing either way is wrong half the time.
    let probe = i64::try_from(state.limits().scan_bound().saturating_add(1)).unwrap_or(i64::MAX);
    let memberships = scoped
        .org_memberships()
        .list_for_org(&auth.connection.organization_id, probe, None)
        .await
        .map_err(|error| store_failure(&error))?;
    if memberships.len() > state.limits().scan_bound() {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            Some("tooMany"),
            "this organization has more members than one request may examine; \
             narrow the request with a userName or externalId filter",
        ));
    }
    let mut matched = Vec::new();
    for membership in &memberships {
        // A membership whose user is gone is skipped rather than fatal: the two rows are not
        // written in one transaction, and one dangling row must not make an entire
        // organization unlistable.
        let Ok(record) = scoped.users().get(&membership.user_id).await else {
            continue;
        };
        let external_id = external_id_of(state, auth, &membership.user_id).await;
        let active = scoped
            .scim_activation()
            .is_active(&auth.connection.organization_id, &membership.user_id)
            .await
            .map_err(|error| store_failure(&error))?;
        let resource = user_resource(&record, external_id.as_deref(), active);
        if let Some(filter) = filter
            && !crate::filter_matches(filter, &resource)
        {
            continue;
        }
        matched.push(resource);
    }
    Ok(matched)
}
