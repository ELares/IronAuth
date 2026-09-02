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
//! Groups, and the boot mount. The router this module extends is still assembled and tested
//! but not served by the binary; mounting it, behind its config flag, is the next slice, and
//! is deliberately done ONCE for the whole surface rather than half now and half later.

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
fn user_resource(record: &UserAdminRecord, external_id: Option<&str>) -> Value {
    let mut body = json!({
        "schemas": [USER_SCHEMA],
        "id": record.id.to_string(),
        "userName": record.identifier,
        "active": record.state == UserState::Active,
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
    Ok(user_resource(&record, external_id.as_deref()))
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
    // Duplicate detection BEFORE the write, so a collision answers 409 without having created
    // an account. `add` refuses the same collision under the unique index, which is what makes
    // this a fast path rather than the check: two concurrent creates both pass here and one
    // loses there.
    match store
        .scoped(scope)
        .user_identifiers()
        .resolve(kind, &parsed.user_name)
        .await
    {
        Ok(found) if !found.is_empty() => {
            return scim_error(
                StatusCode::CONFLICT,
                Some("uniqueness"),
                "a user with this userName already exists",
            );
        }
        Ok(_) => {}
        Err(error) => return store_failure(&error),
    }
    let user_id = UserId::generate(&env, &scope);
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
    // `active: false` on a create is a real thing Okta sends for a staged user, so it is
    // applied rather than ignored: an account created disabled must not be able to sign in
    // between the create and the deactivate the IdP would otherwise have to send.
    if !parsed.active
        && let Err(error) = set_active(&state, &auth, &user_id, false).await
    {
        return error;
    }
    match rendered_user(&state, &auth, &user_id).await {
        Ok(body) => (
            StatusCode::CREATED,
            [
                (header::CONTENT_TYPE, crate::server::SCIM_CONTENT_TYPE),
                (header::LOCATION, "/scim/v2/Users"),
            ],
            body.to_string(),
        )
            .into_response(),
        Err(response) => response,
    }
}

/// Register the account, index its login identifier, and bind it into the credential's
/// organization.
///
/// The THREE writes a create is, in one place, because they are not independently meaningful:
/// an account with no identifier row cannot be resolved by the seam that detects duplicates,
/// and an account with no membership is invisible to the very credential that just created
/// it. They are not one transaction (the repository surface has no way to make them one), so
/// the order is chosen for what a partial failure leaves behind: an orphan account that no
/// connection can see, rather than a membership pointing at nothing.
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

/// Move a user between the active and disabled lifecycle states.
///
/// `active=false` maps to [`UserState::Disabled`] rather than blocked: the issue says so, and
/// the two differ in operator INTENT, which a provisioning system does not have. A user
/// already in the target state is left alone rather than transitioned, because the store
/// refuses a no-op transition and an IdP re-sending a deactivate is ordinary traffic.
async fn set_active(
    state: &ScimState,
    auth: &Authenticated,
    user: &UserId,
    active: bool,
) -> Result<(), Response> {
    let store = state.store();
    let record = store
        .scoped(auth.scope)
        .users()
        .get(user)
        .await
        .map_err(|error| store_failure(&error))?;
    let target = if active {
        UserState::Active
    } else {
        UserState::Disabled
    };
    if record.state == target {
        return Ok(());
    }
    let env = state.env().clone();
    store
        .scoped(auth.scope)
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
    for operation in &parsed.operations {
        if let Err(response) = apply_operation(&state, &auth, &user, operation).await {
            return response;
        }
    }
    match rendered_user(&state, &auth, &user).await {
        Ok(body) => scim_json(StatusCode::OK, &body),
        Err(response) => response,
    }
}

/// Apply one PATCH operation.
///
/// # The two dialects, handled as one
///
/// Okta sends `{"op":"replace","value":{"active":false}}` (no path, a whole object) and Entra
/// sends `{"op":"Replace","path":"active","value":"False"}` (a path, a stringly boolean).
/// Rather than branch on the vendor, both are normalized to the same
/// (attribute, value) pairs and applied by one arm each.
async fn apply_operation(
    state: &ScimState,
    auth: &Authenticated,
    user: &UserId,
    operation: &PatchOperation,
) -> Result<(), Response> {
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
                return Err(unsupported_attribute(raw));
            }
            Some(path.attribute().to_ascii_lowercase())
        }
        None => None,
    };
    match (attribute.as_deref(), operation.value.as_ref()) {
        // Entra's shape: a path naming the attribute and a scalar value.
        (Some("active"), Some(value)) => {
            let Some(active) = scim_bool(value) else {
                return Err(scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidValue"),
                    "active must be a boolean",
                ));
            };
            set_active(state, auth, user, active).await
        }
        (Some("externalid"), Some(Value::String(external_id))) => {
            rebind_external_id(state, auth, user, Some(external_id.as_str())).await
        }
        // Okta's shape: no path, a whole object whose members are the attributes to set.
        (None, Some(Value::Object(members))) => {
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
                        set_active(state, auth, user, active).await?;
                    }
                    "externalid" => {
                        if let Value::String(external_id) = value {
                            rebind_external_id(state, auth, user, Some(external_id.as_str()))
                                .await?;
                        }
                    }
                    // An attribute this surface does not serve is IGNORED inside a
                    // no-path object, not refused. Okta sends whole resources here, most of
                    // whose members are profile attributes; failing the request would make
                    // every ordinary Okta update a 400.
                    _ => {}
                }
            }
            Ok(())
        }
        (Some(other), _) => Err(unsupported_attribute(other)),
        _ => Err(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "the operation carries no value this surface can apply",
        )),
    }
}

/// The refusal for an attribute this slice does not serve.
fn unsupported_attribute(attribute: &str) -> Response {
    scim_error(
        StatusCode::BAD_REQUEST,
        Some("invalidPath"),
        &format!("this surface does not serve the attribute {attribute}"),
    )
}

/// `DELETE /scim/v2/Users/{id}` (RFC 7644 section 3.6).
///
/// # Disable and unbind, never destroy
///
/// The account is moved to disabled and its membership in the credential's organization is
/// removed. It is NOT deleted: one organization's provisioning system must not be able to
/// destroy an account that other organizations in the same environment also hold, and after
/// this call the user is exactly as reachable to those organizations as before.
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
    if let Err(response) = set_active(&state, &auth, &user, false).await {
        return response;
    }
    let env = state.env().clone();
    let memberships = match state
        .store()
        .scoped(auth.scope)
        .org_memberships()
        .list_for_user(&user)
        .await
    {
        Ok(memberships) => memberships,
        Err(error) => return store_failure(&error),
    };
    let acting = state
        .store()
        .scoped(auth.scope)
        .acting(auth.actor, CorrelationId::generate(&env));
    for membership in memberships
        .iter()
        .filter(|membership| membership.organization_id == auth.connection.organization_id)
    {
        if let Err(error) = acting.org_memberships().remove(&env, &membership.id).await {
            return store_failure(&error);
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

/// The query parameters `GET /scim/v2/Users` reads (RFC 7644 section 3.4.2).
#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    #[serde(default)]
    filter: Option<String>,
    #[serde(rename = "startIndex", default)]
    start_index: Option<i64>,
    #[serde(default)]
    count: Option<i64>,
}

impl ListQuery {
    /// The raw filter text, if the caller sent one.
    pub(crate) fn filter(&self) -> Option<&str> {
        self.filter.as_deref()
    }

    /// The 1-based index of the first resource to return (RFC 7644 section 3.4.2.4).
    ///
    /// Clamped up to 1 rather than refused: the RFC says a value less than 1 is interpreted
    /// as 1, and refusing would fail a client that sent 0 meaning "the beginning".
    pub(crate) fn start_index(&self) -> i64 {
        self.start_index.unwrap_or(1).max(1)
    }

    /// The requested page size, for [`ScimLimits::clamp_count`] to bound.
    ///
    /// A NEGATIVE count becomes zero rather than wrapping: `usize::try_from` on a negative
    /// fails, and mapping that failure to the default page size would turn "give me nothing"
    /// into a full page.
    pub(crate) fn count(&self) -> Option<usize> {
        self.count
            .map(|count| usize::try_from(count.max(0)).unwrap_or(0))
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
        let resource = rendered_user(state, auth, &candidate).await?;
        return Ok(if crate::filter_matches(filter, &resource) {
            vec![resource]
        } else {
            Vec::new()
        });
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
    let probe = i64::try_from(state.limits().max_scan.saturating_add(1)).unwrap_or(i64::MAX);
    let memberships = scoped
        .org_memberships()
        .list_for_org(&auth.connection.organization_id, probe, None)
        .await
        .map_err(|error| store_failure(&error))?;
    if memberships.len() > state.limits().max_scan {
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
        let resource = user_resource(&record, external_id.as_deref());
        if let Some(filter) = filter
            && !crate::filter_matches(filter, &resource)
        {
            continue;
        }
        matched.push(resource);
    }
    Ok(matched)
}
