// SPDX-License-Identifier: MIT OR Apache-2.0

//! The effective organization ROLES token claim end to end, against a real Postgres
//! (issue #97, PR 6): the access token carries the union of a member's direct roles,
//! their groups' roles, and the roles inherited from those groups' ancestors, and it
//! carries that union RESOLVED FRESH at every issuance.
//!
//! # What this file exists to pin
//!
//! The design decision under test is `fresh` versus `frozen`, and it is the exact
//! OPPOSITE of the one `tests/org_context.rs` pins for `org_id`. `org_id` freezes onto
//! the session, then the grant, and is REPLAYED on refresh, so
//! `a_refreshed_access_token_keeps_the_same_org_id` must keep passing untouched. A
//! role is an AUTHORIZATION input, so it must NOT be frozen anywhere: it is re-read
//! from the store on every code exchange AND every refresh. The refresh hook is the
//! load-bearing half. Refresh is the highest-volume grant, so a role change visible
//! only on a new code exchange would be invisible for the whole refresh-family
//! lifetime; re-resolving on refresh is what caps the exposure at ONE ACCESS TOKEN
//! LIFETIME. Both directions are pinned here (a grant becoming visible, and a
//! withdrawal becoming invisible), on BOTH grants.
//!
//! The other properties pinned, each of which a plausible refactor would break:
//!
//!   * ABSENT and EMPTY are different answers. No organization context emits NO claim;
//!     a resolved organization context that yields nothing emits `[]`. A consumer must
//!     be able to tell "not an org token" from "org token, no roles".
//!   * THE ORGANIZATION'S OWN LIFECYCLE reaches the claim, on both hooks. Disable and
//!     soft-delete are the coarsest revocations an operator has, and neither hook can
//!     check them for itself (refresh never runs the authorize-time resolution, and a
//!     code exchange on an already-bound session returns from it early), so the fence
//!     lives in the store's shared closure and is driven here through both.
//!   * FAIL CLOSED. A store fault during resolution refuses the token request, and so
//!     does a RECORDED identifier that no longer parses in scope, on either branch. A
//!     role-less token would read downstream as a successful authorization DOWNGRADE,
//!     which is why `roles` deliberately does not ride the fail-OPEN id-token extra
//!     claims bag.
//!   * THE CONFIGURED NESTING BOUND is the one the mint resolves with, observed at the
//!     store call rather than through an accessor.
//!   * The claim is ISSUER-SET ONLY, proved through the real forgery path rather than
//!     asserted from the denylist: a user whose stored claim document contains
//!     `roles`, requested through the OIDC Core 5.5 `claims` parameter, does not get
//!     it stamped into their ID token; and a client whose stored
//!     `custom_token_claims` contains `roles` does not get it stamped into an M2M
//!     access token.
//!   * The ID token never carries roles, and neither machine path does.
//!   * Two issuances against identical stored state produce byte-identical claims.
//!
//! Every claim is read back through the ONE hardened verify path, so a token that
//! fails to verify fails the test before any claim is inspected. Roles, groups, and
//! assignments are seeded through the CONTROL plane (as production does); the data
//! plane resolves them under the low-privilege `ironauth_app` role, so the PR 1 to
//! PR 3 SELECT grants are genuinely exercised.

mod common;

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, SEED_PASSWORD, enc, form, json,
    location_param,
};
use ironauth_jose::verify;
use ironauth_oidc::ClientAuthMethod;
use ironauth_store::{
    ActorRef, CorrelationId, NewMembership, NewOrgGroup, NewOrgGroupMember, NewOrgGroupRole,
    NewOrgMembershipRole, NewOrgRole, OrgGroupId, OrgGroupMemberId, OrgGroupRoleId,
    OrgMembershipId, OrgMembershipRoleId, OrgRoleId, OrganizationId, OrganizationState, Scope,
    ServiceId, UserId,
};
use serde_json::Value;

/// The group nesting depth every test here passes to the store seeding helpers: the
/// shipped `[organizations] max_group_depth` default, which is also what the data
/// plane resolves with when the boot path installed nothing.
const DEFAULT_DEPTH: u32 = 8;

/// The clock-seam instant the seeded rows are dated with. The harness clock is frozen
/// at the Unix epoch, so a literal is the honest value and no wall-clock constructor
/// is needed (the determinism seam forbids one anywhere under `crates/`).
const SEED_MICROS: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Control-plane seeding
// ---------------------------------------------------------------------------

/// Create an ACTIVE organization in the harness scope through the control plane.
async fn create_org(harness: &Harness, display_name: &str) -> OrganizationId {
    create_org_in(harness, harness.scope(), display_name).await
}

/// Create an ACTIVE organization in an ARBITRARY scope through the control plane.
///
/// The scope is a parameter rather than always the harness's own so a test can mint
/// an organization id that is REAL (it satisfies the single-column `grants_org_fk`)
/// and yet does not parse in the harness scope, which is the only way to reach the
/// mint's out-of-scope fail-closed branch through the store rather than by faking it.
async fn create_org_in(harness: &Harness, scope: Scope, display_name: &str) -> OrganizationId {
    let env = harness.env().clone();
    let org_id = OrganizationId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .create(&env, &org_id, SEED_MICROS, display_name, None)
        .await
        .expect("create organization");
    org_id
}

/// Flip an organization's lifecycle state through the control plane: the operator's
/// disable (and re-enable) action, exactly as the management API drives it.
async fn set_org_state(harness: &Harness, org: &OrganizationId, state: OrganizationState) {
    let env = harness.env().clone();
    let scope = harness.scope();
    harness
        .db()
        .control_store()
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .set_state(&env, org, state, None)
        .await
        .expect("set organization state");
}

/// Soft-delete an organization through the control plane: the operator's delete
/// action. The row is retained (only `deleted_at` is written) and NOTHING cascades,
/// which is precisely why the resolution has to observe it itself.
async fn soft_delete_org(harness: &Harness, org: &OrganizationId) {
    let env = harness.env().clone();
    let scope = harness.scope();
    harness
        .db()
        .control_store()
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .delete(&env, org)
        .await
        .expect("soft delete organization");
}

/// Bind `subject` (a `usr_` id string) into `org` as a live member, returning the
/// membership id the direct role assignments address.
async fn add_member(harness: &Harness, org: &OrganizationId, subject: &str) -> OrgMembershipId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let user_id = UserId::parse_in_scope(subject, &scope).expect("subject parses in scope");
    let membership_id = OrgMembershipId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .org_memberships(scope)
        .create(
            &env,
            NewMembership {
                id: &membership_id,
                organization_id: org,
                user_id: &user_id,
                metadata: None,
            },
            SEED_MICROS,
            None,
        )
        .await
        .expect("add membership");
    membership_id
}

/// Define a role in `org` under the immutable `slug` the token claim carries.
async fn create_role(harness: &Harness, org: &OrganizationId, slug: &str) -> OrgRoleId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = OrgRoleId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .org_roles(scope)
        .create(
            &env,
            NewOrgRole {
                id: &id,
                organization_id: org,
                slug,
                display_name: "Role",
                metadata: None,
            },
            SEED_MICROS,
            None,
        )
        .await
        .expect("create role");
    id
}

/// Define a group in `org`, optionally under `parent`.
async fn create_group(
    harness: &Harness,
    org: &OrganizationId,
    slug: &str,
    parent: Option<&OrgGroupId>,
) -> OrgGroupId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = OrgGroupId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .org_groups(scope)
        .create(
            &env,
            NewOrgGroup {
                id: &id,
                organization_id: org,
                parent_id: parent,
                slug,
                display_name: "Group",
                metadata: None,
            },
            SEED_MICROS,
            DEFAULT_DEPTH,
            None,
        )
        .await
        .expect("create group");
    id
}

/// Bind `membership` into `group`.
async fn bind_member(
    harness: &Harness,
    org: &OrganizationId,
    group: &OrgGroupId,
    membership: &OrgMembershipId,
) -> OrgGroupMemberId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = OrgGroupMemberId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .org_group_members(scope)
        .add(
            &env,
            NewOrgGroupMember {
                id: &id,
                organization_id: org,
                group_id: group,
                membership_id: membership,
            },
            SEED_MICROS,
            None,
        )
        .await
        .expect("bind membership into group");
    id
}

/// Grant `role` to every member of `group` and of `group`'s descendants.
async fn grant_group_role(
    harness: &Harness,
    org: &OrganizationId,
    group: &OrgGroupId,
    role: &OrgRoleId,
) -> OrgGroupRoleId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = OrgGroupRoleId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .org_group_roles(scope)
        .assign(
            &env,
            NewOrgGroupRole {
                id: &id,
                organization_id: org,
                group_id: group,
                role_id: role,
            },
            SEED_MICROS,
            None,
        )
        .await
        .expect("grant role to group");
    id
}

/// Grant `role` straight to one membership, with no group involved.
async fn grant_direct_role(
    harness: &Harness,
    org: &OrganizationId,
    membership: &OrgMembershipId,
    role: &OrgRoleId,
) -> OrgMembershipRoleId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = OrgMembershipRoleId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .org_membership_roles(scope)
        .assign(
            &env,
            NewOrgMembershipRole {
                id: &id,
                organization_id: org,
                membership_id: membership,
                role_id: role,
            },
            SEED_MICROS,
            None,
        )
        .await
        .expect("grant role directly");
    id
}

/// Withdraw a DIRECT role grant by its assignment id (the soft delete the
/// resolution's `deleted_at IS NULL` filter must observe on the very next issuance).
async fn withdraw_direct_role(
    harness: &Harness,
    org: &OrganizationId,
    assignment: &OrgMembershipRoleId,
) {
    let env = harness.env().clone();
    let scope = harness.scope();
    harness
        .db()
        .control_store()
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .org_membership_roles(scope)
        .unassign(&env, org, assignment)
        .await
        .expect("withdraw direct role");
}

// ---------------------------------------------------------------------------
// Protocol driving
// ---------------------------------------------------------------------------

/// The public-client authorization query (PKCE mandatory), with any extra pre-encoded
/// `key=value` fragments (for example `organization=org_...`).
fn authorize_query(client_id: &str, extra: &[&str]) -> String {
    let mut query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    );
    for fragment in extra {
        query.push('&');
        query.push_str(fragment);
    }
    query
}

/// The public-client token-exchange form (the PKCE verifier the authorize bound a
/// challenge for).
fn token_form(code: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ])
}

/// Drive authorize (with `cookie`) to a code, expecting a redirect.
async fn authorize_to_code(
    harness: &Harness,
    client_id: &str,
    extra: &[&str],
    cookie: &str,
) -> String {
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(client_id, extra), cookie)
        .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "authorize should redirect: {body}"
    );
    location_param(&headers, "code").expect("code in redirect")
}

/// Exchange `code` and return the verified (ID-token claims, access-token claims,
/// refresh token).
async fn exchange(harness: &Harness, client_id: &str, code: &str) -> (Value, Value, String) {
    let (status, _, body) = harness.token(&token_form(code, client_id)).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let value = json(&body);
    let id_token = value["id_token"].as_str().expect("id_token present");
    let access_token = value["access_token"]
        .as_str()
        .expect("access_token present");
    let refresh_token = value["refresh_token"]
        .as_str()
        .expect("a refresh token is issued for the code flow")
        .to_owned();
    let id_policy = harness.id_token_policy(client_id);
    let access_policy = harness.access_token_policy(client_id);
    let id = verify(id_token, &id_policy, &common::verify_clock()).expect("id token verifies");
    let at = verify(access_token, &access_policy, &common::verify_clock())
        .expect("access token verifies");
    (
        Value::Object(id.claims().raw().clone()),
        Value::Object(at.claims().raw().clone()),
        refresh_token,
    )
}

/// Refresh `refresh_token` and return the verified access-token claims plus the
/// rotated refresh token (the harness's public client always rotates).
async fn refresh(harness: &Harness, client_id: &str, refresh_token: &str) -> (Value, String) {
    let (status, _, body) = harness
        .token(&form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ]))
        .await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    let value = json(&body);
    let access_token = value["access_token"]
        .as_str()
        .expect("access_token present");
    let rotated = value["refresh_token"]
        .as_str()
        .expect("the public client rotates its refresh token")
        .to_owned();
    let verified = verify(
        access_token,
        &harness.access_token_policy(client_id),
        &common::verify_clock(),
    )
    .expect("refreshed access token verifies");
    (Value::Object(verified.claims().raw().clone()), rotated)
}

/// A cookie for a fresh consenting subject of `client_id`, plus that subject id.
async fn consenting_subject(harness: &Harness, client_id: &str) -> (String, String) {
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    (subject, cookie)
}

/// The `organization=<org>` authorize fragment.
fn org_param(org: &OrganizationId) -> String {
    format!("organization={}", enc(&org.to_string()))
}

/// The `roles` claim as a plain `Vec<&str>`, so an assertion reads as an exact set
/// comparison rather than a membership probe. Panics when the claim is absent, which
/// is a distinct outcome every test that cares asserts separately.
fn roles_of(claims: &Value) -> Vec<String> {
    claims["roles"]
        .as_array()
        .unwrap_or_else(|| panic!("roles claim must be an array: {claims}"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("every role slug is a string")
                .to_owned()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The union
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_code_exchange_mints_the_union_of_direct_group_and_ancestor_roles() {
    // The headline resolution property, end to end through the real mint: the access
    // token's `roles` is EXACTLY the union of the three grant paths, deduplicated, and
    // sorted. The forest is grandparent -> parent -> child with the member bound only
    // into `child`, so the `ancestor` role can only arrive by walking two levels up.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org = create_org(&harness, "Acme Corp").await;
    let membership = add_member(&harness, &org, &subject).await;

    let grandparent = create_group(&harness, &org, "grandparent", None).await;
    let parent = create_group(&harness, &org, "parent", Some(&grandparent)).await;
    let child = create_group(&harness, &org, "child", Some(&parent)).await;
    bind_member(&harness, &org, &child, &membership).await;

    let direct = create_role(&harness, &org, "direct").await;
    let via_group = create_role(&harness, &org, "via.group").await;
    let via_ancestor = create_role(&harness, &org, "via.ancestor").await;
    // A role reachable by TWO paths at once, to prove the union deduplicates rather
    // than emitting a slug twice.
    let both = create_role(&harness, &org, "both").await;
    // A role that exists in the organization but is granted to nobody: the claim must
    // not become "every role the organization defines". Never assigned, so its id is
    // deliberately unused.
    create_role(&harness, &org, "ungranted").await;

    grant_direct_role(&harness, &org, &membership, &direct).await;
    grant_direct_role(&harness, &org, &membership, &both).await;
    grant_group_role(&harness, &org, &child, &via_group).await;
    grant_group_role(&harness, &org, &grandparent, &via_ancestor).await;
    grant_group_role(&harness, &org, &parent, &both).await;

    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (id_claims, at_claims, _) = exchange(&harness, &client_id, &code).await;

    assert_eq!(
        roles_of(&at_claims),
        vec!["both", "direct", "via.ancestor", "via.group"],
        "the access token carries the exact union, deduplicated and sorted"
    );
    assert!(
        !roles_of(&at_claims).contains(&"ungranted".to_owned()),
        "a role granted to nobody never appears"
    );
    // Roles ride the ACCESS token only; the ID token stays lean (issue #97).
    assert!(
        id_claims.get("roles").is_none(),
        "the id token carries no roles claim: {id_claims}"
    );
    // Sanity that the org context this resolution hangs off is the one under test.
    assert_eq!(at_claims["org_id"], org.to_string());

    // The bound the ancestor walk above ran under. A directly-built state (which is
    // what this harness is, and what a boot path that installed nothing leaves) uses
    // the SHIPPED default rather than zero, and zero would silently drop every
    // inherited role while every direct one kept working. The builder additionally
    // clamps to the config ceiling rather than trusting its caller, which is defense in
    // depth over the config-load refusal and the store's own clamp.
    assert_eq!(
        harness.state().max_group_depth(),
        DEFAULT_DEPTH,
        "a state the boot path never configured resolves at the shipped default"
    );
    assert_eq!(
        harness
            .state()
            .clone()
            .with_max_group_depth(u32::MAX)
            .max_group_depth(),
        ironauth_config::ORGANIZATIONS_MAX_GROUP_DEPTH_CEILING,
        "the builder clamps an over-large bound to the ceiling"
    );
}

// ---------------------------------------------------------------------------
// Freshness, both directions, on BOTH grants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_withdrawn_role_is_gone_from_the_very_next_refresh() {
    // The property the whole design exists for, direction one, and the direct
    // counterpart of `org_context.rs::a_refreshed_access_token_keeps_the_same_org_id`.
    // A role held at code exchange, then withdrawn, is GONE from the next refreshed
    // access token. If the refresh path replayed a frozen set (the way it correctly
    // replays org_id) the withdrawal would stay invisible for the whole family
    // lifetime, so this is what makes the exposure one access-token lifetime.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org = create_org(&harness, "Freshness Co").await;
    let membership = add_member(&harness, &org, &subject).await;
    let keeper = create_role(&harness, &org, "keeper").await;
    let doomed = create_role(&harness, &org, "doomed").await;
    grant_direct_role(&harness, &org, &membership, &keeper).await;
    let doomed_grant = grant_direct_role(&harness, &org, &membership, &doomed).await;

    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, at_claims, refresh_token) = exchange(&harness, &client_id, &code).await;
    assert_eq!(
        roles_of(&at_claims),
        vec!["doomed", "keeper"],
        "both roles are present at the code exchange"
    );

    withdraw_direct_role(&harness, &org, &doomed_grant).await;

    let (refreshed, _) = refresh(&harness, &client_id, &refresh_token).await;
    assert_eq!(
        roles_of(&refreshed),
        vec!["keeper"],
        "the withdrawn role is gone from the refreshed token, not replayed"
    );
    // The org context itself is still frozen and replayed: this PR must not disturb
    // that, and a refactor that made org_id fresh too would show up here.
    assert_eq!(
        refreshed["org_id"],
        org.to_string(),
        "org_id is still the frozen, replayed value"
    );
}

#[tokio::test]
async fn a_role_granted_after_issuance_appears_on_the_very_next_refresh() {
    // Direction two, the mirror: start with NO roles, refresh (still none), grant, and
    // refresh again. The new role is present. Together with the test above this pins
    // both edges of "next issuance reflects the new resolution" on the refresh grant.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org = create_org(&harness, "Late Grant Co").await;
    let membership = add_member(&harness, &org, &subject).await;

    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, at_claims, refresh_token) = exchange(&harness, &client_id, &code).await;
    assert_eq!(
        roles_of(&at_claims),
        Vec::<String>::new(),
        "a member holding nothing starts with an empty array"
    );

    let (before, rotated) = refresh(&harness, &client_id, &refresh_token).await;
    assert_eq!(
        roles_of(&before),
        Vec::<String>::new(),
        "still nothing before the grant"
    );

    let promoted = create_role(&harness, &org, "promoted").await;
    grant_direct_role(&harness, &org, &membership, &promoted).await;

    let (after, _) = refresh(&harness, &client_id, &rotated).await;
    assert_eq!(
        roles_of(&after),
        vec!["promoted"],
        "the newly granted role appears on the next refresh"
    );
}

#[tokio::test]
async fn a_role_change_is_reflected_on_the_next_code_exchange_too() {
    // The same freshness on the OTHER hook point. A second code exchange on the same
    // session (so the frozen org_id is identical) reflects a grant made after the
    // first exchange, which is only possible because the mint re-reads rather than
    // replaying the code's bindings.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org = create_org(&harness, "Second Exchange Co").await;
    let membership = add_member(&harness, &org, &subject).await;
    let first = create_role(&harness, &org, "first").await;
    let first_grant = grant_direct_role(&harness, &org, &membership, &first).await;

    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, at_claims, _) = exchange(&harness, &client_id, &code).await;
    assert_eq!(roles_of(&at_claims), vec!["first"]);

    let second = create_role(&harness, &org, "second").await;
    grant_direct_role(&harness, &org, &membership, &second).await;
    withdraw_direct_role(&harness, &org, &first_grant).await;

    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, at_claims, _) = exchange(&harness, &client_id, &code).await;
    assert_eq!(
        roles_of(&at_claims),
        vec!["second"],
        "the second exchange reflects both the grant and the withdrawal"
    );
    assert_eq!(
        at_claims["org_id"],
        org.to_string(),
        "the session's org_id is unchanged across the two exchanges"
    );
}

// ---------------------------------------------------------------------------
// The organization's OWN lifecycle: the coarsest revocation there is
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_disabled_organization_stops_minting_its_roles_on_both_hooks() {
    // Disable is the COARSEST kill switch the product exposes, and it must reach the
    // roles claim on BOTH issuance hooks. Neither hook can check it for itself, which
    // is why the check lives in the store's shared closure:
    //
    //   * on REFRESH, the authorize-time organization resolution is never called at
    //     all; the org context is read straight off the family's grant;
    //   * on a CODE EXCHANGE, that resolution returns EARLY for an already-bound
    //     session (first write wins), so its disabled-organization refusal never runs
    //     for any session that has already resolved an org, which is every session
    //     that has one.
    //
    // So both hooks are driven here against the SAME disabled organization. Without
    // the fence every member of a disabled organization keeps receiving freshly
    // re-affirmed `roles` for the whole life of the refresh family, which with
    // offline_access is unbounded.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org = create_org(&harness, "Kill Switch Co").await;
    let membership = add_member(&harness, &org, &subject).await;
    let admin = create_role(&harness, &org, "admin").await;
    grant_direct_role(&harness, &org, &membership, &admin).await;

    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, at_claims, refresh_token) = exchange(&harness, &client_id, &code).await;
    assert_eq!(
        roles_of(&at_claims),
        vec!["admin"],
        "the control exchange carries the role while the organization is active"
    );

    set_org_state(&harness, &org, OrganizationState::Disabled).await;

    // Hook one: the refresh grant.
    let (refreshed, _) = refresh(&harness, &client_id, &refresh_token).await;
    assert_eq!(
        roles_of(&refreshed),
        Vec::<String>::new(),
        "a disabled organization asserts NO role on the very next refresh: {refreshed}"
    );
    // EMPTY, not absent, and not a refusal. The grant really is bound to that
    // organization, so the honest answer is "scoped to it, holding nothing there"
    // rather than a silently org-less token; and a disabled organization is an
    // operator STATE, so refusing would make an administrative action an outage.
    assert_eq!(
        refreshed["org_id"],
        org.to_string(),
        "the frozen org_id is still emitted: {refreshed}"
    );

    // Hook two: a BRAND NEW code exchange on the SAME session. The session is already
    // bound, so /authorize still issues a code (its disabled check is unreachable
    // here) and the whole refusal has to come from the resolution.
    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, at_claims, _) = exchange(&harness, &client_id, &code).await;
    assert_eq!(
        roles_of(&at_claims),
        Vec::<String>::new(),
        "a fresh code exchange on a bound session asserts no role either: {at_claims}"
    );
    assert_eq!(at_claims["org_id"], org.to_string());

    // And re-enabling restores the roles, so this is a FENCE on live state rather
    // than a one-way loss of the assignments (which were never touched).
    set_org_state(&harness, &org, OrganizationState::Active).await;
    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, at_claims, _) = exchange(&harness, &client_id, &code).await;
    assert_eq!(
        roles_of(&at_claims),
        vec!["admin"],
        "re-enabling the organization restores the claim from the untouched grants"
    );
}

#[tokio::test]
async fn a_soft_deleted_organization_stops_minting_its_roles_too() {
    // The other half of the coarsest revocation. `organizations().delete()` is a bare
    // soft delete: the row is retained and NOTHING cascades, so every membership,
    // group, and assignment row underneath it stays live and readable. That is
    // exactly why the resolution has to observe the organization's own `deleted_at`
    // rather than relying on the rows below it going away, and it is why an operator
    // who DELETES an organization and sees its members keep minting its roles would
    // have no lever left at all.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org = create_org(&harness, "Deleted Co").await;
    let membership = add_member(&harness, &org, &subject).await;
    let via_group = create_role(&harness, &org, "via.group").await;
    let direct = create_role(&harness, &org, "direct").await;
    let group = create_group(&harness, &org, "team", None).await;
    bind_member(&harness, &org, &group, &membership).await;
    grant_group_role(&harness, &org, &group, &via_group).await;
    grant_direct_role(&harness, &org, &membership, &direct).await;

    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, at_claims, refresh_token) = exchange(&harness, &client_id, &code).await;
    assert_eq!(
        roles_of(&at_claims),
        vec!["direct", "via.group"],
        "both grant paths carry while the organization is live"
    );

    soft_delete_org(&harness, &org).await;

    let (refreshed, _) = refresh(&harness, &client_id, &refresh_token).await;
    assert_eq!(
        roles_of(&refreshed),
        Vec::<String>::new(),
        "a soft-deleted organization asserts no role on the next refresh: {refreshed}"
    );
    assert_eq!(refreshed["org_id"], org.to_string());

    // The code-exchange hook, same as the disable case: the session is already bound,
    // so the authorize-time resolution short-circuits and never sees the delete.
    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, at_claims, _) = exchange(&harness, &client_id, &code).await;
    assert_eq!(
        roles_of(&at_claims),
        Vec::<String>::new(),
        "and none on a fresh code exchange either: {at_claims}"
    );
}

// ---------------------------------------------------------------------------
// Absent versus empty
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_org_context_means_no_roles_claim_at_all() {
    // ABSENT, not empty. A role is org-scoped, so with no organization there is no set
    // to resolve, and a cross-organization union would be indefensible. A consumer must
    // be able to distinguish this from a resolved-but-empty answer, so the claim must
    // not be present as `[]` here.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    // The subject IS a member of an org holding a role, but names no organization and
    // is a member of two, so no org context is resolved: the roles must not leak in
    // through some other path.
    let org_a = create_org(&harness, "Org A").await;
    let org_b = create_org(&harness, "Org B").await;
    let membership = add_member(&harness, &org_a, &subject).await;
    add_member(&harness, &org_b, &subject).await;
    let role = create_role(&harness, &org_a, "hidden").await;
    grant_direct_role(&harness, &org_a, &membership, &role).await;

    let code = authorize_to_code(&harness, &client_id, &[], &cookie).await;
    let (id_claims, at_claims, refresh_token) = exchange(&harness, &client_id, &code).await;
    assert!(
        at_claims.get("org_id").is_none(),
        "the multi-org subject named no organization"
    );
    assert!(
        at_claims.get("roles").is_none(),
        "no org context emits NO roles claim, not an empty array: {at_claims}"
    );
    assert!(id_claims.get("roles").is_none());

    // And the same on refresh, where the frozen org_id is likewise absent.
    let (refreshed, _) = refresh(&harness, &client_id, &refresh_token).await;
    assert!(
        refreshed.get("roles").is_none(),
        "a no-org refresh carries no roles claim either: {refreshed}"
    );
}

#[tokio::test]
async fn an_org_member_holding_nothing_gets_an_empty_array() {
    // PRESENT and empty. This is a resolved answer ("a member of this organization,
    // holding no roles"), which is a different fact from the test above, and a
    // resource server is entitled to tell them apart.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org = create_org(&harness, "Empty Co").await;
    add_member(&harness, &org, &subject).await;
    // The organization DOES define a role; this member simply does not hold it.
    create_role(&harness, &org, "unheld").await;

    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, at_claims, _) = exchange(&harness, &client_id, &code).await;
    assert!(
        at_claims.get("roles").is_some(),
        "the claim is PRESENT for an org member: {at_claims}"
    );
    assert_eq!(
        at_claims["roles"],
        serde_json::json!([] as [&str; 0]),
        "an org member holding nothing gets an EMPTY ARRAY"
    );
}

// ---------------------------------------------------------------------------
// Fail closed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_store_fault_during_resolution_refuses_the_token_rather_than_dropping_roles() {
    // FAIL CLOSED. The fault is injected the way production would suffer it: the data
    // plane's SELECT grant on one of the resolution's tables is revoked, so the read
    // raises SQLSTATE 42501 (insufficient privilege) INSIDE the mint. The exchange must
    // fail with a server_error, never succeed with the roles quietly missing, because
    // downstream a missing roles claim is indistinguishable from a legitimate
    // authorization downgrade.
    //
    // The revoke happens AFTER the code is issued, so the authorize path (which reads
    // org_memberships, not org_membership_roles) is unaffected and the failure is
    // attributable to the resolution and nothing else.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org = create_org(&harness, "Fault Co").await;
    let membership = add_member(&harness, &org, &subject).await;
    let role = create_role(&harness, &org, "critical").await;
    grant_direct_role(&harness, &org, &membership, &role).await;

    // A control exchange first: with the grant intact this same request succeeds and
    // carries the role, so the refusal below is caused by the revoke and not by the
    // fixture.
    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, at_claims, _) = exchange(&harness, &client_id, &code).await;
    assert_eq!(roles_of(&at_claims), vec!["critical"]);

    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    sqlx::query("REVOKE SELECT ON org_membership_roles FROM ironauth_app")
        .execute(harness.db().owner_pool())
        .await
        .expect("revoke the data plane's read on the assignment table");

    let (status, _, body) = harness.token(&token_form(&code, &client_id)).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a resolution fault fails the token request: {body}"
    );
    assert_eq!(
        json(&body)["error"],
        "server_error",
        "the uniform server_error, never a 200 with roles missing: {body}"
    );
    assert!(
        !body.contains("access_token"),
        "no token is issued at all: {body}"
    );

    // Restore, and prove the refusal was the revoke rather than a wedged harness. This
    // ALSO pins the ordering: the resolution runs inside the mint, which the endpoint
    // performs BEFORE the atomic single-use consume, so a resolution fault must not
    // BURN the code. The SAME code is presented again and now succeeds. A refactor that
    // moved the roles hook below the redeem would destroy a legitimate client's code on
    // a transient store hiccup, which is why this is re-presented rather than reissued.
    sqlx::query("GRANT SELECT ON org_membership_roles TO ironauth_app")
        .execute(harness.db().owner_pool())
        .await
        .expect("restore the grant");
    let (_, at_claims, _) = exchange(&harness, &client_id, &code).await;
    assert_eq!(
        roles_of(&at_claims),
        vec!["critical"],
        "the SAME code still redeems: a resolution fault never burned it"
    );
}

#[tokio::test]
async fn a_store_fault_fails_the_refresh_closed_too() {
    // The same discipline on the refresh hook. A rotation that quietly dropped roles
    // would be the worst version of the bug: the client keeps working, with strictly
    // fewer privileges asserted, and nothing anywhere reports it.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org = create_org(&harness, "Refresh Fault Co").await;
    let membership = add_member(&harness, &org, &subject).await;
    let role = create_role(&harness, &org, "critical").await;
    grant_direct_role(&harness, &org, &membership, &role).await;

    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, at_claims, refresh_token) = exchange(&harness, &client_id, &code).await;
    assert_eq!(roles_of(&at_claims), vec!["critical"]);

    sqlx::query("REVOKE SELECT ON org_membership_roles FROM ironauth_app")
        .execute(harness.db().owner_pool())
        .await
        .expect("revoke the data plane's read on the assignment table");

    let (status, _, body) = harness
        .token(&form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
            ("client_id", &client_id),
        ]))
        .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a resolution fault fails the refresh: {body}"
    );
    assert_eq!(json(&body)["error"], "server_error");
    assert!(!body.contains("access_token"), "no token is rotated out");

    // And the refresh token is NOT consumed by the refusal: the mint runs before the
    // atomic redeem, so the family is untouched and the SAME token still rotates once
    // the fault clears. A hook placed after the redeem would turn a transient store
    // fault into a permanently dead refresh family.
    sqlx::query("GRANT SELECT ON org_membership_roles TO ironauth_app")
        .execute(harness.db().owner_pool())
        .await
        .expect("restore the grant");
    let (refreshed, _) = refresh(&harness, &client_id, &refresh_token).await;
    assert_eq!(
        roles_of(&refreshed),
        vec!["critical"],
        "the SAME refresh token still rotates: the refusal consumed nothing"
    );
}

#[tokio::test]
async fn a_recorded_identifier_that_is_out_of_scope_fails_closed_on_both_branches() {
    // The OTHER two fail-closed branches of the resolution, which a store fault does
    // not reach: a RECORDED identifier that no longer parses in the scope the mint is
    // running under. Both are representable in the shipped schema rather than
    // theoretical, and each is driven here through the hook that actually reads it.
    //
    //   * `grants.org_id` carries `grants_org_fk`, a SINGLE-COLUMN foreign key to
    //     organizations(id), NOT a composite one over (id, tenant, environment). So a
    //     grant can carry an organization id of ANOTHER scope and still satisfy the
    //     key. The refresh path reads the org context from exactly this column.
    //   * `authorization_codes.subject` is free text with no foreign key to `users`
    //     at all. The code exchange reads the subject from exactly this column.
    //
    // Both must be a `server_error` with NO token, never a quietly role-less one: a
    // missing `roles` claim reads downstream as a successful authorization DOWNGRADE.
    // Neither branch had a test before this one, and each survived being mutated to
    // `Ok(None)` with the whole file still green.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    // A second scope of the same tenant, so the ids minted in it are REAL rows that
    // genuinely fail to parse under the harness scope.
    let foreign_scope = harness.second_scope().await;
    let foreign_org = create_org_in(&harness, foreign_scope, "Foreign Co").await;
    let foreign_user = UserId::generate(harness.env(), &foreign_scope).to_string();

    // --- Branch one: the org_id frozen onto the grant, read on REFRESH. ---
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org = create_org(&harness, "Refresh Branch Co").await;
    let membership = add_member(&harness, &org, &subject).await;
    let role = create_role(&harness, &org, "critical").await;
    grant_direct_role(&harness, &org, &membership, &role).await;

    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, at_claims, refresh_token) = exchange(&harness, &client_id, &code).await;
    assert_eq!(
        roles_of(&at_claims),
        vec!["critical"],
        "the control exchange succeeds, so the refusal below is the corruption"
    );

    let affected = sqlx::query("UPDATE grants SET org_id = $1 WHERE subject = $2")
        .bind(foreign_org.to_string())
        .bind(&subject)
        .execute(harness.db().owner_pool())
        .await
        .expect("re-point the grant at another scope's organization")
        .rows_affected();
    assert!(
        affected > 0,
        "the corruption must actually land, or this test proves nothing"
    );

    let (status, _, body) = harness
        .token(&form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
            ("client_id", &client_id),
        ]))
        .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "an out-of-scope org_id refuses the refresh: {body}"
    );
    assert_eq!(
        json(&body)["error"],
        "server_error",
        "the uniform server_error, never a 200 with roles missing: {body}"
    );
    assert!(
        !body.contains("access_token"),
        "no token is rotated out at all: {body}"
    );

    // --- Branch two: the subject recorded on the code, read on a CODE EXCHANGE. ---
    let (other_subject, other_cookie) = consenting_subject(&harness, &client_id).await;
    let other_org = create_org(&harness, "Exchange Branch Co").await;
    let other_membership = add_member(&harness, &other_org, &other_subject).await;
    let other_role = create_role(&harness, &other_org, "critical").await;
    grant_direct_role(&harness, &other_org, &other_membership, &other_role).await;

    let code = authorize_to_code(
        &harness,
        &client_id,
        &[&org_param(&other_org)],
        &other_cookie,
    )
    .await;
    let (_, at_claims, _) = exchange(&harness, &client_id, &code).await;
    assert_eq!(
        roles_of(&at_claims),
        vec!["critical"],
        "the control exchange for the second branch succeeds too"
    );

    // Issue the code FIRST, then corrupt, so the authorize path (which resolves the
    // real subject) is unaffected and the failure is attributable to the resolution.
    let code = authorize_to_code(
        &harness,
        &client_id,
        &[&org_param(&other_org)],
        &other_cookie,
    )
    .await;
    let affected = sqlx::query("UPDATE authorization_codes SET subject = $1 WHERE subject = $2")
        .bind(&foreign_user)
        .bind(&other_subject)
        .execute(harness.db().owner_pool())
        .await
        .expect("re-point the code at another scope's user")
        .rows_affected();
    assert!(affected > 0, "the second corruption must land too");

    let (status, _, body) = harness.token(&token_form(&code, &client_id)).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "an out-of-scope recorded subject refuses the exchange: {body}"
    );
    assert_eq!(json(&body)["error"], "server_error", "{body}");
    assert!(
        !body.contains("access_token"),
        "no token is issued at all: {body}"
    );
}

// ---------------------------------------------------------------------------
// Forgery, through the real paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_users_own_stored_claim_can_never_forge_roles_into_the_id_token() {
    // The genuine end-to-end forgery vector for `roles`, driven rather than assumed.
    // The ID token's extra-claims bag is fed by `assemble_claims` from the USER's
    // stored standard-claim document, selected by the OIDC Core 5.5 `claims` request
    // parameter, and that parameter accepts ARBITRARY claim names. So a user document
    // containing `{"roles":["admin"]}`, requested as `{"id_token":{"roles":null}}`,
    // would be stamped into the ID token verbatim were `roles` not in
    // PROTECTED_ACCESS_TOKEN_CLAIMS (which the id-token fold filters explicitly).
    //
    // The benign claim in the same document IS released, so the drop is attributable to
    // the reserved name and not to the request being ignored wholesale.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let subject = harness
        .seed_user_with_claims(
            "roles-forger@example.test",
            SEED_PASSWORD,
            r#"{"roles":["admin"],"email":"roles-forger@example.test"}"#,
        )
        .await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    let org = create_org(&harness, "Forgery Co").await;
    let membership = add_member(&harness, &org, &subject).await;
    let real = create_role(&harness, &org, "viewer").await;
    grant_direct_role(&harness, &org, &membership, &real).await;

    let requested = r#"{"id_token":{"roles":null,"email":null}}"#;
    let code = authorize_to_code(
        &harness,
        &client_id,
        &[
            &org_param(&org),
            "scope=openid%20email",
            &format!("claims={}", enc(requested)),
        ],
        &cookie,
    )
    .await;
    let (id_claims, at_claims, _) = exchange(&harness, &client_id, &code).await;

    assert!(
        id_claims.get("roles").is_none(),
        "a self-asserted roles claim is DROPPED from the id token: {id_claims}"
    );
    assert_eq!(
        id_claims["email"], "roles-forger@example.test",
        "the benign requested claim still lands, so the drop is targeted"
    );
    assert_eq!(
        roles_of(&at_claims),
        vec!["viewer"],
        "the access token carries the ISSUER-resolved role, never the self-asserted one"
    );
    assert!(
        !roles_of(&at_claims).contains(&"admin".to_owned()),
        "the forged slug never reaches the access token: {at_claims}"
    );
}

#[tokio::test]
async fn the_client_credentials_grant_carries_no_roles_even_when_configured_to() {
    // The machine path, and the second real forgery vector: a client's stored
    // `custom_token_claims` is merged into the M2M access token, and the store
    // deliberately does NOT filter reserved names (the mint is the single enforcement
    // point). So a configured `{"roles":["admin"]}` must be DROPPED at the mint.
    //
    // This doubles as the pin that the machine paths carry no roles at all: attaching
    // roles to an `sva_` principal is issue #99 and must land on both machine paths
    // deliberately, never leak in through this column.
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    let env = harness.env();
    harness
        .store()
        .scoped(harness.scope())
        .acting(
            ActorRef::service(ServiceId::generate(env)),
            CorrelationId::generate(env),
        )
        .clients()
        .set_custom_token_claims(env, &client, Some(r#"{"roles":["admin"],"tier":"gold"}"#))
        .await
        .expect("set custom claims");

    let authorization = format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")));
    let (status, _, body) = harness
        .token_with_auth(
            &form(&[("grant_type", "client_credentials")]),
            Some(&authorization),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "client_credentials: {body}");
    let access_token = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    let verified = verify(
        &access_token,
        &harness.access_token_policy(&client_id),
        &common::verify_clock(),
    )
    .expect("m2m access token verifies");
    let claims = Value::Object(verified.claims().raw().clone());

    assert!(
        claims.get("roles").is_none(),
        "a machine token asserts NO human authorization role: {claims}"
    );
    assert_eq!(
        claims["tier"], "gold",
        "the benign custom claim still lands, so the drop is targeted"
    );
    assert!(
        claims.get("org_id").is_none(),
        "and no human organization context either"
    );
}

// ---------------------------------------------------------------------------
// The configured nesting bound, observed at the store call
// ---------------------------------------------------------------------------

/// Seed one three-level forest (grandparent -> parent -> child) with the member bound
/// only into `child`, a role granted on `parent` (ONE level up) and another on
/// `grandparent` (TWO levels up). Returns the consenting subject's cookie and the
/// organization.
///
/// Two harnesses configured differently are driven over this SAME shape, so the only
/// thing that can move the answer is the bound each was built with.
async fn seed_two_level_ancestry(harness: &Harness, client_id: &str) -> (String, OrganizationId) {
    let (subject, cookie) = consenting_subject(harness, client_id).await;
    let org = create_org(harness, "Nesting Co").await;
    let membership = add_member(harness, &org, &subject).await;
    let grandparent = create_group(harness, &org, "grandparent", None).await;
    let parent = create_group(harness, &org, "parent", Some(&grandparent)).await;
    let child = create_group(harness, &org, "child", Some(&parent)).await;
    bind_member(harness, &org, &child, &membership).await;
    let near = create_role(harness, &org, "via.parent").await;
    let far = create_role(harness, &org, "via.grandparent").await;
    grant_group_role(harness, &org, &parent, &near).await;
    grant_group_role(harness, &org, &grandparent, &far).await;
    (cookie, org)
}

#[tokio::test]
async fn the_configured_group_depth_is_the_bound_the_mint_actually_resolves_with() {
    // The BEHAVIOURAL pin on the nesting bound's wiring, which two independent
    // mutants used to survive: the mint reading a hard-coded default instead of the
    // configured value, and the builder installing the ceiling instead of its
    // argument. Both are silent, and they fail in opposite directions: the first
    // makes an operator who RAISES the bound lose every role inherited above the
    // default (an authorization downgrade with no signal), the second makes an
    // operator who LOWERS it get a deeper walk here than the management plane runs,
    // so the console and the token disagree about the effective set, which is the
    // exact divergence the shared setting exists to prevent.
    //
    // Neither is observable through an accessor: the value has to be watched at the
    // STORE CALL, which means driving a real issuance over a tree deeper than the
    // bound. Groups are seeded through the control plane at the shipped default, so
    // the tree is legal to build and only the READ is bounded, which is the state an
    // operator who lowers the setting under a populated environment leaves behind.
    let deep = Harness::start().await;
    let client_id = deep.client_id().to_string();
    let (cookie, org) = seed_two_level_ancestry(&deep, &client_id).await;
    let code = authorize_to_code(&deep, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, at_claims, _) = exchange(&deep, &client_id, &code).await;
    assert_eq!(
        roles_of(&at_claims),
        vec!["via.grandparent", "via.parent"],
        "at the shipped default the walk reaches both ancestor levels: {at_claims}"
    );

    // The SAME fixture under a bound of ONE. The walk reaches the member's own groups
    // plus one level of ancestor, so the parent's role still arrives and the
    // grandparent's does not. Asserting the near role is PRESENT is what makes this a
    // truncation rather than a walk that silently did not run at all.
    let shallow = Harness::start_with_group_depth(1).await;
    let client_id = shallow.client_id().to_string();
    let (cookie, org) = seed_two_level_ancestry(&shallow, &client_id).await;
    let code = authorize_to_code(&shallow, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, at_claims, _) = exchange(&shallow, &client_id, &code).await;
    assert_eq!(
        roles_of(&at_claims),
        vec!["via.parent"],
        "a bound of one truncates the walk one level up, and only there: {at_claims}"
    );
    assert_eq!(
        shallow.state().max_group_depth(),
        1,
        "the configured bound is what the router's state carries"
    );
}

// ---------------------------------------------------------------------------
// Byte stability
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_issuances_against_identical_state_emit_an_identical_roles_claim() {
    // The determinism the BTreeSet exists for, observed through the wire rather than
    // through the store: two independent exchanges over unchanged stored state produce
    // a byte-identical `roles` array, so a diff between two issued tokens means the
    // stored state changed and nothing else. The roles are created in a deliberately
    // NON-alphabetical order so a stable-but-insertion-ordered implementation would be
    // caught by the sortedness assertion.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org = create_org(&harness, "Stable Co").await;
    let membership = add_member(&harness, &org, &subject).await;
    let group = create_group(&harness, &org, "team", None).await;
    bind_member(&harness, &org, &group, &membership).await;
    for slug in ["zulu", "alpha", "mike", "bravo"] {
        let role = create_role(&harness, &org, slug).await;
        if slug.len() % 2 == 0 {
            grant_direct_role(&harness, &org, &membership, &role).await;
        } else {
            grant_group_role(&harness, &org, &group, &role).await;
        }
    }

    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, first, refresh_token) = exchange(&harness, &client_id, &code).await;
    let code = authorize_to_code(&harness, &client_id, &[&org_param(&org)], &cookie).await;
    let (_, second, _) = exchange(&harness, &client_id, &code).await;
    let (third, _) = refresh(&harness, &client_id, &refresh_token).await;

    assert_eq!(
        roles_of(&first),
        vec!["alpha", "bravo", "mike", "zulu"],
        "emitted in total order, not insertion order"
    );
    assert_eq!(
        serde_json::to_string(&first["roles"]).expect("serialize"),
        serde_json::to_string(&second["roles"]).expect("serialize"),
        "two code exchanges are byte-identical"
    );
    assert_eq!(
        serde_json::to_string(&first["roles"]).expect("serialize"),
        serde_json::to_string(&third["roles"]).expect("serialize"),
        "a refresh is byte-identical to the code exchange it descends from"
    );
}

/// A code exchange out of an IMPERSONATION session mints tokens carrying `act` (issue #101).
///
/// The claim and its protection shipped in #661 and the session reports its impersonation
/// since #662; this is the assertion that the two are connected, which is the difference
/// between the criterion being available and being true.
///
/// The impersonation is planted directly on the session row because no start ENDPOINT exists
/// yet. That is the same shortcut the permission-parity suite used before its writer landed,
/// and it goes away the same way: when the start route lands, this seeds through it.
#[tokio::test]
async fn a_code_exchange_from_an_impersonation_session_mints_the_actor_claim() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;

    // An ordinary exchange first, so the absence below is a DIFFERENCE rather than the
    // default state of a test that never had an impersonation to lose.
    let code = authorize_to_code(&harness, &client_id, &[], &cookie).await;
    let (id_claims, at_claims, _) = exchange(&harness, &client_id, &code).await;
    assert!(
        id_claims.get("act").is_none() && at_claims.get("act").is_none(),
        "an ordinary session mints no actor claim: {id_claims} {at_claims}"
    );

    // Now make the very same session an impersonation. The columns move together or not at
    // all, which migration 0128 enforces, so this writes all five.
    let updated = sqlx::query(
        "UPDATE sessions SET impersonator = $1, impersonation_reason_code = $2, \
                impersonation_reason_text = $3, impersonation_started_at = now(), \
                impersonation_expires_at = now() + INTERVAL '30 minutes' \
         WHERE subject = $4 AND revoked_at IS NULL AND ended_at IS NULL",
    )
    .bind("adm_support_engineer")
    .bind("support_ticket")
    .bind("Ticket 4417: reproducing the checkout failure as the user.")
    .bind(&subject)
    .execute(harness.db().owner_pool())
    .await
    .expect("plant the impersonation on the live session");
    assert_eq!(
        updated.rows_affected(),
        1,
        "exactly one live session belongs to this subject, so the plant is unambiguous"
    );

    let code = authorize_to_code(&harness, &client_id, &[], &cookie).await;
    let (id_claims, at_claims, _) = exchange(&harness, &client_id, &code).await;
    let expected = serde_json::json!({
        "sub": "adm_support_engineer",
        "reason_code": "support_ticket",
    });
    assert_eq!(
        id_claims["act"], expected,
        "the id token names the impersonator and the structured reason: {id_claims}"
    );
    assert_eq!(
        at_claims["act"], expected,
        "and so does the access token: {at_claims}"
    );
    assert_eq!(
        id_claims["sub"], subject,
        "the SUBJECT stays the impersonated user; `act` says who is driving, and swapping the \
         two would make the token authorize the operator instead"
    );
    let rendered = format!("{id_claims}{at_claims}");
    assert!(
        !rendered.contains("Ticket 4417"),
        "the written justification never reaches a token: {rendered}"
    );
}

/// A REFRESHED access token does not yet carry `act` (issue #101), pinned deliberately.
///
/// The refresh resolution carries no session reference, so wiring it would mean a fresh
/// session read on the hot refresh path. The issue asks instead for the actor to be PERSISTED
/// in a form M13's token exchange can consume, and the grant is where that belongs.
///
/// This pin exists so that slice has to FLIP an assertion rather than quietly discover it was
/// already true. The gap it records is real: an access token refreshed out of an impersonated
/// session presently carries no actor.
#[tokio::test]
async fn a_refreshed_token_does_not_yet_carry_the_actor_claim() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    sqlx::query(
        "UPDATE sessions SET impersonator = $1, impersonation_reason_code = $2, \
                impersonation_reason_text = $3, impersonation_started_at = now(), \
                impersonation_expires_at = now() + INTERVAL '30 minutes' \
         WHERE subject = $4 AND revoked_at IS NULL AND ended_at IS NULL",
    )
    .bind("adm_support_engineer")
    .bind("support_ticket")
    .bind("Ticket 4417")
    .bind(&subject)
    .execute(harness.db().owner_pool())
    .await
    .expect("plant the impersonation");

    let code = authorize_to_code(&harness, &client_id, &[], &cookie).await;
    let (_, at_claims, refresh_token) = exchange(&harness, &client_id, &code).await;
    assert!(
        at_claims.get("act").is_some(),
        "the code exchange carries the actor, so the refresh below is the only variable"
    );
    let (refreshed, _) = refresh(&harness, &client_id, &refresh_token).await;
    assert!(
        refreshed.get("act").is_none(),
        "PIN, not an endorsement: the refresh path has no session reference yet, so it mints \
         no actor. The slice that persists the actor onto the grant must flip this: {refreshed}"
    );
}
