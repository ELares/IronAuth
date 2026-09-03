// SPDX-License-Identifier: MIT OR Apache-2.0

//! The effective organization PERMISSIONS token claim end to end, against a real
//! Postgres (issue #98, PR 13, the activation PR).
//!
//! Everything issue #98 shipped before this file existed was inert or admin only. This
//! is where a token first changes shape, so this file is about what a RESOURCE SERVER
//! can observe on the wire and about what no configuration can make it observe.
//!
//! # The three observable wire states
//!
//! A resource server that opted in can distinguish exactly three answers, and the
//! whole design rests on their being distinguishable:
//!
//!   * NEITHER `permissions` nor `permissions_status`: no organization context, or a
//!     target whose audiences did not unanimously opt in.
//!   * `permissions: []`: an organization was resolved and the subject holds nothing.
//!   * `permissions_status`: the set was WITHHELD for a budget reason, and the value
//!     says whether to fall back to `roles` or to consult a policy decision point.
//!
//! Each is decoded from a real minted token, through the one hardened verify path, so
//! a token that fails to verify fails the test before any claim is inspected.
//!
//! # The covenant
//!
//! `no_configuration_produces_a_silent_permission_drop` is the acceptance criterion
//! made mechanical. It drives the CROSS PRODUCT of both overflow modes and all three
//! diagnostics verbosities, forces an overflow in each, and requires for all six that
//! the token carries `permissions_status` AND that an event row exists. The iteration
//! is over each enum's own `ALL` list, so a new variant is already in the cross
//! product, and over a total `match` that gives each variant a slot, so a new variant
//! fails to COMPILE here until it is given one. See `overflow_slot` for which of the
//! two mechanisms catches what.
//!
//! Beside it the file pins the four structural properties the design names: the claim
//! is never a PREFIX, every withholding is on the WIRE, every withholding is RECORDED
//! regardless of verbosity, and (in the admin crate, where the surface lives) the
//! management plane never truncates either.
//!
//! # Boundaries asserted rather than assumed
//!
//! An OPAQUE access token carries no claims at all, and the device,
//! client-credentials and jwt-bearer grants pass no RFC 8707 resource, so none of them
//! can ever carry a permission. Those are the issue #99 boundary and they are driven
//! here rather than inferred from the absence of code.

mod common;

use std::collections::BTreeSet;
use std::fmt::Write as _;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location_param,
};
use ironauth_config::{
    DiagnosticVerbosity, DiagnosticsConfig, PermissionOverflow, TokenClaimsConfig,
};
use ironauth_jose::verify;
use ironauth_oidc::ClientAuthMethod;
use ironauth_store::{
    ActorRef, CorrelationId, NewMembership, NewOrgGroup, NewOrgGroupMember, NewOrgGroupRole,
    NewOrgRole, NewOrgRolePermission, NewPermission, NewResourceServer, OrgGroupId,
    OrgGroupMemberId, OrgGroupRoleId, OrgMembershipId, OrgMembershipRoleId, OrgRoleId,
    OrgRolePermissionId, OrganizationId, OrganizationState, PermissionId, ResourceServerId,
    ServiceId, TokenFormat, TokenSizeKind, UserId,
};
use serde_json::Value;

/// The group nesting depth every test here passes to the store seeding helpers: the
/// shipped `[organizations] max_group_depth` default, which is also what the data plane
/// resolves with when the boot path installed nothing. Seeding at the DEFAULT while a
/// harness resolves at a lower bound is what lets `the_configured_group_depth_...`
/// build a legal tree and bound only the READ.
const DEFAULT_DEPTH: u32 = 8;

/// The clock-seam instant the seeded rows are dated with. The harness clock is frozen
/// at the Unix epoch, so a literal is the honest value and no wall-clock constructor is
/// needed (the determinism seam forbids one anywhere under `crates/`).
const SEED_MICROS: i64 = 1_000_000;

/// An opted-IN resource server audience.
const RS_IN: &str = "https://api.example/in";
/// A second opted-IN resource server audience, for the multi-audience unanimous case.
const RS_IN_TWO: &str = "https://api.example/in2";
/// An opted-OUT resource server audience, for the mixed-target suppression case.
const RS_OUT: &str = "https://api.example/out";
/// An opted-in resource server that issues OPAQUE access tokens.
const RS_OPAQUE: &str = "https://api.example/opaque";

// ---------------------------------------------------------------------------
// Control-plane seeding
// ---------------------------------------------------------------------------

/// A control-plane acting repository handle for the harness scope.
macro_rules! acting {
    ($harness:expr, $env:expr) => {
        $harness.db().control_store().management().acting(
            $harness.db().test_actor($env),
            CorrelationId::generate($env),
        )
    };
}

/// Create an ACTIVE organization in the harness scope.
async fn create_org(harness: &Harness, display_name: &str) -> OrganizationId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let org_id = OrganizationId::generate(&env, &scope);
    acting!(harness, &env)
        .organizations(scope)
        .create(&env, &org_id, SEED_MICROS, display_name, None)
        .await
        .expect("create organization");
    org_id
}

/// Bind `subject` into `org` as an ACTIVE member.
async fn add_member(harness: &Harness, org: &OrganizationId, subject: &str) -> OrgMembershipId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let user_id = UserId::parse_in_scope(subject, &scope).expect("the seeded subject is a user id");
    let id = OrgMembershipId::generate(&env, &scope);
    acting!(harness, &env)
        .org_memberships(scope)
        .create(
            &env,
            NewMembership {
                id: &id,
                organization_id: org,
                user_id: &user_id,
                metadata: None,
            },
            SEED_MICROS,
            None,
        )
        .await
        .expect("bind user into organization");
    id
}

/// Define a role in `org`.
async fn create_role(harness: &Harness, org: &OrganizationId, slug: &str) -> OrgRoleId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = OrgRoleId::generate(&env, &scope);
    acting!(harness, &env)
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

/// Grant `role` straight to one membership.
async fn grant_direct_role(
    harness: &Harness,
    org: &OrganizationId,
    membership: &OrgMembershipId,
    role: &OrgRoleId,
) -> OrgMembershipRoleId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = OrgMembershipRoleId::generate(&env, &scope);
    acting!(harness, &env)
        .org_membership_roles(scope)
        .assign(
            &env,
            ironauth_store::NewOrgMembershipRole {
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

/// Define a group in `org`, optionally under `parent`. Seeded at [`DEFAULT_DEPTH`], so
/// the tree is legal to BUILD whatever bound the harness later resolves with.
async fn create_group(
    harness: &Harness,
    org: &OrganizationId,
    slug: &str,
    parent: Option<&OrgGroupId>,
) -> OrgGroupId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = OrgGroupId::generate(&env, &scope);
    acting!(harness, &env)
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
    acting!(harness, &env)
        .org_group_members(scope)
        .add(
            &env,
            NewOrgGroupMember {
                id: &id,
                organization_id: org,
                group_id: group,
                membership_id: membership,
                source_scim_connection_id: None,
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
    acting!(harness, &env)
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

/// Flip an organization's lifecycle state through the control plane: the operator's
/// disable (and re-enable) action, exactly as the management API drives it.
async fn set_org_state(harness: &Harness, org: &OrganizationId, state: OrganizationState) {
    let env = harness.env().clone();
    let scope = harness.scope();
    acting!(harness, &env)
        .organizations(scope)
        .set_state(&env, org, state, None)
        .await
        .expect("set organization state");
}

/// Soft-delete an organization through the control plane. The row is retained (only
/// `deleted_at` is written) and NOTHING cascades, which is why the resolution has to
/// observe it itself.
async fn soft_delete_org(harness: &Harness, org: &OrganizationId) {
    let env = harness.env().clone();
    let scope = harness.scope();
    acting!(harness, &env)
        .organizations(scope)
        .delete(&env, org)
        .await
        .expect("soft delete organization");
}

/// Define a permission in the environment's vocabulary.
async fn create_permission(harness: &Harness, slug: &str) -> PermissionId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = PermissionId::generate(&env, &scope);
    acting!(harness, &env)
        .permissions(scope)
        .create(
            &env,
            NewPermission {
                id: &id,
                slug,
                display_name: "Capability",
                metadata: None,
            },
            SEED_MICROS,
            None,
        )
        .await
        .expect("create permission");
    id
}

/// Attach `permission` to `role`.
async fn attach(
    harness: &Harness,
    org: &OrganizationId,
    role: &OrgRoleId,
    permission: &PermissionId,
) -> OrgRolePermissionId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = OrgRolePermissionId::generate(&env, &scope);
    acting!(harness, &env)
        .org_role_permissions(scope)
        .assign(
            &env,
            NewOrgRolePermission {
                id: &id,
                organization_id: org,
                role_id: role,
                permission_id: permission,
            },
            SEED_MICROS,
            None,
        )
        .await
        .expect("attach permission to role");
    id
}

/// Detach a role-to-permission mapping (the soft delete a fresh resolution must
/// observe on the very next issuance).
async fn detach(harness: &Harness, org: &OrganizationId, assignment: &OrgRolePermissionId) {
    let env = harness.env().clone();
    let scope = harness.scope();
    acting!(harness, &env)
        .org_role_permissions(scope)
        .unassign(&env, org, assignment)
        .await
        .expect("detach permission from role");
}

/// Register a resource server in the harness scope, optionally opted IN to permission
/// claims. The opt-in is a SEPARATE audited mutation because a registration always
/// writes the column default, exactly as production does it.
async fn register_rs(harness: &Harness, audience: &str, format: TokenFormat, opted_in: bool) {
    let env = harness.env();
    let scope = harness.scope();
    let id = ResourceServerId::generate(env, &scope);
    let actor = || {
        (
            ActorRef::service(ServiceId::generate(env)),
            CorrelationId::generate(env),
        )
    };
    let (who, correlation) = actor();
    harness
        .store()
        .scoped(scope)
        .acting(who, correlation)
        .resource_servers()
        .register(
            env,
            NewResourceServer {
                id: &id,
                audience,
                token_format: format,
                access_token_ttl_secs: None,
            },
        )
        .await
        .expect("register resource server");
    if opted_in {
        let (who, correlation) = actor();
        harness
            .db()
            .control_store()
            .management()
            .acting(who, correlation)
            .resource_servers(scope)
            .set_permission_claims(env, &id, true)
            .await
            .expect("opt the resource server in to permission claims");
    }
}

// ---------------------------------------------------------------------------
// Protocol driving
// ---------------------------------------------------------------------------

/// The public-client authorization query, with an `organization` fragment when one is
/// given and one repeated `resource` parameter per targeted audience.
fn authorize_query(client_id: &str, org: Option<&OrganizationId>, resources: &[&str]) -> String {
    let mut query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    );
    if let Some(org) = org {
        write!(query, "&organization={}", enc(&org.to_string())).expect("write to String");
    }
    for resource in resources {
        write!(query, "&resource={}", enc(resource)).expect("write to String");
    }
    query
}

/// The public-client code-exchange form, with the same repeated resource parameters.
fn token_form(code: &str, client_id: &str, resources: &[&str]) -> String {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ];
    for resource in resources {
        pairs.push(("resource", *resource));
    }
    form(&pairs)
}

/// A cookie for a fresh consenting subject of `client_id`, plus that subject id.
async fn consenting_subject(harness: &Harness, client_id: &str) -> (String, String) {
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    (subject, cookie)
}

/// Drive authorize to a code, expecting the redirect.
async fn authorize_to_code(
    harness: &Harness,
    client_id: &str,
    org: Option<&OrganizationId>,
    resources: &[&str],
    cookie: &str,
) -> String {
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(client_id, org, resources), cookie)
        .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "authorize should redirect: {body}"
    );
    location_param(&headers, "code").expect("code in redirect")
}

/// Exchange `code`, returning the RAW compact access token and the refresh token.
///
/// The raw string and not only its claims, because two tests are about the token's
/// LENGTH: the budget's bound is over the compact form, so a test that only ever saw
/// decoded claims could not check the bound the mint actually applies.
async fn exchange_raw(
    harness: &Harness,
    client_id: &str,
    code: &str,
    resources: &[&str],
) -> (String, String) {
    let (status, _, body) = harness.token(&token_form(code, client_id, resources)).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let value = json(&body);
    let access = value["access_token"]
        .as_str()
        .expect("access_token present")
        .to_owned();
    let refresh = value["refresh_token"]
        .as_str()
        .expect("a refresh token is issued for the code flow")
        .to_owned();
    (access, refresh)
}

/// Verify a compact access token for `audience` and return its claims.
fn claims_of(harness: &Harness, token: &str, audience: &str) -> Value {
    let verified = verify(
        token,
        &harness.access_token_policy(audience),
        &common::verify_clock(),
    )
    .expect("the access token verifies");
    Value::Object(verified.claims().raw().clone())
}

/// Verify a compact ID token for `audience` and return its claims.
///
/// Separate from [`claims_of`] because the two profiles are separate: the policies
/// require their own media type (issue #192), so an ID token read through the
/// access-token policy is refused, which is the point.
fn id_claims_of(harness: &Harness, token: &str, audience: &str) -> Value {
    let verified = verify(
        token,
        &harness.id_token_policy(audience),
        &common::verify_clock(),
    )
    .expect("the id token verifies");
    Value::Object(verified.claims().raw().clone())
}

/// Exchange and decode in one step, for the tests that do not care about the raw
/// token.
async fn exchange(
    harness: &Harness,
    client_id: &str,
    code: &str,
    resources: &[&str],
    audience: &str,
) -> (Value, String) {
    let (access, refresh) = exchange_raw(harness, client_id, code, resources).await;
    (claims_of(harness, &access, audience), refresh)
}

/// Refresh and return the verified access-token claims plus the rotated token.
async fn refresh_claims(
    harness: &Harness,
    client_id: &str,
    refresh_token: &str,
    resources: &[&str],
    audience: &str,
) -> (Value, String) {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    for resource in resources {
        pairs.push(("resource", *resource));
    }
    let (status, _, body) = harness.token(&form(&pairs)).await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    let value = json(&body);
    let access = value["access_token"]
        .as_str()
        .expect("access_token present");
    let rotated = value["refresh_token"]
        .as_str()
        .expect("the public client rotates its refresh token")
        .to_owned();
    (claims_of(harness, access, audience), rotated)
}

/// The `permissions` claim as a plain `Vec<&str>`, so an assertion reads as an exact
/// set comparison. Panics when the claim is absent, which every test that cares about
/// absence asserts separately.
fn permissions_of(claims: &Value) -> Vec<&str> {
    claims["permissions"]
        .as_array()
        .expect("the permissions claim is an array")
        .iter()
        .map(|value| value.as_str().expect("a permission slug is a string"))
        .collect()
}

/// Assert that NEITHER permission claim is present: the "no organization context, or a
/// target that did not unanimously opt in" wire state.
fn assert_no_permission_claims(claims: &Value, context: &str) {
    assert!(
        claims.get("permissions").is_none(),
        "{context}: no permissions claim: {claims}"
    );
    assert!(
        claims.get("permissions_status").is_none(),
        "{context}: and no permissions_status either: {claims}"
    );
}

/// Seed the standard fixture: an organization the subject is an active member of, one
/// role granted directly, and `slugs` attached to that role.
async fn seed_holder(
    harness: &Harness,
    subject: &str,
    slugs: &[&str],
) -> (OrganizationId, OrgRoleId) {
    let org = create_org(harness, "Permissions Co").await;
    let membership = add_member(harness, &org, subject).await;
    let role = create_role(harness, &org, "operator").await;
    grant_direct_role(harness, &org, &membership, &role).await;
    for slug in slugs {
        let permission = create_permission(harness, slug).await;
        attach(harness, &org, &role, &permission).await;
    }
    (org, role)
}

// ---------------------------------------------------------------------------
// The three observable wire states
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_access_token_carries_the_resolved_permission_set_in_total_order() {
    // WIRE STATE 2 (the non-empty half): the claim really appears on a real minted
    // token, decoded from the compact string and not read out of an internal struct.
    // The slugs are attached in a NON-alphabetical order so the assertion is about the
    // BTreeSet's total order and not about how the fixture happened to write them down;
    // determinism is what makes a byte budget over this claim mean anything.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    seed_holder(&harness, &subject, &["orders.write", "billing.read"]).await;

    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (claims, _) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;

    assert_eq!(
        permissions_of(&claims),
        vec!["billing.read", "orders.write"],
        "the complete set, sorted, on the wire: {claims}"
    );
    assert!(
        claims.get("permissions_status").is_none(),
        "an EMITTED set carries no status: the two claims are mutually exclusive"
    );
}

#[tokio::test]
async fn an_organization_member_holding_nothing_emits_an_empty_array() {
    // WIRE STATE 2 (the empty half). ABSENT and EMPTY are DIFFERENT answers, and both
    // are load-bearing: `[]` is a positive, resolved statement that the subject is in
    // this organization and holds no capability, which a resource server must be able
    // to tell apart from "this is not an organization token".
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    let (org, _) = seed_holder(&harness, &subject, &[]).await;

    let code = authorize_to_code(&harness, &client_id, Some(&org), &[RS_IN], &cookie).await;
    let (claims, _) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;

    assert_eq!(
        claims["permissions"],
        serde_json::json!([] as [&str; 0]),
        "an EMPTY ARRAY, present and resolved: {claims}"
    );
    assert!(
        claims.get("permissions").is_some(),
        "the empty case is PRESENT, not absent"
    );
}

#[tokio::test]
async fn no_organization_context_emits_neither_permission_claim() {
    // WIRE STATE 1. A subject in no organization gets NO claim at all, not an empty
    // array, and no status: nothing was withheld, so nothing is reported.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (_, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;

    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (claims, _) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;

    assert_no_permission_claims(&claims, "a subject with no organization context");
    assert!(
        claims.get("org_id").is_none(),
        "and no org_id either, so the two agree: {claims}"
    );
}

#[tokio::test]
async fn a_withheld_set_emits_a_status_and_no_permissions() {
    // WIRE STATE 3. The budget withheld the set, so the token says SO rather than
    // saying nothing: a resource server reading `permissions_status` knows it must not
    // read the absence of `permissions` as "this subject holds nothing".
    let harness =
        withheld_harness(PermissionOverflow::RolesOnly, DiagnosticVerbosity::Standard).await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    seed_holder(&harness, &subject, &["a.read", "b.read"]).await;

    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (claims, _) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;

    assert_eq!(
        claims["permissions_status"], "budget_exceeded",
        "the withholding is ON THE WIRE: {claims}"
    );
    assert!(
        claims.get("permissions").is_none(),
        "and the set itself is ABSENT, never a prefix: {claims}"
    );
    assert!(
        claims.get("roles").is_some(),
        "the roles claim still ships, which is what `roles_only` tells the resource \
         server to fall back to: {claims}"
    );
}

/// A harness whose element budget is `1`, so any set of two or more overflows, under
/// the given overflow mode and diagnostics verbosity.
///
/// An ELEMENT overflow rather than a byte one because it is exact and cheap to force:
/// the byte bound is exercised separately, against a measured real token, by
/// `the_budget_measures_the_token_that_actually_ships`.
async fn withheld_harness(overflow: PermissionOverflow, verbosity: DiagnosticVerbosity) -> Harness {
    let mut harness = Harness::start().await;
    harness.install_token_claims_budget(
        &TokenClaimsConfig {
            permission_claim_max_count: 1,
            permission_claim_warn_count: 1,
            permission_claim_overflow: overflow,
            ..TokenClaimsConfig::default()
        },
        &DiagnosticsConfig {
            verbosity,
            ..DiagnosticsConfig::default()
        },
    );
    harness
}

// ---------------------------------------------------------------------------
// The covenant: no configuration produces a silent drop
// ---------------------------------------------------------------------------

/// Every [`PermissionOverflow`] variant the covenant test drives, taken from the enum's
/// OWN list rather than written out again here.
const OVERFLOW_MODES: [PermissionOverflow; PermissionOverflow::ALL.len()] = PermissionOverflow::ALL;

/// Every [`DiagnosticVerbosity`] setting the covenant test drives, on the same terms.
const VERBOSITIES: [DiagnosticVerbosity; DiagnosticVerbosity::ALL.len()] = DiagnosticVerbosity::ALL;

/// The slot each overflow mode occupies in [`OVERFLOW_MODES`].
///
/// This, together with the arrays being the enums' own `ALL` lists, is what makes the
/// cross product EXHAUSTIVE rather than merely long. Two separate mechanisms, because
/// each catches what the other cannot, and it is worth being precise about which does
/// what:
///
///   * ADDING a variant stops this FILE compiling. The `match` is total over the enum,
///     so a new variant has no arm and there is no way to make the file build again
///     without giving it a slot. That is a compile error here and now, in the file
///     whose coverage is at stake.
///   * The new variant is then ALREADY in the cross product, because the array is
///     `PermissionOverflow::ALL` and not a literal this file maintains. That the enum's
///     own list is complete is measured one crate over, by `ironauth-config`'s
///     `the_overflow_mode_list_holds_every_variant_the_schema_declares`, which compares
///     it against the variant list `schemars` derives from the enum itself.
///
/// A bare array literal in this file had neither property: it would have kept passing
/// silently while covering strictly less than the covenant claims.
const fn overflow_slot(mode: PermissionOverflow) -> usize {
    match mode {
        PermissionOverflow::RolesOnly => 0,
        PermissionOverflow::PdpRequired => 1,
    }
}

/// The slot each verbosity occupies in [`VERBOSITIES`], on the same terms.
const fn verbosity_slot(verbosity: DiagnosticVerbosity) -> usize {
    match verbosity {
        DiagnosticVerbosity::Off => 0,
        DiagnosticVerbosity::Standard => 1,
        DiagnosticVerbosity::Verbose => 2,
    }
}

#[test]
fn the_covenant_cross_product_is_exhaustive() {
    // The runtime half of the guard above: every slot the total functions name is
    // occupied by the variant that names it, so the two arrays hold every variant
    // exactly once, in order, and the cross product below is that many DISTINCT
    // configurations rather than that many of an unknown number. A new variant given a
    // duplicate or an out-of-order slot to silence the compiler fails HERE.
    for (slot, mode) in OVERFLOW_MODES.into_iter().enumerate() {
        assert_eq!(overflow_slot(mode), slot, "{mode:?} sits in its own slot");
    }
    for (slot, verbosity) in VERBOSITIES.into_iter().enumerate() {
        assert_eq!(
            verbosity_slot(verbosity),
            slot,
            "{verbosity:?} sits in its own slot"
        );
    }
    // Deliberately NO assertion that the product is six. The covenant is stated over
    // EVERY combination, not over six of them, so a literal here would have to be
    // edited by the same hand that widened the enum and would guard nothing the two
    // mechanisms above do not already guard.
    assert!(
        !OVERFLOW_MODES.is_empty() && !VERBOSITIES.is_empty(),
        "an empty axis would make the covenant loop below vacuous"
    );
}

#[tokio::test]
async fn no_configuration_produces_a_silent_permission_drop() {
    // THE ACCEPTANCE CRITERION, MADE MECHANICAL. Six combinations, one per
    // (overflow mode, diagnostics verbosity) pair. In every one, force an overflow and
    // require BOTH halves of the covenant:
    //
    //   1. the TOKEN carries `permissions_status`, which is the durable record; and
    //   2. an EVENT ROW exists, which is the operator's convenience view.
    //
    // The verbosity axis is the one that is not obvious and is the reason this test
    // exists in this shape. Every OTHER recorder in `policy_trace` short-circuits at
    // `off`, so a budget event routed through the ordinary gate would make
    // `diagnostics.verbosity = "off"` precisely the configuration that produces a
    // silent drop. `off` is in this list to prove it does not.
    for overflow in OVERFLOW_MODES {
        for verbosity in VERBOSITIES {
            let harness = withheld_harness(overflow, verbosity).await;
            let client_id = harness.client_id().to_string();
            let (subject, cookie) = consenting_subject(&harness, &client_id).await;
            register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
            seed_holder(&harness, &subject, &["a.read", "b.read", "c.read"]).await;

            let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
            let (claims, _) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;

            let context = format!("{overflow:?} at verbosity {verbosity:?}");

            // 1. THE WIRE.
            assert_eq!(
                claims["permissions_status"],
                Value::String(overflow.permissions_status().to_owned()),
                "{context}: the token must SAY the set was withheld: {claims}"
            );
            assert!(
                claims.get("permissions").is_none(),
                "{context}: and must carry no set, complete or partial: {claims}"
            );

            // 2. THE EVENT.
            let events = harness
                .store()
                .scoped(harness.scope())
                .token_size_events()
                .recent_by_kind(TokenSizeKind::AccessToken, 50)
                .await
                .expect("read the budget events");
            let withholding = events
                .iter()
                .find(|event| event.reason.as_deref() == Some("budget_overflow_count"))
                .unwrap_or_else(|| {
                    panic!("{context}: a withholding must be recorded at EVERY verbosity")
                });
            assert_eq!(
                withholding.permission_status.as_deref(),
                Some(overflow.permissions_status()),
                "{context}: the event says what the WIRE said"
            );
            assert_eq!(
                withholding.permission_count,
                Some(3),
                "{context}: and how large the withheld set was"
            );
        }
    }
}

#[tokio::test]
async fn an_emitted_set_that_is_nowhere_near_a_threshold_records_nothing() {
    // The other half of the recording rule, and the one that keeps it from being a
    // write per mint on the hottest endpoint in the product: a verdict an operator
    // could not act on writes no row. Without this the test above would be satisfied by
    // an implementation that records unconditionally, which would be a performance
    // defect rather than a covenant.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    seed_holder(&harness, &subject, &["a.read"]).await;

    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (claims, _) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;
    assert_eq!(permissions_of(&claims), vec!["a.read"]);

    let events = harness
        .store()
        .scoped(harness.scope())
        .token_size_events()
        .recent_by_kind(TokenSizeKind::AccessToken, 50)
        .await
        .expect("read the budget events");
    assert!(
        events.is_empty(),
        "a comfortable mint writes no budget row: {events:?}"
    );
}

#[tokio::test]
async fn an_approaching_set_is_recorded_without_being_withheld() {
    // The early signal: past the warn threshold, still within the maximum. The claim
    // ships COMPLETE and the row exists, which is what makes the warning actionable
    // before anything stops working.
    let mut harness = Harness::start().await;
    harness.install_token_claims_budget(
        &TokenClaimsConfig {
            permission_claim_max_count: 8,
            permission_claim_warn_count: 1,
            ..TokenClaimsConfig::default()
        },
        &DiagnosticsConfig::default(),
    );
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    seed_holder(&harness, &subject, &["a.read", "b.read"]).await;

    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (claims, _) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;
    assert_eq!(
        permissions_of(&claims),
        vec!["a.read", "b.read"],
        "an approaching set is EMITTED IN FULL: nothing is withheld at a threshold"
    );
    assert!(
        claims.get("permissions_status").is_none(),
        "and no status, because nothing was withheld: {claims}"
    );

    let events = harness
        .store()
        .scoped(harness.scope())
        .token_size_events()
        .recent_by_kind(TokenSizeKind::AccessToken, 50)
        .await
        .expect("read the budget events");
    let approaching = events
        .iter()
        .find(|event| event.reason.as_deref() == Some("budget_approaching"))
        .expect("the approach is recorded");
    assert_eq!(
        approaching.permission_status, None,
        "an approach put no status on the wire, so the row records none"
    );
    assert_eq!(approaching.audience.as_deref(), Some(RS_IN));
}

/// Every access-token budget event in the harness scope, newest first.
async fn budget_events(harness: &Harness) -> Vec<ironauth_store::TokenSizeEventRecord> {
    harness
        .store()
        .scoped(harness.scope())
        .token_size_events()
        .recent_by_kind(TokenSizeKind::AccessToken, 50)
        .await
        .expect("read the budget events")
}

/// How many budget events in the harness scope carry `reason`.
async fn budget_event_count(harness: &Harness, reason: &str) -> usize {
    budget_events(harness)
        .await
        .iter()
        .filter(|event| event.reason.as_deref() == Some(reason))
        .count()
}

#[tokio::test]
async fn the_refresh_grant_records_its_own_budget_verdict() {
    // The NEW observability, asserted rather than described. The sink this writes to
    // had only ever seen code exchanges, so refresh, the highest-volume grant in the
    // product, was invisible to it. The code-exchange half is pinned by the covenant
    // test above; this pins the half that is new, and it is pinned by a COUNT rather
    // than by "a row exists", because the exchange that produced the refresh token
    // already wrote one and a membership assertion would be satisfied by that.
    let harness = withheld_harness(
        PermissionOverflow::PdpRequired,
        DiagnosticVerbosity::Standard,
    )
    .await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    seed_holder(&harness, &subject, &["a.read", "b.read", "c.read"]).await;

    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (claims, refresh_token) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;
    assert_eq!(claims["permissions_status"], "pdp_required");
    let after_exchange = budget_event_count(&harness, "budget_overflow_count").await;
    assert_eq!(after_exchange, 1, "the code exchange recorded exactly one");

    let (refreshed, _) =
        refresh_claims(&harness, &client_id, &refresh_token, &[RS_IN], RS_IN).await;
    assert_eq!(
        refreshed["permissions_status"], "pdp_required",
        "the rotated token withholds too: {refreshed}"
    );
    assert_eq!(
        budget_event_count(&harness, "budget_overflow_count").await,
        after_exchange + 1,
        "the REFRESH wrote its own row: without it the highest-volume grant is \
         unobserved and the count here stays at the exchange's one"
    );

    // And it is the same verdict through the same recorder, not a differently shaped
    // row: both grants report the status the wire carried and the size of the set.
    let rows = budget_events(&harness).await;
    for event in rows
        .iter()
        .filter(|event| event.reason.as_deref() == Some("budget_overflow_count"))
    {
        assert_eq!(event.permission_status.as_deref(), Some("pdp_required"));
        assert_eq!(event.permission_count, Some(3));
        assert_eq!(event.audience.as_deref(), Some(RS_IN));
    }
}

#[tokio::test]
async fn a_count_overflow_reports_the_shipped_token_size_and_flags_an_oversize_fallback() {
    // TWO numbers an operator reads off the same mint, both unpinned until now.
    //
    // 1. A count overflow serializes nothing, so the size it reports is the size of
    //    the token that SHIPPED. That is asserted against the byte length of the real
    //    compact token this exchange handed back, so neither a payload-length
    //    measurement (which is shorter than the compact form by the header, the
    //    signature, and two dots) nor a placeholder can pass.
    // 2. The residual case issue #98 records rather than acts on: the roles-only
    //    fallback is ITSELF over the byte budget. A second, distinct row says so. It
    //    is reachable here because the element check settles the withholding FIRST, so
    //    an unreachably small byte bound never gets to decide anything and only
    //    describes the fallback.
    let mut harness = Harness::start().await;
    harness.install_token_claims_budget(
        &TokenClaimsConfig {
            permission_claim_max_count: 1,
            permission_claim_warn_count: 1,
            // Smaller than any real compact token, so the token that ships after the
            // withholding is over the byte budget by construction.
            access_token_max_bytes: 1,
            access_token_warn_bytes: 1,
            ..TokenClaimsConfig::default()
        },
        &DiagnosticsConfig::default(),
    );
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    seed_holder(&harness, &subject, &["a.read", "b.read", "c.read"]).await;

    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (shipped, _) = exchange_raw(&harness, &client_id, &code, &[RS_IN]).await;
    let shipped_len = i64::try_from(shipped.len()).expect("a token length fits an i64");
    let claims = claims_of(&harness, &shipped, RS_IN);
    assert_eq!(
        claims["permissions_status"], "budget_exceeded",
        "the element bound withheld the set: {claims}"
    );

    let events = budget_events(&harness).await;
    let overflow = events
        .iter()
        .find(|event| event.reason.as_deref() == Some("budget_overflow_count"))
        .expect("a count overflow is recorded");
    assert_eq!(
        overflow.byte_size, shipped_len,
        "a count overflow reports the size of the token that SHIPPED, measured over \
         the COMPACT form, which is the number an operator sizes the byte bound against"
    );
    assert_eq!(overflow.permission_count, Some(3));

    let residual = events
        .iter()
        .find(|event| event.reason.as_deref() == Some("roles_only_still_oversize"))
        .expect(
            "the fallback is itself over the byte budget, and the design records that \
             rather than hiding it",
        );
    assert_eq!(
        residual.byte_size, shipped_len,
        "the second row reports the SAME shipped token, which is the thing that does \
         not fit"
    );
    assert!(
        residual.byte_size > 1,
        "and it is over the configured maximum, which is what makes it a residual"
    );
    assert_eq!(
        residual.permission_status.as_deref(),
        Some("budget_exceeded"),
        "it carries the status the wire carried, so the two rows are about one mint"
    );

    // And it is a SECOND row beside the first, never a replacement: the reason a set
    // was withheld and the fact that withholding it did not help are different facts.
    assert_eq!(
        budget_event_count(&harness, "budget_overflow_count").await,
        1
    );
    assert_eq!(
        budget_event_count(&harness, "roles_only_still_oversize").await,
        1
    );
}

#[tokio::test]
async fn a_multi_audience_verdict_names_no_audience() {
    // ONE verdict is reached for the whole TOKEN, so it is attributable to a single
    // audience only when the token targets exactly one. Naming the first would label
    // the verdict as belonging to a resource server that had no more to do with it
    // than the other, and an operator reading the warnings list would chase the wrong
    // API. The single-audience half is asserted by
    // `an_approaching_set_is_recorded_without_being_withheld`, which requires the
    // audience to be NAMED, so the two together pin a choice rather than a constant.
    let harness =
        withheld_harness(PermissionOverflow::RolesOnly, DiagnosticVerbosity::Standard).await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    register_rs(&harness, RS_IN_TWO, TokenFormat::AtJwt, true).await;
    seed_holder(&harness, &subject, &["a.read", "b.read", "c.read"]).await;

    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN, RS_IN_TWO], &cookie).await;
    let (claims, _) = exchange(&harness, &client_id, &code, &[RS_IN, RS_IN_TWO], RS_IN).await;
    assert_eq!(
        claims["permissions_status"], "budget_exceeded",
        "both audiences opted in, so the claim was in play and the budget withheld it"
    );

    let events = budget_events(&harness).await;
    let withholding = events
        .iter()
        .find(|event| event.reason.as_deref() == Some("budget_overflow_count"))
        .expect("the withholding is recorded");
    assert_eq!(
        withholding.audience, None,
        "a two-audience token names NEITHER: {:?}",
        withholding.audience
    );
    assert!(
        withholding.organization_id.is_some(),
        "the organization is still named, so the row is still actionable"
    );
}

// ---------------------------------------------------------------------------
// Fork 3: unanimity or suppress
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_mixed_opt_in_target_emits_no_permissions() {
    // FORK 3. One opted-in and one opted-out audience on ONE token. There is no
    // per-audience claim shape inside a token, so emitting would be a cross-audience
    // privilege leak; refusing with invalid_target would break a request that succeeds
    // today. The claim is SUPPRESSED, and suppressed SILENTLY.
    //
    // Both halves are asserted, and the `permissions_status` half is the load-bearing
    // one: this is a CONFIGURATION fact, not an overflow, and the opted-in resource
    // server can already see the other audience in `aud`. A later change that started
    // reporting it as an overflow turns this test red, which is exactly what should
    // happen.
    //
    // # Why every ORDERING is driven
    //
    // The verdict is an AND fold across the targeted servers, and an AND fold is
    // order-independent only if it really is a fold. A last-wins assignment
    // (`permission_claims = server.permission_claims_enabled`) passes an
    // opted-out-last ordering and MINTS the claim on an opted-in-last one, which is
    // precisely the cross-audience leak this fork exists to prevent: the token would
    // carry `permissions` with the opted-out audience sitting in `aud` beside it. So
    // both orderings run, and each asserts the opted-out audience really IS in `aud`,
    // because a suppression on a token that never targeted the opted-out server would
    // prove nothing.
    //
    // The duplicate listings pin the fold's PLACEMENT as well. It folds per targeted
    // RESOURCE, before the audience de-duplication, so naming a resource twice folds
    // its opt-in twice; AND is idempotent, so the verdict is unchanged, and the
    // de-duplicated `aud` array is unchanged too.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    register_rs(&harness, RS_OUT, TokenFormat::AtJwt, false).await;
    seed_holder(&harness, &subject, &["orders.write"]).await;

    // The control: the SAME subject, the SAME fixture, targeting the opted-in audience
    // ALONE, does carry the claim. Without this the suppression below could be a
    // fixture that never resolved anything.
    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (solo, _) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;
    assert_eq!(permissions_of(&solo), vec!["orders.write"]);

    for resources in [
        // The opted-out server LAST, and FIRST: an assignment rather than a fold
        // survives one of these and mints the claim on the other.
        &[RS_IN, RS_OUT][..],
        &[RS_OUT, RS_IN][..],
        // The same two servers with one named TWICE, in both orders, so the fold's
        // placement before de-duplication is pinned rather than merely commented.
        &[RS_IN, RS_OUT, RS_IN][..],
        &[RS_OUT, RS_IN, RS_IN][..],
    ] {
        let context = format!("{resources:?}");
        let code = authorize_to_code(&harness, &client_id, None, resources, &cookie).await;
        let (mixed, _) = exchange(&harness, &client_id, &code, resources, RS_IN).await;

        assert_no_permission_claims(&mixed, &format!("a mixed opt-in target {context}"));
        // The opted-out audience really is ON this token. Without this the assertion
        // above would also pass for a token that quietly dropped it from `aud`, and
        // the leak the fold prevents is precisely a `permissions` claim sitting beside
        // an audience that never asked for one.
        let audiences: Vec<&str> = mixed["aud"]
            .as_array()
            .expect("a multi-audience token carries an aud ARRAY")
            .iter()
            .map(|value| value.as_str().expect("an audience is a string"))
            .collect();
        assert!(
            audiences.contains(&RS_OUT) && audiences.contains(&RS_IN),
            "{context}: both audiences ride the token: {mixed}"
        );
        assert_eq!(
            audiences.len(),
            2,
            "{context}: and the array is DE-DUPLICATED, whatever the request repeated: \
             {mixed}"
        );
        assert!(
            mixed.get("roles").is_some(),
            "{context}: everything ELSE about the token is unchanged, so the \
             suppression is targeted: {mixed}"
        );
    }
}

#[tokio::test]
async fn a_unanimous_multi_audience_target_still_carries_permissions() {
    // The other half of the fold, without which "unanimity or suppress" could be
    // satisfied by never emitting on a multi-audience token at all.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    register_rs(&harness, RS_IN_TWO, TokenFormat::AtJwt, true).await;
    seed_holder(&harness, &subject, &["orders.write"]).await;

    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN, RS_IN_TWO], &cookie).await;
    let (claims, _) = exchange(&harness, &client_id, &code, &[RS_IN, RS_IN_TWO], RS_IN).await;

    assert_eq!(
        permissions_of(&claims),
        vec!["orders.write"],
        "every targeted audience opted in, so the claim rides: {claims}"
    );
}

#[tokio::test]
async fn a_target_that_did_not_opt_in_carries_no_permissions() {
    // The default posture, and the reason the opt-in exists: a resource server that
    // never asked for permission claims never receives one, even for a subject who
    // holds several.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_OUT, TokenFormat::AtJwt, false).await;
    let (org, _) = seed_holder(&harness, &subject, &["orders.write"]).await;

    let code = authorize_to_code(&harness, &client_id, Some(&org), &[RS_OUT], &cookie).await;
    let (claims, _) = exchange(&harness, &client_id, &code, &[RS_OUT], RS_OUT).await;

    assert_no_permission_claims(&claims, "an opted-out audience");
    assert_eq!(
        claims["org_id"],
        Value::String(org.to_string()),
        "the organization context is still on the token, so the absence is the opt-in \
         and not a missing org: {claims}"
    );
}

#[tokio::test]
async fn the_no_resource_default_audience_carries_no_permissions() {
    // The no-resource branch is opted out BY CONSTRUCTION: it reads no resource-server
    // row, so there is no row that could carry an opt-in. This is also what makes the
    // device, client-credentials and jwt-bearer grants permission-free without any of
    // them knowing about the feature, because they all pass no resource.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let (org, _) = seed_holder(&harness, &subject, &["orders.write"]).await;

    let code = authorize_to_code(&harness, &client_id, Some(&org), &[], &cookie).await;
    let (claims, _) = exchange(&harness, &client_id, &code, &[], &client_id).await;

    assert_no_permission_claims(&claims, "the default client-id audience");
    assert_eq!(claims["org_id"], Value::String(org.to_string()));
}

// ---------------------------------------------------------------------------
// Freshness, on both hooks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_refresh_grant_re_resolves_permissions_in_both_directions() {
    // The refresh hook is the load-bearing half. Refresh is the highest-volume grant,
    // so a capability withdrawn after the code was issued would be invisible for the
    // whole refresh-family lifetime if this replayed a frozen set. Both directions are
    // driven, because an implementation that only ever ADDED would pass a
    // grant-only test.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    let (org, role) = seed_holder(&harness, &subject, &["orders.write"]).await;

    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (claims, refresh_token) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;
    assert_eq!(permissions_of(&claims), vec!["orders.write"]);

    // GRANTED after the code was minted: visible on the very next rotation.
    let added = create_permission(&harness, "billing.read").await;
    let mapping = attach(&harness, &org, &role, &added).await;
    let (claims, refresh_token) =
        refresh_claims(&harness, &client_id, &refresh_token, &[RS_IN], RS_IN).await;
    assert_eq!(
        permissions_of(&claims),
        vec!["billing.read", "orders.write"],
        "a capability attached after issuance is on the NEXT rotated token: {claims}"
    );

    // WITHDRAWN: gone on the next rotation, which is the direction that matters.
    detach(&harness, &org, &mapping).await;
    let (claims, _) = refresh_claims(&harness, &client_id, &refresh_token, &[RS_IN], RS_IN).await;
    assert_eq!(
        permissions_of(&claims),
        vec!["orders.write"],
        "a detached capability stops riding on the NEXT rotated token: {claims}"
    );
}

#[tokio::test]
async fn two_issuances_against_identical_state_emit_an_identical_permissions_claim() {
    // A byte budget over a nondeterministic serialization would be meaningless, so the
    // determinism is a property of the budget and not only of the claim.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    seed_holder(&harness, &subject, &["z.read", "a.read", "m.read"]).await;

    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (first, _) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;
    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (second, _) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;

    assert_eq!(
        serde_json::to_string(&first["permissions"]).expect("serialize"),
        serde_json::to_string(&second["permissions"]).expect("serialize"),
        "two issuances against identical stored state are byte-identical"
    );
}

// ---------------------------------------------------------------------------
// The byte bound, measured against a real token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_budget_measures_the_token_that_actually_ships() {
    // EXACTNESS, proved from the wire rather than from the arithmetic. The budget's
    // bound is over the COMPACT token, and the mint predicts that length before signing
    // from the same protected header and signature width the signing core uses. If the
    // prediction were an ESTIMATE the claim would be withheld at a bound it in fact
    // fits, or emitted past one it does not.
    //
    // The probe needs no access to any internal: mint once with a bound nothing can
    // reach and MEASURE the emitted token, then re-mint with the bound set to exactly
    // that length (which must still emit) and to one byte less (which must withhold).
    // Only an exact predictor passes both.
    let mut harness = Harness::start().await;
    harness
        .install_token_claims_budget(&TokenClaimsConfig::default(), &DiagnosticsConfig::default());
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    seed_holder(&harness, &subject, &["orders.write", "billing.read"]).await;

    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (raw, _) = exchange_raw(&harness, &client_id, &code, &[RS_IN]).await;
    let emitted_len = u32::try_from(raw.len()).expect("a token length fits a u32");
    assert_eq!(
        permissions_of(&claims_of(&harness, &raw, RS_IN)),
        vec!["billing.read", "orders.write"],
        "the baseline mint carries the claim"
    );

    // EXACTLY at the bound: still emitted, because the comparison is strictly
    // greater-than and the predicted length is the emitted one.
    harness.install_token_claims_budget(
        &TokenClaimsConfig {
            access_token_max_bytes: emitted_len,
            access_token_warn_bytes: emitted_len,
            ..TokenClaimsConfig::default()
        },
        &DiagnosticsConfig::default(),
    );
    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (at_bound, _) = exchange_raw(&harness, &client_id, &code, &[RS_IN]).await;
    assert_eq!(
        at_bound.len(),
        raw.len(),
        "the token is the same length every time, so the probe is comparing like with \
         like"
    );
    let claims = claims_of(&harness, &at_bound, RS_IN);
    assert_eq!(
        permissions_of(&claims),
        vec!["billing.read", "orders.write"],
        "a token of exactly `access_token_max_bytes` is WITHIN the bound: {claims}"
    );

    // One byte under: withheld, and the withholding is on the wire.
    harness.install_token_claims_budget(
        &TokenClaimsConfig {
            access_token_max_bytes: emitted_len - 1,
            access_token_warn_bytes: emitted_len - 1,
            ..TokenClaimsConfig::default()
        },
        &DiagnosticsConfig::default(),
    );
    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (under, _) = exchange_raw(&harness, &client_id, &code, &[RS_IN]).await;
    let claims = claims_of(&harness, &under, RS_IN);
    assert!(
        claims.get("permissions").is_none(),
        "one byte under the emitted length, the claim is withheld: {claims}"
    );
    assert_eq!(claims["permissions_status"], "budget_exceeded");

    // And the recorded byte overflow reports the size of the token that was WITHHELD,
    // which is the number an operator needs to size the bound.
    let events = harness
        .store()
        .scoped(harness.scope())
        .token_size_events()
        .recent_by_kind(TokenSizeKind::AccessToken, 50)
        .await
        .expect("read the budget events");
    let overflow = events
        .iter()
        .find(|event| event.reason.as_deref() == Some("budget_overflow_bytes"))
        .expect("a byte overflow is recorded");
    assert_eq!(
        overflow.byte_size,
        i64::from(emitted_len),
        "the event reports the measured size of the withheld token"
    );
}

// ---------------------------------------------------------------------------
// Boundaries: opaque, and the machine grants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_opaque_access_token_can_never_carry_permissions() {
    // An opaque access token carries no claims AT ALL, and `IntrospectionClaims` has no
    // extension point, so permissions are an at+jwt feature or they do not exist. The
    // combination under test (opaque AND opted in) is reachable through a config
    // promotion, which is why it is driven rather than argued away.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_OPAQUE, TokenFormat::Opaque, true).await;
    seed_holder(&harness, &subject, &["orders.write"]).await;

    let code = authorize_to_code(&harness, &client_id, None, &[RS_OPAQUE], &cookie).await;
    let (status, _, body) = harness
        .token(&token_form(&code, &client_id, &[RS_OPAQUE]))
        .await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let access = json(&body)["access_token"]
        .as_str()
        .expect("access_token present")
        .to_owned();
    assert!(
        access.starts_with("ira_at_"),
        "the target selected the opaque format: {access}"
    );
    assert!(
        !access.contains('.'),
        "an opaque reference token is not a JWS and carries no claim segment: {access}"
    );

    // And nothing was recorded either: the budget never ran, because there was never a
    // claim for it to decide about.
    let events = harness
        .store()
        .scoped(harness.scope())
        .token_size_events()
        .recent_by_kind(TokenSizeKind::AccessToken, 50)
        .await
        .expect("read the budget events");
    assert!(
        events.is_empty(),
        "an opaque mint reaches no budget verdict: {events:?}"
    );
}

#[tokio::test]
async fn the_client_credentials_grant_never_carries_permissions() {
    // The issue #99 boundary, ASSERTED. A machine token has a service-account `sub` and
    // no human organization context, and it is built by a DISTINCT claim builder with
    // no permission field to read.
    //
    // The request names an opted-in resource, and the grant IGNORES it: the
    // client-credentials grant does not compose with RFC 8707 resource indicators
    // (there is no prior authorization to downscope from), so it always resolves the
    // NO-RESOURCE target and its audience is the configured default, the client id.
    // That is the second, independent half of the guarantee and it is why the audience
    // asserted below is the client and not `RS_IN`: no resource means no resource-server
    // row, which means `permission_claims` is false by construction.
    let harness = Harness::start().await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let authorization = format!("Basic {}", STANDARD.encode(format!("{client}:{secret}")));

    let (status, _, body) = harness
        .token_with_auth(
            &form(&[("grant_type", "client_credentials"), ("resource", RS_IN)]),
            Some(&authorization),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "client credentials: {body}");
    let access = json(&body)["access_token"]
        .as_str()
        .expect("access_token present")
        .to_owned();
    let claims = claims_of(&harness, &access, &client.to_string());
    assert_eq!(
        claims["aud"],
        Value::String(client.to_string()),
        "the named resource did not move the audience: the M2M grant passes none:          {claims}"
    );
    assert_no_permission_claims(&claims, "a client-credentials token");
    assert!(
        claims.get("roles").is_none(),
        "and no roles either, which is the same #99 boundary: {claims}"
    );
}

// ---------------------------------------------------------------------------
// Fail closed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_store_fault_during_permission_resolution_refuses_the_token() {
    // FAIL CLOSED, injected the way production would suffer it: the data plane's SELECT
    // grant on the mapping table is revoked, so the read raises SQLSTATE 42501 inside
    // the mint. A permission-less token would read downstream as a successful
    // authorization DOWNGRADE, and under `roles_only` it would be worse than that,
    // because the resource server falls back to `roles` and grants SOMETHING.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    seed_holder(&harness, &subject, &["orders.write"]).await;

    // A control exchange first, so the refusal below is caused by the revoke and not by
    // the fixture.
    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (claims, _) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;
    assert_eq!(permissions_of(&claims), vec!["orders.write"]);

    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    sqlx::query("REVOKE SELECT ON org_role_permissions FROM ironauth_app")
        .execute(harness.db().owner_pool())
        .await
        .expect("revoke the data plane's read on the mapping table");

    let (status, _, body) = harness
        .token(&token_form(&code, &client_id, &[RS_IN]))
        .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a resolution fault fails the token request: {body}"
    );
    assert_eq!(json(&body)["error"], "server_error");
    assert!(!body.contains("access_token"), "no token is issued: {body}");

    // Restore, and prove the refusal was the revoke. This ALSO pins the ordering: the
    // resolution runs inside the mint, which happens BEFORE the atomic single-use
    // consume, so a transient store fault must not BURN the code. The SAME code is
    // presented again and now succeeds.
    sqlx::query("GRANT SELECT ON org_role_permissions TO ironauth_app")
        .execute(harness.db().owner_pool())
        .await
        .expect("restore the grant");
    let (claims, _) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;
    assert_eq!(
        permissions_of(&claims),
        vec!["orders.write"],
        "the SAME code still redeems: a resolution fault never burned it"
    );
}

#[tokio::test]
async fn a_store_fault_fails_the_refresh_closed_too() {
    // The same discipline on the refresh hook, which is where a quiet drop would be
    // worst: the client keeps working with strictly fewer capabilities asserted and
    // nothing anywhere reports it.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    seed_holder(&harness, &subject, &["orders.write"]).await;

    let code = authorize_to_code(&harness, &client_id, None, &[RS_IN], &cookie).await;
    let (claims, refresh_token) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;
    assert_eq!(permissions_of(&claims), vec!["orders.write"]);

    sqlx::query("REVOKE SELECT ON permissions FROM ironauth_app")
        .execute(harness.db().owner_pool())
        .await
        .expect("revoke the data plane's read on the vocabulary table");

    let (status, _, body) = harness
        .token(&form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
            ("client_id", &client_id),
            ("resource", RS_IN),
        ]))
        .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a resolution fault fails the refresh: {body}"
    );
    assert_eq!(json(&body)["error"], "server_error");
    assert!(!body.contains("access_token"), "no token is rotated out");

    // And the family is untouched: the mint runs before the atomic redeem, so the SAME
    // refresh token still rotates once the fault clears.
    sqlx::query("GRANT SELECT ON permissions TO ironauth_app")
        .execute(harness.db().owner_pool())
        .await
        .expect("restore the grant");
    let (claims, _) = refresh_claims(&harness, &client_id, &refresh_token, &[RS_IN], RS_IN).await;
    assert_eq!(
        permissions_of(&claims),
        vec!["orders.write"],
        "the SAME refresh token still rotates: the fault never consumed it"
    );
}

#[tokio::test]
async fn an_opaque_target_runs_no_permission_resolution_at_all() {
    // The other half of `an_opaque_access_token_can_never_carry_permissions`, and the
    // half that makes the threat model's "INERT rather than unsafe" row TRUE rather
    // than nearly true. `opaque` plus opted-in is reachable through a config promotion
    // (the management API refuses it, the promotion engine writes both columns in one
    // statement with no handler in the path), so the combination exists in the field.
    //
    // Inert has to mean the resolution never RUNS, not merely that its answer is
    // discarded. A resolution that runs is a store read that can FAIL, and failing
    // closed is the correct behaviour for a claim that will ship; for a claim that
    // cannot ship it turns a documented no-op into a 500 that the same request without
    // the opt-in survives. Driven under the fault the production failure mode would
    // present as: the data plane's SELECT grant on the mapping table revoked.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    register_rs(&harness, RS_OPAQUE, TokenFormat::Opaque, true).await;
    register_rs(&harness, RS_OUT, TokenFormat::Opaque, false).await;
    seed_holder(&harness, &subject, &["orders.write"]).await;

    let opted_in = authorize_to_code(&harness, &client_id, None, &[RS_OPAQUE], &cookie).await;
    let opted_out = authorize_to_code(&harness, &client_id, None, &[RS_OUT], &cookie).await;
    sqlx::query("REVOKE SELECT ON org_role_permissions FROM ironauth_app")
        .execute(harness.db().owner_pool())
        .await
        .expect("revoke the data plane's read on the mapping table");

    // The CONTROL: an opted-OUT opaque target has never touched that table, so it is
    // unaffected. Without it a 200 below could just mean the fault was not injected.
    let (status, _, body) = harness
        .token(&token_form(&opted_out, &client_id, &[RS_OUT]))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an opted-out opaque exchange never reads the mapping table: {body}"
    );

    // And the opted-IN opaque target answers exactly the same, because the format is
    // checked BEFORE the resolution rather than after it. A 500 here is the whole
    // finding: same fault, same format, one flag apart.
    let (status, _, body) = harness
        .token(&token_form(&opted_in, &client_id, &[RS_OPAQUE]))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an opted-IN opaque exchange must be INERT, not merely discarded: a resolution \
         that runs is a read that can fail, and this one has nowhere to put its answer: \
         {body}"
    );
    let access = json(&body)["access_token"]
        .as_str()
        .expect("access_token present")
        .to_owned();
    assert!(
        access.starts_with("ira_at_"),
        "the target still selected the opaque format: {access}"
    );

    sqlx::query("GRANT SELECT ON org_role_permissions TO ironauth_app")
        .execute(harness.db().owner_pool())
        .await
        .expect("restore the grant");
}

// ---------------------------------------------------------------------------
// The nesting bound, on the plane that mints
// ---------------------------------------------------------------------------

/// Seed one three-level forest (grandparent > parent > child) with the member bound only
/// into `child`, a permission reachable through a role granted on `parent` (ONE level
/// up) and another through a role granted on `grandparent` (TWO levels up).
///
/// Two harnesses configured differently are driven over this SAME shape, so the only
/// thing that can move the answer is the bound each was built with.
async fn seed_two_level_permission_ancestry(
    harness: &Harness,
    client_id: &str,
) -> (String, OrganizationId) {
    let (subject, cookie) = consenting_subject(harness, client_id).await;
    let org = create_org(harness, "Nesting Co").await;
    let membership = add_member(harness, &org, &subject).await;
    let grandparent = create_group(harness, &org, "grandparent", None).await;
    let parent = create_group(harness, &org, "parent", Some(&grandparent)).await;
    let child = create_group(harness, &org, "child", Some(&parent)).await;
    bind_member(harness, &org, &child, &membership).await;

    let near_role = create_role(harness, &org, "near").await;
    let far_role = create_role(harness, &org, "far").await;
    grant_group_role(harness, &org, &parent, &near_role).await;
    grant_group_role(harness, &org, &grandparent, &far_role).await;
    for (role, slug) in [(&near_role, "via.parent"), (&far_role, "via.grandparent")] {
        let permission = create_permission(harness, slug).await;
        attach(harness, &org, role, &permission).await;
    }
    (cookie, org)
}

#[tokio::test]
async fn the_configured_group_depth_is_the_bound_the_permission_resolution_uses() {
    // The nesting bound is a SHARED setting whose whole point is that the console and
    // the token cannot answer differently, so it has to be pinned on both planes. This
    // is the mint half; `the_effective_roles_view_resolves_permissions_through_the_full_
    // ancestor_walk` in `ironauth-admin` is the console half.
    //
    // The two failure directions are opposite and both silent. A hard-coded bound makes
    // an operator who RAISES the setting lose every capability inherited above the
    // default, which is an authorization downgrade with no signal. A ceiling installed
    // in place of the argument makes an operator who LOWERS it get a deeper walk here
    // than the management plane runs, so the console and the token disagree.
    //
    // Neither is observable through an accessor, so the value is watched at the STORE
    // CALL by driving a real issuance over a tree deeper than the bound. Groups are
    // seeded at the shipped default, so the tree is legal to build and only the READ is
    // bounded, which is the state an operator who lowers the setting under a populated
    // environment leaves behind.
    let deep = Harness::start().await;
    let client_id = deep.client_id().to_string();
    register_rs(&deep, RS_IN, TokenFormat::AtJwt, true).await;
    let (cookie, org) = seed_two_level_permission_ancestry(&deep, &client_id).await;
    let code = authorize_to_code(&deep, &client_id, Some(&org), &[RS_IN], &cookie).await;
    let (claims, _) = exchange(&deep, &client_id, &code, &[RS_IN], RS_IN).await;
    assert_eq!(
        permissions_of(&claims),
        vec!["via.grandparent", "via.parent"],
        "at the shipped default the walk reaches both ancestor levels: {claims}"
    );

    // The SAME fixture under a bound of ONE. The walk reaches the member's own groups
    // plus one level of ancestor, so the parent's capability still arrives and the
    // grandparent's does not. Asserting the near one is PRESENT is what makes this a
    // truncation rather than a walk that silently did not run at all.
    let shallow = Harness::start_with_group_depth(1).await;
    let client_id = shallow.client_id().to_string();
    register_rs(&shallow, RS_IN, TokenFormat::AtJwt, true).await;
    let (cookie, org) = seed_two_level_permission_ancestry(&shallow, &client_id).await;
    let code = authorize_to_code(&shallow, &client_id, Some(&org), &[RS_IN], &cookie).await;
    let (claims, _) = exchange(&shallow, &client_id, &code, &[RS_IN], RS_IN).await;
    assert_eq!(
        permissions_of(&claims),
        vec!["via.parent"],
        "a bound of one truncates the walk one level up, and only there: {claims}"
    );
    assert_eq!(
        shallow.state().max_group_depth(),
        1,
        "the configured bound is what the router's state carries"
    );
}

// ---------------------------------------------------------------------------
// The organization's OWN lifecycle, and forgery through a real path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_disabled_or_deleted_organization_mints_no_permissions_on_either_hook() {
    // Disable and soft delete are the COARSEST revocations the product exposes, and
    // both must reach the permission claim on BOTH issuance hooks. Neither hook can
    // check the organization's state for itself, which is why the fence lives in the
    // store's shared closure: on REFRESH the authorize-time resolution is never called,
    // and on a CODE EXCHANGE it returns early for an already-bound session, so its own
    // refusal never runs for a session that has an organization.
    //
    // Without the fence every member of a disabled organization keeps receiving freshly
    // re-affirmed CAPABILITIES for the whole life of the refresh family, which with
    // offline_access is unbounded. That is one step sharper than the role case, because
    // a permission names an API capability directly.
    for (label, kill) in [("disabled", false), ("soft deleted", true)] {
        let harness = Harness::start().await;
        let client_id = harness.client_id().to_string();
        let (subject, cookie) = consenting_subject(&harness, &client_id).await;
        register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
        let (org, _) = seed_holder(&harness, &subject, &["orders.write"]).await;

        let code = authorize_to_code(&harness, &client_id, Some(&org), &[RS_IN], &cookie).await;
        let (claims, refresh_token) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;
        assert_eq!(
            permissions_of(&claims),
            vec!["orders.write"],
            "{label}: the control exchange carries the capability while the \
             organization is live"
        );

        if kill {
            soft_delete_org(&harness, &org).await;
        } else {
            set_org_state(&harness, &org, OrganizationState::Disabled).await;
        }

        // Hook one: the refresh grant.
        let (refreshed, _) =
            refresh_claims(&harness, &client_id, &refresh_token, &[RS_IN], RS_IN).await;
        assert_eq!(
            permissions_of(&refreshed),
            Vec::<&str>::new(),
            "{label}: no capability on the very next refresh: {refreshed}"
        );
        // EMPTY, not absent, and not a refusal, exactly as the roles claim answers. The
        // grant really is bound to that organization, so "scoped to it, holding nothing
        // there" is the honest answer; and a lifecycle change is an operator action, so
        // refusing would make an administrative act an outage.
        assert_eq!(
            refreshed["org_id"],
            Value::String(org.to_string()),
            "{label}: the frozen org_id still rides: {refreshed}"
        );
        assert!(
            refreshed.get("permissions_status").is_none(),
            "{label}: nothing was WITHHELD, so no budget status: {refreshed}"
        );

        // Hook two: a BRAND NEW code exchange on the SAME session. The session is
        // already bound, so /authorize still issues a code and the whole refusal has to
        // come from the resolution.
        let code = authorize_to_code(&harness, &client_id, Some(&org), &[RS_IN], &cookie).await;
        let (claims, _) = exchange(&harness, &client_id, &code, &[RS_IN], RS_IN).await;
        assert_eq!(
            permissions_of(&claims),
            Vec::<&str>::new(),
            "{label}: none on a fresh code exchange either: {claims}"
        );
    }
}

#[tokio::test]
async fn a_users_own_stored_claim_can_never_forge_permissions_through_the_live_path() {
    // The genuine end-to-end forgery vector, driven rather than asserted from the
    // denylist. The ID token's extra-claims bag is fed by `assemble_claims` from the
    // USER's stored standard-claim document, selected by the OIDC Core 5.5 `claims`
    // request parameter, and that parameter accepts ARBITRARY claim names. So a user
    // document containing `{"permissions":["billing.admin"]}`, requested as
    // `{"id_token":{"permissions":null}}`, would be stamped into the ID token verbatim
    // were the two names not in PROTECTED_ACCESS_TOKEN_CLAIMS, which the id-token fold
    // filters EXPLICITLY.
    //
    // Both names are driven, for the two different reasons the threat model separates:
    // `permissions` names an API capability, so a forged one is a capability nobody
    // granted; `permissions_status` grants nothing, but a self-asserted one convinces a
    // resource server that a withheld set was simply an empty one.
    //
    // The benign claim in the SAME document IS released, so the drop is attributable to
    // the reserved names and not to the request being ignored wholesale.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let subject = harness
        .seed_user_with_claims(
            "permission-forger@example.test",
            common::SEED_PASSWORD,
            r#"{"permissions":["billing.admin"],"permissions_status":"pdp_required",
                "email":"permission-forger@example.test"}"#,
        )
        .await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    register_rs(&harness, RS_IN, TokenFormat::AtJwt, true).await;
    let (org, _) = seed_holder(&harness, &subject, &["orders.read"]).await;

    let requested = r#"{"id_token":{"permissions":null,"permissions_status":null,"email":null}}"#;
    let query = format!(
        "{}&scope=openid%20email&claims={}",
        authorize_query(&client_id, Some(&org), &[RS_IN]),
        enc(requested),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("code in redirect");

    let (status, _, body) = harness
        .token(&token_form(&code, &client_id, &[RS_IN]))
        .await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let value = json(&body);
    let id_token = value["id_token"].as_str().expect("an id token is issued");
    let id_claims = id_claims_of(&harness, id_token, &client_id);
    assert!(
        id_claims.get("permissions").is_none(),
        "a self-asserted permissions claim is DROPPED from the id token: {id_claims}"
    );
    assert!(
        id_claims.get("permissions_status").is_none(),
        "and a self-asserted status: {id_claims}"
    );
    assert_eq!(
        id_claims["email"], "permission-forger@example.test",
        "the benign requested claim still lands, so the drop is TARGETED: {id_claims}"
    );

    let access = value["access_token"]
        .as_str()
        .expect("access_token present");
    let at_claims = claims_of(&harness, access, RS_IN);
    assert_eq!(
        permissions_of(&at_claims),
        vec!["orders.read"],
        "the access token carries the ISSUER-resolved set, never the self-asserted \
         one: {at_claims}"
    );
    assert!(
        at_claims.get("permissions_status").is_none(),
        "and no forged status rode in beside it: {at_claims}"
    );
}

/// A compile-time reminder that the emitted set is a `BTreeSet` in the mint, so the
/// claim's order is the set's total order rather than the store's row order.
#[test]
fn the_claim_order_is_a_total_order() {
    let set: BTreeSet<String> = ["z", "a", "m"].iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(
        set.iter().collect::<Vec<_>>(),
        vec!["a", "m", "z"],
        "a BTreeSet iterates in its total order"
    );
}
