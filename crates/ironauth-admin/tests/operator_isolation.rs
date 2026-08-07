// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-operator isolation on the LEVEL tables (issue #185).
//!
//! The operator is the root of the resource model, above every tenant. `tenants` and
//! `environments` are NOT row-level-security protected: RLS in this system fences
//! `(tenant, environment)` and the level tables are what DEFINE that pair, so they sit
//! above the mechanism and their isolation has to be a predicate in the query instead.
//!
//! `TenantRepo` already carries the operator and filters on it, in both `get` and
//! `list`. `EnvironmentRepo` did not: it was constructed from a tenant alone, so an
//! environment read was fenced by `(tenant, environment)` and by nothing that connected
//! that tenant to the caller. A caller who names ANOTHER operator's tenant in the path
//! reached that tenant's environments, and everything hanging off them.
//!
//! # Why this was latent rather than exploitable, and why it is still worth closing
//!
//! A deployment self-bootstraps exactly ONE operator and the operator plane is a
//! documented READ surface: there is no endpoint that mints a second operator. So there
//! is currently no second credential to attack from, and issue #185 filed this as LOW
//! and latent for exactly that reason.
//!
//! That makes the fix easy to write and easy to write VACUOUSLY, which is the trap. A
//! test that authenticated as a second operator could not be written at all, and a test
//! that only drove the bootstrap operator against its own tenants would pass whether or
//! not the predicate existed. The scenario is constructible one level down: a second
//! operator ROW owning a tenant needs no credential, because the question is whether the
//! CALLER's operator fences the read, not whether the other operator can log in. That is
//! what these tests build.

mod common;

use axum::http::StatusCode;
use common::{Harness, OPERATOR_TOKEN};
use ironauth_env::Env;
use ironauth_store::{EnvironmentId, OrganizationId, Scope, TenantId};

/// Insert a second operator, a tenant it owns, and a live environment under that tenant,
/// all beneath the API. Returns `(tenant_id, environment_id)`.
///
/// Written with SQL deliberately. Creating these through the API would attribute them to
/// the BOOTSTRAP operator, which is the one thing that would make the whole file
/// vacuous: the rows have to be owned by somebody the caller is not.
async fn foreign_tenant(h: &Harness) -> (String, String) {
    // REAL identifiers, minted the way the product mints them. Hand-rolled strings like
    // "ten_foreign" are refused by `parse_id` before any ownership question is asked, so
    // every assertion below would pass on a malformed id and prove nothing about the
    // operator boundary. The first draft of this file did exactly that.
    let sys = Env::system();
    let tenant_id = TenantId::generate(&sys).to_string();
    let environment_id = EnvironmentId::generate(&sys).to_string();
    let pool = h.db().owner_pool();
    sqlx::query("INSERT INTO operators (id, display_name) VALUES ($1, $2)")
        .bind("opr_foreign")
        .bind("Another operator")
        .execute(pool)
        .await
        .expect("seed the foreign operator");
    sqlx::query("INSERT INTO tenants (id, operator_id, display_name) VALUES ($1, $2, $3)")
        .bind(&tenant_id)
        .bind("opr_foreign")
        .bind("Their tenant")
        .execute(pool)
        .await
        .expect("seed the foreign tenant");
    sqlx::query("INSERT INTO environments (id, tenant_id, display_name) VALUES ($1, $2, $3)")
        .bind(&environment_id)
        .bind(&tenant_id)
        .bind("Their environment")
        .execute(pool)
        .await
        .expect("seed the foreign environment");
    // A ROW inside the foreign environment. Without it the list endpoints answer an
    // empty page and a 200 proves nothing: the question is whether another operator's
    // DATA comes back, not whether the route is reachable.
    let foreign_scope = Scope::new(
        TenantId::parse(&tenant_id).expect("tenant"),
        EnvironmentId::parse(&environment_id).expect("environment"),
    );
    sqlx::query(
        "INSERT INTO organizations (id, tenant_id, environment_id, display_name) \
         VALUES ($1, $2, $3, 'Their private organization')",
    )
    .bind(OrganizationId::generate(&sys, &foreign_scope).to_string())
    .bind(&tenant_id)
    .bind(&environment_id)
    .execute(pool)
    .await
    .expect("seed an organization inside the foreign environment");

    (tenant_id, environment_id)
}

/// The tenant level, which already held. Kept as the CONTROL: if this ever fails, the
/// environment assertions below stop meaning what they claim, because a caller that
/// cannot see the tenant at all would be fenced for the wrong reason.
#[tokio::test]
async fn the_tenant_level_already_fences_another_operators_tenant() {
    let h = Harness::start(50).await;
    let (tenant, _environment) = foreign_tenant(&h).await;

    let (status, _, body) = h
        .get_as(&format!("/v1/tenants/{tenant}"), OPERATOR_TOKEN)
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a tenant owned by another operator must read as absent: {body}"
    );
}

/// THE hole issue #185 names. The environment read hangs off a tenant the caller does
/// not own, and nothing in the query connected that tenant to the caller.
#[tokio::test]
async fn another_operators_environment_is_not_readable() {
    let h = Harness::start(50).await;
    let (tenant, environment) = foreign_tenant(&h).await;

    let (status, _, body) = h
        .get_as(
            &format!("/v1/tenants/{tenant}/environments/{environment}"),
            OPERATOR_TOKEN,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an environment under another operator's tenant must read as absent, or the \
         operator boundary is decoration: {body}"
    );
}

/// And the surface BENEATH the environment, which is the part that actually leaks data.
/// Fencing the environment document while leaving its contents readable would be the
/// worse half of the bug, so it is asserted separately rather than assumed to follow.
#[tokio::test]
async fn nothing_under_another_operators_environment_is_reachable() {
    let h = Harness::start(50).await;
    let (tenant, environment) = foreign_tenant(&h).await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");

    for path in [
        format!("{base}/organizations"),
        format!("{base}/users"),
        format!("{base}/keys"),
    ] {
        let (status, _, body) = h.get_as(&path, OPERATOR_TOKEN).await;
        assert!(
            !body.contains("Their private organization"),
            "{path} returned ANOTHER OPERATOR's data: {body}"
        );
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{path} answered under another operator's environment: {body}"
        );
    }
}

/// A WRITE beneath a foreign environment, because a read fence that a write walks
/// around is not a fence. Minting a management key there would hand the caller a
/// credential INTO another operator's environment, which is the escalation this issue
/// is really about.
#[tokio::test]
async fn no_key_can_be_minted_in_another_operators_environment() {
    let h = Harness::start(50).await;
    let (tenant, environment) = foreign_tenant(&h).await;

    let (status, _, body) = h
        .post_as(
            &format!("/v1/tenants/{tenant}/environments/{environment}/keys"),
            OPERATOR_TOKEN,
            "k-foreign",
            &serde_json::json!({ "display_name": "theirs" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a management key was minted inside another operator's environment: {body}"
    );
}

/// The WRITE that creates an environment under a foreign tenant.
///
/// What this DOES pin: no environment appears under a tenant the caller does not own.
///
/// What it does NOT pin, measured rather than assumed: which layer refuses. The handler
/// resolves the tenant through the operator-filtered `TenantRepo` before the store is
/// reached, so this passes whether or not the repository carries its own ownership
/// check. A mutation folding that check into the parent query's WHERE clause survived
/// here. The repository keeps the stricter form as a backstop for a direct caller, and
/// this test is honest about not being the thing that holds it there.
#[tokio::test]
async fn no_environment_can_be_created_under_another_operators_tenant() {
    let h = Harness::start(50).await;
    let (tenant, _environment) = foreign_tenant(&h).await;

    let (status, _, body) = h
        .post_as(
            &format!("/v1/tenants/{tenant}/environments"),
            OPERATOR_TOKEN,
            "k-foreign-env",
            &serde_json::json!({ "display_name": "Theirs", "kind": "dev" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an environment was created under another operator's tenant: {body}"
    );
}
