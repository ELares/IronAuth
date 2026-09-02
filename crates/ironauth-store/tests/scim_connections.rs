// SPDX-License-Identifier: MIT OR Apache-2.0

//! Inbound SCIM connections and their bearer tokens (issue #135).
//!
//! # What this file is about
//!
//! SCIM endpoints are a proven AUTHORIZATION hot spot, though not in the way a first reading
//! of the issue's citations suggests: Zitadel's CVE-2026-32130 was an authentication BYPASS
//! through URL encoding and Casdoor's CVE-2025-4210 a route carrying no authorization check,
//! so both are failures to authenticate rather than failures to compare, and neither is an
//! IDOR. What the issue asks for on top of authenticating is that a token for organization A
//! be unusable against organization B **by construction**, and this file is where THAT claim
//! is measured rather than asserted.
//!
//! The construction is that the organization is a column on the CREDENTIAL. A caller never
//! supplies one, so there is no request shape in which a token names a second organization --
//! and the tests below are written to fail if that ever stops being true.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewScimConnection, OrganizationId, ScimConnectionId, ScimExternalIdId, Scope,
    UserId,
};

fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// The digest a caller would store for `token`. SHA-256 hex, as migration 0183's CHECK requires.
fn digest(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

async fn seed_org(db: &TestDatabase, env: &Env, scope: Scope, name: &str) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, now_micros(env), name, None)
        .await
        .expect("create organization");
    id
}

async fn connect(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    organization: &OrganizationId,
    token: &str,
) -> ScimConnectionId {
    let id = ScimConnectionId::generate(env, &scope);
    // The CONTROL pool. 0183 grants `ironauth_app` SELECT and nothing else, and
    // `Store::management()` wraps the SAME pool rather than switching to another, so a write
    // through `db.store()` is refused by Postgres with a bare permission error.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .scim_connections()
        .create(
            env,
            NewScimConnection {
                id: &id,
                organization_id: organization,
                display_name: "Okta production",
                provider: "okta",
                token_digest: &digest(token),
                expires_at_unix_micros: None,
            },
        )
        .await
        .expect("create the connection");
    id
}

#[tokio::test]
async fn a_token_authenticates_and_carries_its_own_organization() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let id = connect(&db, &env, scope, &org, "scim_tok_alpha").await;

    let found = db
        .store()
        .scoped(scope)
        .scim_connections()
        .authenticate(&digest("scim_tok_alpha"), now_micros(&env))
        .await
        .expect("authenticate")
        .expect("a live connection");
    assert_eq!(found.id, id);
    // THE POINT. The organization comes off the credential, not off the request, so a handler
    // has nothing to compare and nothing to forget to compare.
    assert_eq!(found.organization_id, org);
    assert_eq!(found.provider, "okta");
    assert!(!found.revoked);

    // A token nobody issued resolves to nothing, which is what makes the positive meaningful.
    assert!(
        db.store()
            .scoped(scope)
            .scim_connections()
            .authenticate(&digest("scim_tok_invented"), now_micros(&env))
            .await
            .expect("authenticate")
            .is_none()
    );
}

#[tokio::test]
async fn a_token_for_one_organization_never_resolves_another() {
    // THE CVE CLASS, as a property of the schema. Two organizations in ONE environment, each
    // with its own connection: neither token can ever name the other's organization, because
    // the organization is not something the presenter says.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org_a = seed_org(&db, &env, scope, "Alpha").await;
    let org_b = seed_org(&db, &env, scope, "Beta").await;
    connect(&db, &env, scope, &org_a, "scim_tok_a").await;
    connect(&db, &env, scope, &org_b, "scim_tok_b").await;

    for (token, expected) in [("scim_tok_a", &org_a), ("scim_tok_b", &org_b)] {
        let found = db
            .store()
            .scoped(scope)
            .scim_connections()
            .authenticate(&digest(token), now_micros(&env))
            .await
            .expect("authenticate")
            .expect("a live connection");
        assert_eq!(
            found.organization_id, *expected,
            "{token} resolves ONLY its own organization"
        );
    }
}

#[tokio::test]
async fn a_token_from_another_scope_does_not_resolve() {
    // The tenant and environment boundary, which is the older half of the same property. The
    // digest is a global handle with no scope embedded in it, so nothing refuses a foreign
    // value before the query runs: the isolation rests entirely on the row filter and forced
    // row-level security, exactly as the agent probes in `idor.rs` do.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let org_b = seed_org(&db, &env, scope_b, "Beta").await;
    connect(&db, &env, scope_b, &org_b, "scim_tok_foreign").await;

    assert!(
        db.store()
            .scoped(scope_a)
            .scim_connections()
            .authenticate(&digest("scim_tok_foreign"), now_micros(&env))
            .await
            .expect("authenticate")
            .is_none(),
        "a token minted in another scope must not resolve here"
    );
    // And it still resolves in its OWN scope, so the refusal above is a boundary rather than a
    // token that never worked.
    assert!(
        db.store()
            .scoped(scope_b)
            .scim_connections()
            .authenticate(&digest("scim_tok_foreign"), now_micros(&env))
            .await
            .expect("authenticate")
            .is_some()
    );
}

#[tokio::test]
async fn revoking_stops_authentication_and_keeps_the_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let id = connect(&db, &env, scope, &org, "scim_tok_doomed").await;

    let revoked = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &id, now_micros(&env))
        .await
        .expect("revoke");
    assert!(revoked, "a live connection was revoked");

    assert!(
        db.store()
            .scoped(scope)
            .scim_connections()
            .authenticate(&digest("scim_tok_doomed"), now_micros(&env))
            .await
            .expect("authenticate")
            .is_none(),
        "a revoked token authenticates nothing"
    );

    // THE ROW SURVIVES, which is what makes the revocation observable. A deleted row would
    // make "this credential was revoked" indistinguishable from "no such credential", and the
    // audit rows naming the handle would stop resolving.
    let listed = db
        .store()
        .scoped(scope)
        .scim_connections()
        .list_for_organization(&org)
        .await
        .expect("list");
    assert_eq!(listed.len(), 1, "the revoked connection is still listed");
    assert!(listed[0].revoked, "and is shown as revoked");

    // Revoking again is a no-op rather than a second revocation.
    let first_revoked_at = listed[0].revoked_at_unix_micros.expect("a revocation time");
    let again = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &id, now_micros(&env) + 5_000_000)
        .await
        .expect("revoke again");
    assert!(!again, "an already-revoked connection reports no change");
    // AND THE TIMESTAMP IS THE FIRST ONE. That is what `revoke`'s doc justifies the
    // `revoked_at IS NULL` clause with, and it was unobservable while the read side exposed
    // only a boolean.
    let relisted = db
        .store()
        .scoped(scope)
        .scim_connections()
        .list_for_organization(&org)
        .await
        .expect("list");
    assert_eq!(
        relisted[0].revoked_at_unix_micros,
        Some(first_revoked_at),
        "a re-revocation keeps the FIRST revocation time"
    );
}

#[tokio::test]
async fn an_expired_token_stops_authenticating_without_being_revoked() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let id = ScimConnectionId::generate(&env, &scope);
    let now = now_micros(&env);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .create(
            &env,
            NewScimConnection {
                id: &id,
                organization_id: &org,
                display_name: "Entra staging",
                provider: "entra",
                token_digest: &digest("scim_tok_stale"),
                // One second in the past.
                expires_at_unix_micros: Some(now - 1_000_000),
            },
        )
        .await
        .expect("create");

    assert!(
        db.store()
            .scoped(scope)
            .scim_connections()
            .authenticate(&digest("scim_tok_stale"), now)
            .await
            .expect("authenticate")
            .is_none(),
        "expiry is enforced in SQL, not left to a caller to remember"
    );
    // Expiry is not revocation: the row is untouched, so an operator can still tell the two
    // apart when asking why provisioning stopped.
    let listed = db
        .store()
        .scoped(scope)
        .scim_connections()
        .list_for_organization(&org)
        .await
        .expect("list");
    assert!(!listed[0].revoked, "expired is not revoked");
}

#[tokio::test]
async fn the_listing_is_per_organization_and_not_per_environment() {
    // An operator asking "what provisions into this organization" must not be shown another
    // organization's credentials, even in the same environment.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org_a = seed_org(&db, &env, scope, "Alpha").await;
    let org_b = seed_org(&db, &env, scope, "Beta").await;
    let a = connect(&db, &env, scope, &org_a, "scim_tok_list_a").await;
    connect(&db, &env, scope, &org_b, "scim_tok_list_b").await;

    let listed = db
        .store()
        .scoped(scope)
        .scim_connections()
        .list_for_organization(&org_a)
        .await
        .expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, a);
}

#[tokio::test]
async fn a_connection_cannot_be_bound_to_another_tenants_organization() {
    // THE SLICE'S WHOLE CLAIM, and the first version did not enforce it.
    //
    // The `organizations` foreign key is id-only, and Postgres referential integrity checks
    // BYPASS row-level security, so an untyped `organization_id` string resolved any globally
    // existing organization -- another tenant's included. `create` then bound a credential to
    // it and `authenticate` handed that foreign organization to the caller as the boundary it
    // should trust. A reviewer proved it by measurement; nothing here had driven it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let org_b = seed_org(&db, &env, scope_b, "Beta").await;

    let id = ScimConnectionId::generate(&env, &scope_a);
    let outcome = db
        .control_store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .create(
            &env,
            NewScimConnection {
                id: &id,
                // Scope A's connection, scope B's organization.
                organization_id: &org_b,
                display_name: "Cross-tenant",
                provider: "generic",
                token_digest: &digest("scim_tok_cross"),
                expires_at_unix_micros: None,
            },
        )
        .await;
    assert!(
        matches!(outcome, Err(ironauth_store::StoreError::NotFound)),
        "an organization from another tenant is refused, not bound: {outcome:?}"
    );

    // And nothing was written, so the refusal is not a half-done create.
    assert!(
        db.store()
            .scoped(scope_a)
            .scim_connections()
            .authenticate(&digest("scim_tok_cross"), now_micros(&env))
            .await
            .expect("authenticate")
            .is_none()
    );
}

#[tokio::test]
async fn every_scope_guard_refuses_a_foreign_id() {
    // The three `NotFound` paths the repo documents. None was driven, which is the blind spot
    // that let the cross-tenant bind above ship: a guard nothing exercises is a guard nobody
    // notices the absence of.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let org_a = seed_org(&db, &env, scope_a, "Alpha").await;
    let org_b = seed_org(&db, &env, scope_b, "Beta").await;
    let foreign_id = ScimConnectionId::generate(&env, &scope_b);

    // `create` with a foreign CONNECTION id.
    let outcome = db
        .control_store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .create(
            &env,
            NewScimConnection {
                id: &foreign_id,
                organization_id: &org_a,
                display_name: "Foreign handle",
                provider: "generic",
                token_digest: &digest("scim_tok_foreign_id"),
                expires_at_unix_micros: None,
            },
        )
        .await;
    assert!(matches!(outcome, Err(ironauth_store::StoreError::NotFound)));

    // `revoke` with a foreign connection id.
    let outcome = db
        .control_store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &foreign_id, now_micros(&env))
        .await;
    assert!(matches!(outcome, Err(ironauth_store::StoreError::NotFound)));

    // `list_for_organization` with a foreign organization.
    let outcome = db
        .store()
        .scoped(scope_a)
        .scim_connections()
        .list_for_organization(&org_b)
        .await;
    assert!(matches!(outcome, Err(ironauth_store::StoreError::NotFound)));
}

#[tokio::test]
async fn revoking_a_handle_that_names_nothing_is_not_found() {
    // And it writes no audit row, which the shape of `revoke` now guarantees: an absent handle
    // returns before the audit write. The first version wrapped the UPDATE unconditionally, so
    // revoking a handle that was never created still recorded `scim_connection.revoked`
    // naming a connection that did not exist -- the opposite of "revocation is observable".
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let never = ScimConnectionId::generate(&env, &scope);
    let outcome = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &never, now_micros(&env))
        .await;
    assert!(
        matches!(outcome, Err(ironauth_store::StoreError::NotFound)),
        "a handle naming no connection is NotFound rather than a silent no-op: {outcome:?}"
    );
}

/// Run one statement as `ironauth_control` with this scope's RLS settings bound.
///
/// The suite otherwise goes through the repository, which is the right level for behaviour --
/// but the grant and the policy are enforced by POSTGRES, and a repository that never attempts
/// a forbidden write cannot tell whether they are there. A reviewer proved that: reverting the
/// column-scoped grant to a whole-table one, and deleting the one-way revocation policy
/// outright, both left the whole suite green.
async fn as_control(db: &TestDatabase, scope: Scope, sql: &str) -> Result<u64, sqlx::Error> {
    let mut tx = db.control_pool().begin().await?;
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(scope.tenant().to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(scope.environment().to_string())
        .execute(&mut *tx)
        .await?;
    let affected = sqlx::query(sql).execute(&mut *tx).await?.rows_affected();
    tx.commit().await?;
    Ok(affected)
}

/// Run one statement as `ironauth_app` -- the DATA plane role -- with this scope's RLS
/// settings bound. The mirror of [`as_control`], and it exists for the mirror reason: the
/// read grant and the absent write grants are enforced by Postgres, and a suite that only ever
/// reads through the repository cannot tell a table the data plane may not write from one it
/// may.
async fn as_app(db: &TestDatabase, scope: Scope, sql: &str) -> Result<u64, sqlx::Error> {
    let mut tx = db.app_pool().begin().await?;
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(scope.tenant().to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(scope.environment().to_string())
        .execute(&mut *tx)
        .await?;
    let affected = sqlx::query(sql).execute(&mut *tx).await?.rows_affected();
    tx.commit().await?;
    Ok(affected)
}

#[tokio::test]
async fn the_control_role_may_revoke_and_may_change_nothing_else() {
    // THE GRANT AND THE POLICY, driven rather than read. Without both, the role that creates
    // connections can re-point the boundary at another organization, swap the verifier for one
    // it chose, or restore a credential an operator has just killed.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let other = seed_org(&db, &env, scope, "Initech").await;
    let id = connect(&db, &env, scope, &org, "scim_tok_grant").await;

    // Each forbidden column, one statement each. `42501` is "permission denied for table",
    // which is the column-scoped GRANT refusing before any policy runs.
    for (column, value) in [
        ("organization_id", format!("'{other}'")),
        ("token_digest", format!("'{}'", digest("attacker-chosen"))),
        ("display_name", "'renamed'".to_owned()),
        ("expires_at", "now()".to_owned()),
    ] {
        let outcome = as_control(
            &db,
            scope,
            &format!("UPDATE scim_connections SET {column} = {value} WHERE id = '{id}'"),
        )
        .await;
        let error = outcome.expect_err(&format!("{column} must not be updatable"));
        assert!(
            error.to_string().contains("permission denied"),
            "{column} is refused by the column grant, not by something else: {error}"
        );
    }

    // Revocation IS permitted, so the refusals above are the narrowing rather than a role that
    // can do nothing.
    let affected = as_control(
        &db,
        scope,
        &format!("UPDATE scim_connections SET revoked_at = now() WHERE id = '{id}'"),
    )
    .await
    .expect("revocation is the one permitted update");
    assert_eq!(affected, 1);

    // The AFTER half of the policy, which the revoke above cannot exercise. `USING
    // (revoked_at IS NULL)` admits a live row and `WITH CHECK (revoked_at IS NOT NULL)`
    // requires the result to be revoked, so an update that TOUCHES a live row without
    // revoking it is refused by the WITH CHECK half alone. A reviewer weakened that half to
    // `true` and the whole suite stayed green; this is the statement that notices.
    let live = connect(&db, &env, scope, &org, "scim_tok_touch").await;
    let outcome = as_control(
        &db,
        scope,
        &format!("UPDATE scim_connections SET updated_at = now() WHERE id = '{live}'"),
    )
    .await;
    let error = outcome.expect_err("a live row may not be touched without being revoked");
    assert!(
        error.to_string().contains("row-level security"),
        "refused by the policy's WITH CHECK half, not by something else: {error}"
    );

    // And it is ONE WAY. The grant cannot express this, because `revoked_at` is exactly the
    // column a revoke must write; the RESTRICTIVE policy is what does.
    let affected = as_control(
        &db,
        scope,
        &format!("UPDATE scim_connections SET revoked_at = NULL WHERE id = '{id}'"),
    )
    .await
    .expect("an un-revocation is filtered, not errored");
    assert_eq!(
        affected, 0,
        "the one-way policy leaves an un-revocation matching no row"
    );

    // The connection is still revoked, so nothing above quietly restored it.
    assert!(
        db.store()
            .scoped(scope)
            .scim_connections()
            .authenticate(&digest("scim_tok_grant"), now_micros(&env))
            .await
            .expect("authenticate")
            .is_none()
    );
}

#[tokio::test]
async fn only_a_real_revocation_writes_an_audit_row() {
    // The three outcomes, COUNTED. `revoke`'s doc says an already-revoked connection "commits
    // and audits nothing", and a reviewer showed that sentence was unmeasured: adding an audit
    // write to that branch left the suite green.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let id = connect(&db, &env, scope, &org, "scim_tok_audit").await;

    let count = |action: &'static str| {
        let db = &db;
        async move {
            let (count,): (i64,) = sqlx::query_as(
                "SELECT count(*) FROM audit_log /* query-audit-allow: owner test read */ \
                 WHERE action = $1",
            )
            .bind(action)
            .fetch_one(db.owner_pool())
            .await
            .expect("count audit rows");
            count
        }
    };

    // The CREATE row carries the organization in its detail, which is the only thing about a
    // connection that decides what it may provision.
    assert_eq!(count("scim_connection.created").await, 1);
    let (detail,): (Option<String>,) = sqlx::query_as(
        "SELECT detail FROM audit_log /* query-audit-allow: owner test read */ \
         WHERE action = 'scim_connection.created'",
    )
    .fetch_one(db.owner_pool())
    .await
    .expect("read the create row");
    assert_eq!(
        detail.as_deref(),
        Some(org.to_string().as_str()),
        "the created row names the organization"
    );

    assert_eq!(
        count("scim_connection.revoked").await,
        0,
        "nothing revoked yet"
    );

    let acting = || {
        db.control_store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .scim_connections()
    };

    acting()
        .revoke(&env, &id, now_micros(&env))
        .await
        .expect("the real revocation");
    assert_eq!(count("scim_connection.revoked").await, 1);

    // Twice more, both no-ops. The count must not move.
    for _ in 0..2 {
        assert!(
            !acting()
                .revoke(&env, &id, now_micros(&env))
                .await
                .expect("a re-revocation is not an error")
        );
    }
    assert_eq!(
        count("scim_connection.revoked").await,
        1,
        "an already-revoked connection commits and audits NOTHING"
    );

    // And a handle naming no connection writes none either.
    let never = ScimConnectionId::generate(&env, &scope);
    let outcome = acting().revoke(&env, &never, now_micros(&env)).await;
    assert!(matches!(outcome, Err(ironauth_store::StoreError::NotFound)));
    assert_eq!(count("scim_connection.revoked").await, 1);
}

#[tokio::test]
async fn a_credential_does_not_outlive_the_organization_it_provisions_into() {
    // A reviewer found this: the token could not reach ANOTHER organization, but deleting its
    // own did not stop it provisioning, and the listing went on reporting it healthy. So an
    // operator who deleted an organization was not told that provisioning into it continued.
    // `ApiKeyRepo::verify`, the credential this table copies in three other respects, has
    // carried the liveness join all along.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Doomed").await;
    connect(&db, &env, scope, &org, "scim_tok_orphan").await;

    assert!(
        db.store()
            .scoped(scope)
            .scim_connections()
            .authenticate(&digest("scim_tok_orphan"), now_micros(&env))
            .await
            .expect("authenticate")
            .is_some(),
        "live while the organization is"
    );

    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .delete(&env, &org)
        .await
        .expect("soft delete the organization");

    assert!(
        db.store()
            .scoped(scope)
            .scim_connections()
            .authenticate(&digest("scim_tok_orphan"), now_micros(&env))
            .await
            .expect("authenticate")
            .is_none(),
        "a deleted organization takes its provisioning credentials with it"
    );
}

#[tokio::test]
async fn a_credential_stops_working_when_its_organization_is_merely_disabled() {
    // THE OTHER HALF of the liveness join, and it needs its own test because the two halves
    // are not reachable through one action: `OrganizationRepo::delete` sets `deleted_at` and
    // never touches `state`, so the soft-delete test above exercises `deleted_at IS NULL`
    // alone. A reviewer deleted `AND o.state = 'active'` from `authenticate` and the entire
    // suite stayed green -- an operator could disable an organization and its provisioning
    // would carry on, which is exactly what the doc on `authenticate` promises it does not.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Suspended").await;
    connect(&db, &env, scope, &org, "scim_tok_disabled").await;

    assert!(
        db.store()
            .scoped(scope)
            .scim_connections()
            .authenticate(&digest("scim_tok_disabled"), now_micros(&env))
            .await
            .expect("authenticate")
            .is_some(),
        "live while the organization is active"
    );

    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .set_state(
            &env,
            &org,
            ironauth_store::OrganizationState::Disabled,
            None,
        )
        .await
        .expect("disable the organization");

    assert!(
        db.store()
            .scoped(scope)
            .scim_connections()
            .authenticate(&digest("scim_tok_disabled"), now_micros(&env))
            .await
            .expect("authenticate")
            .is_none(),
        "a disabled organization provisions nothing, exactly as a deleted one does not"
    );
}

#[tokio::test]
async fn the_data_plane_role_may_read_a_connection_and_may_not_write_one() {
    // The migration calls this a privilege boundary: a provisioning credential that could
    // mint another provisioning credential would be an escalation with no operator in the
    // loop. A reviewer granted `ironauth_app` full INSERT, UPDATE and DELETE on the table and
    // the suite stayed green, so the boundary was asserted in a comment and measured nowhere.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let id = connect(&db, &env, scope, &org, "scim_tok_dataplane").await;

    // Reading is granted, so the refusals below are the narrowing and not a role locked out
    // of the table altogether.
    assert!(
        db.store()
            .scoped(scope)
            .scim_connections()
            .authenticate(&digest("scim_tok_dataplane"), now_micros(&env))
            .await
            .expect("authenticate")
            .is_some(),
        "the data plane reads connections; that is how a SCIM request authenticates"
    );

    for (what, sql) in [
        (
            "mint a second credential",
            format!(
                "INSERT INTO scim_connections                  (id, tenant_id, environment_id, organization_id, display_name, provider,                   token_digest)                  VALUES ('{id}x', '{}', '{}', '{org}', 'minted', 'okta', '{}')",
                scope.tenant(),
                scope.environment(),
                digest("attacker-minted"),
            ),
        ),
        (
            "swap the verifier",
            format!(
                "UPDATE scim_connections SET token_digest = '{}' WHERE id = '{id}'",
                digest("attacker-chosen"),
            ),
        ),
        (
            "destroy the audit trail",
            format!("DELETE FROM scim_connections WHERE id = '{id}'"),
        ),
    ] {
        let outcome = as_app(&db, scope, &sql).await;
        let error = outcome.expect_err(&format!("the data plane must not {what}"));
        assert!(
            error.to_string().contains("permission denied"),
            "{what} is refused by the grant, not by something else: {error}"
        );
    }
}

#[tokio::test]
async fn the_column_checks_refuse_a_malformed_digest_and_an_unknown_provider() {
    // Both CHECK constraints were droppable with the suite still green. The digest one carries
    // a security rationale (a truncated digest compares equal more often than a full one) and
    // the provider one is promised by `create`'s own `# Errors` doc, so each was a sentence
    // nothing measured.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;

    for (what, provider, token_digest) in [
        ("a digest that is not 64 hex characters", "okta", "abc123"),
        (
            "a digest with a non-hex character in it",
            "okta",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ),
        (
            "a provider outside the closed vocabulary",
            "google",
            "1111111111111111111111111111111111111111111111111111111111111111",
        ),
    ] {
        let outcome = db
            .control_store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .scim_connections()
            .create(
                &env,
                NewScimConnection {
                    id: &ScimConnectionId::generate(&env, &scope),
                    organization_id: &org,
                    display_name: "Rejected",
                    provider,
                    token_digest,
                    expires_at_unix_micros: None,
                },
            )
            .await;
        assert!(
            matches!(outcome, Err(ironauth_store::StoreError::Database(_))),
            "{what} must be refused by the column CHECK, got {outcome:?}"
        );
    }
}

/// Seed a user through the ordinary registration path.
async fn seed_user(db: &TestDatabase, env: &Env, scope: Scope, handle: &str) -> UserId {
    let id = UserId::generate(env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register_passwordless(env, &id, handle, None)
        .await
        .expect("register user");
    id
}

#[tokio::test]
async fn two_connections_may_use_the_same_external_id_for_different_people() {
    // THE REASON THIS TABLE IS KEYED ON THE CONNECTION.
    //
    // Okta's `externalId` is a directory id and Entra's is an object id; neither knows about
    // the other, and nothing stops them colliding. Keyed per ENVIRONMENT, the second IdP's
    // first create would either collide or silently update the first IdP's person -- and
    // silently updating is the worse of the two, because provisioning would report success.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let okta = connect(&db, &env, scope, &org, "scim_tok_okta").await;
    let entra = connect(&db, &env, scope, &org, "scim_tok_entra").await;

    let alice = seed_user(&db, &env, scope, "alice@example.test").await;
    let bob = seed_user(&db, &env, scope, "bob@example.test").await;

    // THE SAME external id, two connections, two different people.
    let collide = "00u1abcdef";
    for (connection, user) in [(&okta, &alice), (&entra, &bob)] {
        db.store()
            .scoped(scope)
            .scim_external_ids()
            .bind(
                &ScimExternalIdId::generate(&env, &scope),
                connection,
                collide,
                user,
            )
            .await
            .expect("bind the external id");
    }

    // Each connection resolves ITS OWN person.
    for (connection, expected) in [(&okta, &alice), (&entra, &bob)] {
        let found = db
            .store()
            .scoped(scope)
            .scim_external_ids()
            .resolve(connection, collide)
            .await
            .expect("resolve")
            .expect("a mapping");
        assert_eq!(found, *expected, "each connection resolves its own person");
    }

    // And the round trip: what each connection calls the person it knows.
    assert_eq!(
        db.store()
            .scoped(scope)
            .scim_external_ids()
            .external_id_for(&okta, &alice)
            .await
            .expect("round trip"),
        Some(collide.to_owned())
    );
    // Okta has no mapping for Bob, who is Entra's person.
    assert_eq!(
        db.store()
            .scoped(scope)
            .scim_external_ids()
            .external_id_for(&okta, &bob)
            .await
            .expect("round trip"),
        None
    );
}

#[tokio::test]
async fn one_connection_cannot_bind_an_external_id_twice() {
    // The unique index, which is what makes a retried provisioning run a 409 rather than a
    // second person. RFC 7644 section 3.3 asks for exactly that.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let okta = connect(&db, &env, scope, &org, "scim_tok_dup").await;
    let alice = seed_user(&db, &env, scope, "alice@example.test").await;
    let bob = seed_user(&db, &env, scope, "bob@example.test").await;

    db.store()
        .scoped(scope)
        .scim_external_ids()
        .bind(
            &ScimExternalIdId::generate(&env, &scope),
            &okta,
            "00u1dup",
            &alice,
        )
        .await
        .expect("the first bind");

    // The same external id, a DIFFERENT person: a conflict, not a silent re-point.
    let outcome = db
        .store()
        .scoped(scope)
        .scim_external_ids()
        .bind(
            &ScimExternalIdId::generate(&env, &scope),
            &okta,
            "00u1dup",
            &bob,
        )
        .await;
    assert!(
        matches!(outcome, Err(ironauth_store::StoreError::Conflict)),
        "a second bind of one external id is a conflict: {outcome:?}"
    );

    // And the SAME person under a second external id is a conflict too, by the by-user index:
    // a connection that could call one person two things would break the round trip, which
    // has to answer with exactly one value.
    let outcome = db
        .store()
        .scoped(scope)
        .scim_external_ids()
        .bind(
            &ScimExternalIdId::generate(&env, &scope),
            &okta,
            "00u1second",
            &alice,
        )
        .await;
    assert!(matches!(outcome, Err(ironauth_store::StoreError::Conflict)));

    // The first mapping is untouched by either refusal.
    assert_eq!(
        db.store()
            .scoped(scope)
            .scim_external_ids()
            .resolve(&okta, "00u1dup")
            .await
            .expect("resolve"),
        Some(alice)
    );
}

#[tokio::test]
async fn an_external_id_mapping_refuses_a_foreign_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let org_b = seed_org(&db, &env, scope_b, "Beta").await;
    let connection_b = connect(&db, &env, scope_b, &org_b, "scim_tok_scoped").await;
    let user_a = seed_user(&db, &env, scope_a, "alice@example.test").await;

    // A connection from another scope.
    let outcome = db
        .store()
        .scoped(scope_a)
        .scim_external_ids()
        .bind(
            &ScimExternalIdId::generate(&env, &scope_a),
            &connection_b,
            "00u1foreign",
            &user_a,
        )
        .await;
    assert!(matches!(outcome, Err(ironauth_store::StoreError::NotFound)));

    // And resolving through one.
    let outcome = db
        .store()
        .scoped(scope_a)
        .scim_external_ids()
        .resolve(&connection_b, "00u1foreign")
        .await;
    assert!(matches!(outcome, Err(ironauth_store::StoreError::NotFound)));
}

#[tokio::test]
async fn a_second_external_id_for_the_same_person_is_refused() {
    // The `scim_external_ids_by_user` unique index, which a reviewer replaced with a plain
    // index leaving every suite green. It is what makes `external_id_for` a single answer: two
    // rows for one (connection, user) would make "what does this connection call this person"
    // ambiguous, and the read would return whichever the planner picked.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let okta = connect(&db, &env, scope, &org, "scim_tok_two_keys").await;
    let alice = seed_user(&db, &env, scope, "alice@example.test").await;

    db.store()
        .scoped(scope)
        .scim_external_ids()
        .bind(
            &ScimExternalIdId::generate(&env, &scope),
            &okta,
            "00u1first",
            &alice,
        )
        .await
        .expect("the first key");

    let outcome = db
        .store()
        .scoped(scope)
        .scim_external_ids()
        .bind(
            &ScimExternalIdId::generate(&env, &scope),
            &okta,
            "00u1second",
            &alice,
        )
        .await;
    assert!(
        matches!(outcome, Err(ironauth_store::StoreError::Conflict)),
        "one connection calls one person by ONE name, got {outcome:?}"
    );

    // The control: the first mapping is intact and readable, so the refusal above is the
    // index rather than a bind that never works twice.
    assert_eq!(
        db.store()
            .scoped(scope)
            .scim_external_ids()
            .external_id_for(&okta, &alice)
            .await
            .expect("read back"),
        Some("00u1first".to_owned())
    );
}

#[tokio::test]
async fn a_cross_scope_bind_is_refused_by_the_guard_before_any_write() {
    // `bind`'s three-way scope guard, which a reviewer replaced with `if false` leaving every
    // suite green. Each id is varied ALONE, so a guard that checked only one of the three is
    // caught by the other two rather than hidden by them.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let here = db.seed_scope(&env).await;
    let there = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, here, "Globex").await;
    let okta = connect(&db, &env, here, &org, "scim_tok_scoped").await;
    let alice = seed_user(&db, &env, here, "alice@example.test").await;

    let foreign_org = seed_org(&db, &env, there, "Elsewhere").await;
    let foreign_connection = connect(&db, &env, there, &foreign_org, "scim_tok_elsewhere").await;
    let foreign_user = seed_user(&db, &env, there, "bob@example.test").await;

    for (what, id, connection, user) in [
        (
            "a mapping id from another scope",
            ScimExternalIdId::generate(&env, &there),
            okta,
            alice,
        ),
        (
            "a connection from another scope",
            ScimExternalIdId::generate(&env, &here),
            foreign_connection,
            alice,
        ),
        (
            "a user from another scope",
            ScimExternalIdId::generate(&env, &here),
            okta,
            foreign_user,
        ),
    ] {
        let outcome = db
            .store()
            .scoped(here)
            .scim_external_ids()
            .bind(&id, &connection, "00u1cross", &user)
            .await;
        assert!(
            matches!(outcome, Err(ironauth_store::StoreError::NotFound)),
            "{what} must be refused, got {outcome:?}"
        );
    }

    // The control: all three in scope binds, so the refusals above are the guard rather than a
    // bind that never succeeds.
    db.store()
        .scoped(here)
        .scim_external_ids()
        .bind(
            &ScimExternalIdId::generate(&env, &here),
            &okta,
            "00u1cross",
            &alice,
        )
        .await
        .expect("all three in scope");
}
