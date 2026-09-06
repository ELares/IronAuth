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
            None,
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
        .list_for_organization(&org, 100, None, now_micros(&env))
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
        .list_for_organization(&org, 100, None, now_micros(&env))
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
            None,
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
        .list_for_organization(&org, 100, None, now_micros(&env))
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
        .list_for_organization(&org_a, 100, None, now_micros(&env))
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
            None,
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
    // EVERY `NotFound` path the repo documents. None was driven at first, which is the blind
    // spot that let the cross-tenant bind above ship: a guard nothing exercises is a guard
    // nobody notices the absence of. It happened AGAIN with `exists_in_organization`: that
    // function landed with a scope guard, this test's own doc still said "the three paths",
    // and a reviewer measured that deleting both of its checks broke nothing across 30 tests.
    // So the count is gone from this comment and the loop below drives whatever the repo
    // documents.
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
            None,
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
        .list_for_organization(&org_b, 100, None, now_micros(&env))
        .await;
    assert!(matches!(outcome, Err(ironauth_store::StoreError::NotFound)));

    // `exists_in_organization`, which fences on BOTH arguments, so both are driven. It is the
    // revoke handler's ownership check: without the connection-id guard a handle minted in
    // another tenant would answer the same as one of ours, and the handler would go on to
    // revoke it.
    let local_org = seed_org(&db, &env, scope_a, "Alpha two").await;
    let local_id = ScimConnectionId::generate(&env, &scope_a);
    for (label, org, id) in [
        ("a foreign ORGANIZATION", &org_b, &local_id),
        ("a foreign CONNECTION id", &local_org, &foreign_id),
        ("both foreign", &org_b, &foreign_id),
    ] {
        let outcome = db
            .store()
            .scoped(scope_a)
            .scim_connections()
            .exists_in_organization(org, id)
            .await;
        assert!(
            matches!(outcome, Err(ironauth_store::StoreError::NotFound)),
            "exists_in_organization accepted {label}: {outcome:?}"
        );
    }

    // The CONTROL. Both arguments in scope answers `Ok(false)` for a handle nothing created,
    // so the refusals above are the scope guard and not this function refusing everything.
    let outcome = db
        .store()
        .scoped(scope_a)
        .scim_connections()
        .exists_in_organization(&local_org, &local_id)
        .await;
    assert!(
        matches!(outcome, Ok(false)),
        "an in-scope pair naming no row must answer Ok(false), not a refusal: {outcome:?}"
    );
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
                None,
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

/// Rotate a connection's token, superseding the live ones after `overlap_secs`.
async fn rotate(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    id: &ScimConnectionId,
    new_token: &str,
    overlap_secs: i64,
    at_micros: i64,
) -> Result<Option<i64>, ironauth_store::StoreError> {
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .scim_connections()
        .rotate_token(env, id, &digest(new_token), overlap_secs, at_micros)
        .await
}

#[tokio::test]
async fn both_tokens_authenticate_during_the_overlap_and_the_old_one_then_fails_closed() {
    // ISSUE #140, ACCEPTANCE CRITERION 5, VERBATIM: "SCIM token rotation provides an overlap
    // window during which both tokens authenticate, then the old token fails closed".
    //
    // The window exists because the token lives in an identity provider's configuration that a
    // human edits by hand. Killing the old one at the moment the new one is minted takes
    // provisioning down from the mint until the paste, on a schedule nobody controls.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &organization, "old-token").await;

    let at = now_micros(&env);
    let overlap = 3600_i64;
    rotate(&db, &env, scope, &connection, "new-token", overlap, at)
        .await
        .expect("rotate");

    // DURING THE WINDOW, BOTH WORK, and both resolve to the SAME connection: a rotation that
    // produced a second connection would satisfy "both authenticate" and strand everything keyed
    // on the first one, which is the shape this table exists to replace.
    let read = db.store().scoped(scope);
    let old = read
        .scim_connections()
        .authenticate(&digest("old-token"), at + 1_000_000)
        .await
        .expect("read")
        .expect("the superseded token still authenticates inside the window");
    let new = read
        .scim_connections()
        .authenticate(&digest("new-token"), at + 1_000_000)
        .await
        .expect("read")
        .expect("the new token authenticates");
    assert_eq!(old.id, connection);
    assert_eq!(new.id, connection);
    assert_eq!(old.organization_id, new.organization_id);

    // AND AFTER IT, THE OLD ONE FAILS CLOSED while the new one keeps working. Asserting only the
    // first half would pass against a rotation that killed both.
    let after = at + overlap * 1_000_000 + 1_000_000;
    assert!(
        read.scim_connections()
            .authenticate(&digest("old-token"), after)
            .await
            .expect("read")
            .is_none(),
        "the superseded token still authenticates after the overlap window"
    );
    assert!(
        read.scim_connections()
            .authenticate(&digest("new-token"), after)
            .await
            .expect("read")
            .is_some(),
        "the rotation expired the token it had just minted, so provisioning stops entirely"
    );
}

#[tokio::test]
async fn a_second_rotation_inside_the_window_supersedes_every_live_token() {
    // THE PLURAL IN "every other live token". An admin who rotates twice in an afternoon would
    // otherwise leave the FIRST token live with nothing to supersede it, because the second
    // rotation would only look at the token it replaced. The statement supersedes by
    // CONNECTION, which is also why a caller is never asked to name a digest it has no reason
    // to know.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &organization, "token-1").await;

    // A LONG FIRST WINDOW AND A SHORT SECOND ONE, and the ORDER is the whole test.
    //
    // `LEAST` means superseding a token that ALREADY has a horizon can only move it EARLIER. So
    // a fixture whose SECOND window is the longer one cannot distinguish the real statement from
    // one narrowed to "tokens with no horizon yet": `LEAST` keeps the first rotation's horizon
    // either way. A previous version of this test had exactly that shape, and a mutation run
    // confirmed it passed against the implementation it is named to refuse.
    //
    // Long then short separates them. The real statement pulls token-1 in from `at+7200s` to
    // `at+1s+600s`; the narrowed one leaves it out at `at+7200s`.
    let at = now_micros(&env);
    rotate(&db, &env, scope, &connection, "token-2", 7200, at)
        .await
        .expect("first rotation");
    rotate(
        &db,
        &env,
        scope,
        &connection,
        "token-3",
        600,
        at + 1_000_000,
    )
    .await
    .expect("second rotation");

    let read = db.store().scoped(scope);
    // PAST THE SECOND ROTATION'S SHORT WINDOW, and far inside the first's long one.
    let after = at + 602 * 1_000_000;
    // TOKEN-1 IS DEAD, and this is the assertion the narrowed implementation fails. It carried
    // the FIRST rotation's `at+7200s`; only a supersede that reached a token which ALREADY had a
    // horizon can have pulled it in to the second rotation's `at+1s+600s`.
    assert!(
        read.scim_connections()
            .authenticate(&digest("token-1"), after)
            .await
            .expect("read")
            .is_none(),
        "token-1 still authenticates past the SECOND rotation's window, so that rotation \
         superseded only tokens with no horizon yet and left an older credential alive for the \
         first rotation's much longer window"
    );
    // TOKEN-2 IS DEAD TOO: it had no horizon when the second rotation ran, so both the real and
    // the narrowed statement reach it. It keeps the pair honest rather than discriminating.
    assert!(
        read.scim_connections()
            .authenticate(&digest("token-2"), after)
            .await
            .expect("read")
            .is_none(),
        "token-2 still authenticates past the window the second rotation gave it"
    );
    // AND THE NEWEST IS ALIVE, so the two assertions above are not satisfied by everything dying
    // at once.
    assert!(
        read.scim_connections()
            .authenticate(&digest("token-3"), after)
            .await
            .expect("read")
            .is_some(),
        "the newest token does not authenticate"
    );
}

#[tokio::test]
async fn a_revoked_token_stops_authenticating_while_its_siblings_keep_working() {
    // `scim_connection_tokens.revoked_at` HAS A WRITER NOW, and this is what it is for: a LEAK,
    // where the overlap is the problem rather than the point. Without a writer the column, its
    // one-way policy, its grant and `authenticate`'s `t.revoked_at IS NULL` conjunct were all
    // unreachable -- four pieces of machinery nothing could exercise, and deleting any of them
    // left the suite green.
    //
    // PER TOKEN, not per connection: revoking the connection kills everything, which is the
    // blunt instrument. This kills one leaked credential and leaves provisioning up on the
    // others, which is the whole reason tokens are rows.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &organization, "leaked-token").await;

    let at = now_micros(&env);
    rotate(&db, &env, scope, &connection, "good-token", 3600, at)
        .await
        .expect("rotate");

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke_token(&env, &connection, &digest("leaked-token"), at + 1_000_000)
        .await
        .expect("revoke the leaked token");

    let read = db.store().scoped(scope);
    assert!(
        read.scim_connections()
            .authenticate(&digest("leaked-token"), at + 2_000_000)
            .await
            .expect("read")
            .is_none(),
        "a revoked token still authenticates inside its overlap window"
    );
    // AND THE SIBLING IS UNTOUCHED, so revoking one token is not a way to take provisioning
    // down: that is what revoking the CONNECTION is for, and the two must stay distinguishable.
    assert!(
        read.scim_connections()
            .authenticate(&digest("good-token"), at + 2_000_000)
            .await
            .expect("read")
            .is_some(),
        "revoking one token killed its sibling"
    );
}

#[tokio::test]
async fn a_rotation_never_extends_a_token_that_was_already_expiring() {
    // THIS TEST DOES NOT MEASURE `LEAST`, and its name overpromises. It gives the CONNECTION an
    // expiry, which `authenticate` checks independently of the token's, so the connection's
    // horizon kills the token first and every assertion here passes with `LEAST` deleted
    // entirely. What it DOES pin is that a connection-level expiry is honoured through a
    // rotation, which is worth having and is all it can claim.
    //
    // `LEAST` ITSELF IS MEASURED BY `a_second_rotation_does_not_push_out_the_first_rotations_horizon`,
    // which builds the only state that distinguishes it: a TOKEN lapsing sooner than the
    // requested window while its CONNECTION does not. That needs two rotations, and this fixture
    // cannot produce it.
    // `LEAST`, AND WHY. A bare assignment would push a token that was already lapsing OUT to the
    // end of the new window, so rotating would be a way to KEEP an old credential alive -- the
    // opposite of what a rotation is for, and reachable by anybody who can rotate.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;

    let at = now_micros(&env);
    // A connection whose token expires in sixty seconds.
    let id = ScimConnectionId::generate(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .create(
            &env,
            NewScimConnection {
                id: &id,
                organization_id: &organization,
                display_name: "Okta production",
                provider: "okta",
                token_digest: &digest("expiring-token"),
                expires_at_unix_micros: Some(at + 60_000_000),
            },
            None,
        )
        .await
        .expect("create the connection");

    // Rotate with a window an hour long, far beyond the token's own sixty seconds.
    rotate(&db, &env, scope, &id, "fresh-token", 3600, at)
        .await
        .expect("rotate");

    let read = db.store().scoped(scope);
    assert!(
        read.scim_connections()
            .authenticate(&digest("expiring-token"), at + 61_000_000)
            .await
            .expect("read")
            .is_none(),
        "the rotation EXTENDED a token that was already expiring, so rotating is a way to keep \
         an old credential alive"
    );
}

#[tokio::test]
async fn a_revoked_connection_cannot_be_revived_by_rotating_it() {
    // AN UN-REVOCATION THROUGH A DIFFERENT DOOR. `scim_connections` carries a RESTRICTIVE policy
    // making revocation one way, and it guards that table's `revoked_at` column. Minting a fresh
    // token row for a revoked connection would walk around it entirely -- the connection stays
    // revoked and a working credential exists for it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &organization, "doomed-token").await;

    let at = now_micros(&env);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &connection, at)
        .await
        .expect("revoke the connection");

    let refused = rotate(
        &db,
        &env,
        scope,
        &connection,
        "revival-token",
        600,
        at + 1_000_000,
    )
    .await;
    assert!(
        matches!(refused, Err(ironauth_store::StoreError::NotFound)),
        "a revoked connection was rotated back into service: {refused:?}"
    );
    // THE ROW ITSELF, counted directly, and the first version of this test could not do it. It
    // asserted that the revival token does not AUTHENTICATE -- which is true whether or not the
    // rotation inserted it, because `authenticate` independently refuses a revoked connection.
    // Deleting the pre-check from `rotate_token_with_event` therefore left the assertion green
    // while the un-revocation-through-another-door it names actually happened.
    //
    // What distinguishes them is whether the ROW exists, so that is what this reads.
    let rows: (i64,) =
        sqlx::query_as("SELECT count(*) FROM scim_connection_tokens WHERE token_digest = $1")
            .bind(digest("revival-token"))
            .fetch_one(db.owner_pool())
            .await
            .expect("count the revival token");
    assert_eq!(
        rows.0, 0,
        "the refused rotation inserted a token row for a REVOKED connection, which is the \
         un-revocation the one-way policy on `scim_connections` exists to prevent, reached by \
         writing a different table"
    );
}

#[tokio::test]
async fn revoking_a_connection_kills_every_token_it_has() {
    // THE CONNECTION-LEVEL CHECK IN `authenticate`, which the token-level one cannot replace. A
    // token minted by a rotation has no horizon of its own, so if only the token's own liveness
    // were consulted, revoking the connection would leave the newest token working.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &organization, "first-token").await;

    let at = now_micros(&env);
    rotate(&db, &env, scope, &connection, "second-token", 3600, at)
        .await
        .expect("rotate");
    // BOTH WORK FIRST, so the refusals below are the revocation rather than the rotation having
    // gone wrong.
    let read = db.store().scoped(scope);
    for token in ["first-token", "second-token"] {
        assert!(
            read.scim_connections()
                .authenticate(&digest(token), at + 1_000_000)
                .await
                .expect("read")
                .is_some()
        );
    }

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &connection, at + 2_000_000)
        .await
        .expect("revoke");

    for token in ["first-token", "second-token"] {
        assert!(
            read.scim_connections()
                .authenticate(&digest(token), at + 3_000_000)
                .await
                .expect("read")
                .is_none(),
            "{token} still authenticates after its connection was revoked"
        );
    }
}

#[tokio::test]
async fn a_second_rotation_does_not_push_out_the_first_rotations_horizon() {
    // `LEAST`, MEASURED ON THE TOKEN'S OWN HORIZON. The connection here never expires, so
    // nothing but the supersede statement can kill a token, and the first rotation's short
    // window is the value a bare assignment would overwrite.
    //
    // Deleting `LEAST(COALESCE(expires_at,'infinity'), ...)` from the supersede makes this fail:
    // token-1 would be pushed from at+60s out to at+3600s, so a rotation would EXTEND a
    // credential the operator had already decided to replace -- reachable by anybody who can
    // rotate, and the exact inversion of what rotating is for.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &organization, "token-a").await;

    let at = now_micros(&env);
    // SIXTY SECONDS: token-a is superseded with a short horizon.
    rotate(&db, &env, scope, &connection, "token-b", 60, at)
        .await
        .expect("first rotation");
    // AN HOUR: a bare assignment would move token-a's horizon from at+60s to at+3600s.
    rotate(
        &db,
        &env,
        scope,
        &connection,
        "token-c",
        3600,
        at + 1_000_000,
    )
    .await
    .expect("second rotation");

    let read = db.store().scoped(scope);
    assert!(
        read.scim_connections()
            .authenticate(&digest("token-a"), at + 61_000_000)
            .await
            .expect("read")
            .is_none(),
        "the second rotation EXTENDED the first rotation's superseded token, so rotating is a \
         way to keep an old credential alive"
    );
    // AND token-b KEEPS the horizon the second rotation gave it, so the assertion above is
    // about `LEAST` rather than about everything dying at once.
    assert!(
        read.scim_connections()
            .authenticate(&digest("token-b"), at + 61_000_000)
            .await
            .expect("read")
            .is_some(),
        "the token superseded by the SECOND rotation died at the first rotation's horizon"
    );
}

#[tokio::test]
async fn the_rotation_reports_the_horizon_it_actually_wrote() {
    // THE 200 IS READ BACK FROM THE WRITE. It used to be the handler's own arithmetic,
    // `now + overlap`, which is wrong exactly when `LEAST` does its job: a token already lapsing
    // sooner keeps its horizon, and the response claimed a later one. A consumer scheduling a
    // reminder from that number would fire it after provisioning had already broken.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &organization, "token-p").await;

    let at = now_micros(&env);
    // THE ONLY SHAPE THAT DISTINGUISHES READ-BACK FROM ARITHMETIC. The supersede runs BEFORE the
    // mint, so a token minted by a previous rotation always has `expires_at IS NULL` and always
    // receives exactly `now + overlap` -- which means any fixture built only from rotations
    // reports the arithmetic and cannot tell the two implementations apart. The first version of
    // this test was exactly that, and asserted `now + overlap` under a name claiming otherwise.
    //
    // A connection created WITH an expiry gives its token a horizon that `LEAST` keeps, so the
    // reported value is below `now + overlap` and only a read-back can produce it.
    let short = ScimConnectionId::generate(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .create(
            &env,
            NewScimConnection {
                id: &short,
                organization_id: &organization,
                display_name: "Okta production",
                provider: "okta",
                token_digest: &digest("short-token"),
                expires_at_unix_micros: Some(at + 60_000_000),
            },
            None,
        )
        .await
        .expect("create a connection whose token lapses in a minute");

    let reported = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .rotate_token(&env, &short, &digest("long-token"), 3600, at + 1_000_000)
        .await
        .expect("rotate with an hour-long window")
        .expect("a horizon was written");

    assert_eq!(
        reported,
        at + 60_000_000,
        "the reported horizon is `now + overlap` rather than what LEAST wrote, so the response \
         and the event promise a customer an hour of overlap they do not have"
    );
    // AND IT IS NOT `now + overlap`, stated separately so the failure names the defect rather
    // than a mismatched integer.
    assert_ne!(
        reported,
        at + 1_000_000 + 3600 * 1_000_000,
        "the reported horizon is exactly the handler arithmetic this read-back replaced"
    );
    let _ = &connection;
}

#[tokio::test]
async fn a_connection_written_by_an_old_binary_still_authenticates() {
    // THE ROLLING-UPGRADE HOLE THE FALLBACK CLOSES. An old binary creating a connection writes
    // only `scim_connections.token_digest`; it has never heard of `scim_connection_tokens`. A
    // read that consulted the new table alone would refuse that connection's token FOREVER,
    // because nothing backfills a row created after the migration ran, and the customer's
    // provisioning would never work with no visible cause.
    //
    // Simulated by deleting the token row the new create writes, which is exactly the state an
    // old binary leaves behind.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &organization, "legacy-token").await;

    sqlx::query("DELETE FROM scim_connection_tokens WHERE connection_id = $1")
        .bind(connection.to_string())
        .execute(db.owner_pool())
        .await
        .expect("simulate an old binary's create");

    let at = now_micros(&env);
    assert!(
        db.store()
            .scoped(scope)
            .scim_connections()
            .authenticate(&digest("legacy-token"), at)
            .await
            .expect("read")
            .is_some(),
        "a connection created by an un-upgraded binary cannot authenticate at all, so its \
         customer's provisioning is permanently broken by the migration"
    );
}

#[tokio::test]
async fn the_old_column_stops_answering_once_the_connection_has_token_rows() {
    // THE GUARD ON THE FALLBACK, which is the half that keeps it from being a hole. Once a
    // rotation has happened the connection HAS token rows, so `scim_connections.token_digest` --
    // which still holds the ORIGINAL digest and which no rotation rewrites -- must stop being
    // consulted. Without the `NOT EXISTS`, the first token would authenticate forever on new
    // binaries, which is strictly worse than the un-upgraded-replica window 0205 documents.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &organization, "original-token").await;

    let at = now_micros(&env);
    rotate(&db, &env, scope, &connection, "replacement-token", 60, at)
        .await
        .expect("rotate");

    let read = db.store().scoped(scope);
    // Past the overlap: the original token is dead in the token table, and the old column still
    // holds its digest.
    let after = at + 61 * 1_000_000;
    assert!(
        read.scim_connections()
            .authenticate(&digest("original-token"), after)
            .await
            .expect("read")
            .is_none(),
        "the superseded token authenticated through the legacy column, so a rotation never \
         expires anything on an upgraded binary either"
    );
    assert!(
        read.scim_connections()
            .authenticate(&digest("replacement-token"), after)
            .await
            .expect("read")
            .is_some(),
        "the replacement token does not authenticate"
    );
}

#[tokio::test]
async fn an_expired_connection_cannot_be_rotated() {
    // THE PRE-CHECK'S EXPIRY HALF, which nothing drove. `authenticate` refuses a connection past
    // its own `expires_at`, so rotating one hands back a token that can never work -- and spends
    // the operator's belief that they have just fixed provisioning. Worse, the rotation also
    // supersedes whatever was there, so the state after is strictly worse than before.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;

    let at = now_micros(&env);
    let id = ScimConnectionId::generate(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .create(
            &env,
            NewScimConnection {
                id: &id,
                organization_id: &organization,
                display_name: "Okta production",
                provider: "okta",
                token_digest: &digest("short-lived"),
                expires_at_unix_micros: Some(at + 60_000_000),
            },
            None,
        )
        .await
        .expect("create the connection");

    // IT ROTATES WHILE LIVE, so the refusal below is the expiry rather than the connection
    // being unrotatable for some other reason.
    assert!(
        rotate(&db, &env, scope, &id, "in-time", 60, at + 1_000_000)
            .await
            .is_ok()
    );

    let refused = rotate(&db, &env, scope, &id, "too-late", 60, at + 61_000_000).await;
    assert!(
        matches!(refused, Err(ironauth_store::StoreError::NotFound)),
        "an EXPIRED connection was rotated, handing back a token that can never authenticate \
         while superseding whatever was still there: {refused:?}"
    );
}

#[tokio::test]
async fn rotating_a_legacy_connection_still_gives_the_old_token_its_overlap() {
    // THE ZERO-OVERLAP DEFECT THE `NOT EXISTS` FALLBACK CREATED. That guard answers only while a
    // connection has NO token rows, so the moment a rotation minted the first one the legacy
    // digest stopped being consulted -- and the old token died at the INSTANT of the rotation
    // rather than at the end of the window. On exactly the population the fallback exists for,
    // with the customer's identity provider still configured with the token that just stopped
    // working: the outage the overlap exists to prevent, caused by the fix for a different one.
    //
    // The rotation now ADOPTS the legacy digest as a real row first, so the supersede gives it
    // the same horizon every other superseded token gets.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &organization, "legacy-live").await;

    // The state an old binary leaves: the connection row only.
    sqlx::query("DELETE FROM scim_connection_tokens WHERE connection_id = $1")
        .bind(connection.to_string())
        .execute(db.owner_pool())
        .await
        .expect("simulate an old binary's create");

    let at = now_micros(&env);
    rotate(&db, &env, scope, &connection, "fresh-after-legacy", 600, at)
        .await
        .expect("rotate a legacy connection");

    let read = db.store().scoped(scope);
    // INSIDE THE WINDOW BOTH WORK, which is the whole point of an overlap and what the defect
    // removed entirely for this population.
    assert!(
        read.scim_connections()
            .authenticate(&digest("legacy-live"), at + 1_000_000)
            .await
            .expect("read")
            .is_some(),
        "the legacy token died at the instant of the rotation, so the customer's provisioning \
         broke the moment an operator rotated and stayed broken until somebody re-pasted"
    );
    assert!(
        read.scim_connections()
            .authenticate(&digest("fresh-after-legacy"), at + 1_000_000)
            .await
            .expect("read")
            .is_some(),
        "the new token does not authenticate"
    );

    // AND AFTER THE WINDOW THE LEGACY ONE FAILS CLOSED, so adoption preserved the overlap
    // without making the old digest immortal.
    let after = at + 601 * 1_000_000;
    assert!(
        read.scim_connections()
            .authenticate(&digest("legacy-live"), after)
            .await
            .expect("read")
            .is_none(),
        "the adopted legacy token never expires, so a rotation cannot retire it at all"
    );
    assert!(
        read.scim_connections()
            .authenticate(&digest("fresh-after-legacy"), after)
            .await
            .expect("read")
            .is_some()
    );
}

#[tokio::test]
async fn the_token_tables_grants_and_one_way_policy_are_enforced() {
    // THE NEW CREDENTIAL TABLE'S GUARDS, PINNED. `scim_connections` has all three of these
    // driven; migration 0205 makes the identical three claims for `scim_connection_tokens` and
    // the change that added it pinned none of them. A grant nothing drives is a grant somebody
    // widens without noticing, and this table now holds the verifier.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let id = connect(&db, &env, scope, &org, "grant-probe").await;

    // THE CONTROL ROLE MAY NOT RE-POINT A TOKEN OR SWAP ITS VERIFIER. Both are the escalation
    // 0183 records for the table this one copies: a token moved to another connection is a
    // credential for an organization nobody granted, and a swapped digest is a known credential
    // installed by the role that mints them.
    for (column, value) in [
        ("connection_id", "'scim_somewhere_else'"),
        ("token_digest", &format!("'{}'", "0".repeat(64))[..]),
    ] {
        let outcome = as_control(
            &db,
            scope,
            &format!(
                "UPDATE scim_connection_tokens SET {column} = {value} \
                 WHERE connection_id = '{id}'"
            ),
        )
        .await;
        let error = outcome.expect_err(&format!("{column} must not be updatable"));
        assert!(
            error.to_string().contains("permission denied"),
            "{column} is refused by the column grant, not by something else: {error}"
        );
    }

    // SUPERSEDING IS PERMITTED, so the refusals above are the narrowing rather than a role that
    // can do nothing to this table.
    let affected = as_control(
        &db,
        scope,
        &format!(
            "UPDATE scim_connection_tokens SET expires_at = now() + interval '1 hour' \
             WHERE connection_id = '{id}'"
        ),
    )
    .await
    .expect("superseding is a permitted update");
    assert_eq!(affected, 1);

    // REVOCATION IS ONE WAY. `USING (revoked_at IS NULL)` is what carries it: an already-revoked
    // row is invisible to an UPDATE and cannot be cleared. The WITH CHECK does NOT carry it --
    // `SET revoked_at = NULL, expires_at = ...` satisfies it -- which is why this drives the
    // USING half specifically.
    let revoked = as_control(
        &db,
        scope,
        &format!(
            "UPDATE scim_connection_tokens SET revoked_at = now() WHERE connection_id = '{id}'"
        ),
    )
    .await
    .expect("revocation is permitted");
    assert_eq!(revoked, 1);
    let un_revoked = as_control(
        &db,
        scope,
        &format!(
            "UPDATE scim_connection_tokens SET revoked_at = NULL, expires_at = now() \
             WHERE connection_id = '{id}'"
        ),
    )
    .await
    .expect("an un-revocation is refused by the policy rather than erroring");
    assert_eq!(
        un_revoked, 0,
        "a revoked token was un-revoked, so the one-way policy admits the row it must hide"
    );

    // AND THE DATA PLANE MAY NOT WRITE AT ALL. A provisioning credential that could mint another
    // would be a privilege escalation with no operator in the loop.
    for statement in [
        "INSERT INTO scim_connection_tokens (token_digest, connection_id, tenant_id, \
         environment_id) VALUES (repeat('a', 64), 'scim_x', 'ten_x', 'env_x')",
        "UPDATE scim_connection_tokens SET revoked_at = now()",
        "DELETE FROM scim_connection_tokens",
    ] {
        let outcome = as_app(&db, scope, statement).await;
        let error = outcome.expect_err("the data plane must not write to this table");
        assert!(
            error.to_string().contains("permission denied"),
            "the app role is refused by the grant rather than by something else: {error}"
        );
    }
}

#[tokio::test]
async fn the_listing_reports_the_soonest_live_token_horizon() {
    // WHAT AN OPERATOR NEEDS WARNING ABOUT is the moment provisioning could STOP, and after a
    // rotation that is the SUPERSEDED token's horizon rather than the connection's own or the
    // fresh token's (which usually has none). Reporting the connection's `expires_at` would say
    // nothing about a rotation; reporting the latest would say the opposite of the truth.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &organization, "soonest-a").await;

    let at = now_micros(&env);
    // BEFORE ANY ROTATION there is no horizon: one token, no expiry.
    let listed = db
        .store()
        .scoped(scope)
        .scim_connections()
        .list_for_organization(&organization, 50, None, at)
        .await
        .expect("list");
    assert_eq!(
        listed
            .iter()
            .find(|c| c.id == connection)
            .and_then(|c| c.soonest_token_expiry_unix_micros),
        None,
        "a connection nobody has rotated reports a token horizon"
    );

    rotate(&db, &env, scope, &connection, "soonest-b", 600, at)
        .await
        .expect("rotate");

    let listed = db
        .store()
        .scoped(scope)
        .scim_connections()
        .list_for_organization(&organization, 50, None, at)
        .await
        .expect("list");
    let reported = listed
        .iter()
        .find(|c| c.id == connection)
        .and_then(|c| c.soonest_token_expiry_unix_micros)
        .expect("a rotated connection has a token horizon");
    assert_eq!(
        reported,
        at + 600 * 1_000_000,
        "the listing does not report the superseded token's horizon"
    );

    // A REVOKED TOKEN IS EXCLUDED. It is already not working, so warning about when it would
    // have lapsed points an operator at a deadline with no effect -- and, worse, hides the next
    // real one behind it.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke_token(&env, &connection, &digest("soonest-a"), at + 1_000_000)
        .await
        .expect("revoke the superseded token");
    let listed = db
        .store()
        .scoped(scope)
        .scim_connections()
        .list_for_organization(&organization, 50, None, at)
        .await
        .expect("list");
    assert_eq!(
        listed
            .iter()
            .find(|c| c.id == connection)
            .and_then(|c| c.soonest_token_expiry_unix_micros),
        None,
        "a REVOKED token's horizon is still reported, so the listing warns about a deadline \
         that cannot arrive"
    );
}

#[tokio::test]
async fn a_completed_rotation_stops_warning_once_the_overlap_has_passed() {
    // THE DEFECT THE FIRST VERSION SHIPPED. The horizon was a MIN over non-REVOKED tokens with
    // no lower bound, and a rotation supersedes a token WITHOUT revoking it. Nothing sweeps the
    // row and no route exposes per-token revocation, so the superseded token's already-past
    // timestamp became a permanent floor: every connection anybody had ever rotated reported
    // itself expiring forever, and any genuine future horizon was hidden behind the dead one.
    //
    // On the shipped fourteen-day default that was every rotated connection in the deployment --
    // precisely the always-on warning the configuration cap exists to prevent, produced by the
    // feature's own headline operation.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &organization, "settled-a").await;

    let at = now_micros(&env);
    rotate(&db, &env, scope, &connection, "settled-b", 600, at)
        .await
        .expect("rotate");

    let read = db.store().scoped(scope);
    // DURING the overlap the horizon is the superseded token's, which is the warning working.
    let during = read
        .scim_connections()
        .list_for_organization(&organization, 50, None, at + 1_000_000)
        .await
        .expect("list")
        .into_iter()
        .find(|c| c.id == connection)
        .expect("listed");
    assert_eq!(
        during.soonest_token_expiry_unix_micros,
        Some(at + 600 * 1_000_000)
    );
    assert_eq!(
        during.live_token_count, 2,
        "both tokens are live inside the window"
    );

    // AFTER it, the cutover is complete and provisioning is healthy on the fresh token. There is
    // nothing to warn about, and the dead row must not answer.
    let after = read
        .scim_connections()
        .list_for_organization(&organization, 50, None, at + 601 * 1_000_000)
        .await
        .expect("list")
        .into_iter()
        .find(|c| c.id == connection)
        .expect("listed");
    assert_eq!(
        after.soonest_token_expiry_unix_micros, None,
        "a completed rotation still reports the superseded token's dead horizon, so this \
         connection warns forever and its next real deadline is hidden behind it"
    );
    assert_eq!(
        after.live_token_count, 1,
        "the fresh token is not counted live after the overlap"
    );
}

#[tokio::test]
async fn a_connection_whose_every_token_has_lapsed_reports_no_live_token() {
    // THE OTHER HALF, and the reason the count is a separate field. A connection whose tokens
    // have ALL lapsed publishes no horizon -- and so does a perfectly healthy one whose token
    // never expires. Through the horizon alone those two are indistinguishable, and one of them
    // needs an operator today.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;

    let at = now_micros(&env);
    let id = ScimConnectionId::generate(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .create(
            &env,
            NewScimConnection {
                id: &id,
                organization_id: &organization,
                display_name: "Okta production",
                provider: "okta",
                token_digest: &digest("lapses-soon"),
                expires_at_unix_micros: Some(at + 60_000_000),
            },
            None,
        )
        .await
        .expect("create");

    let read = db.store().scoped(scope);
    let live = read
        .scim_connections()
        .list_for_organization(&organization, 50, None, at)
        .await
        .expect("list")
        .into_iter()
        .find(|c| c.id == id)
        .expect("listed");
    assert_eq!(
        live.live_token_count, 1,
        "the token is live before its expiry"
    );

    let lapsed = read
        .scim_connections()
        .list_for_organization(&organization, 50, None, at + 61_000_000)
        .await
        .expect("list")
        .into_iter()
        .find(|c| c.id == id)
        .expect("listed");
    assert_eq!(
        lapsed.live_token_count, 0,
        "a connection whose only token has lapsed still counts it live, so nothing distinguishes \
         broken provisioning from a healthy connection that never expires"
    );
    assert_eq!(lapsed.soonest_token_expiry_unix_micros, None);
}

#[tokio::test]
async fn the_horizon_is_the_soonest_of_several_live_tokens_and_is_per_connection() {
    // MIN RATHER THAN MAX, and CORRELATED to this connection. The first version of the store
    // test had at most one token with a horizon at every assertion, so flipping the aggregate to
    // MAX -- or dropping the correlation and reporting the environment's earliest -- left the
    // suite green. Two live horizons on ONE connection, and a SIBLING with an earlier one, is
    // the state that tells all three implementations apart.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;

    let at = now_micros(&env);
    // THE SUBJECT'S TWO HORIZONS MUST DIFFER, and two rotations alone cannot produce that:
    // `LEAST` collapses every superseded token onto the newest rotation's value, so
    // MIN == MAX over the set and flipping the aggregate changes nothing. Two earlier versions
    // of this test had exactly that shape and a mutation run confirmed both survived MAX.
    //
    // A CREATE-TIME EXPIRY is what separates them. The connection's first token carries
    // `at+100s`, which `LEAST` keeps through a rotation asking for an hour, so the live set is
    // {at+100s, at+3601s, NULL} and the two aggregates disagree.
    let subject = ScimConnectionId::generate(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .create(
            &env,
            NewScimConnection {
                id: &subject,
                organization_id: &organization,
                display_name: "Okta production",
                provider: "okta",
                token_digest: &digest("multi-1"),
                // FAR ENOUGH OUT that the connection's own horizon is not the minimum: this test
                // is about the TOKEN aggregate, and a connection expiry inside the window would
                // answer for it.
                expires_at_unix_micros: Some(at + 90 * 24 * 60 * 60 * 1_000_000),
            },
            None,
        )
        .await
        .expect("create with a horizon");
    // Give the first token a SHORT horizon of its own.
    rotate(&db, &env, scope, &subject, "multi-2", 100, at)
        .await
        .expect("first rotation");
    // And ask for a much longer one, which `LEAST` must NOT apply to the first token.
    rotate(&db, &env, scope, &subject, "multi-3", 3600, at + 1_000_000)
        .await
        .expect("second rotation");

    // A SIBLING with an earlier horizon than either of the subject's. If the subquery were not
    // correlated, the subject would report this one.
    let sibling = connect(&db, &env, scope, &organization, "sibling-1").await;
    rotate(&db, &env, scope, &sibling, "sibling-2", 60, at)
        .await
        .expect("sibling rotation");

    let listed = db
        .store()
        .scoped(scope)
        .scim_connections()
        .list_for_organization(&organization, 50, None, at + 2_000_000)
        .await
        .expect("list");
    let subject_row = listed.iter().find(|c| c.id == subject).expect("listed");

    // THE FIRST TOKEN'S OWN `at+100s` IS THE MINIMUM. `LEAST` kept it through the second
    // rotation's hour-long window, so the live set holds two DIFFERENT horizons and this
    // assertion fails against MAX, which would answer `at+1s+3600s`.
    assert_eq!(
        subject_row.soonest_token_expiry_unix_micros,
        Some(at + 100 * 1_000_000),
        "the horizon is not the SOONEST of this connection's live tokens; MAX and MIN cannot be \
         told apart by this fixture unless two of them differ"
    );
    assert_eq!(subject_row.live_token_count, 3);

    let sibling_row = listed.iter().find(|c| c.id == sibling).expect("listed");
    assert_eq!(
        sibling_row.soonest_token_expiry_unix_micros,
        Some(at + 60 * 1_000_000),
        "the sibling's own earlier horizon is not reported against the sibling"
    );
    assert_ne!(
        subject_row.soonest_token_expiry_unix_micros, sibling_row.soonest_token_expiry_unix_micros,
        "two connections report one horizon, so the subquery is not correlated per connection"
    );
}

#[tokio::test]
async fn a_rotated_connection_still_warns_about_its_own_expiry() {
    // THE SILENCE THE FIRST FIX CREATED. `authenticate` requires the CONNECTION to be live as
    // well as the token, and a rotation mints its fresh token with NO horizon. So a connection
    // created with a ninety-day expiry and rotated on day thirty had no live TOKEN horizon at
    // all once the overlap passed -- reported none, reported one live token, and then stopped
    // working on day ninety with nothing having warned.
    //
    // Reading only half of what the authenticator reads is what produced it: the round-1 fix
    // removed the dead timestamp that had been keeping the row visible for the wrong reason, and
    // left nothing in its place.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;

    let at = now_micros(&env);
    let horizon = at + 90 * 24 * 60 * 60 * 1_000_000;
    let id = ScimConnectionId::generate(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .create(
            &env,
            NewScimConnection {
                id: &id,
                organization_id: &organization,
                display_name: "Pilot",
                provider: "okta",
                token_digest: &digest("pilot-a"),
                expires_at_unix_micros: Some(horizon),
            },
            None,
        )
        .await
        .expect("create a connection with a horizon");
    rotate(&db, &env, scope, &id, "pilot-b", 3600, at)
        .await
        .expect("rotate");

    let read = db.store().scoped(scope);
    // PAST THE OVERLAP: the superseded token is gone and the fresh one has no horizon of its
    // own, so the only thing that can still stop this connection is its OWN expiry.
    let after = read
        .scim_connections()
        .list_for_organization(&organization, 50, None, at + 7200 * 1_000_000)
        .await
        .expect("list")
        .into_iter()
        .find(|c| c.id == id)
        .expect("listed");
    assert_eq!(
        after.soonest_token_expiry_unix_micros,
        Some(horizon),
        "a rotated connection reports no horizon at all, so it will stop working on its own \
         expiry with nothing having warned"
    );
    assert_eq!(
        after.live_token_count, 1,
        "the fresh token is usable before the horizon"
    );

    // AND PAST ITS OWN EXPIRY it authenticates nothing, however many token rows are live.
    let dead = read
        .scim_connections()
        .list_for_organization(&organization, 50, None, horizon + 1_000_000)
        .await
        .expect("list")
        .into_iter()
        .find(|c| c.id == id)
        .expect("listed");
    assert_eq!(
        dead.live_token_count, 0,
        "a connection past its own expiry counts a token live, so the listing reports healthy \
         while every provisioning request is refused"
    );
}

#[tokio::test]
async fn a_legacy_connection_with_no_token_rows_is_not_reported_broken() {
    // THE FALLBACK POPULATION, which counting ROWS gets exactly backwards. A connection created
    // by a binary that predates migration 0205 has no token rows and authenticates through the
    // fallback on `scim_connections.token_digest` -- it provisions perfectly. Counting rows
    // reported it as having zero live credentials, i.e. "provisioning has stopped", on every
    // listing, for the whole population the fallback exists to serve.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &organization, "legacy-listed").await;

    sqlx::query("DELETE FROM scim_connection_tokens WHERE connection_id = $1")
        .bind(connection.to_string())
        .execute(db.owner_pool())
        .await
        .expect("simulate an old binary's create");

    let at = now_micros(&env);
    let read = db.store().scoped(scope);
    // IT AUTHENTICATES, which is the premise: this is not a broken connection.
    assert!(
        read.scim_connections()
            .authenticate(&digest("legacy-listed"), at)
            .await
            .expect("read")
            .is_some()
    );
    let listed = read
        .scim_connections()
        .list_for_organization(&organization, 50, None, at)
        .await
        .expect("list")
        .into_iter()
        .find(|c| c.id == connection)
        .expect("listed");
    assert_eq!(
        listed.live_token_count, 1,
        "a legacy connection that authenticates fine is reported as having no usable \
         credential, so an operator is told provisioning has stopped when it has not"
    );
}

/// One connection's live-credential count, as the listing reports it right now.
async fn live_count(
    db: &TestDatabase,
    scope: Scope,
    organization: &OrganizationId,
    id: &ScimConnectionId,
    at: i64,
) -> i64 {
    db.store()
        .scoped(scope)
        .scim_connections()
        .list_for_organization(organization, 50, None, at)
        .await
        .expect("list")
        .into_iter()
        .find(|c| &c.id == id)
        .expect("listed")
        .live_token_count
}

/// A revoked connection, and one whose organization was disabled, each count zero live
/// credentials.
///
/// # Why one test for two conditions
///
/// Because the assertion each makes is the same one and the control they need is the same
/// control: the SAME connection, counted as live first, then counted as zero after exactly one
/// thing changed. Split apart, each would repeat that setup to assert one number.
///
/// The count claims that something a customer can present will authenticate. `authenticate`
/// refuses a revoked connection and refuses one whose organization is soft-deleted or disabled,
/// and neither was visible to a count that looked only at token rows: an operator scanning the
/// listing for the broken connections would have seen these two reported healthy, having stopped
/// provisioning.
#[tokio::test]
async fn a_connection_that_cannot_authenticate_counts_no_live_credential() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope, "Initech").await;
    let revoked = connect(&db, &env, scope, &organization, "count-revoked").await;
    let disabled = connect(&db, &env, scope, &organization, "count-disabled").await;

    let at = now_micros(&env);

    // THE CONTROL. Both are live and counted, so the two zeroes below are the change and not
    // the state this fixture starts in.
    assert_eq!(live_count(&db, scope, &organization, &revoked, at).await, 1, "the control: revoked-to-be");
    assert_eq!(live_count(&db, scope, &organization, &disabled, at).await, 1, "the control: disabled-to-be");

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &revoked, at)
        .await
        .expect("revoke");

    let after = now_micros(&env);
    assert_eq!(
        live_count(&db, scope, &organization, &revoked, after).await,
        0,
        "a REVOKED connection is counted as having a usable credential; authenticate refuses \
         it, so an operator is told provisioning works when it has stopped"
    );
    // And the other connection in the same organization is untouched, so the zero above is
    // about the revoked row rather than about the listing having gone blank.
    assert_eq!(
        live_count(&db, scope, &organization, &disabled, after).await,
        1,
        "revoking one connection must not zero the count of its neighbour"
    );

    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .set_state(
            &env,
            &organization,
            ironauth_store::OrganizationState::Disabled,
            None,
        )
        .await
        .expect("disable the organization");

    let after = now_micros(&env);
    assert!(
        db.store()
            .scoped(scope)
            .scim_connections()
            .authenticate(&digest("count-disabled"), after)
            .await
            .expect("authenticate")
            .is_none(),
        "the premise: a disabled organization provisions nothing"
    );
    assert_eq!(
        live_count(&db, scope, &organization, &disabled, after).await,
        0,
        "a connection in a DISABLED organization is counted as having a usable credential; \
         authenticate refuses it, so the listing contradicts the surface it describes"
    );
}
