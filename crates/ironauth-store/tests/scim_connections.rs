// SPDX-License-Identifier: MIT OR Apache-2.0

//! Inbound SCIM connections and their bearer tokens (issue #135).
//!
//! # What this file is about
//!
//! SCIM endpoints are a proven IDOR hot spot: Zitadel's CVE-2026-32130 was a SCIM auth bypass
//! through URL encoding, and Casdoor's CVE-2025-4210 was a SCIM authorization gap. The issue
//! asks that a token for organization A be unusable against organization B **by construction**,
//! and this file is where that claim is measured rather than asserted.
//!
//! The construction is that the organization is a column on the CREDENTIAL. A caller never
//! supplies one, so there is no request shape in which a token names a second organization --
//! and the tests below are written to fail if that ever stops being true.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, NewScimConnection, OrganizationId, ScimConnectionId, Scope};

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
                organization_id: &organization.to_string(),
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
    assert_eq!(found.organization_id, org.to_string());
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
            found.organization_id,
            expected.to_string(),
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
    let again = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &id, now_micros(&env))
        .await
        .expect("revoke again");
    assert!(!again, "an already-revoked connection reports no change");
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
                organization_id: &org.to_string(),
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
