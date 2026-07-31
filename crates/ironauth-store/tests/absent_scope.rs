// SPDX-License-Identifier: MIT OR Apache-2.0

//! A WRITE into a scope that does not exist answers the uniform not-found, over a real
//! database (`DATABASE_URL`). Issues #409 and #449.
//!
//! # The asymmetry this file closes
//!
//! Row-level security already makes a READ in an absent scope indistinguishable from a
//! read in an empty one: it matches no rows either way, which is the anti-oracle
//! contract the store's module documentation states. A WRITE could not hide behind
//! that. Every scoped table carries a foreign key to `tenants` and, for the
//! environment-scoped ones, a composite foreign key to `environments`, so a write
//! naming a scope that was never created reached that constraint and failed, and the
//! failure surfaced as [`StoreError::Database`], a fault.
//!
//! On the management plane that was a contract defect: an integrator who mistyped an
//! environment id got a `500` (issue #409). On the UNAUTHENTICATED data plane it was
//! worse than that. The same request answered `200` for a real environment and `500`
//! for one that never existed, with no credential of any kind, which is a tenant and
//! environment enumeration oracle (issue #449) over exactly the fact issue #433 went to
//! lengths to withhold at the token endpoint.
//!
//! # Why the recognition rule is checked against the SCHEMA and not against a list
//!
//! The conversion recognizes the failure by constraint NAME, because that is the only
//! discriminator `sqlx` surfaces for a foreign-key violation. A name rule is exactly
//! the kind of thing that silently stops covering the whole set: one future table that
//! names its constraint explicitly, or renames a column, and the gap reopens with
//! nothing failing to say so.
//!
//! [`the_recognition_rule_matches_the_scope_foreign_keys_and_nothing_else`] therefore
//! derives its subject list from the LIVE SCHEMA rather than from anything written here,
//! and measures the rule in BOTH directions.
//!
//! COMPLETENESS is the direction the gap was found in: every foreign key referencing
//! `tenants` or `environments` must be recognized, or a write that trips it answers a
//! fault and the oracle reopens. A new scoped table is covered the moment it is
//! migrated.
//!
//! SOUNDNESS is the opposite direction and it is the one a widening breaks: every
//! constraint whose NAME the rule matches must really reference a scope table, or a
//! genuine referential failure against a row that IS there answers not-found. The
//! convention holding this up is a column ORDER (see the rule's own documentation), and
//! the schema already carries both orders, so it is one keystroke from breaking.
//!
//! Both halves read the suffix from THE SOURCE
//! ([`ironauth_store::test_support::SCOPE_FK_SUFFIX`]) rather than restating it, so
//! widening the source widens the query too and the soundness half goes red on the
//! extra constraints the widened rule would now swallow.

use std::collections::BTreeSet;

use ironauth_env::Env;
use ironauth_store::test_support::{SCOPE_FK_SUFFIX, TestDatabase};
use ironauth_store::{CorrelationId, EnvironmentId, Scope, StoreError, TenantId};

/// A `(tenant, environment)` pair that is well formed, in the right shape, and belongs
/// to no tenant this deployment ever created: the shape an enumeration probe sends.
fn ghost_scope(env: &Env) -> Scope {
    Scope::new(TenantId::generate(env), EnvironmentId::generate(env))
}

/// One foreign key the live schema declares, as the two halves of the rule see it.
#[derive(Debug)]
struct ForeignKey {
    constraint: String,
    child: String,
    parent: String,
}

impl ForeignKey {
    /// Whether the PARENT is a scope table, which is what makes recognizing this
    /// constraint as an absent scope TRUE rather than merely convenient.
    fn onto_a_scope_table(&self) -> bool {
        self.parent == "tenants" || self.parent == "environments"
    }

    /// Whether the shipped rule would recognize this constraint, by the SAME suffix the
    /// conversion uses rather than a copy of it.
    fn recognized(&self) -> bool {
        self.constraint.ends_with(SCOPE_FK_SUFFIX)
    }
}

/// Every foreign key in the public schema that is EITHER onto a scope table or named
/// the way the rule recognizes.
///
/// Selecting on both is what makes the two directions measurable. Filtering only by
/// parent, which is what this query did first, can see a constraint the rule MISSES but
/// can never see one the rule wrongly CLAIMS, because such a constraint is by definition
/// not onto a scope table and so is not in the result set at all.
///
/// The name half binds the suffix rather than inlining it, so a widened suffix widens
/// this query and the soundness assertion below sees every constraint the widened rule
/// would newly swallow.
async fn candidate_foreign_keys(db: &TestDatabase) -> Vec<ForeignKey> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT con.conname, child.relname, parent.relname \
         FROM pg_constraint con \
         JOIN pg_class child ON child.oid = con.conrelid \
         JOIN pg_class parent ON parent.oid = con.confrelid \
         JOIN pg_namespace ns ON ns.oid = child.relnamespace \
         WHERE con.contype = 'f' AND ns.nspname = 'public' \
         AND (parent.relname IN ('tenants', 'environments') \
              OR con.conname LIKE '%' || $1) \
         ORDER BY con.conname",
        // The suffix contains `_`, which is a LIKE wildcard, so the name half selects a
        // SUPERSET of what the rule recognizes. That is the safe direction: an extra
        // candidate is filtered out by `ForeignKey::recognized` below, which is the real
        // predicate, while a subset could hide the very constraint being looked for.
    )
    .bind(SCOPE_FK_SUFFIX)
    .fetch_all(db.owner_pool())
    .await
    .expect("read the live schema's foreign keys");
    rows.into_iter()
        .map(|(constraint, child, parent)| ForeignKey {
            constraint,
            child,
            parent,
        })
        .collect()
}

#[tokio::test]
async fn the_recognition_rule_matches_the_scope_foreign_keys_and_nothing_else() {
    let db = TestDatabase::start().await;
    let keys = candidate_foreign_keys(&db).await;

    // The inventory has to be non-trivial, or an empty result would pass this test while
    // measuring nothing. The schema declares these on essentially every scoped table, so
    // a handful would already mean the query is wrong.
    let onto_scope = keys.iter().filter(|key| key.onto_a_scope_table()).count();
    assert!(
        onto_scope > 50,
        "the live schema must declare a scope foreign key on the scoped tables; found \
         {onto_scope} which means this query is reading the wrong thing rather than that \
         the constraints are gone"
    );

    // COMPLETENESS. Every foreign key onto a scope table is recognized, so none of them
    // can trip and answer a fault.
    let unrecognized: Vec<&ForeignKey> = keys
        .iter()
        .filter(|key| key.onto_a_scope_table() && !key.recognized())
        .collect();
    assert!(
        unrecognized.is_empty(),
        "every foreign key onto a scope table must be recognizable as an absent scope, \
         or a write that trips it answers a server fault instead of the uniform \
         not-found and becomes an existence oracle on the unauthenticated data plane. \
         These are not: {unrecognized:#?}"
    );

    // SOUNDNESS, the direction the parent-only query could not see at all. Every
    // constraint the rule MATCHES really does reference a scope table, so the conversion
    // cannot answer not-found for a referential failure against a row that is there.
    //
    // This is not hypothetical safety. The schema carries eleven constraints of the
    // shape `FOREIGN KEY (x_id, tenant_id, environment_id)` onto a non-scope parent, and
    // every one of them is kept out of this rule's reach only by `environment_id` coming
    // LAST in the column list. The scope keys themselves use the opposite order, so both
    // orders are already in the schema and a new table written the other way round would
    // land here.
    let wrongly_matched: Vec<&ForeignKey> = keys
        .iter()
        .filter(|key| key.recognized() && !key.onto_a_scope_table())
        .collect();
    assert!(
        wrongly_matched.is_empty(),
        "every constraint the absent-scope rule matches must reference a scope table, or \
         a genuine referential failure against a row that IS present answers the uniform \
         not-found and the caller is told a resource is missing when it is not. These \
         match the rule and point elsewhere: {wrongly_matched:#?}"
    );

    // And BOTH parents are really represented, so the rule is not passing because one
    // half of the set happens to be empty. Which of the two a request trips is a
    // property of the request, not of the code: a wholly invented pair trips the tenant
    // key, and a real tenant with an invented environment trips the composite one.
    // Recognizing only the composite one left the first shape, the one a probe actually
    // sends, still answering a fault.
    for parent in ["tenants", "environments"] {
        assert!(
            keys.iter().any(|key| key.parent == parent),
            "the inventory must cover foreign keys onto {parent}"
        );
    }

    // The constraints are spread across the scoped tables rather than concentrated on a
    // few, which is what makes the name rule a rule about the SCHEMA CONVENTION and not
    // a coincidence that happens to hold for one table.
    let children: BTreeSet<&str> = keys
        .iter()
        .filter(|key| key.onto_a_scope_table())
        .map(|key| key.child.as_str())
        .collect();
    assert!(
        children.len() > 25,
        "the scope foreign keys must span the scoped tables; found only {children:?}"
    );
}

#[tokio::test]
async fn a_write_into_a_scope_that_never_existed_is_the_uniform_not_found() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    // THE CONTROL, first: the same write into a REAL scope succeeds. Without it this
    // test could pass against a store that refuses everything, and the not-found below
    // would be measuring breakage rather than the rule.
    let live = db.seed_scope(&env).await;
    let allowed = db
        .store()
        .scoped(live)
        .dcr_rate_limiter()
        .check_and_increment("absent_scope_probe", 10, 300, 0)
        .await
        .expect("a counter write into a live scope succeeds");
    assert!(allowed, "the control write must be under the limit");

    // A scope naming a tenant that never existed: this trips the single-column tenant
    // foreign key.
    let ghost = ghost_scope(&env);
    let error = db
        .store()
        .scoped(ghost)
        .dcr_rate_limiter()
        .check_and_increment("absent_scope_probe", 10, 300, 0)
        .await
        .expect_err("a counter write into a scope that never existed cannot land");
    assert!(
        matches!(error, StoreError::NotFound),
        "a write into a scope that never existed must be the uniform not-found and \
         never a database fault: {error:?}"
    );

    // A scope naming a REAL tenant with an environment that never existed: this trips
    // the COMPOSITE foreign key instead, which is a different constraint and therefore
    // a different code path through the recognition rule.
    let ghost_environment = Scope::new(live.tenant(), EnvironmentId::generate(&env));
    let error = db
        .store()
        .scoped(ghost_environment)
        .dcr_rate_limiter()
        .check_and_increment("absent_scope_probe", 10, 300, 0)
        .await
        .expect_err("a counter write into an environment that never existed cannot land");
    assert!(
        matches!(error, StoreError::NotFound),
        "a real tenant with an environment that never existed must be the uniform \
         not-found too: {error:?}"
    );
}

#[tokio::test]
async fn a_genuine_database_fault_is_still_a_database_fault() {
    // THE COST OF THE RULE ABOVE, pinned. Converting a foreign-key violation to the
    // uniform not-found is only safe if it cannot swallow a real fault, so this drives
    // three and requires each to stay the shape it was.
    //
    // The THIRD case below is the one that makes this test able to see a WIDENING. The
    // other two drive SQLSTATEs the rule does not operate on at all (a missing relation
    // and a uniqueness violation), so no amount of widening INSIDE the foreign-key class
    // moves them. That was measured: with only those two, widening the suffix to `_fkey`
    // left this whole file green while every referential failure in the schema had
    // started answering not-found.
    let db = TestDatabase::start().await;
    let error = sqlx::query("SELECT * FROM a_table_that_does_not_exist")
        .execute(db.owner_pool())
        .await
        .expect_err("selecting from a missing table fails")
        .into();
    assert!(
        matches!(error, StoreError::Database(_)),
        "an error that is not a scope foreign-key violation must stay a fault: {error:?}"
    );

    // And a UNIQUENESS violation, which is the other constraint class a scoped write
    // reaches, is untouched by the rule: it is still the caller-facing conflict rather
    // than a not-found. The two are neighbours in the same conversion, so widening the
    // absent-scope rule to cover more SQLSTATEs than it should would land here first.
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    acting
        .users()
        .register(&env, "duplicate@example.test", "argon2-placeholder-hash")
        .await
        .expect("the first registration succeeds");
    let duplicate = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .register(&env, "duplicate@example.test", "argon2-placeholder-hash")
        .await;
    assert!(
        matches!(duplicate, Err(StoreError::Conflict)),
        "reusing a login identifier must stay a conflict, not become a not-found: \
         {duplicate:?}"
    );

    // AND A REAL FOREIGN-KEY VIOLATION, SQLSTATE 23503, ON A KEY THAT IS NOT A SCOPE KEY.
    // This is the case the rule actually operates on, so it is the only one of the three
    // that can see the rule widen WITHIN its own class.
    //
    // The subject is deliberately one of the near misses the soundness half of
    // [`the_recognition_rule_matches_the_scope_foreign_keys_and_nothing_else`] guards:
    // a child of a SEEDED scope whose own parent row is absent. Both scope keys are
    // satisfied (the scope was really created), so the only constraint that can fire is
    // the one onto the non-scope parent, and it must stay a fault: the referenced row is
    // genuinely missing from a scope the caller can address, which is a broken write
    // rather than an absent scope, and answering not-found would tell the caller a
    // resource is gone when the resource in question is the one they just named.
    //
    // Raw SQL is used rather than a repository call because no repository offers a way
    // to write a child against a parent it never created; that is the point of the
    // constraint. Test files are exempt from the query audit for exactly this reason.
    let absent_parent = sqlx::query(
        "INSERT INTO acme_challenges \
         (id, tenant_id, environment_id, domain_id, challenge_type, token) \
         VALUES ($1, $2, $3, $4, 'http-01', 'absent-scope-probe-token')",
    )
    .bind("acme-challenge-probe")
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind("a-custom-domain-row-that-was-never-created")
    .execute(db.owner_pool())
    .await
    .expect_err("a child row naming a parent that does not exist cannot land");

    // Pinned by CONSTRAINT NAME as well as by SQLSTATE, so this cannot start passing
    // because some unrelated failure happened first.
    let raw = absent_parent
        .as_database_error()
        .expect("the failure is a database error");
    assert_eq!(
        raw.code().as_deref(),
        Some("23503"),
        "the probe must drive a foreign-key violation: {raw:?}"
    );
    assert_eq!(
        raw.constraint(),
        Some("acme_challenges_domain_id_tenant_id_environment_id_fkey"),
        "the probe must trip the NON-scope foreign key, or it is measuring the scope \
         keys again: {raw:?}"
    );
    let converted: StoreError = absent_parent.into();
    assert!(
        matches!(converted, StoreError::Database(_)),
        "a foreign-key violation on a key that does not bind a row to its scope must \
         stay a fault; converting it would answer not-found for a row the caller can \
         address: {converted:?}"
    );
}
