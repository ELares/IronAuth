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
         not-found: a contract defect on the management plane, and an existence oracle \
         wherever the table is reachable from the unauthenticated data plane. \
         These are not: {unrecognized:#?}"
    );

    // SOUNDNESS, the direction the parent-only query could not see at all. Every
    // constraint the rule MATCHES really does reference a scope table, so the conversion
    // cannot answer not-found for a referential failure against a row that is there.
    //
    // This is not hypothetical safety. The schema carries a dozen constraints of the shape
    // `FOREIGN KEY (x_id, tenant_id, environment_id)` onto a non-scope parent, and every one
    // of them is kept out of this rule's reach only by `environment_id` coming LAST in the
    // column list. (Eleven when that sentence was written; 0147 added the twelfth, which is
    // the argument for the assertion below reading the live schema rather than for anyone
    // writing the number down again.) The scope keys themselves use the opposite order, so
    // both orders are already in the schema and a new table written the other way round
    // would land here.
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

/// The two tables that BROKE the convention answer the uniform not-found too (issues #111,
/// #112).
///
/// The schema-wide rule above is a proxy: it asserts every scope foreign key is
/// RECOGNIZABLE by name. This asserts the thing the proxy stands for, on the two tables
/// that were unrecognizable until migration 0150, so the fix is measured by behaviour and
/// not only by a naming scan.
///
/// It matters that these two are the ones. `message_templates` (0145) and `flow_targets`
/// (0146) declared the composite key with the columns in the opposite order to every other
/// scoped table, so Postgres named the constraint `..._tenant_id_environment_id_fkey`
/// instead of `..._environment_id_tenant_id_fkey`. The conversion matches on the suffix
/// `_tenant_id_fkey`, which the second name carries and the first does not, so a write into
/// an absent environment answered a SERVER FAULT rather than the uniform not-found.
///
/// ON THESE TWO TABLES THAT IS ISSUE #409's MANAGEMENT-PLANE CONTRACT DEFECT AND NOT A LIVE
/// ORACLE, and the difference is worth stating precisely because an earlier draft of this
/// comment got it wrong in the alarming direction. Both are control plane only: 0145 and
/// 0146 grant `ironauth_app` SELECT alone, so no unauthenticated caller can reach either
/// write. It becomes issue #449's oracle the day either table acquires a data-plane write
/// path, which is exactly why the fix is the naming convention rather than a note on these
/// two tables.
///
/// The module documentation above predicted exactly this ("the schema already carries both
/// orders, so it is one keystroke from breaking"), and it went unseen for two migrations
/// because the CI job that runs this suite was dying on disk exhaustion before it got here.
#[tokio::test]
async fn a_template_write_into_an_absent_environment_is_the_uniform_not_found() {
    use ironauth_store::message_template::TemplateLevel;
    use ironauth_store::{MessageTemplateId, NewMessageTemplate};

    let db = TestDatabase::start().await;
    let env = Env::system();
    let live = db.seed_scope(&env).await;

    let write = async |scope: Scope| {
        let id = MessageTemplateId::generate(&env, &scope);
        // The CONTROL-plane store: `message_templates` is a control-plane table and the
        // data-plane role has no grant on it, so `db.store()` would fail with a permission
        // error and this test would be measuring the wrong refusal.
        db.control_store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .message_templates()
            .set(
                &env,
                &id,
                0,
                NewMessageTemplate {
                    level: TemplateLevel::Environment,
                    organization_id: None,
                    kind: "invitation",
                    locale: "en",
                    subject: "s",
                    body_text: "b",
                    body_html: None,
                    locked: false,
                },
            )
            .await
    };

    // THE CONTROL. Without it a not-found below would be measuring breakage rather than
    // the rule, which is the failure mode this whole file is written against.
    write(live)
        .await
        .expect("the write into a LIVE scope lands");

    // A real tenant, an environment that never existed: this trips the COMPOSITE key, which
    // is the one whose name broke.
    let ghost_environment = Scope::new(live.tenant(), EnvironmentId::generate(&env));
    let error = write(ghost_environment)
        .await
        .expect_err("a write into an absent environment cannot land");
    assert!(
        matches!(error, StoreError::NotFound),
        "an absent environment must be the uniform not-found and never a database fault, \
         or a caller that can reach this write distinguishes a scope that exists from one \
         that does not: {error:?}"
    );

    // And a wholly invented tenant AND environment, reaching the same composite key from
    // the other direction. NOT a single-column tenant key: `message_templates` declares
    // exactly one foreign key (0145), so both cases above report
    // `message_templates_environment_id_tenant_id_fkey`. An earlier version of this comment
    // claimed the single-column key by copying the framing from the sibling test above,
    // where it is true.
    let error = write(ghost_scope(&env))
        .await
        .expect_err("a write into an absent tenant cannot land");
    assert!(
        matches!(error, StoreError::NotFound),
        "an absent tenant must be the uniform not-found too: {error:?}"
    );
}

/// EVERY forced-row-level-security table declares a scope foreign key (issues #409, #449).
///
/// The recognition rule above asserts that every scope foreign key is RECOGNIZABLE. It
/// cannot see a scoped table that has no scope foreign key at all, and neither can the
/// behavioural test. Measured on the file as it stood BEFORE this test existed: dropping
/// `message_templates`' composite key without re-adding it left all four tests of that
/// version green, because the write then lands and the audit row's own recognized key
/// produces the not-found a caller sees. (On the current file that mutation fails two tests,
/// this one and the cascade check, which is the point.)
///
/// The module documentation above asserts this property in prose ("Every scoped table
/// carries a foreign key to `tenants` and, for the environment-scoped ones, a composite
/// foreign key to `environments`") and nothing enforced it. A scoped table without one is
/// worse than an unrecognized constraint: row-level security still hides its reads, so a
/// write into an absent scope SUCCEEDS and the row is then invisible to everybody.
///
/// BOTH HALVES OF THAT SENTENCE, because the first version of this test enforced only the
/// first. "A foreign key onto a scope table" is a DISJUNCTION: an environment-scoped table
/// carrying the single-column `tenants` key and no `environments` key satisfies it, and
/// that is precisely the write-into-an-absent-environment gap migration 0150 exists to
/// close. So the second assertion below requires an `environments` key of every table that
/// has an `environment_id` column at all. It costs nothing today: it passes against the
/// same three documented exceptions.
///
/// "Scoped" is read from the schema as forced row-level security, the same DEFINITION
/// `scripts/scoped-table-registration.sh` uses, though not the same SOURCE: that script
/// derives from migration TEXT and this reads the live catalogue. They can diverge, and in
/// one direction nothing catches it. A new scoped table is covered the moment it is
/// migrated, but a table LEAVING the subject set is invisible: `ALTER TABLE x NO FORCE ROW
/// LEVEL SECURITY` drops it out of this query while the script's regex still matches the
/// original `FORCE` statement, so its floor stays satisfied. Measured, `NO FORCE` plus
/// dropping that table's scope key passes both suites. Worth knowing rather than worth new
/// machinery: `NO FORCE` only affects the table owner, so the data plane is unaffected.
#[tokio::test]
async fn every_scoped_table_declares_a_scope_foreign_key() {
    // The scope tables THEMSELVES, held out as belt and braces rather than because they
    // reach this filter today. An earlier version of this comment said "both still force
    // row-level security", which is false: no migration enables it on either, so neither
    // can appear in `forced` and this exclusion is inert. Dropping it changes no outcome,
    // measured.
    //
    // It stays because the day either one is brought under forced row-level security is
    // exactly the day this test would start reporting the root of the scope tree as a gap.
    // Only `tenants` would need it even then: `environments` declares
    // `tenant_id text NOT NULL REFERENCES tenants (id)` (0001), a plain single-column key
    // onto a scope table, which `ForeignKey::onto_a_scope_table` accepts, so it lands in
    // `with_scope_key` on its own. `tenants` is the root and has nothing above it to
    // reference.
    const THE_SCOPE_TABLES: [&str; 2] = ["tenants", "environments"];

    // THREE TABLES THAT DO NOT SATISFY THE RULE TODAY, listed rather than filtered away.
    //
    // Every one predates this migration and belongs to a different subsystem, so fixing
    // them is issue #920 rather than this change: each needs its own schema migration, and
    // adding a foreign key VALIDATES existing rows, so on a deployment that already carries
    // an orphan the migration fails rather than the write. That is a decision to take
    // deliberately and not inside a naming fix.
    //
    // What each is missing, measured from its own migration:
    //
    // * `webhook_endpoints` (0111) declares NO foreign key at all, only a non-empty CHECK
    //   on the two scope columns. A store-level write naming an environment that never
    //   existed lands. The management handler resolves the scope first, so nothing reaches
    //   it today; the store invariant is still false.
    // * `webhook_delivery_attempts` (0113) keys onto `outbox_messages (id)`, and
    //   `user_trait_login_index` (0131) onto `users (id)`. Both parents are scoped, so in
    //   practice a ghost scope has no parent row to reference and the write fails on THAT
    //   key instead. That is a weaker guarantee than a scope key and it is not the one the
    //   module documentation above claims.
    //
    // Asserted as an EXACT set, both directions. A fourth table fails here the day it is
    // migrated, and so does fixing one of these three without removing it from this list,
    // which is what keeps the list from rotting into a permanent excuse.
    const KNOWN_MISSING: [&str; 3] = [
        "user_trait_login_index",
        "webhook_delivery_attempts",
        "webhook_endpoints",
    ];

    let db = TestDatabase::start().await;

    let forced: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relforcerowsecurity \
         ORDER BY c.relname",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("read the forced row-level-security tables");

    // A non-triviality floor, so an empty or truncated result cannot satisfy every assertion
    // below while measuring nothing. 100 rather than 50: the live schema has 117 and
    // `scripts/scoped-table-registration.sh` pins its own floor at 117, so a query that
    // silently returned 51 rows would have cleared the old bound by a factor of two.
    assert!(
        forced.len() > 100,
        "the schema must force row-level security on the scoped tables; found {} which \
         means this query is reading the wrong thing rather than that the tables are gone",
        forced.len()
    );

    // ONE read of the catalogue, used by both assertions. It was read twice.
    let keys = candidate_foreign_keys(&db).await;
    let with_scope_key: BTreeSet<&str> = keys
        .iter()
        .filter(|key| key.onto_a_scope_table())
        .map(|key| key.child.as_str())
        .collect();

    let missing: BTreeSet<&str> = forced
        .iter()
        .map(String::as_str)
        .filter(|table| !THE_SCOPE_TABLES.contains(table) && !with_scope_key.contains(*table))
        .collect();
    let known: BTreeSet<&str> = KNOWN_MISSING.into_iter().collect();
    let unexpected: Vec<&&str> = missing.difference(&known).collect();
    assert!(
        unexpected.is_empty(),
        "every table with forced row-level security must declare a foreign key onto a \
         scope table, or a write naming a scope that was never created SUCCEEDS and the row \
         it wrote is then reachable only by repeating that same absent scope, invisible to \
         every scope that exists. These do not, and are not on the documented list: \
         {unexpected:#?}"
    );
    let fixed: Vec<&&str> = known.difference(&missing).collect();
    assert!(
        fixed.is_empty(),
        "these are documented above as MISSING a scope foreign key and now have one, so \
         the list here is stale and hides the next real gap: {fixed:#?}"
    );

    // THE SECOND HALF: an ENVIRONMENT-scoped table needs an `environments` key specifically.
    // The assertion above accepts a `tenants` key alone, which is the shape 113 tables have
    // and which says nothing about whether a write into an absent ENVIRONMENT can land.
    let environment_scoped: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         JOIN pg_attribute a ON a.attrelid = c.oid \
         WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relforcerowsecurity \
         AND a.attname = 'environment_id' AND a.attnum > 0 AND NOT a.attisdropped \
         ORDER BY c.relname",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("read the environment-scoped tables");
    // ITS OWN FLOOR. This is a SECOND query with an extra join, so the floor above does not
    // bound it, and it hardcodes a COLUMN NAME (`environment_id`). That is the rot mode this
    // module's doc is written against: a migration renaming the scope column would reduce
    // this assertion to nothing while the first assertion and its floor stayed green.
    // Measured on the file as it stood BEFORE this floor existed: mutating this query to
    // return zero rows left the whole suite passing. With the floor it fails here.
    assert!(
        environment_scoped.len() > 100,
        "the schema must carry an environment_id column on the scoped tables; found {} \
         which means this query is reading the wrong thing",
        environment_scoped.len()
    );
    let onto_environments: BTreeSet<&str> = keys
        .iter()
        .filter(|key| key.parent == "environments")
        .map(|key| key.child.as_str())
        .collect();
    // `THE_SCOPE_TABLES` is inert HERE for a different reason than above: neither scope
    // table has an `environment_id` column, so neither can reach this subject set at all.
    // Kept for symmetry with the first assertion rather than because it filters anything.
    let missing_environment_key: Vec<&str> = environment_scoped
        .iter()
        .map(String::as_str)
        .filter(|table| !THE_SCOPE_TABLES.contains(table) && !onto_environments.contains(*table))
        .filter(|table| !known.contains(table))
        .collect();
    assert!(
        missing_environment_key.is_empty(),
        "every forced-row-level-security table with an environment_id column must declare \
         a foreign key onto environments, or a write naming an environment that never \
         existed lands: {missing_environment_key:#?}"
    );
}

/// The two constraints migration 0150 rewrites keep `ON DELETE CASCADE` (issues #111, #112).
///
/// 0150 DROPs and re-ADDs both keys, and its header states the delete behaviour is
/// "preserved exactly". Nothing measured that: re-adding either one without the clause left
/// every test in this file and in `message_templates.rs` and `flow_targets.rs` green.
///
/// Losing it is silent and permanent. Deleting an environment would fail on a dangling
/// template or flow target instead of cascading, and the migration that caused it is
/// checksummed, so the claim in its header could not be corrected afterwards.
#[tokio::test]
async fn the_rewritten_scope_keys_still_cascade_on_delete() {
    let db = TestDatabase::start().await;

    for (constraint, table) in [
        (
            "message_templates_environment_id_tenant_id_fkey",
            "message_templates",
        ),
        ("flow_targets_environment_id_tenant_id_fkey", "flow_targets"),
    ] {
        let definition: Option<String> = sqlx::query_scalar(
            "SELECT pg_get_constraintdef(con.oid) FROM pg_constraint con \
             JOIN pg_class child ON child.oid = con.conrelid \
             JOIN pg_namespace ns ON ns.oid = child.relnamespace \
             WHERE ns.nspname = 'public' AND con.contype = 'f' AND con.conname = $1",
        )
        .bind(constraint)
        .fetch_optional(db.owner_pool())
        .await
        .expect("read the constraint definition");

        // Its EXISTENCE under the new name first: without this the assertion below passes
        // vacuously on a `None` the day the constraint is renamed again.
        let definition = definition
            .unwrap_or_else(|| panic!("{table} must declare {constraint} after migration 0150"));
        assert!(
            definition.contains("ON DELETE CASCADE"),
            "{constraint} must keep ON DELETE CASCADE, which 0150 says it preserves \
             exactly: {definition}"
        );
    }
}

/// The `DO` block migration 0150 opens with, read out of the migration file itself.
///
/// `include_str!` rather than a copy, because a copy is what the previous version of the
/// test used and it measured nothing: three separate mutations of the shipped migration
/// (removing `nullif`, deleting the block, changing the default) all left the test green,
/// while mutating the copy failed it. A test that drives its own paraphrase is a test of the
/// paraphrase.
///
/// The `assert!` NAMES a failure rather than causing one, and an earlier version of this
/// sentence over-credited it: deleting the block is red either way, via the `.expect` on
/// `find`. What the assertion buys is the message. If the extraction ever picks up a
/// DIFFERENT `DO` block (one inserted earlier in the file, say), it says so instead of
/// letting the test fail as `left: "0" right: "3s"`.
///
/// What nothing here observes is the block's POSITION. Moving it after the `ALTER`s would
/// set `lock_timeout` after the locks it exists to bound, and this test would stay green;
/// 0150 is checksummed, so once shipped nobody can move it without a mismatch on every
/// deployed database, and that is what the property rests on.
fn lock_timeout_block() -> &'static str {
    const SQL: &str = include_str!("../migrations/0150_scope_fk_naming.sql");
    let start = SQL.find("DO $$").expect("0150 must open with a DO block");
    let end = SQL[start..]
        .find("$$;")
        .expect("the DO block must terminate")
        + start
        + 3;
    let block = &SQL[start..end];
    assert!(
        block.contains("set_config") && block.contains("lock_timeout"),
        "0150's DO block must still be the lock_timeout block: {block}"
    );
    block
}

/// Migration 0150's `lock_timeout` expression resolves in every state an operator can leave
/// the knob in (issues #111, #112).
///
/// This needs NO lock contention and no timing, which is the part an earlier round got
/// wrong: I declined to test the expression on the grounds that measuring a `lock_timeout`
/// means holding a lock, and the property that actually matters is not the WAIT, it is what
/// the expression evaluates to. There are three input states and they are all cheap.
///
/// The state that matters is the middle one. `current_setting(name, true)` returns NULL only
/// for a setting that was NEVER defined; for one an operator set and then cleared it returns
/// the EMPTY STRING, and `set_config('lock_timeout', '', true)` raises. Without `nullif` the
/// migration aborts for an operator who did nothing but tidy up a knob the header recommends,
/// with an error naming `lock_timeout` rather than the setting they touched. 0150 re-runs on
/// every new database on the cluster, so it is not a one-shot risk.
#[tokio::test]
async fn the_migration_lock_timeout_resolves_in_every_operator_state() {
    let db = TestDatabase::start().await;

    // (what the operator did, what `lock_timeout` must end up as)
    for (setup, expected) in [
        ("", "3s"),
        (
            "SET ironauth.migration_lock_timeout = '11s'; RESET ironauth.migration_lock_timeout;",
            "3s",
        ),
        ("SET ironauth.migration_lock_timeout = '21s';", "21s"),
    ] {
        let mut conn = db.owner_pool().acquire().await.expect("connection");
        if !setup.is_empty() {
            sqlx::raw_sql(setup)
                .execute(&mut *conn)
                .await
                .expect("apply the operator's setting");
        }
        // The block READ OUT OF 0150, not a copy of it. An earlier version of this test
        // pasted the expression here and claimed it "cannot drift from the migration by
        // being paraphrased", which was exactly backwards: nothing linked the two, so
        // mutating the shipped migration left this green while mutating the copy failed it.
        let sql = format!("BEGIN; {}", lock_timeout_block());
        sqlx::raw_sql(&sql)
            .execute(&mut *conn)
            .await
            .unwrap_or_else(|error| {
                panic!("the 0150 lock_timeout expression must not raise after `{setup}`: {error}")
            });
        let effective: String = sqlx::query_scalar("SHOW lock_timeout")
            .fetch_one(&mut *conn)
            .await
            .expect("read lock_timeout");
        sqlx::raw_sql("COMMIT;")
            .execute(&mut *conn)
            .await
            .expect("commit");
        assert_eq!(
            effective, expected,
            "after `{setup}` the migration must run with lock_timeout {expected}"
        );
    }
}
