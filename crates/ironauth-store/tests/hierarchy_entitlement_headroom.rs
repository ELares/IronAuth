// SPDX-License-Identifier: MIT OR Apache-2.0

//! The hierarchy and entitlement extensions need no breaking migration (issue #103,
//! acceptance criterion 4).
//!
//! The criterion asks for "a recorded schema review [that] confirms hierarchy and
//! entitlement extensions require no breaking migration, WITH A MIGRATION DRY-RUN AS
//! EVIDENCE". A review that concludes "no breaking migration" without attempting one is a
//! claim about code nobody has written, and it is the kind of claim that reads as settled
//! for years and turns out false the day someone tries.
//!
//! So this is the attempt. It applies the candidate migration
//! (`docs/design/candidate-0999-hierarchy-entitlements.sql`) to a real database ON TOP OF
//! the entire shipped chain, and then asserts the two properties that make it non
//! breaking: it applies at all, and it is purely additive.
//!
//! # Why the candidate is not in the migrations directory
//!
//! Shipping it would graduate bets 2 and 3, which #103 explicitly does not do. It lives
//! in `docs/design/` and is exercised from here, so the evidence stays true as the
//! shipped chain moves underneath it: if a future migration makes these extensions
//! impossible, this test goes red and the review's conclusion is retracted by the build
//! rather than by somebody noticing.
//!
//! # What "no breaking migration" is taken to mean, concretely
//!
//! Every statement is `ADD COLUMN` (nullable, no default), `CREATE TABLE`, or `CREATE
//! INDEX`. Nothing drops, renames, retypes, or backfills. A nullable column with no
//! default rewrites no rows and invalidates no existing query; a new table is invisible
//! to everything that does not name it. Those are checkable properties, which is why they
//! are the definition used rather than a prose judgement.

use ironauth_store::test_support::TestDatabase;

/// The candidate, read at compile time so a rename cannot leave this test silently
/// exercising nothing.
const CANDIDATE: &str =
    include_str!("../../../docs/design/candidate-0999-hierarchy-entitlements.sql");

/// Statement shapes that would make the migration BREAKING.
const DESTRUCTIVE: &[&str] = &[
    "drop table",
    "drop column",
    "drop constraint",
    "rename to",
    "rename column",
    "alter column",
    "set not null",
    "set default",
    "update ",
    "delete from",
    "truncate",
];

#[test]
fn the_candidate_is_purely_additive() {
    let lowered = CANDIDATE.to_ascii_lowercase();
    // Comments explain what the file does NOT do, and name those very shapes, so the
    // scan reads statements only.
    let statements: String = lowered
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");

    for shape in DESTRUCTIVE {
        assert!(
            !statements.contains(shape),
            "the candidate migration contains {shape:?}, which makes it BREAKING. The \
             review's conclusion is that these extensions are additive; a statement that \
             drops, renames, retypes or backfills retracts it."
        );
    }
    // Non-vacuity: the file really does declare the extensions, so a truncated or empty
    // read cannot pass the scan above trivially.
    for expected in [
        "create table org_policy_inheritance",
        "create table org_plans",
        "create table org_plan_features",
        "create table org_plan_assignments",
    ] {
        assert!(
            statements.contains(expected),
            "the candidate does not declare {expected:?}, so this test is not reading \
             the extensions it claims to review"
        );
    }
}

/// The dry run: the candidate applies to a database carrying the WHOLE shipped chain.
///
/// This is the half a text scan cannot do. Additive statements still fail if they name a
/// table that no longer exists, a column that was renamed, or a foreign key whose target
/// lost its unique constraint, and every one of those is a way the shipped chain could
/// drift out from under this design without anyone noticing.
#[tokio::test]
async fn the_candidate_applies_on_top_of_the_shipped_chain() {
    let db = TestDatabase::start().await;
    // `TestDatabase::start` has already run the production chain, so the database this
    // executes against is the real shipped schema, not a hand-built subset.
    sqlx::raw_sql(CANDIDATE)
        .execute(db.owner_pool())
        .await
        .expect(
            "the candidate hierarchy/entitlement migration must apply cleanly on top of \
             the shipped chain. If this fails, the schema review recorded on issue #103 \
             is no longer true: something in the chain has made these extensions require \
             a breaking change, and the design needs revisiting rather than the test \
             being deleted",
        );
}

/// The entitlement finding, asserted rather than described: a FEATURE is a permission.
///
/// This is the decision the criterion asks to be confirmed, that "no schema decision
/// makes features a second universe". `org_plan_features` carries a foreign key to
/// `permissions`, so a plan cannot grant a feature the vocabulary does not define, and a
/// future `isEntitled` resolves permissions and features through one join rather than
/// reconciling two systems.
#[tokio::test]
async fn a_plan_can_only_grant_a_feature_the_permission_vocabulary_defines() {
    let db = TestDatabase::start().await;
    sqlx::raw_sql(CANDIDATE)
        .execute(db.owner_pool())
        .await
        .expect("apply the candidate");

    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;

    sqlx::query(
        "INSERT INTO org_plans (id, tenant_id, environment_id, slug, display_name) \
         VALUES ('pln_x', $1, $2, 'plan.pro', 'Pro')",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(db.owner_pool())
    .await
    .expect("create a plan");

    // A feature slug that is NOT in the permission vocabulary must be unrepresentable.
    let orphan = sqlx::query(
        "INSERT INTO org_plan_features \
         (id, tenant_id, environment_id, plan_id, permission_id) \
         VALUES ('plf_x', $1, $2, 'pln_x', 'prm_does_not_exist')",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(db.owner_pool())
    .await;

    assert!(
        orphan.is_err(),
        "a plan granted a feature the permission vocabulary does not define. That is \
         precisely 'features as a second universe': the two would drift, and no single \
         check could answer whether a caller is entitled"
    );
}
