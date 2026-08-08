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
    // The candidate ALTERS shipped tables, which is a materially different risk from
    // creating new ones: an additive statement against a live table can still take a
    // heavy lock or fail on existing data. Every alteration is enumerated so a new one
    // has to be argued for here rather than added quietly.
    //
    // Both current entries are safe for the same reason: neither can fail on any existing
    // row. `organizations` gains a NULLABLE column with no default, and `permissions`
    // gains a UNIQUE constraint on `(id, kind)` whose leading column is already the
    // primary key, so it adds no uniqueness that is not already guaranteed. The scan
    // above independently refuses `set not null`, `set default` and `alter column`, which
    // are the shapes that would make either of them unsafe.
    //
    // The list caught the first draft of this comment, which asserted `permissions` was
    // the only altered table. It was not.
    let alterations: Vec<&str> = statements
        .lines()
        .filter(|line| line.trim_start().starts_with("alter table"))
        .collect();
    assert_eq!(
        alterations,
        vec!["alter table organizations", "alter table permissions"],
        "the candidate alters a shipped table this review has not accounted for"
    );

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
///
/// This covers only the ORPHAN direction, which is the weaker half. That a plan cannot
/// bundle an ordinary permission is the half with teeth and it has its own test below.
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

/// A plan can bundle an ENTITLEMENT and cannot bundle an ordinary PERMISSION.
///
/// The half the orphan test above cannot see, and the one criterion 5 actually asks for
/// ("use the reserved slug namespace"). The reserved namespace is not a slug prefix: it is
/// `permissions.kind`, which migration 0091 shipped with `'entitlement'` admitted from day
/// one and its live-unique index keyed on, precisely so a plan slug and a permission slug
/// can coexist. The first draft of this candidate described a "reserved first segment" that
/// nothing implemented, and its plain `REFERENCES permissions (id)` would have let a plan
/// bundle `billing.invoice.delete`.
///
/// That is not a tidiness point. A plan is a BILLING artifact an operator edits to sell a
/// tier; a permission is a grant of authority. If one can carry the other, adding a plan is
/// writing an access-control policy without knowing it.
#[tokio::test]
async fn a_plan_can_bundle_an_entitlement_and_never_an_ordinary_permission() {
    let db = TestDatabase::start().await;
    sqlx::raw_sql(CANDIDATE)
        .execute(db.owner_pool())
        .await
        .expect("apply the candidate");

    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();

    for (id, kind, slug) in [
        ("prm_authority", "permission", "billing.invoice.delete"),
        ("prm_feature", "entitlement", "plan.seats"),
    ] {
        sqlx::query(
            "INSERT INTO permissions \
             (id, tenant_id, environment_id, kind, slug, display_name) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(id)
        .bind(&tenant)
        .bind(&environment)
        .bind(kind)
        .bind(slug)
        .bind(slug)
        .execute(db.owner_pool())
        .await
        .unwrap_or_else(|error| panic!("seed the {kind} row: {error}"));
    }

    sqlx::query(
        "INSERT INTO org_plans (id, tenant_id, environment_id, slug, display_name) \
         VALUES ('pln_k', $1, $2, 'plan.enterprise', 'Enterprise')",
    )
    .bind(&tenant)
    .bind(&environment)
    .execute(db.owner_pool())
    .await
    .expect("create a plan");

    // The entitlement bundles.
    sqlx::query(
        "INSERT INTO org_plan_features \
         (id, tenant_id, environment_id, plan_id, permission_id) \
         VALUES ('plf_ok', $1, $2, 'pln_k', 'prm_feature')",
    )
    .bind(&tenant)
    .bind(&environment)
    .execute(db.owner_pool())
    .await
    .expect(
        "a plan must be able to bundle an entitlement. If this fails the composite \
         foreign key is refusing everything and the test below proves nothing",
    );

    // The ordinary permission does not, and no value of `permission_kind` reaches it: the
    // CHECK refuses anything but 'entitlement', and 'entitlement' does not match the row.
    for attempted_kind in ["entitlement", "permission"] {
        let refused = sqlx::query(
            "INSERT INTO org_plan_features \
             (id, tenant_id, environment_id, plan_id, permission_id, permission_kind) \
             VALUES ($1, $2, $3, 'pln_k', 'prm_authority', $4)",
        )
        .bind(format!("plf_no_{attempted_kind}"))
        .bind(&tenant)
        .bind(&environment)
        .bind(attempted_kind)
        .execute(db.owner_pool())
        .await;
        assert!(
            refused.is_err(),
            "a plan bundled the ordinary permission billing.invoice.delete by writing \
             permission_kind={attempted_kind}. A billing artifact must not be able to \
             carry a grant of authority"
        );
    }
}

/// The reserved kind vocabulary is the SHIPPED one, not one this candidate invented.
///
/// Pinned against `pg_constraint` rather than read off the migration text, because the
/// whole design rests on `'entitlement'` being admissible in `permissions.kind` today. A
/// later migration narrowing that CHECK back to `'permission'` alone would silently make
/// every plan unbundlable, and it would break HERE with the reason attached rather than in
/// whichever PR first tried to graduate bet 3.
#[tokio::test]
async fn the_shipped_permissions_kind_check_admits_entitlement() {
    let db = TestDatabase::start().await;
    let definition: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
         WHERE conname = 'permissions_kind_known'",
    )
    .fetch_one(db.owner_pool())
    .await
    .expect("the shipped permissions kind CHECK exists");

    assert!(
        definition.contains("'entitlement'"),
        "permissions.kind no longer admits 'entitlement', so the reserved namespace this \
         candidate depends on is gone. Got: {definition}"
    );
    assert!(
        definition.contains("'permission'"),
        "permissions.kind no longer admits 'permission'. Got: {definition}"
    );
}
