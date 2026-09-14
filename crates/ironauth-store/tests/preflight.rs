// SPDX-License-Identifier: MIT OR Apache-2.0

//! `ironauth doctor`'s pre-upgrade data preflight, against a real database (issue #148).
//!
//! The pure derivation (which statement becomes which probe) is unit-tested beside the
//! parser in `src/preflight.rs`. What needs a database is the other half: that the probe
//! it derived, run against rows that are actually there, finds them; that it finds none
//! when there are none; and that the answer does not depend on which role asked.
//!
//! Every chain here is a custom one against a fresh, empty database. The shipped chain
//! is fully applied in any database the harness builds, so it has nothing pending and
//! could not exercise a pending constraint at all.

use ironauth_store::preflight::{self, UnansweredReason};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{Migration, MigrationRunner, Phase};

/// v1: a table with a nullable column, and no constraint on it yet.
const CREATE: &str = "\
CREATE TABLE widgets (id bigint PRIMARY KEY, owner text, region text);
CREATE TABLE owners (name text PRIMARY KEY);";

fn v1() -> Migration {
    Migration {
        version: 1,
        name: "create widgets",
        phase: Phase::Expand,
        sql: CREATE,
    }
}

fn pending(version: i64, name: &'static str, sql: &'static str) -> Migration {
    Migration {
        version,
        name,
        phase: Phase::Expand,
        sql,
    }
}

/// Apply v1, then seed whatever the case needs.
async fn database_at_v1(seed: &str) -> sqlx::PgPool {
    let pool = TestDatabase::fresh_owner_pool().await;
    MigrationRunner::from_migrations(&pool, vec![v1()])
        .run()
        .await
        .expect("v1 applies to an empty database");
    if !seed.is_empty() {
        // raw_sql, not query: a seed may hold several statements, and a prepared
        // statement takes exactly one.
        sqlx::raw_sql(seed)
            .execute(&pool)
            .await
            .expect("seed applies");
    }
    pool
}

/// The acceptance criterion, in its narrowest form: rows that are already there, a
/// pending migration that would reject them, and a preflight that says so BEFORE the
/// upgrade rather than after it has half happened.
#[tokio::test]
async fn seeded_rows_that_would_reject_a_pending_constraint_block_the_upgrade() {
    let pool = database_at_v1(
        "INSERT INTO widgets (id, owner, region) VALUES (1, 'a', 'eu'), (2, NULL, 'us'), (3, NULL, 'eu')",
    )
    .await;

    let chain = vec![
        v1(),
        pending(
            2,
            "owner becomes mandatory",
            "ALTER TABLE widgets ALTER COLUMN owner SET NOT NULL;",
        ),
    ];
    let report = preflight::run(&pool, &chain).await.expect("preflight runs");

    assert!(report.blocks(), "two NULL owners must block: {report:#?}");
    assert_eq!(
        report.pending,
        vec![(2, "owner becomes mandatory".to_owned())]
    );
    assert_eq!(report.findings.len(), 1);
    let finding = &report.findings[0];
    assert_eq!(finding.version, 2);
    assert_eq!(finding.rows, 2, "exactly the two rows with a NULL owner");
    assert!(
        report.unanswered.is_empty(),
        "nothing here is unreadable: {:?}",
        report.unanswered
    );

    // The criterion asks for the report CONTENT, not just the refusal. An operator who
    // cannot see which rows, in which migration, and how to list them has been told to
    // stop without being told what to do.
    let rendered = preflight::render(&report);
    assert!(
        rendered.contains("migration 2 (owner becomes mandatory)"),
        "{rendered}"
    );
    assert!(
        rendered.contains("widgets.owner becomes mandatory"),
        "{rendered}"
    );
    assert!(rendered.contains("2 row(s) in the way"), "{rendered}");
    assert!(
        rendered.contains("SELECT count(*) AS n FROM widgets WHERE owner IS NULL"),
        "the report must hand over the query that finds the rows: {rendered}"
    );
    assert!(rendered.contains("UPGRADE BLOCKED"), "{rendered}");
}

/// The same pending migration against data that satisfies it. Without this the test
/// above is satisfied by a preflight that blocks unconditionally.
#[tokio::test]
async fn the_same_pending_constraint_passes_when_no_row_violates_it() {
    let pool = database_at_v1(
        "INSERT INTO widgets (id, owner, region) VALUES (1, 'a', 'eu'), (2, 'b', 'us')",
    )
    .await;

    let chain = vec![
        v1(),
        pending(
            2,
            "owner becomes mandatory",
            "ALTER TABLE widgets ALTER COLUMN owner SET NOT NULL;",
        ),
    ];
    let report = preflight::run(&pool, &chain).await.expect("preflight runs");

    assert!(!report.blocks(), "no row violates it: {report:#?}");
    assert_eq!(report.probes_run, 1, "the probe must have actually run");
    assert!(report.findings.is_empty());
    let rendered = preflight::render(&report);
    assert!(
        rendered.contains("no row in this database would reject"),
        "{rendered}"
    );

    // And the migration really does apply, which is the claim the clean verdict makes.
    MigrationRunner::from_migrations(&pool, chain)
        .run()
        .await
        .expect("a clean preflight means the pending migration applies");
}

/// Blocking is not the same as understanding. A preflight that cannot read a statement
/// must say which one, and must not fold it into the clean verdict.
#[tokio::test]
async fn a_statement_the_preflight_cannot_read_blocks_and_is_named_as_unread() {
    let pool = database_at_v1("INSERT INTO widgets (id, owner) VALUES (1, 'a')").await;

    let chain = vec![
        v1(),
        pending(
            2,
            "widgets gain a primary key constraint",
            "ALTER TABLE owners ADD CONSTRAINT owners_pkey2 PRIMARY KEY (name);",
        ),
    ];
    let report = preflight::run(&pool, &chain).await.expect("preflight runs");

    assert!(report.blocks());
    assert!(
        report.findings.is_empty(),
        "there is no finding, only an unread statement"
    );
    assert_eq!(report.unanswered.len(), 1);
    assert_eq!(report.unanswered[0].reason, UnansweredReason::NotRead);

    let rendered = preflight::render(&report);
    assert!(
        rendered.contains("could NOT be checked. This is not a pass"),
        "{rendered}"
    );
    assert!(rendered.contains("PRIMARY KEY"), "{rendered}");
}

/// Most constraints in a migration are on tables that same migration creates. Nothing
/// can be stranded in a table that does not exist, so those probes are clean, and they
/// must be counted separately rather than inflating the number of probes that looked at
/// real rows.
#[tokio::test]
async fn a_constraint_on_a_table_a_pending_migration_creates_is_clean_and_counted_apart() {
    let pool = database_at_v1("").await;

    let chain = vec![
        v1(),
        pending(
            2,
            "a new table with its own constraint",
            "CREATE TABLE gadgets (id bigint PRIMARY KEY, size int);
             ALTER TABLE gadgets ADD CONSTRAINT gadgets_size_positive CHECK (size > 0);",
        ),
    ];
    let report = preflight::run(&pool, &chain).await.expect("preflight runs");

    assert!(!report.blocks(), "{report:#?}");
    assert_eq!(report.probes_not_yet_applicable, 1);
    assert_eq!(
        report.probes_run, 0,
        "no probe touched live rows, and the report must not claim one did"
    );
}

/// The column half of the same excuse, and the one a mutation sweep found uncovered.
///
/// A migration routinely adds a column and constrains it in the same file, so the probe
/// for the constraint names a column that is not there yet and Postgres answers
/// `undefined_column` rather than `undefined_table`. Excusing only `undefined_table`
/// leaves that probe reported as an unanswered failure, which blocks an upgrade that was
/// never at risk. Nothing here has rows to strand: the column does not exist.
#[tokio::test]
async fn a_constraint_on_a_column_the_same_pending_migration_adds_is_clean() {
    let pool = database_at_v1("INSERT INTO widgets (id, owner) VALUES (1, 'a')").await;

    let chain = vec![
        v1(),
        pending(
            2,
            "a new column with its own constraint",
            "ALTER TABLE widgets ADD COLUMN size int;
             ALTER TABLE widgets ADD CONSTRAINT widgets_size_positive CHECK (size > 0);",
        ),
    ];
    let report = preflight::run(&pool, &chain).await.expect("preflight runs");

    assert!(
        !report.blocks(),
        "a column that does not exist yet holds no rows to strand: {report:#?}"
    );
    assert_eq!(report.probes_not_yet_applicable, 1);
    assert_eq!(report.probes_run, 0);

    // And Postgres agrees the migration applies, which is what the clean verdict claims.
    MigrationRunner::from_migrations(&pool, chain)
        .run()
        .await
        .expect("adding a column and constraining it in one migration applies");
}

/// A CHECK is violated only when its expression is FALSE. A row whose expression is NULL
/// is ACCEPTED by Postgres, so a preflight that reports it has blocked an upgrade that
/// would have applied. This is the case that separates `IS FALSE` from `NOT (...)`, and
/// it is checked against Postgres rather than against the string the parser emitted.
#[tokio::test]
async fn a_null_expression_is_accepted_by_the_check_and_so_by_the_preflight() {
    let pool = database_at_v1(
        "INSERT INTO widgets (id, owner, region) VALUES (1, 'a', NULL), (2, 'b', 'eu')",
    )
    .await;

    let chain = vec![
        v1(),
        pending(
            2,
            "region must be known",
            "ALTER TABLE widgets ADD CONSTRAINT widgets_region_valid CHECK (region IN ('eu', 'us'));",
        ),
    ];
    let report = preflight::run(&pool, &chain).await.expect("preflight runs");

    assert!(
        !report.blocks(),
        "the NULL region does not violate the CHECK, so nothing should block: {report:#?}"
    );

    // Postgres is the authority on that claim, so make it answer: the constraint applies.
    MigrationRunner::from_migrations(&pool, chain)
        .run()
        .await
        .expect("Postgres accepts a CHECK whose expression is NULL for some rows");
}

/// The same shape with a row that genuinely violates it, so the test above is not
/// passing because the probe found nothing at all.
#[tokio::test]
async fn a_false_expression_is_rejected_by_the_check_and_so_by_the_preflight() {
    let pool = database_at_v1(
        "INSERT INTO widgets (id, owner, region) VALUES (1, 'a', NULL), (2, 'b', 'mars')",
    )
    .await;

    let chain = vec![
        v1(),
        pending(
            2,
            "region must be known",
            "ALTER TABLE widgets ADD CONSTRAINT widgets_region_valid CHECK (region IN ('eu', 'us'));",
        ),
    ];
    let report = preflight::run(&pool, &chain).await.expect("preflight runs");

    assert!(report.blocks());
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings[0].rows, 1,
        "only the 'mars' row, not the NULL one"
    );

    // And Postgres agrees that this one does not apply.
    let refused = MigrationRunner::from_migrations(&pool, chain).run().await;
    assert!(
        refused.is_err(),
        "the preflight blocked, so the migration must genuinely fail"
    );
}

/// A duplicate over the indexed columns blocks; NULLs do not, because a unique index
/// treats them as distinct.
#[tokio::test]
async fn a_unique_index_counts_duplicate_groups_and_ignores_nulls() {
    let pool = database_at_v1(
        "INSERT INTO widgets (id, owner, region) VALUES \
         (1, 'a', 'eu'), (2, 'a', 'eu'), (3, NULL, 'us'), (4, NULL, 'us'), (5, 'b', 'eu')",
    )
    .await;

    let chain = vec![
        v1(),
        pending(
            2,
            "owner and region are unique together",
            "CREATE UNIQUE INDEX widgets_owner_region ON widgets (owner, region);",
        ),
    ];
    let report = preflight::run(&pool, &chain).await.expect("preflight runs");

    assert!(report.blocks());
    assert_eq!(
        report.findings[0].rows, 1,
        "one duplicated group ('a','eu'); the two NULL owners are distinct to the index"
    );

    // Postgres settles both halves: it refuses this index, and it accepts the same index
    // once only the NULL pair remains.
    let refused = MigrationRunner::from_migrations(&pool, chain).run().await;
    assert!(
        refused.is_err(),
        "the duplicate must genuinely refuse the index"
    );

    sqlx::query("DELETE FROM widgets WHERE id = 2")
        .execute(&pool)
        .await
        .expect("remove the duplicate");
    let chain = vec![
        v1(),
        pending(
            2,
            "owner and region are unique together",
            "CREATE UNIQUE INDEX widgets_owner_region ON widgets (owner, region);",
        ),
    ];
    let report = preflight::run(&pool, &chain).await.expect("preflight runs");
    assert!(
        !report.blocks(),
        "with the duplicate gone the two NULL rows must not block: {report:#?}"
    );
    MigrationRunner::from_migrations(&pool, chain)
        .run()
        .await
        .expect("Postgres accepts a unique index over rows whose key is NULL");
}

/// An orphan blocks a pending foreign key; a NULL reference does not.
#[tokio::test]
async fn a_foreign_key_counts_orphans_and_permits_a_null_reference() {
    let pool = database_at_v1(
        "INSERT INTO owners (name) VALUES ('a'); \
         INSERT INTO widgets (id, owner) VALUES (1, 'a'), (2, NULL), (3, 'ghost')",
    )
    .await;

    let chain = vec![
        v1(),
        pending(
            2,
            "widgets reference owners",
            "ALTER TABLE widgets ADD CONSTRAINT widgets_owner_fk \
             FOREIGN KEY (owner) REFERENCES owners (name);",
        ),
    ];
    let report = preflight::run(&pool, &chain).await.expect("preflight runs");

    assert!(report.blocks());
    assert_eq!(
        report.findings[0].rows, 1,
        "only the 'ghost' row; a NULL reference is permitted by a foreign key"
    );
    let refused = MigrationRunner::from_migrations(&pool, chain).run().await;
    assert!(refused.is_err(), "the orphan must genuinely refuse the key");
}

/// A database already at the head of the chain has nothing pending, and must say so
/// rather than report a clean scan it never performed.
#[tokio::test]
async fn a_database_at_the_head_of_the_chain_reports_nothing_pending() {
    let pool = database_at_v1("").await;
    let report = preflight::run(&pool, &[v1()])
        .await
        .expect("preflight runs");

    assert!(!report.blocks());
    assert!(report.pending.is_empty());
    assert_eq!(report.probes_run, 0);
    assert!(
        preflight::render(&report).contains("nothing is pending"),
        "{}",
        preflight::render(&report)
    );
}

/// The false-pass guard, and the reason `ironauth doctor` asks before it reports.
///
/// The scoped tables are FORCE ROW LEVEL SECURITY and `ironauth_app` is deliberately
/// neither superuser nor owner, so a probe on that connection returns zero rows for
/// every scoped table no matter what is in them. Zero rows is what a clean preflight
/// looks like, so running the doctor on the server's own credential would not be
/// occasionally wrong: it would be reassuring and wrong, always.
#[tokio::test]
async fn the_application_role_cannot_see_through_row_level_security_and_says_so() {
    let database = TestDatabase::start().await;

    assert!(
        !database
            .store()
            .sees_through_row_level_security()
            .await
            .expect("the app role can read pg_roles"),
        "ironauth_app must report that it is restricted, so the doctor refuses to use it"
    );
    assert!(
        database
            .audit_retention_store()
            .sees_through_row_level_security()
            .await
            .is_ok(),
        "the probe must answer for any role, not error"
    );
}
