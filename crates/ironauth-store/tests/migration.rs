// SPDX-License-Identifier: MIT OR Apache-2.0

//! The expand-contract migration framework, against a real database.
//!
//! Custom chains run against a fresh, empty database (an empty ledger) so they
//! are isolated from the two-migration production chain. The worked
//! expand-contract example lives here as a test-only chain (it never ships to a
//! real schema), and the production chain is separately asserted to contain
//! only its two migrations and leave no demo object behind.

use std::time::Duration;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{Migration, MigrationError, MigrationRunner, NewOutboxMessage, Phase};
use sqlx::Row;

/// What every shipped migration is ABOUT, in chain order, comma separated.
///
/// A `const` rather than a literal inside an assertion message, because
/// [`production_chain_is_only_the_real_migrations_and_ships_no_demo_object`] asserts its
/// length against the applied count. As a message it was decoration: nothing read it, so
/// nothing noticed a subject that was never written down.
const CHAIN_SUBJECTS: &str = "isolation, audit log, \
     management API, OIDC authorization, signing keys, login/consent, authentication \
     context, redirect registration, UserInfo claims, consent scope upsert, resource \
     servers, opaque access \
     tokens, client auth suite, dynamic client registration, pushed authorization requests, \
     refresh tokens, client-credentials service accounts, DCR abuse controls, resource \
     indicators, JWT bearer assertion grant, device authorization, session model, RP-initiated \
     logout, session-ended events, back-channel logout, front-channel logout, resource-model \
     APIs, envelope encryption, environment guardrails, tenant lifecycle, BYOK bindings, \
     snapshot export, custom domains, environment secrets and variables, config promotion, \
     self-service account, admin user lifecycle, identity traits, foreign password \
     import, user invitations, flexible identifiers, exit-export credential grants, \
     migration state machine, webauthn credentials, totp credentials, credential abuse \
     defenses, step-up policies, email OTP and scanner-safe magic links, credential-class \
     policies, guarded SMS OTP, passkey attestation, admin sudo elevations, trusted devices, \
     risk engine, account recovery, federation connectors, registration abuse defenses, \
     federation login state, enterprise inbound routing, upstream token vault, \
     guarded account links, account linking wiring, FedCM assertion nonces, third-party \
     risk signals, signup fraud review, advanced recovery modes, headless flows, branding, \
     locale bundles, brand assets, diagnostic reason detail, diagnostics control read, \
     policy decision traces, flows control read, signup forms, consent lockdown, client admin \
     grants, consent control grants, flow version pin, flow versions, first-party challenge \
     codes, DPoP binding, DPoP proof replay, organization membership, organization token \
     context, organization roles, organization groups, organization group members, \
     organization role assignments, organization authentication policies, permission \
     vocabulary, role-to-permission mapping, organization default role, resource-server \
     permission claims, token size event budget columns, client allowed scopes, \
     email-factor downgrade configuration, control-plane dead-surface grants, generic \
     transactional outbox, control-plane writes on environment secrets, \
     control-plane writes on the migration-run ledger, outbox retention, \
     broker cutover and policy bounds, user identifier delete grant, \
     sms otp control grants, column scope consume latches, \
     column scope remaining app updates, \
     unused app insert and delete grants, idempotency key retention, \
     step up policy control grants, webhook endpoints, webhook secret rotation, webhook \
     delivery attempts, webhook auto disable, client par requirement control grant, webhook \
     event type filter, domain rule verification, management credential grants, management credential org confinement, project grants, org scoped clients, org token lifetime, api keys, membership principal arc, \
     control reads service account identity, \
     service account membership uniqueness, \
     control reads service account client, \
     impersonation sessions, \
     impersonated refresh families, \
     impersonation authorizations, user trait login index, backfill login index job \
     kind, audit stream, audit stream backfill, audit chain, audit retention role, log streams, audit organization, log stream organization, log stream dead letters, \
     authorization code DPoP binding, client allow bearer tokens, \
     client token exchange policy, log stream signing secret, message templates, \
     flow targets, \
     CIBA backchannel authentication requests, \
     client backchannel delivery, \
     external issuer audience allow, scope fk naming, \
     backchannel approved requires grant, backchannel approved grant validated, \
     external issuer control grants, outbound messages, sealed message recipient, \
     message sending state, message suppressions, message resend count, \
     declarative claim mappings, claim mappings data plane read, claim mapping delete grant, token hooks, token hooks delete grant, token hook failure policy, token hook versions, \
     token hook component bound, token hook ordering, token hook named identity, \
     token hook secrets, token hook fetch budget, challenge components, aot artifacts, \
     session token templates.";

/// A throwaway migration with the given version, phase, and SQL text.
fn step(version: i64, phase: Phase, sql: &'static str) -> Migration {
    Migration {
        version,
        name: "test-step",
        phase,
        sql,
    }
}

async fn table_exists(pool: &sqlx::PgPool, name: &str) -> bool {
    sqlx::query("SELECT to_regclass($1) IS NOT NULL AS present")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("regclass lookup")
        .get("present")
}

async fn column_exists(pool: &sqlx::PgPool, table: &str, column: &str) -> bool {
    sqlx::query(
        "SELECT EXISTS ( \
            SELECT 1 FROM information_schema.columns \
            WHERE table_name = $1 AND column_name = $2 \
         ) AS present",
    )
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await
    .expect("column lookup")
    .get("present")
}

/// The SQL `data_type` of `table.column` (`information_schema.columns`), for
/// asserting a sealed column is a `bytea` (secret material at rest is ciphertext).
async fn column_data_type(pool: &sqlx::PgPool, table: &str, column: &str) -> String {
    sqlx::query(
        "SELECT data_type FROM information_schema.columns \
         WHERE table_name = $1 AND column_name = $2",
    )
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await
    .expect("data type lookup")
    .get("data_type")
}

/// Whether `table.column` is declared `NOT NULL` (`information_schema.columns`).
async fn column_is_not_null(pool: &sqlx::PgPool, table: &str, column: &str) -> bool {
    let is_nullable: String = sqlx::query(
        "SELECT is_nullable FROM information_schema.columns \
         WHERE table_name = $1 AND column_name = $2",
    )
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await
    .expect("nullability lookup")
    .get("is_nullable");
    is_nullable == "NO"
}

/// The `column_default` expression of `table.column` (`information_schema.columns`), or
/// `None` when the column carries no default.
async fn column_default(pool: &sqlx::PgPool, table: &str, column: &str) -> Option<String> {
    sqlx::query(
        "SELECT column_default FROM information_schema.columns \
         WHERE table_name = $1 AND column_name = $2",
    )
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await
    .expect("default lookup")
    .get("column_default")
}

/// Whether `role` holds `privilege` (e.g. `UPDATE`) on `table` (`has_table_privilege`).
/// Used to prove a security-immutability property physically: the app role must NOT hold
/// UPDATE on an immutable snapshot table, so a widened grant fails the guard closed.
async fn role_has_table_privilege(
    pool: &sqlx::PgPool,
    role: &str,
    table: &str,
    privilege: &str,
) -> bool {
    sqlx::query("SELECT has_table_privilege($1, $2, $3) AS present")
        .bind(role)
        .bind(table)
        .bind(privilege)
        .fetch_one(pool)
        .await
        .expect("table privilege lookup")
        .get("present")
}

/// Whether `role` holds `privilege` on the specific `table`.`column`
/// (`has_column_privilege`). Used to prove a grant is COLUMN-scoped: the control role may
/// UPDATE only the named column, and the app role holds no such grant, so a widened grant
/// (table-wide, or reaching the app role) fails the guard closed.
async fn role_has_column_privilege(
    pool: &sqlx::PgPool,
    role: &str,
    table: &str,
    column: &str,
    privilege: &str,
) -> bool {
    sqlx::query("SELECT has_column_privilege($1, $2, $3, $4) AS present")
        .bind(role)
        .bind(table)
        .bind(column)
        .bind(privilege)
        .fetch_one(pool)
        .await
        .expect("column privilege lookup")
        .get("present")
}

/// Every live column of `table` on which `role` holds UPDATE, in catalog order.
///
/// The positive form of `role_has_any_column_privilege`: rather than asking whether some
/// column is writable, it names WHICH are, so a test can assert the exact set. A hand-written
/// list of columns NOT to be writable silently stops covering a column the table gains later,
/// and worse, is easy to write so that it omits the columns that matter.
async fn writable_columns(pool: &sqlx::PgPool, role: &str, table: &str) -> Vec<String> {
    sqlx::query(
        "SELECT a.attname::text AS column_name \
         FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid \
         WHERE c.relname::text = $2 AND a.attnum > 0 AND NOT a.attisdropped \
           AND has_column_privilege($1, c.oid, a.attnum, 'UPDATE') \
         ORDER BY a.attnum",
    )
    .bind(role)
    .bind(table)
    .fetch_all(pool)
    .await
    .expect("writable column sweep")
    .into_iter()
    .map(|row| row.get::<String, _>("column_name"))
    .collect()
}

/// Whether `role` holds `privilege` on ANY live column of `table`, swept over the
/// catalog rather than a hand-written column list (so a column added later is
/// covered the moment it exists).
///
/// This is the only way to prove a role holds NO write grant of any shape:
/// `has_table_privilege` does NOT see a COLUMN-scoped grant, so
/// `GRANT INSERT (id, ...) ON t TO r` leaves the table-wide probe reading false
/// while genuinely allowing the write.
async fn role_has_any_column_privilege(
    pool: &sqlx::PgPool,
    role: &str,
    table: &str,
    privilege: &str,
) -> bool {
    sqlx::query(
        "SELECT COALESCE(bool_or(has_column_privilege($1, c.oid, a.attnum, $3)), false) \
         AS present \
         FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid \
         WHERE c.relname::text = $2 AND a.attnum > 0 AND NOT a.attisdropped",
    )
    .bind(role)
    .bind(table)
    .bind(privilege)
    .fetch_one(pool)
    .await
    .expect("column privilege sweep")
    .get("present")
}

/// Whether the VIEW `view` exposes an output column named `column` (`pg_class` relkind `v`).
/// Used to prove the scope-forced guardrail projection actually SURFACES a column to the data
/// plane, not merely that the base table carries it.
async fn view_exposes_column(pool: &sqlx::PgPool, view: &str, column: &str) -> bool {
    sqlx::query(
        "SELECT EXISTS ( \
            SELECT 1 FROM pg_catalog.pg_attribute att \
            JOIN pg_catalog.pg_class c ON c.oid = att.attrelid \
            WHERE c.relname = $1 AND c.relkind = 'v' \
              AND att.attname = $2 AND att.attnum > 0 AND NOT att.attisdropped \
         ) AS present",
    )
    .bind(view)
    .bind(column)
    .fetch_one(pool)
    .await
    .expect("view column lookup")
    .get("present")
}

/// Whether `table` has BOTH `ENABLE` and `FORCE` row-level security on (`pg_class`).
async fn rls_enabled_and_forced(pool: &sqlx::PgPool, table: &str) -> bool {
    sqlx::query(
        "SELECT (relrowsecurity AND relforcerowsecurity) AS present \
         FROM pg_catalog.pg_class WHERE oid = $1::regclass",
    )
    .bind(table)
    .fetch_one(pool)
    .await
    .expect("rls lookup")
    .get("present")
}

/// Whether a row-level-security policy named `policy` exists on `table`.
async fn policy_exists(pool: &sqlx::PgPool, table: &str, policy: &str) -> bool {
    sqlx::query(
        "SELECT EXISTS ( \
            SELECT 1 FROM pg_catalog.pg_policies \
            WHERE tablename = $1 AND policyname = $2 \
         ) AS present",
    )
    .bind(table)
    .bind(policy)
    .fetch_one(pool)
    .await
    .expect("policy lookup")
    .get("present")
}

/// Whether a CHECK constraint named `constraint_name` exists on `table`.
async fn check_constraint_exists(pool: &sqlx::PgPool, table: &str, constraint_name: &str) -> bool {
    sqlx::query(
        "SELECT EXISTS ( \
            SELECT 1 FROM pg_catalog.pg_constraint \
            WHERE conrelid = $1::regclass AND contype = 'c' AND conname = $2 \
         ) AS present",
    )
    .bind(table)
    .bind(constraint_name)
    .fetch_one(pool)
    .await
    .expect("check constraint lookup")
    .get("present")
}

/// Whether `table` has a FOREIGN KEY on `column` whose `ON DELETE` action is CASCADE
/// (`pg_constraint.confdeltype = 'c'`). Used to prove the upstream token vault shares the
/// session's lifetime: deleting the session CASCADE-deletes its captured tokens.
async fn fk_on_delete_cascade(pool: &sqlx::PgPool, table: &str, column: &str) -> bool {
    sqlx::query(
        "SELECT EXISTS ( \
            SELECT 1 FROM pg_catalog.pg_constraint con \
            JOIN pg_catalog.pg_attribute att \
              ON att.attrelid = con.conrelid AND att.attnum = ANY (con.conkey) \
            WHERE con.conrelid = $1::regclass AND con.contype = 'f' \
              AND con.confdeltype = 'c' AND att.attname = $2 \
         ) AS present",
    )
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await
    .expect("fk cascade lookup")
    .get("present")
}

/// Whether `table` has a FOREIGN KEY constraint on `column` (any referential action).
/// Used to prove `account_links` references its owning local user.
async fn fk_references(pool: &sqlx::PgPool, table: &str, column: &str) -> bool {
    sqlx::query(
        "SELECT EXISTS ( \
            SELECT 1 FROM pg_catalog.pg_constraint con \
            JOIN pg_catalog.pg_attribute att \
              ON att.attrelid = con.conrelid AND att.attnum = ANY (con.conkey) \
            WHERE con.conrelid = $1::regclass AND con.contype = 'f' \
              AND att.attname = $2 \
         ) AS present",
    )
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await
    .expect("fk lookup")
    .get("present")
}

/// Whether a UNIQUE constraint named `constraint_name` exists on `table`
/// (`pg_constraint.contype = 'u'`). Used to prove the `account_links` anti-takeover
/// invariant: a federated identity resolves to at most one local user per scope.
async fn unique_constraint_exists(pool: &sqlx::PgPool, table: &str, constraint_name: &str) -> bool {
    sqlx::query(
        "SELECT EXISTS ( \
            SELECT 1 FROM pg_catalog.pg_constraint \
            WHERE conrelid = $1::regclass AND contype = 'u' AND conname = $2 \
         ) AS present",
    )
    .bind(table)
    .bind(constraint_name)
    .fetch_one(pool)
    .await
    .expect("unique constraint lookup")
    .get("present")
}

/// Whether a PARTIAL non-unique index named `index` exists on `table` (an index
/// with a `WHERE` predicate that does NOT enforce uniqueness).
///
/// Used to prove a TRAVERSAL index really is present. A missing traversal index is
/// invisible to every functional assertion (the query still returns the right rows)
/// and shows up only as a sequential scan per recursion level, so it has to be
/// asserted structurally or not at all.
async fn partial_index_exists(pool: &sqlx::PgPool, table: &str, index: &str) -> bool {
    sqlx::query(
        "SELECT EXISTS ( \
            SELECT 1 FROM pg_catalog.pg_index i \
            JOIN pg_catalog.pg_class c ON c.oid = i.indexrelid \
            WHERE i.indrelid = $1::regclass AND c.relname = $2 \
              AND NOT i.indisunique AND i.indpred IS NOT NULL \
         ) AS present",
    )
    .bind(table)
    .bind(index)
    .fetch_one(pool)
    .await
    .expect("partial index lookup")
    .get("present")
}

/// The leading column names of `index`, in index order.
///
/// The recursive descendant walk joins each child's `parent_id` against the current
/// frontier, so `parent_id` must lead the index after the scope columns. An index
/// with the right NAME and the wrong COLUMN ORDER serves the walk no better than no
/// index at all, and nothing else in the suite can tell the difference.
async fn index_columns(pool: &sqlx::PgPool, table: &str, index: &str) -> Vec<String> {
    sqlx::query(
        "SELECT a.attname::text AS column_name \
           FROM pg_catalog.pg_index i \
           JOIN pg_catalog.pg_class c ON c.oid = i.indexrelid \
           JOIN generate_subscripts(i.indkey, 1) AS k(position) ON true \
           JOIN pg_catalog.pg_attribute a \
             ON a.attrelid = i.indrelid AND a.attnum = i.indkey[k.position] \
          WHERE i.indrelid = $1::regclass AND c.relname = $2 \
          ORDER BY k.position",
    )
    .bind(table)
    .bind(index)
    .fetch_all(pool)
    .await
    .expect("index column lookup")
    .iter()
    .map(|row| row.get::<String, _>("column_name"))
    .collect()
}

/// Whether a PARTIAL UNIQUE index named `index` exists on `table` (unique with a
/// `WHERE` predicate).
async fn partial_unique_index_exists(pool: &sqlx::PgPool, table: &str, index: &str) -> bool {
    sqlx::query(
        "SELECT EXISTS ( \
            SELECT 1 FROM pg_catalog.pg_index i \
            JOIN pg_catalog.pg_class c ON c.oid = i.indexrelid \
            WHERE i.indrelid = $1::regclass AND c.relname = $2 \
              AND i.indisunique AND i.indpred IS NOT NULL \
         ) AS present",
    )
    .bind(table)
    .bind(index)
    .fetch_one(pool)
    .await
    .expect("partial unique index lookup")
    .get("present")
}

/// The rendered `WHERE` predicate of a partial index, as Postgres stores it.
///
/// [`partial_unique_index_exists`] reads only `indpred IS NOT NULL` and
/// [`index_columns`] reads only `indkey`, so BOTH are blind to a predicate that was
/// NARROWED rather than removed. Narrowing a live-uniqueness predicate is a real
/// weakening (it stops refusing duplicates for every row the narrower predicate
/// excludes) and it is invisible to every structural probe that does not read the
/// predicate TEXT, which is why the text is pinned exactly as the constraint text is.
async fn index_predicate(pool: &sqlx::PgPool, table: &str, index: &str) -> String {
    sqlx::query(
        "SELECT pg_get_expr(i.indpred, i.indrelid) AS predicate \
           FROM pg_catalog.pg_index i \
           JOIN pg_catalog.pg_class c ON c.oid = i.indexrelid \
          WHERE i.indrelid = $1::regclass AND c.relname = $2",
    )
    .bind(table)
    .bind(index)
    .fetch_one(pool)
    .await
    .expect("partial index predicate lookup")
    .get::<Option<String>, _>("predicate")
    .unwrap_or_else(|| panic!("{index} on {table} must be a PARTIAL index"))
}

#[tokio::test]
async fn in_order_apply_records_each_and_is_idempotent() {
    let pool = TestDatabase::fresh_owner_pool().await;
    let chain = vec![
        step(1, Phase::Expand, "CREATE TABLE mtest_a (id int);"),
        step(2, Phase::Expand, "CREATE TABLE mtest_b (id int);"),
        step(3, Phase::Expand, "CREATE TABLE mtest_c (id int);"),
    ];

    let report = MigrationRunner::from_migrations(&pool, chain.clone())
        .run()
        .await
        .expect("apply chain");
    assert_eq!(
        report.newly_applied().to_vec(),
        vec![1_i64, 2, 3],
        "all three applied in order"
    );
    assert_eq!(report.already_applied(), 0);

    // The ledger recorded each migration.
    let recorded: i64 = sqlx::query("SELECT count(*) AS c FROM _schema_migrations")
        .fetch_one(&pool)
        .await
        .expect("count ledger")
        .get("c");
    assert_eq!(recorded, 3, "each migration is recorded");

    // Each table was created.
    for table in ["mtest_a", "mtest_b", "mtest_c"] {
        assert!(table_exists(&pool, table).await, "{table} should exist");
    }

    // Idempotent: a second run applies nothing.
    let again = MigrationRunner::from_migrations(&pool, chain)
        .run()
        .await
        .expect("re-run chain");
    assert!(
        again.newly_applied().is_empty(),
        "a second run applies nothing"
    );
    assert_eq!(again.already_applied(), 3);
}

#[tokio::test]
async fn out_of_order_application_is_rejected_and_applies_nothing() {
    let pool = TestDatabase::fresh_owner_pool().await;
    let m1 = step(1, Phase::Expand, "CREATE TABLE mooo_1 (id int);");
    let m2 = step(2, Phase::Expand, "CREATE TABLE mooo_2 (id int);");
    let m3 = step(3, Phase::Expand, "CREATE TABLE mooo_3 (id int);");

    // Apply only version 1.
    MigrationRunner::from_migrations(&pool, vec![m1])
        .run()
        .await
        .expect("apply version 1");

    // Plant version 3 as already applied (with its correct checksum, so the
    // checksum check passes and the ORDERING check is what fires) while version
    // 2 remains pending.
    sqlx::query(
        "INSERT INTO _schema_migrations (version, name, checksum, phase) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(m3.version)
    .bind(m3.name)
    .bind(m3.checksum())
    .bind(m3.phase.as_str())
    .execute(&pool)
    .await
    .expect("plant version 3");

    // Running [1, 2, 3] now: version 2 is pending but version 3 is applied.
    let err = MigrationRunner::from_migrations(&pool, vec![m1, m2, m3])
        .run()
        .await
        .expect_err("out-of-order application must be refused");
    assert!(
        matches!(
            err,
            MigrationError::OutOfOrder {
                applied: 3,
                missing: 2
            }
        ),
        "expected OutOfOrder{{applied:3, missing:2}}, got: {err:?}"
    );

    // A refused run applies nothing: version 2's table was never created.
    assert!(
        !table_exists(&pool, "mooo_2").await,
        "a rejected run must apply nothing"
    );
}

#[tokio::test]
async fn checksum_mismatch_on_an_applied_migration_is_rejected() {
    let pool = TestDatabase::fresh_owner_pool().await;

    // Apply version 1 with its original text.
    MigrationRunner::from_migrations(
        &pool,
        vec![step(1, Phase::Expand, "CREATE TABLE mck_1 (id int);")],
    )
    .run()
    .await
    .expect("apply original");

    // Present the same version with different text: its checksum no longer
    // matches what the ledger recorded.
    let tampered = step(1, Phase::Expand, "CREATE TABLE mck_1_tampered (id int);");
    let err = MigrationRunner::from_migrations(&pool, vec![tampered])
        .run()
        .await
        .expect_err("a checksum drift must be refused");
    assert!(
        matches!(err, MigrationError::ChecksumMismatch { version: 1 }),
        "expected ChecksumMismatch{{version:1}}, got: {err:?}"
    );
}

/// The worked expand-contract example, TEST-ONLY (it never ships to the
/// production schema). Expand adds a nullable column and seeds a row; migrate
/// backfills it; contract drops the old column. Proves all three phases run in
/// order and that contract removed the expanded-from artifact.
#[tokio::test]
async fn expand_contract_example_chain_runs_all_three_phases_and_contract_removes_the_old_column() {
    let pool = TestDatabase::fresh_owner_pool().await;
    let chain = vec![
        step(
            1,
            Phase::Expand,
            "CREATE TABLE migration_demo (id text PRIMARY KEY, legacy_name text NOT NULL); \
             INSERT INTO migration_demo (id, legacy_name) VALUES ('demo-1', 'alpha'); \
             ALTER TABLE migration_demo ADD COLUMN display_name text;",
        ),
        step(
            2,
            Phase::Migrate,
            "UPDATE migration_demo SET display_name = legacy_name WHERE display_name IS NULL;",
        ),
        step(
            3,
            Phase::Contract,
            "ALTER TABLE migration_demo DROP COLUMN legacy_name;",
        ),
    ];

    let report = MigrationRunner::from_migrations(&pool, chain)
        .run()
        .await
        .expect("apply the expand-contract chain");
    assert_eq!(
        report.newly_applied().to_vec(),
        vec![1_i64, 2, 3],
        "all three phases applied in order"
    );

    // The phases are recorded in order.
    let pool_ref = &pool;
    let phase_of = |version: i64| async move {
        sqlx::query("SELECT phase FROM _schema_migrations WHERE version = $1")
            .bind(version)
            .fetch_one(pool_ref)
            .await
            .expect("phase lookup")
            .get::<String, _>("phase")
    };
    assert_eq!(phase_of(1).await, "expand");
    assert_eq!(phase_of(2).await, "migrate");
    assert_eq!(phase_of(3).await, "contract");

    // Forward chain: the migrate step backfilled display_name from legacy_name.
    let display: String =
        sqlx::query("SELECT display_name FROM migration_demo WHERE id = 'demo-1'")
            .fetch_one(&pool)
            .await
            .expect("demo row")
            .get("display_name");
    assert_eq!(
        display, "alpha",
        "the migrate phase backfilled display_name from legacy_name"
    );

    // Contract removed the expanded-from artifact; the expanded column remains.
    assert!(
        !column_exists(&pool, "migration_demo", "legacy_name").await,
        "the contract phase dropped legacy_name"
    );
    assert!(
        column_exists(&pool, "migration_demo", "display_name").await,
        "the expanded column remains after contract"
    );
}

/// The PRODUCTION chain (`MigrationRunner::new`) is exactly the shipped migrations
/// and leaves no throwaway demo object in a real database.
///
/// The chain's length appears as a number exactly once, in the assertion below,
/// and never in this name or in this sentence. The subject list and the version
/// vector that follow it encode the same length structurally rather than as a
/// number, so the same edit turns all three red together. A count in prose rots
/// silently on the next migration and has done so here before; a count in an
/// assertion goes red and makes a human look at what was added, which is the
/// control this test exists to be.
///
/// The body is long, and its stack demand is measured rather than assumed. On the
/// pinned toolchain the whole test runs in roughly 452 KiB of the 2 MiB a default
/// test thread gets, and every await point added to it costs around half a
/// kilobyte, so it holds thousands more before the budget is a concern. Re-measure
/// by bisecting `RUST_MIN_STACK` over a direct run of the test binary
/// (`RUST_MIN_STACK=<bytes> target/debug/deps/migration-<hash> --exact <name>`)
/// until the run reports `has overflowed its stack` instead of a test result.
/// A direct run needs `DATABASE_URL` set the way `scripts/with-test-db.sh` sets
/// it, otherwise the run panics in the harness before it reaches the body.
// A long but linear ledger-and-table assertion sweep (one line per migration and
// per real table); splitting it would not make it clearer.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn production_chain_is_only_the_real_migrations_and_ships_no_demo_object() {
    const APPROVED_HAS_GRANT: &str = "backchannel_authentication_requests_approved_has_grant";
    // TestDatabase::start runs Store::migrate() (the production chain) on a
    // fresh, empty database.
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // Re-running is idempotent and reports exactly the tracked migrations.
    let report = MigrationRunner::new(pool)
        .run()
        .await
        .expect("re-run the production chain");
    assert!(
        report.newly_applied().is_empty(),
        "the harness already applied the production chain"
    );
    assert_eq!(
        report.already_applied(),
        173,
        "a migration was added to or removed from the production chain; this count is a \
         deliberate checkpoint, not a bug, so read the new migration, satisfy yourself that it \
         belongs in the shipped chain, then update this number and CHAIN_SUBJECTS and the \
         version vector that follows. The chain this test pins is: {CHAIN_SUBJECTS}"
    );
    // The subject list is ASSERTED, not merely printed (issue #250). It used to live
    // only inside the message above, which meant nothing checked it: a migration could
    // be added with the count bumped and no subject written down, or a subject could be
    // dropped while editing an adjacent one, and this test stayed green either way. A
    // count is a weak check on a prose list and it is the strongest one available here,
    // but it is the check that catches the ACTUAL failure mode, which is forgetting the
    // list exists.
    let subjects: Vec<&str> = CHAIN_SUBJECTS
        .trim_end_matches('.')
        .split(", ")
        .map(str::trim)
        .collect();
    assert_eq!(
        subjects.len(),
        report.already_applied(),
        "CHAIN_SUBJECTS names {} migrations and the chain applied {}; the list is the \
         record of WHAT shipped, so a new migration writes a subject here as well as \
         bumping the count. The list as parsed: {subjects:?}",
        subjects.len(),
        report.already_applied()
    );

    // The ledger holds exactly the shipped versions, contiguous and in order.
    assert_eq!(
        applied_versions(pool).await,
        vec![
            1_i64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67,
            68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
            90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142,
            143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
            160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173
        ]
    );
    let phase_of = |version: i64| async move {
        sqlx::query("SELECT phase FROM _schema_migrations WHERE version = $1")
            .bind(version)
            .fetch_one(pool)
            .await
            .expect("phase lookup")
            .get::<String, _>("phase")
    };
    assert_eq!(phase_of(1).await, "expand");
    assert_eq!(phase_of(2).await, "expand");
    assert_eq!(phase_of(3).await, "expand");
    assert_eq!(phase_of(4).await, "expand");
    assert_eq!(phase_of(5).await, "expand");
    assert_eq!(phase_of(6).await, "expand");
    assert_eq!(phase_of(7).await, "expand");
    assert_eq!(phase_of(8).await, "expand");
    assert_eq!(phase_of(9).await, "expand");
    assert_eq!(phase_of(10).await, "expand");
    // A CREATE TABLE is an additive expand (issue #29).
    assert_eq!(phase_of(11).await, "expand");
    assert_eq!(phase_of(12).await, "expand");
    // An ALTER TABLE ADD COLUMN and a CREATE TABLE are both additive expands (#25).
    assert_eq!(phase_of(13).await, "expand");
    // The DCR clients-column expand is additive (#30).
    assert_eq!(phase_of(14).await, "expand");
    // A CREATE TABLE and an additive ALTER TABLE ADD COLUMN are both expands (#27).
    assert_eq!(phase_of(15).await, "expand");
    // Two CREATE TABLEs and two additive ALTERs are all expands (issue #21).
    assert_eq!(phase_of(16).await, "expand");
    // A CREATE TABLE plus two additive clients ALTERs are all expands (issue #23),
    // and three CREATE TABLEs plus additive clients and audit_log ALTERs are all
    // expands (issue #31).
    assert_eq!(phase_of(17).await, "expand");
    assert_eq!(phase_of(18).await, "expand");
    // The resource-indicator columns are all additive ALTER TABLE ADD COLUMNs plus a
    // CHECK and a column-scoped grant, so this is an expand too (issue #28).
    assert_eq!(phase_of(19).await, "expand");
    // Three CREATE TABLEs (the trust anchors, the subject-mapping rules, and the
    // external-issuer jti replay cache) are all additive expands (issue #26).
    assert_eq!(phase_of(20).await, "expand");
    // A CREATE TABLE plus two additive clients ALTERs are all expands (issue #24).
    assert_eq!(phase_of(21).await, "expand");
    // The session-model expand (issue #32): an additive sessions ALTER, a new
    // client_sessions table, and additive refresh_families indexes are all expands.
    assert_eq!(phase_of(22).await, "expand");
    // The RP-initiated logout expand (issue #33): an additive clients ALTER ADD COLUMN
    // (post_logout_redirect_uris) plus its column-scoped grant is an expand.
    assert_eq!(phase_of(23).await, "expand");
    // The session-ended outbox (issue #35): one new CREATE TABLE plus its indexes,
    // policy, and column-scoped grants are all additive, so this is an expand too.
    assert_eq!(phase_of(24).await, "expand");
    // Back-channel logout (issue #34): two additive clients ALTER ADD COLUMNs plus one
    // new backchannel_logout_deliveries table, indexes, policy, and column-scoped grants
    // are all additive, so this is an expand too.
    assert_eq!(phase_of(25).await, "expand");
    // The front-channel logout expand (issue #39): two additive clients ALTER ADD
    // COLUMNs (frontchannel_logout_uri, frontchannel_logout_session_required) plus a
    // column-scoped grant are all expands.
    assert_eq!(phase_of(26).await, "expand");
    // The resource-model APIs expand (issue #41): one additive organizations ALTER
    // ADD COLUMN (deleted_at) plus control-plane grants, and a REVOKE of the unused
    // over-broad data-plane grant on organizations (the #31 least-privilege lesson).
    // The revoke is expand-safe: no pre-#41 binary issued an organization statement
    // as ironauth_app, so removing the grant depends on and breaks nothing.
    assert_eq!(phase_of(27).await, "expand");
    // The envelope-encryption migration (issue #48): three new CREATE TABLEs
    // (tenant_keks, tenant_deks, encrypted_secrets) with their indexes, policies,
    // and column-scoped grants, PLUS the conversion of the two plaintext users PII
    // columns to sealed envelope columns (a full expand-contract folded in, since
    // the pre-1.0 bootstrap users table has no cross-release contract to protect).
    // The predominant shape is additive, so it is registered as an expand.
    assert_eq!(phase_of(28).await, "expand");
    // The environment-guardrails expand (issue #42): two additive environments
    // ALTER ADD COLUMNs (kind, custom_domain), one CHECK pinning the closed kind
    // set, and a GRANT INSERT on signing_keys to the control role (so environment
    // creation can provision the day-one key). Purely additive, so it is an expand.
    assert_eq!(phase_of(29).await, "expand");
    // The tenant-lifecycle migration (issue #46): additive tenants.status,
    // tenants.home_region, tenants.purged_at, and environments.region columns, a new
    // environment_states scoped table with its policy and grants, and a
    // control-plane crypto-shred grant on tenant_keks. All additive, so this is an
    // expand too.
    assert_eq!(phase_of(30).await, "expand");
    // The BYOK-bindings migration (issue #49): one new tenant_byok_bindings scoped
    // table with its index, isolation policy, nonempty-scope and value CHECKs, and
    // column-scoped grants (data-plane SELECT/INSERT, control-plane SELECT plus a
    // column-scoped sever UPDATE). Purely additive, so it is an expand too.
    assert_eq!(phase_of(31).await, "expand");
    // The snapshot-export migration (issue #43): a single GRANT SELECT on
    // resource_servers to the control role, so the management-plane snapshot export
    // can read the promotable resource-server registry. A pure grant, no schema
    // change, so this is an expand too.
    assert_eq!(phase_of(32).await, "expand");
    // The custom-domains migration (issue #47): two new tenant-scoped tables
    // (custom_domains and acme_challenges) with their indexes, policies, and
    // column-scoped grants, plus a global partial unique index that gives a
    // verified domain exactly one owner platform-wide. All additive, so it is an
    // expand.
    assert_eq!(phase_of(33).await, "expand");
    // The environment secrets and variables migration (issue #45): two new
    // tenant-scoped tables (environment_variables and environment_secrets) with
    // their indexes, isolation policies, nonempty-scope CHECKs, and column-scoped
    // grants (a control-plane SELECT on variables for the snapshot export). All
    // additive, so it is an expand too.
    assert_eq!(phase_of(34).await, "expand");
    // The config-promotion migration (issue #44): a set of control-plane grants so
    // the transactional promotion apply can create, overwrite, and remove the
    // promoted resource types (resource servers, DCR policies, environment
    // variables) and read the presence of an environment secret. A pure grant, no
    // schema change, so this is an expand too.
    assert_eq!(phase_of(35).await, "expand");
    // The self-service account migration (issue #61): a column-scoped UPDATE grant
    // on users.password_hash (so a self-service password change can replace the
    // verifier) plus one new account_credentials scoped table with its indexes,
    // isolation policy, nonempty-scope and closed-type CHECKs, and column-scoped
    // grants. All additive, so this is an expand too.
    assert_eq!(phase_of(36).await, "expand");
    // The admin-user-lifecycle migration (issue #52): additive users columns (state,
    // external-id blind index + sealed value + its DEK version, scheduled-offboarding
    // instant, updated_at, deleted_at), a state CHECK, a per-scope partial unique
    // index on the external-id blind index, and a set of grants (control-plane
    // SELECT/INSERT plus a column-scoped UPDATE on users, and control-plane
    // SELECT/INSERT on the envelope key tables). All additive, so it is an expand too.
    assert_eq!(phase_of(37).await, "expand");
    // The identity-traits migration (issue #53): two new tenant-scoped tables
    // (trait_schemas, trait_migration_jobs) with their indexes, isolation policies,
    // nonempty-scope CHECKs, and column-scoped grants, plus three additive users
    // columns (traits_sealed, traits_dek_version, traits_schema_version) with a
    // column-scoped grant. All additive, so it is an expand too.
    assert_eq!(phase_of(38).await, "expand");
    // The foreign-password-import migration (issue #55): two additive nullable users
    // columns (foreign_password_hash, foreign_password_algo) plus a column-scoped
    // UPDATE grant to the data and control roles so the verify-then-rehash login
    // landing can retire the foreign hash. All additive, so it is an expand too.
    assert_eq!(phase_of(39).await, "expand");
    // The user-invitations migration (issue #60): one new user_invitations scoped
    // table with its unique digest index, scope and identifier indexes, isolation
    // policy, nonempty-scope / closed-credential-type / closed-state CHECKs, and
    // column-scoped grants (control-plane SELECT/INSERT plus a lifecycle UPDATE,
    // data-plane SELECT plus an accept UPDATE). All additive, so it is an expand too.
    assert_eq!(phase_of(40).await, "expand");
    // The flexible-identifiers migration (issue #54): one new user_identifiers scoped
    // table with its resolution and per-user indexes, the partial uniqueness index on
    // the mode discriminator, isolation policy, nonempty-scope / closed-type CHECKs,
    // and column-scoped grants. The identifier value is sealed and blind-indexed (no
    // plaintext PII column). All additive, so it is an expand too.
    assert_eq!(phase_of(41).await, "expand");
    // The exit-export credential-grant migration (issue #58): a purely additive pair
    // of control-plane privileges (SELECT + INSERT) on the existing
    // account_credentials table so the full export reads the credential registry and
    // the mirror import restores it. No table, column, policy, or backfill, so it is
    // an expand.
    assert_eq!(phase_of(42).await, "expand");
    // The migration state-machine migration (issue #59): two new tenant-scoped tables
    // (migration_runs, migration_run_records) with their indexes, isolation policies,
    // nonempty-scope / closed-kind / closed-state / closed-outcome CHECKs, and
    // column-scoped grants. The record subject is sealed and blind-indexed (no plaintext
    // PII column). All additive, so it is an expand too.
    assert_eq!(phase_of(43).await, "expand");
    // The WebAuthn passkey migration (issue #65) is an EXPAND: two new tenant-scoped
    // tables, no rewrite of existing state.
    assert_eq!(phase_of(44).await, "expand");
    // The TOTP migration (issue #69) is an EXPAND: two new tenant-scoped tables
    // (totp_credentials, recovery_codes), no rewrite of existing state.
    assert_eq!(phase_of(45).await, "expand");
    // The credential-abuse-defenses migration (issue #64) is an EXPAND: one new
    // tenant-scoped ban table, no rewrite of existing state.
    assert_eq!(phase_of(46).await, "expand");
    // The step-up policies migration (issue #72) is an EXPAND: one new tenant-scoped
    // per-scope policy table plus additive clients and refresh_families columns, no
    // rewrite of existing state.
    assert_eq!(phase_of(47).await, "expand");
    // The email-OTP + magic-links migration (issue #68) is an EXPAND: two new
    // tenant-scoped tables (email_otp_codes, magic_link_tokens), no rewrite of existing
    // state.
    assert_eq!(phase_of(48).await, "expand");
    // The credential-class-policies migration (issue #66) is an EXPAND: two new
    // tenant-scoped tables (credential_class_policies, attestation_config) plus additive
    // users columns and a guard trigger, no rewrite of existing state.
    assert_eq!(phase_of(49).await, "expand");
    // The guarded SMS-OTP migration (issue #70) is an EXPAND: four new tenant-scoped
    // tables (sms_otp_codes, sms_config, sms_country_allowlist, sms_route_stats), no
    // rewrite of existing state.
    assert_eq!(phase_of(50).await, "expand");
    // The passkey-attestation migration (issue #66, PR B) is an EXPAND: two new
    // tenant-scoped tables (mds3_blob_cache, aaguid_rules) plus additive
    // webauthn_credentials attestation columns, no rewrite of existing state.
    assert_eq!(phase_of(51).await, "expand");
    // The admin-sudo-elevations migration (issue #73) is an EXPAND: one new
    // tenant-scoped append-only ledger table, no rewrite of existing state.
    assert_eq!(phase_of(52).await, "expand");
    // The trusted-devices migration (issue #71) is an EXPAND: one new tenant-scoped
    // remember-device state table, no rewrite of existing state.
    assert_eq!(phase_of(53).await, "expand");
    // The risk-engine migration (issue #79) is an EXPAND: three new tenant-scoped tables
    // (risk_login_geo, risk_decisions, risk_disavowal_tokens), no rewrite of existing state.
    assert_eq!(phase_of(54).await, "expand");
    // The account-recovery migration (issue #81) is an EXPAND: one new tenant-scoped
    // recovery-flow state-machine table, no rewrite of existing state.
    assert_eq!(phase_of(55).await, "expand");
    // The federation-connectors migration (issue #75) is an EXPAND: one new tenant-scoped
    // table (connectors), no rewrite of existing state.
    assert_eq!(phase_of(56).await, "expand");
    // The registration-abuse-defenses migration (issue #80) is an EXPAND: one new
    // tenant-scoped table (pow_challenges) plus an additive widen of the users.state CHECK
    // to admit 'waitlisted', no rewrite of existing state.
    assert_eq!(phase_of(57).await, "expand");
    // The federation-login-state migration (issue #75, PR B) is an EXPAND: one new
    // tenant-scoped single-use correlation table (federation_login_states), no rewrite of
    // existing state.
    assert_eq!(phase_of(58).await, "expand");
    // The enterprise-inbound-routing migration (issue #77) is an EXPAND: two new
    // tenant-scoped tables (org_connections, routing_rules) plus additive nullable
    // org_connection_id columns on federation_login_states and users, no rewrite of
    // existing state.
    assert_eq!(phase_of(59).await, "expand");
    // The upstream-token-vault migration (issue #77, PR 3) is an EXPAND: two new
    // tenant-scoped tables (upstream_tokens, upstream_token_grants), no rewrite of
    // existing state.
    assert_eq!(phase_of(60).await, "expand");
    // The guarded-account-linking migration (issue #78, PR 1) is an EXPAND: one new
    // tenant-scoped table (account_links), no rewrite of existing state.
    assert_eq!(phase_of(61).await, "expand");
    // The account-linking wiring migration (issue #78, PR 2) is an EXPAND: two additive
    // nullable columns (federation_login_states.link_target_user_id and
    // environments.auto_link_posture) plus one view replace and one column grant.
    assert_eq!(phase_of(62).await, "expand");
    // The FedCM assertion-nonce migration (issue #83) is an EXPAND: one new tenant-scoped
    // single-use replay table (fedcm_assertion_nonces) with its index, isolation policy,
    // nonempty-scope CHECK, and a no-DELETE column grant. No rewrite of existing state.
    assert_eq!(phase_of(63).await, "expand");
    // The third-party risk-signal migration (issue #82, PR 1) is an EXPAND: one new
    // tenant-scoped table (risk_signals) with its indexes, isolation policy,
    // nonempty-scope CHECK, subject-format CHECK, single-delivery UNIQUE, and a no-DELETE
    // append-only grant. No rewrite of existing state.
    assert_eq!(phase_of(64).await, "expand");

    // The FedCM assertion-nonce store (issue #83) is a NEW tenant-scoped table, so it must
    // ENABLE and FORCE row-level security, carry the (tenant, environment) isolation policy,
    // and pin the nonempty-scope CHECK, exactly like every other scoped table.
    assert!(
        rls_enabled_and_forced(pool, "fedcm_assertion_nonces").await,
        "fedcm_assertion_nonces must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(
            pool,
            "fedcm_assertion_nonces",
            "fedcm_assertion_nonces_tenant_isolation"
        )
        .await,
        "fedcm_assertion_nonces must carry the (tenant, environment) isolation policy"
    );
    assert!(
        check_constraint_exists(
            pool,
            "fedcm_assertion_nonces",
            "fedcm_assertion_nonces_scope_nonempty"
        )
        .await,
        "fedcm_assertion_nonces must carry the nonempty-scope CHECK"
    );
    // The single-use latch column is present and nullable (NULL until consumed), so a
    // consumed row is the durable replay evidence.
    assert!(
        !column_is_not_null(pool, "fedcm_assertion_nonces", "consumed_at").await,
        "fedcm_assertion_nonces.consumed_at must be nullable (the single-use latch)"
    );

    // The cross-node DPoP proof jti replay store (issue #368, 0083) is a NEW
    // tenant-scoped table, so it must ENABLE and FORCE row-level security, carry the
    // (tenant, environment) isolation policy, and pin the nonempty-scope CHECK, exactly
    // like every other scoped table.
    assert!(
        rls_enabled_and_forced(pool, "dpop_proof_replay").await,
        "dpop_proof_replay must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(
            pool,
            "dpop_proof_replay",
            "dpop_proof_replay_tenant_isolation"
        )
        .await,
        "dpop_proof_replay must carry the (tenant, environment) isolation policy"
    );
    assert!(
        check_constraint_exists(
            pool,
            "dpop_proof_replay",
            "dpop_proof_replay_scope_nonempty"
        )
        .await,
        "dpop_proof_replay must carry the nonempty-scope CHECK"
    );

    // The third-party risk-signal store (issue #82, PR 1) is a NEW tenant-scoped table, so
    // it must ENABLE and FORCE row-level security, carry the (tenant, environment) isolation
    // policy, and pin the nonempty-scope CHECK, exactly like every other scoped table.
    assert!(
        rls_enabled_and_forced(pool, "risk_signals").await,
        "risk_signals must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "risk_signals", "risk_signals_tenant_isolation").await,
        "risk_signals must carry the (tenant, environment) isolation policy"
    );
    assert!(
        check_constraint_exists(pool, "risk_signals", "risk_signals_scope_nonempty").await,
        "risk_signals must carry the nonempty-scope CHECK"
    );
    // The RFC 9493 subject-format CHECK pins the closed set: an unknown format can never be
    // written, so the subject binding is always one of the recognized identifier formats.
    assert!(
        check_constraint_exists(pool, "risk_signals", "risk_signals_subject_format_known").await,
        "risk_signals must pin the closed RFC 9493 subject-format set"
    );
    // The STRUCTURAL single-delivery invariant: a source's SET is ingested at most once per
    // scope (the idempotent-delivery / dedup UNIQUE on (tenant, env, source, source_jti)).
    let risk_signals_uniq: String = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'risk_signals'::regclass AND conname = 'risk_signals_delivery_uniq'",
    )
    .fetch_one(pool)
    .await
    .expect("risk_signals delivery UNIQUE lookup")
    .get("def");
    assert!(
        risk_signals_uniq.contains("source_jti")
            && risk_signals_uniq.contains("source")
            && risk_signals_uniq.starts_with("UNIQUE"),
        "risk_signals must pin the single-delivery UNIQUE on source + source_jti, got: \
         {risk_signals_uniq}"
    );
    // The external subject is a keyed blind index (bytea), never a plaintext column: a
    // database dump reveals no external subject. The resolved local subject is nullable
    // (NULL when the external subject maps to no local account, an inert row).
    assert!(
        column_exists(pool, "risk_signals", "subject_bidx").await,
        "risk_signals must carry the blind-index external-subject column"
    );
    assert!(
        !column_is_not_null(pool, "risk_signals", "subject").await,
        "risk_signals.subject (the resolved local usr_ id) must be nullable"
    );

    // The signup fraud review queue (issue #82, PR 2): an additive users.quarantined ALTER
    // ADD COLUMN with a control-only column-scoped UPDATE grant, plus one new
    // signup_quarantines table with its indexes, policy, nonempty-scope CHECK, closed reason
    // and state CHECKs, and column-scoped grants. All additive, so it is an expand.
    assert_eq!(phase_of(65).await, "expand");

    // users.quarantined (issue #82, PR 2): the orthogonal quarantine flag, additive with a
    // NOT NULL DEFAULT false, so every existing account back-fills to unquarantined.
    assert!(
        column_exists(pool, "users", "quarantined").await,
        "users.quarantined exists after 0065"
    );
    assert_eq!(
        column_data_type(pool, "users", "quarantined").await,
        "boolean",
        "users.quarantined is a boolean"
    );
    // The quarantine flag is CONTROL-ONLY to clear: the control role holds a column-scoped
    // UPDATE(quarantined), and the data-plane role holds NONE, so a quarantined account has
    // no data-plane path to self-approve (the self-approval-impossible guarantee at the grant
    // level, mirroring the #31 client-quarantine split).
    assert!(
        role_has_column_privilege(pool, "ironauth_control", "users", "quarantined", "UPDATE").await,
        "the control role must hold column-scoped UPDATE on users.quarantined"
    );
    assert!(
        !role_has_column_privilege(pool, "ironauth_app", "users", "quarantined", "UPDATE").await,
        "the data-plane role must NOT hold UPDATE on users.quarantined (no self-approval path)"
    );

    // signup_quarantines (issue #82, PR 2) is a NEW tenant-scoped table, so it must ENABLE and
    // FORCE row-level security, carry the (tenant, environment) isolation policy, and pin the
    // nonempty-scope CHECK, exactly like every other scoped table.
    assert!(
        rls_enabled_and_forced(pool, "signup_quarantines").await,
        "signup_quarantines must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(
            pool,
            "signup_quarantines",
            "signup_quarantines_tenant_isolation"
        )
        .await,
        "signup_quarantines must carry the (tenant, environment) isolation policy"
    );
    assert!(
        check_constraint_exists(
            pool,
            "signup_quarantines",
            "signup_quarantines_scope_nonempty"
        )
        .await,
        "signup_quarantines must carry the nonempty-scope CHECK"
    );
    // AND THE SPLIT ITSELF, read off the files. The `convalidated` assertion further down
    // proves the END STATE is
    // right; it cannot prove HOW it got there, and the how is the entire point: one file
    // holding both statements takes AccessExclusiveLock through the scan, which is what round
    // 8 of review measured as buying nothing. These two assertions are what make that
    // regression visible, since collapsing the files back into one leaves the schema
    // identical.
    let add_sql = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("migrations/0151_backchannel_approved_requires_grant.sql"),
    )
    .expect("0151 is readable");
    let validate_sql = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("migrations/0152_backchannel_approved_grant_validated.sql"),
    )
    .expect("0152 is readable");
    // STATEMENTS, not the file text, and UPPERCASED. Three ways this assertion has been
    // measured passing for the wrong reason:
    //
    // * a `contains` over the whole FILE matched the headers, which mention `NOT VALID`, so
    //   it stayed green with the SQL saying the opposite. Only that half was ever at risk
    //   from the prose: neither header contains the string `VALIDATE CONSTRAINT`;
    // * SQL keywords are case-insensitive, so appending `validate constraint ...` in
    //   lowercase to 0151 restored the collapsed one-file form and stayed green;
    // * `NOT VALID` left only inside a `PERFORM` string literal, with the real ALTER
    //   validating, satisfied a whole-statement `contains` and produced an end state
    //   `convalidated` cannot distinguish.
    //
    // Hence: comments stripped, uppercased, and the NOT VALID check anchored to the
    // ADD CONSTRAINT statement rather than to the file.
    let statements_of = |sql: &str| -> String {
        // Line comments cut at `--`, not just whole lines that begin with it. A TRAILING
        // `-- ... NOT VALID ...` beside a validating ALTER was a bypass, and a trailing
        // `-- ... VALIDATE CONSTRAINT ...` was a false alarm on correct SQL. Both are the
        // same omission: the previous version only dropped lines that STARTED with `--`.
        let without_line_comments = sql
            .lines()
            .map(|line| line.split_once("--").map_or(line, |(code, _)| code))
            .collect::<Vec<_>>()
            .join("\n");
        // Block comments out, then whitespace collapsed. Both are about not raising a FALSE
        // alarm on SQL that is correct: `ADD` and `CONSTRAINT` on separate lines, and
        // `NOT/**/VALID`, are both accepted by Postgres and both produce exactly the intended
        // `convalidated = false`, and both failed the previous version of this assertion.
        // Stripping block comments also closes a real bypass, a trailing `/* NOT VALID */`
        // beside an ALTER that validates.
        let mut out = String::with_capacity(without_line_comments.len());
        let mut rest = without_line_comments.as_str();
        while let Some(open) = rest.find("/*") {
            out.push_str(&rest[..open]);
            out.push(' ');
            let Some(close) = rest[open..].find("*/") else {
                rest = "";
                break;
            };
            rest = &rest[open + close + 2..];
        }
        out.push_str(rest);
        out.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_uppercase()
    };
    let add_statements = statements_of(&add_sql);
    let validate_statements = statements_of(&validate_sql);
    // EVERY `ADD CONSTRAINT`, each cut at the next semicolon, with the constraint's NAME
    // required in the same span as `NOT VALID`.
    //
    // WHAT THIS IS AND IS NOT. It is a text scan, so it catches the regression it exists for,
    // which is somebody collapsing the two files back into one and writing a plain validating
    // `ADD CONSTRAINT`. It is not a SQL parser and cannot be made into one by tightening:
    // review has now defeated successive versions with a string literal, a `COMMENT ON`, a
    // block comment, a decoy constraint of the same name on another table, and a nested block
    // comment, and each tightening produced a new way in. Saying "cut at the next semicolon"
    // rather than "at its own terminating semicolon" is part of that honesty: a `;` inside a
    // string literal in the CHECK expression ends the span early.
    //
    // The enforcement that does not depend on spelling is elsewhere and is measured: the code
    // guards in `decide`, `approved_details`, `redeem` and `redeem_approved`, and the
    // `convalidated` assertion below. This one protects the LOCK property, which nothing in
    // the schema can see.
    //
    // The previous version took everything from the FIRST `ADD CONSTRAINT` to end of file and
    // called it a statement. Four ways past it, all measured, all leaving 0151 taking
    // AccessExclusiveLock and scanning, which is the regression the split exists to prevent:
    // the `NOT VALID` literal in a `PERFORM` placed AFTER the ALTER rather than before it; a
    // `COMMENT ON CONSTRAINT ... IS '... NOT VALID ...'` after it; a trailing block comment,
    // since only full-line `--` comments are stripped; and a DECOY `ADD CONSTRAINT ... NOT
    // VALID` earlier in the file while the real one validates.
    //
    // None is visible to the database either: a validating ADD followed later by a VALIDATE
    // leaves `convalidated` true and `pg_get_constraintdef` byte-identical, so the assertions
    // below cannot stand in for this one.
    let unvalidated_add = add_statements
        .match_indices("ADD CONSTRAINT")
        .map(|(at, _)| &add_statements[at..])
        .map(|rest| rest.split_once(';').map_or(rest, |(head, _)| head))
        .any(|statement| {
            statement.contains(&APPROVED_HAS_GRANT.to_uppercase())
                && statement.contains("NOT VALID")
        });
    assert!(
        unvalidated_add && !add_statements.contains("VALIDATE CONSTRAINT"),
        "0151 must ADD {APPROVED_HAS_GRANT} with NOT VALID in that same statement, and must \
         not validate it: the runner wraps each FILE in one transaction, so both statements \
         together hold AccessExclusiveLock across the scan and the split buys nothing. \
         Uppercased, comment-stripped statements were: {add_statements}"
    );
    assert!(
        validate_statements.contains("VALIDATE CONSTRAINT"),
        "0152 must be the file that validates, so the scan runs in its own transaction under \
         ShareUpdateExclusiveLock. Uppercased, comment-stripped statements were: \
         {validate_statements}"
    );

    // The CIBA approved-has-grant CHECK is present AND VALIDATED (issue #131), which is the
    // only observable difference between the two-file split and the one-file version it
    // replaced.
    //
    // It needs asserting because nothing else can see it. Replacing 0152's
    // `VALIDATE CONSTRAINT` with `SELECT 1` left this crate's suite byte-identical, and
    // deleting `NOT VALID` from 0151 produces an END-STATE SCHEMA that is indistinguishable
    // from the correct one, so no assertion about the constraint's definition could catch
    // either. `convalidated` is the one column that separates them, and the split exists so
    // the validating scan does not hold AccessExclusiveLock on a table that grows with
    // production traffic.
    let approved_has_grant = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def, convalidated \
         FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'backchannel_authentication_requests'::regclass \
           AND conname = 'backchannel_authentication_requests_approved_has_grant'",
    )
    .fetch_one(pool)
    .await
    .expect("the CIBA approved-has-grant CHECK must exist");
    let approved_has_grant_def: String = approved_has_grant.get("def");
    let approved_has_grant_validated: bool = approved_has_grant.get("convalidated");
    assert!(
        approved_has_grant_def.contains("status <> 'approved'::text")
            && approved_has_grant_def.contains("grant_id IS NOT NULL"),
        "the CHECK must still say that an approved request names a grant: {approved_has_grant_def}"
    );
    assert!(
        approved_has_grant_validated,
        "0152 must VALIDATE the constraint 0151 adds NOT VALID. An unvalidated constraint is \
         enforced on new rows but leaves a permanent 'we never checked' on a table whose \
         whole argument is that the shape is unrepresentable, and this is the only column \
         that can tell the two files apart from their end state"
    );

    // The closed reason and state CHECKs pin their sets: an unknown reason or state can never
    // be written.
    let reason_check: String = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'signup_quarantines'::regclass \
         AND conname = 'signup_quarantines_reason_known'",
    )
    .fetch_one(pool)
    .await
    .expect("signup_quarantines reason check lookup")
    .get("def");
    for reason in ["risk_output", "challenge_failure"] {
        assert!(
            reason_check.contains(reason),
            "the signup_quarantines reason CHECK must admit {reason}, got: {reason_check}"
        );
    }
    let state_check: String = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'signup_quarantines'::regclass \
         AND conname = 'signup_quarantines_state_known'",
    )
    .fetch_one(pool)
    .await
    .expect("signup_quarantines state check lookup")
    .get("def");
    for state in ["pending", "approved", "rejected", "extended"] {
        assert!(
            state_check.contains(state),
            "the signup_quarantines state CHECK must admit {state}, got: {state_check}"
        );
    }
    // The verdict columns are control-plane-owned (the #31 split): the control role holds a
    // column-scoped UPDATE over EXACTLY the review columns (state / quarantined_until / the
    // reviewer stamp / the note), and the data-plane role holds NONE, so only the admin
    // review queue can move a case forward.
    for column in [
        "state",
        "quarantined_until",
        "reviewed_by_kind",
        "reviewed_by_id",
        "reviewed_at",
        "review_note",
    ] {
        assert!(
            role_has_column_privilege(
                pool,
                "ironauth_control",
                "signup_quarantines",
                column,
                "UPDATE"
            )
            .await,
            "the control role must hold column-scoped UPDATE on signup_quarantines.{column}"
        );
        assert!(
            !role_has_column_privilege(
                pool,
                "ironauth_app",
                "signup_quarantines",
                column,
                "UPDATE"
            )
            .await,
            "the data-plane role must NOT hold UPDATE on signup_quarantines.{column}"
        );
    }
    // The IDENTITY columns are NOT in the control grant: the control role decides a case but
    // can never rewrite WHAT it is about (its subject or reason).
    for column in ["subject", "reason"] {
        assert!(
            !role_has_column_privilege(
                pool,
                "ironauth_control",
                "signup_quarantines",
                column,
                "UPDATE"
            )
            .await,
            "the control role must NOT hold UPDATE on the identity column signup_quarantines.{column}"
        );
    }
    // The one-open-case-per-account invariant: a PARTIAL UNIQUE index over
    // (tenant, environment, subject) WHERE state IN ('pending','extended'), so an account has
    // at most one OPEN review case at a time (re-quarantining an already-open subject is a
    // structural conflict, not a silent duplicate).
    assert!(
        partial_unique_index_exists(pool, "signup_quarantines", "signup_quarantines_open_uniq")
            .await,
        "signup_quarantines must carry the one-open-case-per-account partial unique index"
    );

    // The advanced recovery modes (issue #82, PR 3): an additive recovery_flows.method ALTER
    // ADD COLUMN with a CHECK pinning the closed method set, plus four new tenant-scoped tables
    // (recovery_approvals, recovery_trusted_contacts, recovery_contact_confirmations,
    // recovery_idv_sessions) with their indexes, policies, nonempty-scope CHECKs, and
    // column-scoped grants. All additive, so it is an expand.
    assert_eq!(phase_of(66).await, "expand");

    // recovery_flows.method (issue #82, PR 3): the recovery-method seam, additive with a
    // NOT NULL DEFAULT 'standard', so every existing flow back-fills to the unchanged path,
    // and a CHECK pins the closed method set.
    assert!(
        column_exists(pool, "recovery_flows", "method").await,
        "recovery_flows.method exists after 0066"
    );
    let method_check: String = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'recovery_flows'::regclass AND conname = 'recovery_flows_method_known'",
    )
    .fetch_one(pool)
    .await
    .expect("recovery_flows method check lookup")
    .get("def");
    for method in ["standard", "admin_approved", "trusted_contact", "idv"] {
        assert!(
            method_check.contains(method),
            "the recovery_flows method CHECK must admit {method}, got: {method_check}"
        );
    }

    // Each of the four new tables is a tenant-scoped table, so it must ENABLE and FORCE
    // row-level security, carry the (tenant, environment) isolation policy, and pin the
    // nonempty-scope CHECK, exactly like every other scoped table.
    for table in [
        "recovery_approvals",
        "recovery_trusted_contacts",
        "recovery_contact_confirmations",
        "recovery_idv_sessions",
    ] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "{table} must carry the (tenant, environment) isolation policy"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the nonempty-scope CHECK"
        );
    }

    // recovery_approvals: the control plane OWNS the verdict (a column-scoped UPDATE over the
    // review columns), and the data-plane role holds NONE, so only an admin can approve or
    // reject a recovery (the self-approval-impossible guarantee at the grant level).
    for column in [
        "state",
        "reviewed_by_kind",
        "reviewed_by_id",
        "reviewed_at",
        "note",
    ] {
        assert!(
            role_has_column_privilege(
                pool,
                "ironauth_control",
                "recovery_approvals",
                column,
                "UPDATE"
            )
            .await,
            "the control role must hold column-scoped UPDATE on recovery_approvals.{column}"
        );
        assert!(
            !role_has_column_privilege(
                pool,
                "ironauth_app",
                "recovery_approvals",
                column,
                "UPDATE"
            )
            .await,
            "the data-plane role must NOT hold UPDATE on recovery_approvals.{column}"
        );
    }
    // The IDENTITY columns are NOT in the control grant: an admin decides a case but can never
    // rewrite WHAT recovery it is about (its flow or subject).
    for column in ["flow_id", "subject"] {
        assert!(
            !role_has_column_privilege(
                pool,
                "ironauth_control",
                "recovery_approvals",
                column,
                "UPDATE"
            )
            .await,
            "the control role must NOT hold UPDATE on the identity column recovery_approvals.{column}"
        );
    }

    // recovery_approvals: the data-plane INSERT is COLUMN-SCOPED to exactly the open() columns
    // and EXCLUDES `state`, so the app role can never INSERT a chosen (non-pending) state: a
    // self-approve INSERT of state='approved' is denied at the grant level, and every app-opened
    // row falls to the DEFAULT 'pending'. This is the structural self-approve defense on the
    // INSERT path (mirroring the control-only UPDATE split above).
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "flow_id",
        "subject",
        "created_at",
    ] {
        assert!(
            role_has_column_privilege(pool, "ironauth_app", "recovery_approvals", column, "INSERT")
                .await,
            "the data-plane role must hold column-scoped INSERT on the open() column recovery_approvals.{column}"
        );
    }
    // The `state` and review-attribution columns are EXCLUDED from the data-plane INSERT grant,
    // so the app role cannot choose an approved/rejected state or forge a reviewer at INSERT.
    for column in [
        "state",
        "reviewed_by_kind",
        "reviewed_by_id",
        "reviewed_at",
        "note",
    ] {
        assert!(
            !role_has_column_privilege(
                pool,
                "ironauth_app",
                "recovery_approvals",
                column,
                "INSERT"
            )
            .await,
            "the data-plane role must NOT hold INSERT on recovery_approvals.{column} (self-approve defense)"
        );
    }
    // recovery_approvals.state must carry the DEFAULT 'pending', so an app INSERT that omits it
    // (the open() path) lands a pending row without the app choosing the state.
    let approvals_state_default: Option<String> = sqlx::query(
        "SELECT column_default FROM information_schema.columns \
         WHERE table_name = 'recovery_approvals' AND column_name = 'state'",
    )
    .fetch_one(pool)
    .await
    .expect("recovery_approvals.state default lookup")
    .get("column_default");
    assert!(
        approvals_state_default
            .as_deref()
            .is_some_and(|d| d.contains("pending")),
        "recovery_approvals.state must DEFAULT to 'pending', got: {approvals_state_default:?}"
    );

    // recovery_contact_confirmations: the no-double-count invariant is a UNIQUE index over
    // (tenant, environment, flow_id, contact_id), so one contact can confirm a flow at most
    // once (a single contact can never reach a threshold of two by confirming twice). The
    // single-use latch column (confirmed_at) is nullable (NULL until confirmed).
    let confirm_uniq: String = sqlx::query(
        "SELECT pg_get_indexdef(indexrelid) AS def FROM pg_catalog.pg_index i \
         JOIN pg_catalog.pg_class c ON c.oid = i.indexrelid \
         WHERE c.relname = 'recovery_contact_confirmations_flow_contact_uniq'",
    )
    .fetch_one(pool)
    .await
    .expect("confirmation flow+contact unique index lookup")
    .get("def");
    assert!(
        confirm_uniq.contains("UNIQUE")
            && confirm_uniq.contains("flow_id")
            && confirm_uniq.contains("contact_id"),
        "recovery_contact_confirmations must pin the no-double-count UNIQUE on (flow_id, contact_id), \
         got: {confirm_uniq}"
    );
    assert!(
        !column_is_not_null(pool, "recovery_contact_confirmations", "confirmed_at").await,
        "recovery_contact_confirmations.confirmed_at must be nullable (the single-use latch)"
    );

    // recovery_idv_sessions: the case binding is a UNIQUE index over
    // (tenant, environment, flow_id, redirect_state_digest), so a state minted for another
    // flow selects no row (no cross-case). The single-use latch column (consumed_at) is
    // nullable (NULL until a callback is consumed).
    let idv_uniq: String = sqlx::query(
        "SELECT pg_get_indexdef(indexrelid) AS def FROM pg_catalog.pg_index i \
         JOIN pg_catalog.pg_class c ON c.oid = i.indexrelid \
         WHERE c.relname = 'recovery_idv_sessions_state_uniq'",
    )
    .fetch_one(pool)
    .await
    .expect("idv session state unique index lookup")
    .get("def");
    assert!(
        idv_uniq.contains("UNIQUE")
            && idv_uniq.contains("flow_id")
            && idv_uniq.contains("redirect_state_digest"),
        "recovery_idv_sessions must pin the case-binding UNIQUE on (flow_id, redirect_state_digest), \
         got: {idv_uniq}"
    );
    assert!(
        !column_is_not_null(pool, "recovery_idv_sessions", "consumed_at").await,
        "recovery_idv_sessions.consumed_at must be nullable (the single-use latch)"
    );
    // The trusted-contact address is a SEALED bytea (issue #48), never a plaintext PII column.
    assert_eq!(
        column_data_type(pool, "recovery_trusted_contacts", "contact_sealed").await,
        "bytea",
        "recovery_trusted_contacts.contact_sealed must be a sealed bytea (no plaintext contact PII)"
    );

    // The step-up second-factor abuse path (issue #72): migration 0047 WIDENED the
    // abuse_bans auth_path CHECK (0046 pinned the closed set) to also admit
    // 'second_factor', so the RFC 9470 step-up challenge is a first-class throttled
    // path that can carry a ban independently of password/passkey. The widened CHECK
    // definition names the new value.
    let auth_path_check: String = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'abuse_bans'::regclass AND conname = 'abuse_bans_auth_path_known'",
    )
    .fetch_one(pool)
    .await
    .expect("auth_path check constraint lookup")
    .get("def");
    assert!(
        auth_path_check.contains("second_factor"),
        "the abuse_bans auth_path CHECK must admit the step-up second-factor path, got: \
         {auth_path_check}"
    );

    // The headless flows migration (issue #84) is an EXPAND: one new tenant-scoped
    // single-use completion table (flows) with its submit-token index, isolation policy,
    // nonempty-scope CHECK, and a no-DELETE column grant. No rewrite of existing state.
    assert_eq!(phase_of(67).await, "expand");

    // The flows store (issue #84) is a NEW tenant-scoped table, so it must ENABLE and
    // FORCE row-level security, carry the (tenant, environment) isolation policy, and pin
    // the nonempty-scope CHECK, exactly like every other scoped table.
    assert!(
        rls_enabled_and_forced(pool, "flows").await,
        "flows must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "flows", "flows_tenant_isolation").await,
        "flows must carry the (tenant, environment) isolation policy"
    );
    assert!(
        check_constraint_exists(pool, "flows", "flows_scope_nonempty").await,
        "flows must carry the nonempty-scope CHECK"
    );
    // The single-use completion latch column is present and nullable (NULL until the flow
    // completes), so a completed row is the durable single-use evidence.
    assert!(
        !column_is_not_null(pool, "flows", "consumed_at").await,
        "flows.consumed_at must be nullable (the single-use completion latch)"
    );
    // The transient client payload lives ONLY on the flow row (never on an identity table),
    // so the passthrough cannot persist on the identity by construction.
    assert!(
        column_exists(pool, "flows", "transient_payload").await,
        "flows.transient_payload exists (the transient payload lives only here)"
    );

    // The branding migration (issue #86) is an EXPAND: one new tenant-scoped table (brands),
    // no rewrite of existing state.
    assert_eq!(phase_of(68).await, "expand");

    // The brands store (issue #86) is a NEW tenant-scoped table, so it must ENABLE and FORCE
    // row-level security, carry the (tenant, environment) isolation policy, and pin the
    // nonempty-scope CHECK, exactly like every other scoped table.
    assert!(
        rls_enabled_and_forced(pool, "brands").await,
        "brands must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "brands", "brands_tenant_isolation").await,
        "brands must carry the (tenant, environment) isolation policy"
    );
    assert!(
        check_constraint_exists(pool, "brands", "brands_scope_nonempty").await,
        "brands must carry the nonempty-scope CHECK"
    );
    // At most one DEFAULT brand per scope: the partial unique index is the structural
    // single-default invariant.
    assert!(
        partial_unique_index_exists(pool, "brands", "brands_default_idx").await,
        "brands must carry the one-default-per-scope partial unique index"
    );
    // The typed tokens and sanitized slots are jsonb, never a raw HTML/CSS text column.
    assert_eq!(
        column_data_type(pool, "brands", "tokens").await,
        "jsonb",
        "brands.tokens must be jsonb (typed design tokens, never free-form CSS)"
    );
    assert_eq!(
        column_data_type(pool, "brands", "slots").await,
        "jsonb",
        "brands.slots must be jsonb (sanitized rich-text slots, never raw HTML)"
    );
    // The data plane READS a brand on the render path but never writes it: SELECT only, no
    // INSERT/UPDATE/DELETE (the control plane owns the brand lifecycle).
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "brands", "SELECT").await,
        "the data-plane role must hold SELECT on brands (the render read)"
    );
    assert!(
        !role_has_table_privilege(pool, "ironauth_app", "brands", "INSERT").await,
        "the data-plane role must NOT hold INSERT on brands (the control plane owns writes)"
    );

    // The locale-bundles migration (issue #86, PR 2) is an EXPAND: one new tenant-scoped table
    // (locale_bundles), no rewrite of existing state.
    assert_eq!(phase_of(69).await, "expand");

    // The locale_bundles store (issue #86) is a NEW tenant-scoped table, so it must ENABLE and
    // FORCE row-level security, carry the (tenant, environment) isolation policy, and pin the
    // nonempty-scope CHECK, exactly like every other scoped table.
    assert!(
        rls_enabled_and_forced(pool, "locale_bundles").await,
        "locale_bundles must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "locale_bundles", "locale_bundles_tenant_isolation").await,
        "locale_bundles must carry the (tenant, environment) isolation policy"
    );
    assert!(
        check_constraint_exists(pool, "locale_bundles", "locale_bundles_scope_nonempty").await,
        "locale_bundles must carry the nonempty-scope CHECK"
    );
    // At most one ENV DEFAULT locale per scope: the partial unique index is the structural
    // single-default invariant.
    assert!(
        partial_unique_index_exists(pool, "locale_bundles", "locale_bundles_default_idx").await,
        "locale_bundles must carry the one-default-per-scope partial unique index"
    );
    // The bundle entries are jsonb, never a raw HTML/markup text column.
    assert_eq!(
        column_data_type(pool, "locale_bundles", "entries").await,
        "jsonb",
        "locale_bundles.entries must be jsonb (numeric-id to plain-text map, never markup)"
    );
    // The data plane READS the installed locales on the render / discovery path but never
    // writes them: SELECT only, no INSERT/UPDATE/DELETE (the control plane owns the lifecycle).
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "locale_bundles", "SELECT").await,
        "the data-plane role must hold SELECT on locale_bundles (the render / discovery read)"
    );
    assert!(
        !role_has_table_privilege(pool, "ironauth_app", "locale_bundles", "INSERT").await,
        "the data-plane role must NOT hold INSERT on locale_bundles (control plane owns writes)"
    );

    // The brand-assets migration (issue #86, PR 3) is an EXPAND: one new tenant-scoped table
    // (brand_assets) plus two additive partial unique indexes on the existing brands columns, no
    // rewrite of existing state.
    assert_eq!(phase_of(70).await, "expand");

    // The brand_assets store (issue #86, PR 3) is a NEW tenant-scoped table, so it must ENABLE and
    // FORCE row-level security, carry the (tenant, environment) isolation policy, and pin the
    // nonempty-scope CHECK, exactly like every other scoped table.
    assert!(
        rls_enabled_and_forced(pool, "brand_assets").await,
        "brand_assets must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "brand_assets", "brand_assets_tenant_isolation").await,
        "brand_assets must carry the (tenant, environment) isolation policy"
    );
    assert!(
        check_constraint_exists(pool, "brand_assets", "brand_assets_scope_nonempty").await,
        "brand_assets must carry the nonempty-scope CHECK"
    );
    // The closed kind CHECK pins the raster set of asset kinds: an unknown kind can never be
    // written.
    let asset_kind_check: String = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'brand_assets'::regclass AND conname = 'brand_assets_kind_known'",
    )
    .fetch_one(pool)
    .await
    .expect("brand_assets kind check lookup")
    .get("def");
    for kind in ["logo", "favicon"] {
        assert!(
            asset_kind_check.contains(kind),
            "the brand_assets kind CHECK must admit {kind}, got: {asset_kind_check}"
        );
    }
    // The size ceiling CHECK bounds the stored payload, so a management key holder cannot store an
    // oversize asset that inflates the serve cost.
    assert!(
        check_constraint_exists(pool, "brand_assets", "brand_assets_size_bounded").await,
        "brand_assets must carry the size-bounded CHECK"
    );
    // One logo and one favicon per brand: the natural key (scope, brand_slug, kind) is the
    // PRIMARY KEY, so a second asset of the same kind for the same brand is a structural conflict.
    let asset_pk: String = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'brand_assets'::regclass AND conname = 'brand_assets_pkey'",
    )
    .fetch_one(pool)
    .await
    .expect("brand_assets pkey lookup")
    .get("def");
    assert!(
        asset_pk.starts_with("PRIMARY KEY")
            && asset_pk.contains("brand_slug")
            && asset_pk.contains("kind"),
        "brand_assets must pin the one-asset-per-(brand,kind) PRIMARY KEY, got: {asset_pk}"
    );
    // The bytes are jsonb-free binary: a bytea column, never a text HTML/CSS column.
    assert_eq!(
        column_data_type(pool, "brand_assets", "bytes").await,
        "bytea",
        "brand_assets.bytes must be a bytea (inert raster bytes, never markup)"
    );
    // The data plane READS an asset on the serve path but never writes it: SELECT only.
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "brand_assets", "SELECT").await,
        "the data-plane role must hold SELECT on brand_assets (the serve read)"
    );
    assert!(
        !role_has_table_privilege(pool, "ironauth_app", "brand_assets", "INSERT").await,
        "the data-plane role must NOT hold INSERT on brand_assets (control plane owns writes)"
    );

    // The two brands selection partial unique indexes (issue #86, PR 3): the routing-confusion
    // structural defense on the EXISTING brands columns. Within a scope, a host_pattern and a
    // client_id each select at most one brand, so per-domain / per-client selection is never
    // ambiguous.
    assert!(
        partial_unique_index_exists(pool, "brands", "brands_host_pattern_idx").await,
        "brands must carry the per-scope host_pattern partial unique index"
    );
    assert!(
        partial_unique_index_exists(pool, "brands", "brands_client_id_idx").await,
        "brands must carry the per-scope client_id partial unique index"
    );

    // The diagnostic-reason-detail migration (issue #91) is an EXPAND: two additive nullable
    // columns (skew_seconds, expected) on the EXISTING client_auth_diagnostics table for the M9
    // flow inspector's richer reasons, no rewrite of existing state.
    assert_eq!(phase_of(71).await, "expand");

    // The two derived, non-secret columns exist and are NULLABLE (NULL for every pre-#91 row and
    // for a standard-verbosity capture; only a verbose capture of the relevant reason fills them).
    for column in ["skew_seconds", "expected"] {
        assert!(
            column_exists(pool, "client_auth_diagnostics", column).await,
            "client_auth_diagnostics.{column} exists after 0071"
        );
        assert!(
            !column_is_not_null(pool, "client_auth_diagnostics", column).await,
            "client_auth_diagnostics.{column} must be nullable (a derived field, absent by default)"
        );
    }
    assert_eq!(
        column_data_type(pool, "client_auth_diagnostics", "skew_seconds").await,
        "bigint",
        "client_auth_diagnostics.skew_seconds must be a bigint (a bounded integer bucket)"
    );
    // The ALTER preserves the sink's row level security: after adding the columns the table must
    // STILL ENABLE and FORCE RLS and carry its (tenant, environment) isolation policy, exactly as
    // migration 0013 declared, so the M9 read stays scope-confined.
    assert!(
        rls_enabled_and_forced(pool, "client_auth_diagnostics").await,
        "client_auth_diagnostics must still ENABLE and FORCE row-level security after 0071"
    );
    assert!(
        policy_exists(
            pool,
            "client_auth_diagnostics",
            "client_auth_diagnostics_tenant_isolation"
        )
        .await,
        "client_auth_diagnostics must still carry the (tenant, environment) isolation policy"
    );
    // The data-plane role reads the sink for the M9 view (a table-level SELECT that already covers
    // the two new columns) but never mutates a diagnostic in place: no UPDATE grant exists.
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "client_auth_diagnostics", "SELECT").await,
        "the data-plane role must hold SELECT on client_auth_diagnostics (the M9 read)"
    );
    assert!(
        !role_has_table_privilege(pool, "ironauth_app", "client_auth_diagnostics", "UPDATE").await,
        "the data-plane role must NOT hold UPDATE on client_auth_diagnostics (a diagnostic is \
         never mutated in place)"
    );

    // The diagnostics-control-read migration (issue #91) is an EXPAND: a single table-level
    // GRANT SELECT to the control-plane role, so the M9 admin flow inspector can READ the sink.
    assert_eq!(phase_of(72).await, "expand");
    // After 0072 the control-plane role holds SELECT on the sink (the M9 admin read), and ONLY
    // SELECT: it never writes or prunes a diagnostic (the data-plane recorder owns that), so it
    // holds neither INSERT nor DELETE. This is the grant the admin endpoint's read depends on.
    assert!(
        role_has_table_privilege(
            pool,
            "ironauth_control",
            "client_auth_diagnostics",
            "SELECT"
        )
        .await,
        "the control-plane role must hold SELECT on client_auth_diagnostics after 0072 (the M9 read)"
    );
    for privilege in ["INSERT", "UPDATE", "DELETE"] {
        assert!(
            !role_has_table_privilege(
                pool,
                "ironauth_control",
                "client_auth_diagnostics",
                privilege
            )
            .await,
            "the control-plane role must NOT hold {privilege} on client_auth_diagnostics (it only \
             reads the sink)"
        );
    }

    // The policy-decision-traces migration (issue #91, PR 3) is an EXPAND that adds the two M9
    // diagnostics sinks (the traces and the token-size events). Each MUST enforce scope isolation
    // (ENABLE and FORCE row-level security plus its (tenant, environment) policy), be append-only
    // for the data-plane recorder (SELECT, INSERT, and the retention DELETE, never UPDATE), and be
    // read-only for the control-plane admin view (SELECT only, never a write).
    assert_eq!(phase_of(73).await, "expand");
    for table in ["policy_decision_traces", "token_size_events"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "{table} must carry the (tenant, environment) isolation policy"
        );
        for privilege in ["SELECT", "INSERT", "DELETE"] {
            assert!(
                role_has_table_privilege(pool, "ironauth_app", table, privilege).await,
                "the data-plane role must hold {privilege} on {table} (record and prune)"
            );
        }
        assert!(
            !role_has_table_privilege(pool, "ironauth_app", table, "UPDATE").await,
            "the data-plane role must NOT hold UPDATE on {table} (a trace is never mutated)"
        );
        assert!(
            role_has_table_privilege(pool, "ironauth_control", table, "SELECT").await,
            "the control-plane role must hold SELECT on {table} (the M9 admin read)"
        );
        for privilege in ["INSERT", "UPDATE", "DELETE"] {
            assert!(
                !role_has_table_privilege(pool, "ironauth_control", table, privilege).await,
                "the control-plane role must NOT hold {privilege} on {table} (it only reads)"
            );
        }
    }

    // The signup-forms migration (issue #87) is an EXPAND: one new tenant-scoped table
    // (signup_forms), no rewrite of existing state.
    assert_eq!(phase_of(75).await, "expand");

    // The signup_forms store (issue #87) is a NEW tenant-scoped table, so it must ENABLE and
    // FORCE row-level security, carry the (tenant, environment) isolation policy, and pin the
    // nonempty-scope CHECK, exactly like every other scoped table.
    assert!(
        rls_enabled_and_forced(pool, "signup_forms").await,
        "signup_forms must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "signup_forms", "signup_forms_tenant_isolation").await,
        "signup_forms must carry the (tenant, environment) isolation policy"
    );
    assert!(
        check_constraint_exists(pool, "signup_forms", "signup_forms_scope_nonempty").await,
        "signup_forms must carry the nonempty-scope CHECK"
    );
    // The field list is jsonb, never a raw text column.
    assert_eq!(
        column_data_type(pool, "signup_forms", "fields").await,
        "jsonb",
        "signup_forms.fields must be jsonb (the validated field list, never a raw text blob)"
    );
    // The CONTROL plane owns the signup form lifecycle (set, get, delete); the DATA plane READS
    // the active form on the flow-creation path but never writes it: SELECT only.
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "signup_forms", "SELECT").await,
        "the data-plane role must hold SELECT on signup_forms (the flow-creation read)"
    );
    assert!(
        !role_has_table_privilege(pool, "ironauth_app", "signup_forms", "INSERT").await,
        "the data-plane role must NOT hold INSERT on signup_forms (the control plane owns writes)"
    );

    // Revocable consent and first-party classification (issue #88, migration 0076): the
    // additive columns exist with the right types and the column-grant split holds.
    assert!(
        column_exists(pool, "consents", "revoked_at").await,
        "consents.revoked_at exists after 0076"
    );
    assert!(
        column_exists(pool, "clients", "first_party").await,
        "clients.first_party exists after 0076"
    );
    assert_eq!(
        column_data_type(pool, "clients", "first_party").await,
        "boolean",
        "clients.first_party is a boolean"
    );
    // consents.revoked_at is a self-service kill switch: the data-plane role flips exactly this
    // column (through its existing table SELECT), and holds no wider write. A revoked grant is
    // read as absent, so the app must be able to set revoked_at but nothing else new.
    assert!(
        role_has_column_privilege(pool, "ironauth_app", "consents", "revoked_at", "UPDATE").await,
        "the data-plane role must hold column-scoped UPDATE on consents.revoked_at (self-service revoke)"
    );
    assert!(
        !role_has_column_privilege(pool, "ironauth_app", "consents", "subject", "UPDATE").await,
        "the data-plane role must NOT hold UPDATE on consents.subject (no widening past revoked_at)"
    );
    // clients.first_party is the lockdown carve-out flag: control-plane write-only, exactly like
    // quarantined and verified_at, so a compromised data plane can never self-classify a client as
    // first-party to defeat the PR3 lockdown gate.
    assert!(
        role_has_column_privilege(pool, "ironauth_control", "clients", "first_party", "UPDATE")
            .await,
        "the control role must hold column-scoped UPDATE on clients.first_party"
    );
    assert!(
        !role_has_column_privilege(pool, "ironauth_app", "clients", "first_party", "UPDATE").await,
        "the data-plane role must NOT hold UPDATE on clients.first_party (no self-classification)"
    );

    // The client-admin-grants migration (issue #88, PR 4, migration 0077) is an EXPAND: one new
    // tenant-scoped table (client_admin_grants), no rewrite of existing state.
    assert_eq!(phase_of(77).await, "expand");

    // The client_admin_grants store is a NEW tenant-scoped table, so it must ENABLE and FORCE
    // row-level security, carry the (tenant, environment) isolation policy, and pin the
    // nonempty-scope CHECK, exactly like every other scoped table.
    assert!(
        rls_enabled_and_forced(pool, "client_admin_grants").await,
        "client_admin_grants must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(
            pool,
            "client_admin_grants",
            "client_admin_grants_tenant_isolation"
        )
        .await,
        "client_admin_grants must carry the (tenant, environment) isolation policy"
    );
    assert!(
        check_constraint_exists(
            pool,
            "client_admin_grants",
            "client_admin_grants_scope_nonempty"
        )
        .await,
        "client_admin_grants must carry the nonempty-scope CHECK"
    );
    // The CONTROL plane owns the pre-authorization lifecycle (set, get, delete); the DATA plane
    // READS the active pre-authorization on the consent gate path but never writes it: SELECT only.
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "client_admin_grants", "SELECT").await,
        "the data-plane role must hold SELECT on client_admin_grants (the consent gate read)"
    );
    assert!(
        !role_has_table_privilege(pool, "ironauth_app", "client_admin_grants", "INSERT").await,
        "the data-plane role must NOT hold INSERT on client_admin_grants (the control plane owns writes)"
    );
    assert!(
        role_has_table_privilege(pool, "ironauth_control", "client_admin_grants", "INSERT").await,
        "the control-plane role must hold INSERT on client_admin_grants (it owns the lifecycle)"
    );

    // The consent-control-grants migration (issue #88, PR 5, migration 0078) is an EXPAND: a
    // pure pair of grants (no table, column, or policy change).
    assert_eq!(phase_of(78).await, "expand");

    // The control plane gains the two coherent privileges the admin consent revocation surface
    // needs: SELECT (to target a row and list a subject's grants) and a COLUMN-scoped
    // UPDATE (revoked_at) (to flip it), matching the data plane's own column-scoped grant (0076).
    assert!(
        role_has_table_privilege(pool, "ironauth_control", "consents", "SELECT").await,
        "the control-plane role must hold SELECT on consents (target the row and list grants)"
    );
    assert!(
        role_has_column_privilege(pool, "ironauth_control", "consents", "revoked_at", "UPDATE")
            .await,
        "the control-plane role must hold column-scoped UPDATE on consents.revoked_at (admin revoke)"
    );
    // The UPDATE is COLUMN scoped, never table-wide: the control plane can never rewrite a
    // consent's subject (or any column but revoked_at), so it can review and revoke, nothing more.
    assert!(
        !role_has_column_privilege(pool, "ironauth_control", "consents", "subject", "UPDATE").await,
        "the control-plane role must NOT hold UPDATE on consents.subject (revoke is revoked_at only)"
    );
    // The control plane never MINTS or DELETES a consent (only the data-plane gate records one,
    // and a revoked row is retained for audit rather than deleted), so it holds neither privilege.
    assert!(
        !role_has_table_privilege(pool, "ironauth_control", "consents", "INSERT").await,
        "the control-plane role must NOT hold INSERT on consents (only the data plane mints one)"
    );
    assert!(
        !role_has_table_privilege(pool, "ironauth_control", "consents", "DELETE").await,
        "the control-plane role must NOT hold DELETE on consents (a revoked row is retained)"
    );
    // The data plane's own self-service grant (0076) is untouched: it still holds column-scoped
    // UPDATE (revoked_at), so 0078 added the control-plane grants WITHOUT disturbing the data plane.
    assert!(
        role_has_column_privilege(pool, "ironauth_app", "consents", "revoked_at", "UPDATE").await,
        "the data-plane role must still hold column-scoped UPDATE on consents.revoked_at (0076)"
    );

    // The custom-journey version registry migration (issue #92, PR 5, migration 0080) is an
    // EXPAND: two new tenant-scoped tables (flow_versions, flow_version_pins) plus the deferred
    // flows foreign key, no rewrite of existing state.
    assert_eq!(phase_of(80).await, "expand");

    // Both new tables ENABLE and FORCE row-level security, carry the (tenant, environment)
    // isolation policy, and pin the nonempty-scope CHECK, exactly like every other scoped table.
    for table in ["flow_versions", "flow_version_pins"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "{table} must carry the (tenant, environment) isolation policy"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the nonempty-scope CHECK"
        );
    }
    // The journey artifact is jsonb (a validated, canonicalizable document, never a raw text blob).
    assert_eq!(
        column_data_type(pool, "flow_versions", "artifact").await,
        "jsonb",
        "flow_versions.artifact must be jsonb"
    );
    // The CONTROL plane OWNS journey authoring (create a version, set a pin), and a version is
    // immutable and never deleted (append-only): it holds SELECT and INSERT on flow_versions but
    // never UPDATE or DELETE.
    assert!(
        role_has_table_privilege(pool, "ironauth_control", "flow_versions", "SELECT").await
            && role_has_table_privilege(pool, "ironauth_control", "flow_versions", "INSERT").await,
        "the control-plane role must hold SELECT and INSERT on flow_versions (journey authoring)"
    );
    for privilege in ["UPDATE", "DELETE"] {
        assert!(
            !role_has_table_privilege(pool, "ironauth_control", "flow_versions", privilege).await,
            "the control-plane role must NOT hold {privilege} on flow_versions (append-only registry)"
        );
    }
    // The DATA plane READS a pinned version's artifact on the custom-flow creation and drive path,
    // so it holds SELECT only on both tables, never a write.
    for table in ["flow_versions", "flow_version_pins"] {
        assert!(
            role_has_table_privilege(pool, "ironauth_app", table, "SELECT").await,
            "the data-plane role must hold SELECT on {table} (the custom-flow read)"
        );
        assert!(
            !role_has_table_privilege(pool, "ironauth_app", table, "INSERT").await,
            "the data-plane role must NOT hold INSERT on {table} (the control plane owns writes)"
        );
    }
    // Moving the active pin is the only mutation of flow_version_pins, so the control plane's
    // UPDATE is COLUMN-scoped to flow_version_id (and updated_at), never a table-wide UPDATE: it
    // can never rewrite a pin's journey_id or scope.
    assert!(
        role_has_column_privilege(
            pool,
            "ironauth_control",
            "flow_version_pins",
            "flow_version_id",
            "UPDATE"
        )
        .await,
        "the control-plane role must hold column-scoped UPDATE on flow_version_pins.flow_version_id"
    );
    assert!(
        !role_has_column_privilege(
            pool,
            "ironauth_control",
            "flow_version_pins",
            "journey_id",
            "UPDATE"
        )
        .await,
        "the control-plane role must NOT hold UPDATE on flow_version_pins.journey_id (pin move only)"
    );
    // The deferred flows foreign key is now closed: flows.flow_version_id references flow_versions.
    let flows_fk: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_constraint \
         WHERE conrelid = 'flows'::regclass AND contype = 'f' \
         AND conname = 'flows_flow_version_id_fkey')",
    )
    .fetch_one(pool)
    .await
    .expect("query the flows foreign key");
    assert!(
        flows_fk,
        "the flows.flow_version_id foreign key into flow_versions must exist after 0080"
    );

    // EXPAND (issue #93): an additive browserless flag on the authorization codes table for the
    // OAuth 2.0 Authorization Challenge Endpoint's browserless first-party codes.
    assert_eq!(phase_of(81).await, "expand");
    assert!(
        column_exists(pool, "authorization_codes", "browserless").await,
        "authorization_codes.browserless exists after 0081"
    );

    // The demo object never reaches a production database.
    assert!(
        !table_exists(pool, "migration_demo").await,
        "the production migrate() must not create a demo table"
    );
    // The real tables and the audit log do exist.
    assert!(table_exists(pool, "clients").await, "clients exists");
    assert!(table_exists(pool, "audit_log").await, "audit_log exists");
    // The management-plane tables (issue #11) exist.
    assert!(
        table_exists(pool, "management_credentials").await,
        "management_credentials exists"
    );
    assert!(
        table_exists(pool, "idempotency_keys").await,
        "idempotency_keys exists"
    );
    // The OIDC authorization tables (issue #12) exist.
    assert!(table_exists(pool, "grants").await, "grants exists");
    assert!(
        table_exists(pool, "authorization_codes").await,
        "authorization_codes exists"
    );
    assert!(
        table_exists(pool, "issued_tokens").await,
        "issued_tokens exists"
    );
    // The per-environment signing keys table (issue #19) exists.
    assert!(
        table_exists(pool, "signing_keys").await,
        "signing_keys exists"
    );
    // The typed-environment columns (issue #42): the environment kind (dev,
    // staging, prod) that drives the guardrail asymmetry, and the configured
    // custom domain the production custom-domain guardrail requires.
    assert!(
        column_exists(pool, "environments", "kind").await,
        "environments.kind exists"
    );
    assert!(
        column_exists(pool, "environments", "custom_domain").await,
        "environments.custom_domain exists"
    );
    // The bootstrap login/consent/session tables (issue #20) exist.
    assert!(table_exists(pool, "users").await, "users exists");
    assert!(table_exists(pool, "sessions").await, "sessions exists");
    assert!(table_exists(pool, "consents").await, "consents exists");
    // The self-service account-credential registry (issue #61) exists, with its
    // per-user credential columns: the subject the credential belongs to, the closed
    // factor type, the sealed friendly name and its DEK version (user PII never lands
    // on a plaintext column), the primary-login-usable flag, and the created /
    // last-used timestamps the account UI shows.
    assert!(
        table_exists(pool, "account_credentials").await,
        "account_credentials exists"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "credential_type",
        "friendly_name_sealed",
        "pii_dek_version",
        "usable_for_login",
        "created_at",
        "last_used_at",
    ] {
        assert!(
            column_exists(pool, "account_credentials", column).await,
            "account_credentials.{column} exists after 0036"
        );
    }
    // A credential's friendly name is user-authored PII, sealed under the scope DEK
    // (issue #48): the plaintext label never lands on a column.
    assert!(
        !column_exists(pool, "account_credentials", "friendly_name").await,
        "account_credentials must have no plaintext friendly_name column after 0036"
    );
    // The trusted-devices remember-device state (issue #71): a tenant-scoped, RLS-forced
    // table with the server-side secret digest (never a self-contained token), the
    // subject+session lineage binding, sealed UA/geo (PII), the max-age/idle duration
    // columns, and the immediate revoked_at kill switch.
    assert!(
        table_exists(pool, "trusted_devices").await,
        "trusted_devices exists after 0053"
    );
    assert!(
        rls_enabled_and_forced(pool, "trusted_devices").await,
        "trusted_devices has row-level security ENABLED and FORCED"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "device_secret_hash",
        "session_lineage",
        "user_agent_sealed",
        "geo_sealed",
        "pii_dek_version",
        "created_at",
        "last_seen_at",
        "max_age_expires_at",
        "idle_expires_at",
        "revoked_at",
        "revoke_reason",
    ] {
        assert!(
            column_exists(pool, "trusted_devices", column).await,
            "trusted_devices.{column} exists after 0053"
        );
    }
    // The device metadata is end-user PII, sealed under the scope DEK (issue #48): the
    // plaintext User-Agent and location never land on a column.
    assert!(
        !column_exists(pool, "trusted_devices", "user_agent").await,
        "trusted_devices must have no plaintext user_agent column after 0053"
    );
    assert!(
        !column_exists(pool, "trusted_devices", "geo").await,
        "trusted_devices must have no plaintext geo column after 0053"
    );
    // The revoke-reason CHECK pins the closed set, so an unknown reason can never be
    // written and the reason is present exactly when the row is revoked.
    let trusted_device_revoke_check: String = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'trusted_devices'::regclass \
         AND conname = 'trusted_devices_revoke_reason_known'",
    )
    .fetch_one(pool)
    .await
    .expect("trusted_devices revoke-reason check lookup")
    .get("def");
    for reason in ["user", "admin", "password_change", "factor_change"] {
        assert!(
            trusted_device_revoke_check.contains(reason),
            "the trusted_devices revoke-reason CHECK must admit {reason}, got: \
             {trusted_device_revoke_check}"
        );
    }
    // The account-recovery state machine (issue #81): a tenant-scoped, RLS-forced table
    // with the recovery state / entry point (closed sets), the recover-factor strength
    // the downgrade invariant protects, the cancellation-token digest (never the token),
    // the sealed recipient (PII), and the delay-window / lifecycle timestamps.
    assert!(
        table_exists(pool, "recovery_flows").await,
        "recovery_flows exists after 0055"
    );
    assert!(
        rls_enabled_and_forced(pool, "recovery_flows").await,
        "recovery_flows has row-level security ENABLED and FORCED"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "state",
        "entry_point",
        "recover_acr",
        "cancel_token_digest",
        "recipient_sealed",
        "pii_dek_version",
        "initiated_at",
        "hold_until",
        "cancelled_at",
        "cancel_reason",
        "completed_at",
    ] {
        assert!(
            column_exists(pool, "recovery_flows", column).await,
            "recovery_flows.{column} exists after 0055"
        );
    }
    // The recovery recipient is end-user PII, sealed under the scope DEK (issue #48): the
    // plaintext recipient never lands on a column.
    assert!(
        !column_exists(pool, "recovery_flows", "recipient").await,
        "recovery_flows must have no plaintext recipient column after 0055"
    );
    assert!(
        check_constraint_exists(pool, "recovery_flows", "recovery_flows_scope_nonempty").await,
        "recovery_flows has the nonempty-scope CHECK"
    );
    // The state CHECK pins the closed recovery state-machine set.
    let recovery_state_check: String = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'recovery_flows'::regclass \
         AND conname = 'recovery_flows_state_known'",
    )
    .fetch_one(pool)
    .await
    .expect("recovery_flows state check lookup")
    .get("def");
    for state in ["initiated", "held", "cancelled", "completed"] {
        assert!(
            recovery_state_check.contains(state),
            "the recovery_flows state CHECK must admit {state}, got: {recovery_state_check}"
        );
    }
    // The entry-point CHECK pins the closed entry-point set.
    let recovery_entry_check: String = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'recovery_flows'::regclass \
         AND conname = 'recovery_flows_entry_point_known'",
    )
    .fetch_one(pool)
    .await
    .expect("recovery_flows entry-point check lookup")
    .get("def");
    for entry in ["lost_password", "lost_second_factor", "lost_all_factors"] {
        assert!(
            recovery_entry_check.contains(entry),
            "the recovery_flows entry-point CHECK must admit {entry}, got: {recovery_entry_check}"
        );
    }
    // The proof-of-work challenge state (issue #80): a tenant-scoped, RLS-forced table with
    // the (non-secret) challenge bytes, the difficulty, the endpoint+context binding, the
    // single-use spent latch, and the expiry.
    assert!(
        table_exists(pool, "pow_challenges").await,
        "pow_challenges exists after 0057"
    );
    assert!(
        rls_enabled_and_forced(pool, "pow_challenges").await,
        "pow_challenges has row-level security ENABLED and FORCED"
    );
    assert!(
        policy_exists(pool, "pow_challenges", "pow_challenges_tenant_isolation").await,
        "pow_challenges has the tenant-isolation policy"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "challenge",
        "difficulty_bits",
        "context_hash",
        "spent_at",
        "expires_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "pow_challenges", column).await,
            "pow_challenges.{column} exists after 0057"
        );
    }
    for constraint in [
        "pow_challenges_scope_nonempty",
        "pow_challenges_difficulty_range",
    ] {
        assert!(
            check_constraint_exists(pool, "pow_challenges", constraint).await,
            "pow_challenges has the {constraint} CHECK"
        );
    }
    // The waitlist state (issue #80): the users.state CHECK was WIDENED to admit
    // 'waitlisted', so a self-service signup made while waitlist mode is on can land in the
    // pending state that cannot authenticate.
    let users_state_check: String = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'users'::regclass AND conname = 'users_state_valid'",
    )
    .fetch_one(pool)
    .await
    .expect("users_state_valid check lookup")
    .get("def");
    assert!(
        users_state_check.contains("waitlisted"),
        "the users.state CHECK must admit the waitlist 'waitlisted' state, got: {users_state_check}"
    );
    // The authentication-context columns (issue #14) exist: the recorded login
    // methods on sessions and codes, the frozen auth_time on codes, and the
    // client's require_auth_time registration flag.
    assert!(
        column_exists(pool, "sessions", "auth_methods").await,
        "sessions.auth_methods exists"
    );
    assert!(
        column_exists(pool, "authorization_codes", "auth_methods").await,
        "authorization_codes.auth_methods exists"
    );
    assert!(
        column_exists(pool, "authorization_codes", "auth_time").await,
        "authorization_codes.auth_time exists"
    );
    assert!(
        column_exists(pool, "clients", "require_auth_time").await,
        "clients.require_auth_time exists"
    );
    // The registered redirect URIs for the exact-string redirect match (issue #13).
    assert!(
        column_exists(pool, "clients", "redirect_uris").await,
        "clients.redirect_uris exists"
    );
    // The UserInfo standard-claim store (issue #15) is now SEALED, not plaintext
    // (issue #48): migration 0027 replaced the plaintext users.claims text column
    // with the sealed claims_sealed ciphertext (asserted with the other users PII
    // columns below). The persisted `claims` request parameter (which claim NAMES
    // to release, not values) stays plaintext on the grant (read by UserInfo) and
    // the code (read at the token endpoint).
    assert!(
        column_exists(pool, "grants", "claims_request").await,
        "grants.claims_request exists"
    );
    assert!(
        column_exists(pool, "authorization_codes", "claims_request").await,
        "authorization_codes.claims_request exists"
    );
    // The resource-server registry and the digest-only opaque-token store (issue
    // #29): the audience-to-format table the mint reads, and the digest-only table
    // the internal resolve reads.
    assert!(
        table_exists(pool, "resource_servers").await,
        "resource_servers exists"
    );
    assert!(
        table_exists(pool, "opaque_access_tokens").await,
        "opaque_access_tokens exists"
    );
    // The JWT-assertion client-authentication suite (issue #25): the additive
    // clients key/alg registration columns, the cross-node single-use jti replay
    // cache, and the out-of-band diagnostics sink.
    assert!(
        column_exists(pool, "clients", "jwks").await,
        "clients.jwks exists"
    );
    assert!(
        column_exists(pool, "clients", "jwks_uri").await,
        "clients.jwks_uri exists"
    );
    assert!(
        column_exists(pool, "clients", "token_endpoint_auth_signing_alg").await,
        "clients.token_endpoint_auth_signing_alg exists"
    );
    assert!(
        table_exists(pool, "client_assertion_jtis").await,
        "client_assertion_jtis exists"
    );
    assert!(
        table_exists(pool, "client_auth_diagnostics").await,
        "client_auth_diagnostics exists"
    );
    // The Dynamic Client Registration and configuration-management columns (issue
    // #30): the RFC 7592 registration access token hash and client URI, the
    // negotiated id_token signing algorithm, the RFC 8252 application type, and the
    // DCR-origin flag.
    assert!(
        column_exists(pool, "clients", "registration_access_token_hash").await,
        "clients.registration_access_token_hash exists"
    );
    assert!(
        column_exists(pool, "clients", "registration_client_uri").await,
        "clients.registration_client_uri exists"
    );
    assert!(
        column_exists(pool, "clients", "id_token_signed_response_alg").await,
        "clients.id_token_signed_response_alg exists"
    );
    assert!(
        column_exists(pool, "clients", "application_type").await,
        "clients.application_type exists"
    );
    assert!(
        column_exists(pool, "clients", "dcr_registered").await,
        "clients.dcr_registered exists"
    );
    // The pushed-authorization-request store and the per-client require-PAR flag
    // (issue #27): the single-use request_uri table and the additive clients column.
    assert!(
        table_exists(pool, "pushed_authorization_requests").await,
        "pushed_authorization_requests exists"
    );
    assert!(
        column_exists(pool, "clients", "require_pushed_authorization_requests").await,
        "clients.require_pushed_authorization_requests exists"
    );
    // The refresh-token rotation suite (issue #21): the family spine, the
    // digest-only token store, the additive clients consent-mode / rotation-override
    // columns, and the additive consents.expires_at.
    assert!(
        table_exists(pool, "refresh_families").await,
        "refresh_families exists"
    );
    assert!(
        table_exists(pool, "refresh_tokens").await,
        "refresh_tokens exists"
    );
    assert!(
        column_exists(pool, "clients", "consent_mode").await,
        "clients.consent_mode exists"
    );
    assert!(
        column_exists(pool, "clients", "skip_consent").await,
        "clients.skip_consent exists"
    );
    assert!(
        column_exists(pool, "clients", "store_skipped_consent").await,
        "clients.store_skipped_consent exists"
    );
    assert!(
        column_exists(pool, "clients", "refresh_rotation").await,
        "clients.refresh_rotation exists"
    );
    assert!(
        column_exists(pool, "consents", "expires_at").await,
        "consents.expires_at exists"
    );
    // The digest-only invariant (issue #21, acceptance criterion 7): the
    // refresh_tokens table has NO plaintext-token column, only a digest.
    assert!(
        column_exists(pool, "refresh_tokens", "token_digest").await,
        "refresh_tokens stores a digest"
    );
    for forbidden in ["token", "secret", "plaintext", "refresh_token"] {
        assert!(
            !column_exists(pool, "refresh_tokens", forbidden).await,
            "refresh_tokens must have no plaintext-token column ({forbidden})"
        );
    }
    // The client-credentials service-account principal table and the per-client
    // custom-claims column (issue #23): the stable machine-`sub` mapping and the
    // declarative M2M token claims.
    assert!(
        table_exists(pool, "service_accounts").await,
        "service_accounts exists"
    );
    assert!(
        column_exists(pool, "clients", "custom_token_claims").await,
        "clients.custom_token_claims exists"
    );
    // The Dynamic Client Registration abuse-control tables (issue #31): the
    // reusable named policy objects, the SHA-256-hashed initial-access-token store,
    // and the endpoint-local rate counters.
    assert!(
        table_exists(pool, "dcr_policies").await,
        "dcr_policies exists"
    );
    assert!(
        table_exists(pool, "dcr_initial_access_tokens").await,
        "dcr_initial_access_tokens exists"
    );
    assert!(
        table_exists(pool, "dcr_rate_counters").await,
        "dcr_rate_counters exists"
    );
    // The initial-access-token store keeps only the token's HASH, never the
    // plaintext (the credential-at-rest invariant, issue #31).
    assert!(
        column_exists(pool, "dcr_initial_access_tokens", "token_hash").await,
        "dcr_initial_access_tokens stores a hash"
    );
    for forbidden in ["token", "secret", "plaintext"] {
        assert!(
            !column_exists(pool, "dcr_initial_access_tokens", forbidden).await,
            "dcr_initial_access_tokens must have no plaintext-token column ({forbidden})"
        );
    }
    // The unverified-client quarantine columns (issue #31): the quarantine flag,
    // the admin verification timestamp, and the policy-chain snapshot that binds
    // RFC 7592 updates for the client's lifetime.
    assert!(
        column_exists(pool, "clients", "quarantined").await,
        "clients.quarantined exists"
    );
    assert!(
        column_exists(pool, "clients", "verified_at").await,
        "clients.verified_at exists"
    );
    assert!(
        column_exists(pool, "clients", "dcr_policy_chain").await,
        "clients.dcr_policy_chain exists"
    );
    // The out-of-band actionable audit detail dimension (issue #31).
    assert!(
        column_exists(pool, "audit_log", "detail").await,
        "audit_log.detail exists"
    );
    // The device-authorization grant table (issue #24, RFC 8628): the digest-only
    // device-code and hashed user-code store, plus the two additive clients columns
    // (the grant allowlist and the display logo).
    assert!(
        table_exists(pool, "device_codes").await,
        "device_codes exists"
    );
    // The device-authorization credential-at-rest invariant (RFC 8628 5.1/6.1): the
    // table stores only a digest of the device code and a hash of the user code,
    // never a plaintext of either.
    assert!(
        column_exists(pool, "device_codes", "device_code_digest").await,
        "device_codes stores a device-code digest"
    );
    assert!(
        column_exists(pool, "device_codes", "user_code_hash").await,
        "device_codes stores a user-code hash"
    );
    for forbidden in ["device_code", "user_code", "secret", "plaintext"] {
        assert!(
            !column_exists(pool, "device_codes", forbidden).await,
            "device_codes must have no plaintext device_code/user_code column ({forbidden})"
        );
    }
    // The polling and cross-device-BCP bookkeeping columns (issue #24): the enforced
    // slow_down interval and last-poll instant, the failed-match death counter, and
    // the initiation-location hint.
    for column in [
        "interval_secs",
        "last_poll_at",
        "failed_attempts",
        "initiation_hint",
        "status",
    ] {
        assert!(
            column_exists(pool, "device_codes", column).await,
            "device_codes.{column} exists"
        );
    }
    // The per-client device-grant allowlist and display logo (issue #24).
    assert!(
        column_exists(pool, "clients", "grant_types").await,
        "clients.grant_types exists"
    );
    assert!(
        column_exists(pool, "clients", "logo_uri").await,
        "clients.logo_uri exists"
    );
    // The RFC 8707 resource-indicator columns (issue #28): the per-client allowlist
    // and no-resource policy, the frozen granted-resource ceiling on the grant and
    // the code, and the recorded audience array on an opaque token.
    assert!(
        column_exists(pool, "clients", "allowed_resources").await,
        "clients.allowed_resources exists"
    );
    assert!(
        column_exists(pool, "clients", "resource_indicator_policy").await,
        "clients.resource_indicator_policy exists"
    );
    assert!(
        column_exists(pool, "grants", "granted_resources").await,
        "grants.granted_resources exists"
    );
    assert!(
        column_exists(pool, "authorization_codes", "granted_resources").await,
        "authorization_codes.granted_resources exists"
    );
    assert!(
        column_exists(pool, "opaque_access_tokens", "audiences").await,
        "opaque_access_tokens.audiences exists"
    );
    // The JWT bearer assertion grant trust and mapping stores (issue #26): the
    // registered external assertion issuers, the explicit subject-mapping rules, and
    // the external-issuer single-use jti replay cache (distinct from the #25 client
    // cache so an external jti cannot collide with a client-assertion jti).
    assert!(
        table_exists(pool, "external_assertion_issuers").await,
        "external_assertion_issuers exists"
    );
    assert!(
        table_exists(pool, "external_assertion_subject_mappings").await,
        "external_assertion_subject_mappings exists"
    );
    assert!(
        table_exists(pool, "external_assertion_jtis").await,
        "external_assertion_jtis exists"
    );
    // The external-issuer jti cache is keyed by the ISSUER (not a client id), the
    // distinct-table choice that keeps an external jti from colliding with a
    // client-assertion jti.
    assert!(
        column_exists(pool, "external_assertion_jtis", "issuer").await,
        "external_assertion_jtis is keyed by issuer"
    );
    // A registered issuer carries an enable switch and a key source.
    assert!(
        column_exists(pool, "external_assertion_issuers", "enabled").await,
        "external_assertion_issuers.enabled exists"
    );
    // A subject-mapping rule maps to an explicit principal (never auto-provisioned).
    assert!(
        column_exists(pool, "external_assertion_subject_mappings", "principal").await,
        "external_assertion_subject_mappings.principal exists"
    );
    // Both trust-config tables carry an `enabled` switch, so a compromised issuer or
    // a mis-authored mapping can be REVOKED through the column-scoped data-plane
    // grant (issue #26 revocability fix). The issuer switch shipped with the table;
    // the mapping switch is the additive column this fix added within migration 20.
    assert!(
        column_exists(pool, "external_assertion_subject_mappings", "enabled").await,
        "external_assertion_subject_mappings.enabled exists"
    );
    // The authoritative two-tier session model (issue #32). Tier two is the new
    // per-client session table: it carries the per-(client, session) `sid` claim,
    // which is STORED (never `sid = session_id`), so it is stable per pair and
    // distinct across pairs.
    assert!(
        table_exists(pool, "client_sessions").await,
        "client_sessions exists"
    );
    for column in ["session_id", "client_id", "sid", "revoked_at"] {
        assert!(
            column_exists(pool, "client_sessions", column).await,
            "client_sessions.{column} exists"
        );
    }
    // Tier one is the EXPANDED sessions table. It gains the immediate-revocation and
    // rotation-lineage guard columns (a revoked or rotated session must stop
    // resolving at once, never merely on expiry) and the session-expiry columns THIS
    // issue owns (idle_expires_at, absolute_expires_at, ended_at, end_cause), so a
    // later issue must not re-add them.
    for column in [
        "revoked_at",
        "revoke_reason",
        "superseded_by",
        "idle_expires_at",
        "absolute_expires_at",
        "ended_at",
        "end_cause",
        "last_seen_at",
        "user_agent",
        "peer_ip",
    ] {
        assert!(
            column_exists(pool, "sessions", column).await,
            "sessions.{column} exists"
        );
    }
    // The RP-initiated logout registered set (issue #33): the additive clients column
    // the end_session endpoint matches a post_logout_redirect_uri against by exact
    // string.
    assert!(
        column_exists(pool, "clients", "post_logout_redirect_uris").await,
        "clients.post_logout_redirect_uris exists"
    );
    // The durable session-ended outbox (issue #35): the transactional-outbox table the
    // session domain enqueues a row on for EVERY terminal end, drained by the
    // back-channel logout worker. Its lifecycle columns (claimed_at, delivered_at) are
    // the only ones a draining consumer is granted UPDATE on.
    assert!(
        table_exists(pool, "session_ended_events").await,
        "session_ended_events exists"
    );
    for column in [
        "session_id",
        "subject",
        "cause",
        "actor_kind",
        "occurred_at",
        "claimed_at",
        "delivered_at",
    ] {
        assert!(
            column_exists(pool, "session_ended_events", column).await,
            "session_ended_events.{column} exists"
        );
    }
    // Back-channel logout registration and the per-RP delivery queue (issue #34): the two
    // additive clients columns the worker resolves a participant from, and the
    // at-least-once delivery table with its own attempts / backoff / dead-letter state.
    assert!(
        column_exists(pool, "clients", "backchannel_logout_uri").await,
        "clients.backchannel_logout_uri exists"
    );
    assert!(
        column_exists(pool, "clients", "backchannel_logout_session_required").await,
        "clients.backchannel_logout_session_required exists"
    );
    assert!(
        table_exists(pool, "backchannel_logout_deliveries").await,
        "backchannel_logout_deliveries exists"
    );
    for column in [
        "event_id",
        "session_id",
        "client_id",
        "sid",
        "logout_uri",
        "jti",
        "attempts",
        "next_attempt_at",
        "claimed_at",
        "delivered_at",
        "dead_lettered_at",
    ] {
        assert!(
            column_exists(pool, "backchannel_logout_deliveries", column).await,
            "backchannel_logout_deliveries.{column} exists"
        );
    }
    // The generic transactional outbox and lease based job queue (issue #104): the ONE
    // at-least-once dispatch substrate every async path drains, which the session-ended
    // fan-out above is now the first consumer on. Its routing columns (consumer,
    // idempotency_key, ordering_key) and its payload are immutable once enqueued; the six
    // lifecycle columns are the only ones a drain is granted UPDATE on.
    assert!(
        table_exists(pool, "outbox_messages").await,
        "outbox_messages exists"
    );
    for column in [
        "consumer",
        "idempotency_key",
        "ordering_key",
        "payload",
        "attempts",
        "next_attempt_at",
        "claimed_at",
        "last_error",
        "completed_at",
        "dead_lettered_at",
        "enqueued_at",
    ] {
        assert!(
            column_exists(pool, "outbox_messages", column).await,
            "outbox_messages.{column} exists"
        );
    }
    // The Front-Channel Logout per-client registration (issue #39): the two additive
    // clients columns the end_session flow reads to decide which RPs get a hidden
    // logout iframe, and whether it carries iss and the RP's own sid.
    for column in [
        "frontchannel_logout_uri",
        "frontchannel_logout_session_required",
    ] {
        assert!(
            column_exists(pool, "clients", column).await,
            "clients.{column} exists"
        );
    }
    // The four-level resource model as public APIs (issue #41): the organizations
    // level table (a schema slot since #6) gains a soft-delete column so it can be
    // deactivated as a first-class management resource without ever hard-deleting a
    // row the append-only audit log references. The operators, tenants, and
    // environments level tables already exist from the isolation root.
    assert!(
        table_exists(pool, "organizations").await,
        "organizations exists"
    );
    assert!(table_exists(pool, "operators").await, "operators exists");
    assert!(
        column_exists(pool, "organizations", "deleted_at").await,
        "organizations.deleted_at exists"
    );
    // The per-tenant envelope-encryption tables (issue #48): the wrapped
    // key-encryption keys, the wrapped data-encryption keys, and the transparent
    // encrypted-secret store.
    assert!(
        table_exists(pool, "tenant_keks").await,
        "tenant_keks exists"
    );
    assert!(
        table_exists(pool, "tenant_deks").await,
        "tenant_deks exists"
    );
    assert!(
        table_exists(pool, "encrypted_secrets").await,
        "encrypted_secrets exists"
    );
    // A KEK/DEK row stores only WRAPPED key material, never a plaintext key.
    assert!(
        column_exists(pool, "tenant_keks", "wrapped_kek").await,
        "tenant_keks stores a wrapped KEK"
    );
    assert!(
        column_exists(pool, "tenant_deks", "wrapped_dek").await,
        "tenant_deks stores a wrapped DEK"
    );
    for forbidden in ["key", "key_material", "plaintext", "secret"] {
        assert!(
            !column_exists(pool, "tenant_keks", forbidden).await,
            "tenant_keks must have no plaintext-key column ({forbidden})"
        );
        assert!(
            !column_exists(pool, "tenant_deks", forbidden).await,
            "tenant_deks must have no plaintext-key column ({forbidden})"
        );
    }
    // The encrypted-secret store holds ONLY ciphertext, never a plaintext column.
    assert!(
        column_exists(pool, "encrypted_secrets", "ciphertext").await,
        "encrypted_secrets stores ciphertext"
    );
    for forbidden in ["plaintext", "secret_value", "value", "secret"] {
        assert!(
            !column_exists(pool, "encrypted_secrets", forbidden).await,
            "encrypted_secrets must have no plaintext column ({forbidden})"
        );
    }

    // The bootstrap users directory now routes its two PII columns through the
    // envelope substrate (issue #48): the plaintext identifier and claims columns
    // are GONE, replaced by a blind index for lookup, a sealed identifier, a sealed
    // claim document, and the DEK version that sealed them. A database dump of the
    // users table therefore carries neither the login handle nor the claim values.
    for forbidden in ["identifier", "claims"] {
        assert!(
            !column_exists(pool, "users", forbidden).await,
            "users must have no plaintext PII column ({forbidden}) after 0027"
        );
    }
    for sealed in [
        "identifier_bidx",
        "identifier_sealed",
        "claims_sealed",
        "pii_dek_version",
    ] {
        assert!(
            column_exists(pool, "users", sealed).await,
            "users.{sealed} exists after 0027"
        );
    }

    // The tenant lifecycle and residency attributes (issue #46): the reversible
    // suspend/resume status and the recorded home_region on tenants, plus the new
    // environment_states scoped table the data plane reads to fence a suspended
    // scope. The plaintext PII invariant does not apply here: home_region is an
    // operator-chosen region label, not end-user PII, and the serving status is a
    // control-plane flag.
    assert!(
        column_exists(pool, "tenants", "status").await,
        "tenants.status exists after 0030"
    );
    assert!(
        column_exists(pool, "tenants", "home_region").await,
        "tenants.home_region exists after 0030"
    );
    assert!(
        column_exists(pool, "tenants", "purged_at").await,
        "tenants.purged_at exists after 0030"
    );
    assert!(
        column_exists(pool, "environments", "region").await,
        "environments.region exists after 0030"
    );
    assert!(
        table_exists(pool, "environment_states").await,
        "environment_states exists after 0030"
    );
    for column in [
        "tenant_id",
        "environment_id",
        "serving_status",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "environment_states", column).await,
            "environment_states.{column} exists after 0030"
        );
    }

    // The BYOK bindings table (issue #49): the per-scope customer-managed-key
    // binding, holding the driver, an opaque external key REFERENCE (never key
    // material), and the binding's lifecycle status. The plaintext-PII invariant
    // does not apply: key_ref is a non-secret handle, not a key or end-user PII.
    assert!(
        table_exists(pool, "tenant_byok_bindings").await,
        "tenant_byok_bindings exists after 0031"
    );
    for column in [
        "tenant_id",
        "environment_id",
        "provider",
        "key_ref",
        "status",
        "created_at",
        "destroyed_at",
    ] {
        assert!(
            column_exists(pool, "tenant_byok_bindings", column).await,
            "tenant_byok_bindings.{column} exists after 0031"
        );
    }
    // The per-environment custom-domain registry and the ACME challenge lifecycle
    // (issue #47): the domains table and the challenges table, both new after 0033.
    assert!(
        table_exists(pool, "custom_domains").await,
        "custom_domains exists after 0033"
    );
    assert!(
        table_exists(pool, "acme_challenges").await,
        "acme_challenges exists after 0033"
    );
    for column in [
        "domain_name",
        "challenge_type",
        "verification_status",
        "cert_secret_id",
        "cert_not_after",
    ] {
        assert!(
            column_exists(pool, "custom_domains", column).await,
            "custom_domains.{column} exists after 0033"
        );
    }
    for column in [
        "domain_id",
        "challenge_type",
        "token",
        "status",
        "attempts",
        "next_attempt_at",
    ] {
        assert!(
            column_exists(pool, "acme_challenges", column).await,
            "acme_challenges.{column} exists after 0033"
        );
    }
    // A custom domain's certificate PRIVATE KEY is never stored on the domain row:
    // custom_domains carries only an opaque handle to the sealed bundle in
    // encrypted_secrets (issue #48), never a key or a certificate column. A dump of
    // custom_domains therefore reveals no key material.
    for forbidden in [
        "private_key",
        "cert_pem",
        "certificate",
        "key_material",
        "private_key_pem",
    ] {
        assert!(
            !column_exists(pool, "custom_domains", forbidden).await,
            "custom_domains must have no plaintext key/cert column ({forbidden})"
        );
    }
    // The per-environment secrets and variables store (issue #45): two new tables
    // after 0034. Variables carry a plaintext value (promotable, non-secret);
    // secrets carry ONLY sealed ciphertext, never a plaintext value column.
    assert!(
        table_exists(pool, "environment_variables").await,
        "environment_variables exists after 0034"
    );
    assert!(
        table_exists(pool, "environment_secrets").await,
        "environment_secrets exists after 0034"
    );
    for column in ["name", "value", "version", "created_at", "updated_at"] {
        assert!(
            column_exists(pool, "environment_variables", column).await,
            "environment_variables.{column} exists after 0034"
        );
    }
    for column in [
        "name",
        "dek_version",
        "ciphertext",
        "version",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "environment_secrets", column).await,
            "environment_secrets.{column} exists after 0034"
        );
    }
    // A secret VALUE is never stored in the clear: environment_secrets carries only
    // the sealed ciphertext, never a plaintext value / secret column. A dump of the
    // table therefore reveals no secret.
    for forbidden in ["value", "plaintext", "secret", "secret_value"] {
        assert!(
            !column_exists(pool, "environment_secrets", forbidden).await,
            "environment_secrets must have no plaintext secret column ({forbidden})"
        );
    }

    // The admin-user-lifecycle columns folded onto users (issue #52): the lifecycle
    // state, the external-id blind index + sealed value + its DEK version (the
    // plaintext external id never lands on a column), the scheduled-offboarding
    // instant, and the mutation / soft-delete timestamps.
    for column in [
        "state",
        "external_id_bidx",
        "external_id_sealed",
        "external_id_dek_version",
        "scheduled_offboarding_at",
        "updated_at",
        "deleted_at",
    ] {
        assert!(
            column_exists(pool, "users", column).await,
            "users.{column} exists after 0037"
        );
    }
    // The external id is a lookup key, so it follows the blind-index pattern (issue
    // #48): the plaintext external id never lands on a column.
    assert!(
        !column_exists(pool, "users", "external_id").await,
        "users must have no plaintext external_id column after 0037"
    );

    // The identity-traits tables and the per-user sealed trait columns (issue #53).
    assert!(
        table_exists(pool, "trait_schemas").await,
        "trait_schemas exists after 0038"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "version",
        "schema_json",
        "status",
    ] {
        assert!(
            column_exists(pool, "trait_schemas", column).await,
            "trait_schemas.{column} exists after 0038"
        );
    }
    assert!(
        table_exists(pool, "trait_migration_jobs").await,
        "trait_migration_jobs exists after 0038"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "kind",
        "from_version",
        "to_version",
        "transform_json",
        "status",
        "cursor_id",
        "total_count",
        "processed_count",
        "migrated_count",
        "failure_count",
        "failures_json",
    ] {
        assert!(
            column_exists(pool, "trait_migration_jobs", column).await,
            "trait_migration_jobs.{column} exists after 0038"
        );
    }
    // A user's traits are user profile PII, sealed under the scope DEK (issue #48):
    // the document lands only on the sealed bytea column, never a plaintext one, and
    // the identity records the schema version it was validated against.
    for column in [
        "traits_sealed",
        "traits_dek_version",
        "traits_schema_version",
    ] {
        assert!(
            column_exists(pool, "users", column).await,
            "users.{column} exists after 0038"
        );
    }
    assert!(
        !column_exists(pool, "users", "traits").await,
        "users must have no plaintext traits column after 0038"
    );
    // The foreign-password-import columns folded onto users (issue #55): the
    // algorithm-tagged foreign verifier and its non-secret algorithm tag, both
    // added by 0039. A password hash is a one-way verifier, not PII, so it is stored
    // as text exactly like the native password_hash.
    for column in ["foreign_password_hash", "foreign_password_algo"] {
        assert!(
            column_exists(pool, "users", column).await,
            "users.{column} exists after 0039"
        );
    }

    // The user-invitations table (issue #60): the pending invitation row with the
    // user it provisions, the token digest (never the token), the sealed and
    // blind-indexed invited identifier (user PII never lands on a plaintext column),
    // the closed credential type and lifecycle state, the expiry, and the terminal
    // timestamps.
    assert!(
        table_exists(pool, "user_invitations").await,
        "user_invitations exists after 0040"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "user_id",
        "token_digest",
        "target_identifier_sealed",
        "target_identifier_bidx",
        "pii_dek_version",
        "credential_type",
        "state",
        "org_context",
        "expires_at",
        "created_at",
        "updated_at",
        "accepted_at",
        "revoked_at",
    ] {
        assert!(
            column_exists(pool, "user_invitations", column).await,
            "user_invitations.{column} exists after 0040"
        );
    }
    // The digest-only invariant (issue #60, acceptance criterion 6): the
    // user_invitations table stores only a digest of the token, never a plaintext
    // token, so a database read cannot yield a redeemable link.
    assert!(
        column_exists(pool, "user_invitations", "token_digest").await,
        "user_invitations stores a token digest"
    );
    for forbidden in ["token", "secret", "plaintext", "invite_token", "raw_token"] {
        assert!(
            !column_exists(pool, "user_invitations", forbidden).await,
            "user_invitations must have no plaintext-token column ({forbidden})"
        );
    }
    // The invited identifier is user PII, sealed and blind-indexed (issue #48): the
    // plaintext identifier / email never lands on a column.
    for forbidden in ["target_identifier", "identifier", "email"] {
        assert!(
            !column_exists(pool, "user_invitations", forbidden).await,
            "user_invitations must have no plaintext identifier column ({forbidden})"
        );
    }

    // The flexible-identifiers table (issue #54): one new user_identifiers scoped
    // table with the owning user, the closed identifier kind, the CANONICAL blind
    // index and the RAW sealed value (user PII never lands on a plaintext column),
    // its DEK version, the per-identifier verified flag, the uniqueness-mode
    // discriminator, and the terminal timestamps.
    assert!(
        table_exists(pool, "user_identifiers").await,
        "user_identifiers exists after 0041"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "user_id",
        "identifier_type",
        "canonical_bidx",
        "raw_sealed",
        "pii_dek_version",
        "verified",
        "uniqueness_key",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "user_identifiers", column).await,
            "user_identifiers.{column} exists after 0041"
        );
    }
    // The identifier value is user PII, stored ONLY as the sealed raw value and the
    // canonical blind index (issue #48): no plaintext identifier / email / phone /
    // canonical column ever lands in the schema.
    for forbidden in [
        "identifier",
        "email",
        "phone",
        "phone_number",
        "canonical",
        "raw",
    ] {
        assert!(
            !column_exists(pool, "user_identifiers", forbidden).await,
            "user_identifiers must have no plaintext identifier column ({forbidden})"
        );
    }
    // The tenant-scoped-table obligations (migrate.rs checklist), asserted structurally
    // against pg_catalog: forced row-level security, the (tenant, environment) isolation
    // policy, the nonempty-scope and closed-type CHECK constraints, and the partial
    // UNIQUE index that enforces uniqueness-as-configuration. A future edit that drops
    // any of these silently reopens a cross-tenant leak or the uniqueness gap; this
    // fails the build instead.
    assert!(
        rls_enabled_and_forced(pool, "user_identifiers").await,
        "user_identifiers must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(
            pool,
            "user_identifiers",
            "user_identifiers_tenant_isolation"
        )
        .await,
        "the (tenant, environment) isolation policy must exist on user_identifiers"
    );
    for constraint in [
        "user_identifiers_scope_nonempty",
        "user_identifiers_type_known",
    ] {
        assert!(
            check_constraint_exists(pool, "user_identifiers", constraint).await,
            "user_identifiers must carry the {constraint} CHECK constraint"
        );
    }
    assert!(
        partial_unique_index_exists(pool, "user_identifiers", "user_identifiers_uniqueness").await,
        "the partial UNIQUE index user_identifiers_uniqueness must exist"
    );

    // The migration state-machine tables (issue #59): the run row carrying the named
    // lifecycle state and the count/backfill thresholds, and the per-record accounting
    // ledger the invariants re-evaluate against.
    assert!(
        table_exists(pool, "migration_runs").await,
        "migration_runs exists after 0043"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "kind",
        "state",
        "source_total",
        "backfill_expected",
        "subject_ref",
        "abandoned_reason",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "migration_runs", column).await,
            "migration_runs.{column} exists after 0043"
        );
    }
    assert!(
        table_exists(pool, "migration_run_records").await,
        "migration_run_records exists after 0043"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "run_id",
        "subject_bidx",
        "subject_sealed",
        "subject_dek_version",
        "outcome",
        "consistent",
        "backfilled",
        "detail",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "migration_run_records", column).await,
            "migration_run_records.{column} exists after 0043"
        );
    }
    // A record's natural subject is user PII, stored ONLY as the sealed value and the
    // blind index (issue #48): no plaintext subject / identifier / email column ever
    // lands in the schema.
    for forbidden in ["subject", "identifier", "email", "key", "subject_plain"] {
        assert!(
            !column_exists(pool, "migration_run_records", forbidden).await,
            "migration_run_records must have no plaintext subject column ({forbidden})"
        );
    }
    // The tenant-scoped-table obligations for both new tables (migrate.rs checklist),
    // asserted structurally against pg_catalog: forced row-level security, the
    // (tenant, environment) isolation policy, and the nonempty-scope / closed-set CHECKs.
    for table in ["migration_runs", "migration_run_records"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
    }
    for constraint in ["migration_runs_kind_known", "migration_runs_state_known"] {
        assert!(
            check_constraint_exists(pool, "migration_runs", constraint).await,
            "migration_runs must carry the {constraint} CHECK constraint"
        );
    }
    assert!(
        check_constraint_exists(
            pool,
            "migration_run_records",
            "migration_run_records_outcome_known"
        )
        .await,
        "migration_run_records must carry the outcome-known CHECK constraint"
    );

    // ---- 0044 webauthn credentials + challenges (issue #65) ----
    assert!(
        table_exists(pool, "webauthn_credentials").await,
        "webauthn_credentials exists after 0044"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "credential_id",
        "cose_public_key",
        "sign_count",
        "aaguid",
        "transports",
        "backup_eligible",
        "backup_state",
        "discoverable",
        "clone_detected",
        "nickname_sealed",
        "pii_dek_version",
        "created_at",
        "last_used_at",
    ] {
        assert!(
            column_exists(pool, "webauthn_credentials", column).await,
            "webauthn_credentials.{column} exists after 0044"
        );
    }
    // The user-authored nickname is user PII, stored ONLY as the sealed value
    // (issue #48): no plaintext nickname / friendly-name column ever lands.
    for forbidden in ["nickname", "friendly_name", "label"] {
        assert!(
            !column_exists(pool, "webauthn_credentials", forbidden).await,
            "webauthn_credentials must have no plaintext nickname column ({forbidden})"
        );
    }
    assert!(
        table_exists(pool, "webauthn_challenges").await,
        "webauthn_challenges exists after 0044"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "ceremony",
        "subject",
        "challenge",
        "consumed_at",
        "expires_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "webauthn_challenges", column).await,
            "webauthn_challenges.{column} exists after 0044"
        );
    }
    // The tenant-scoped-table obligations for both new tables.
    for table in ["webauthn_credentials", "webauthn_challenges"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
    }
    assert!(
        check_constraint_exists(
            pool,
            "webauthn_challenges",
            "webauthn_challenges_ceremony_known"
        )
        .await,
        "webauthn_challenges must carry the ceremony-known CHECK constraint"
    );

    // ---- 0045 totp credentials + recovery codes (issue #69) ----
    assert!(
        table_exists(pool, "totp_credentials").await,
        "totp_credentials exists after 0045"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "totp_seed",
        "friendly_name_sealed",
        "pii_dek_version",
        "algorithm",
        "digits",
        "period_secs",
        "status",
        "last_consumed_step",
        "last_offset",
        "created_at",
        "activated_at",
        "last_used_at",
    ] {
        assert!(
            column_exists(pool, "totp_credentials", column).await,
            "totp_credentials.{column} exists after 0045"
        );
    }
    // The RFC 6238 SEED is secret material: it lands ONLY as a sealed `bytea`
    // ciphertext (issue #48), never a plaintext column, and the pii-encryption-scan
    // enforces this structurally too. Assert the type is bytea and that no plaintext
    // seed / secret column ever exists.
    assert_eq!(
        column_data_type(pool, "totp_credentials", "totp_seed").await,
        "bytea",
        "the TOTP seed must be a sealed bytea, never plaintext"
    );
    for forbidden in [
        "seed",
        "secret",
        "totp_secret",
        "seed_plaintext",
        "shared_secret",
    ] {
        assert!(
            !column_exists(pool, "totp_credentials", forbidden).await,
            "totp_credentials must have no plaintext seed column ({forbidden})"
        );
    }
    assert!(
        table_exists(pool, "recovery_codes").await,
        "recovery_codes exists after 0045"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "code_hash",
        "generation",
        "consumed_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "recovery_codes", column).await,
            "recovery_codes.{column} exists after 0045"
        );
    }
    // Recovery codes are stored ONLY as a one-way hash, never a plaintext code.
    for forbidden in ["code", "code_plaintext", "recovery_code", "plaintext"] {
        assert!(
            !column_exists(pool, "recovery_codes", forbidden).await,
            "recovery_codes must have no plaintext code column ({forbidden})"
        );
    }
    // The tenant-scoped-table obligations for both new tables.
    for table in ["totp_credentials", "recovery_codes"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
    }
    // The closed status and RFC 6238 hash sets (no HOTP): a corrupt or unknown value
    // can never be written.
    assert!(
        check_constraint_exists(pool, "totp_credentials", "totp_credentials_status_known").await,
        "totp_credentials must carry the status-known CHECK constraint"
    );
    assert!(
        check_constraint_exists(pool, "totp_credentials", "totp_credentials_algorithm_known").await,
        "totp_credentials must carry the algorithm-known CHECK constraint (no HOTP)"
    );

    // The credential-abuse ban registry (issue #64, migration 0046).
    assert!(
        table_exists(pool, "abuse_bans").await,
        "abuse_bans exists after 0046"
    );
    for column in [
        "id",
        "subject_kind",
        "subject_bidx",
        "subject_sealed",
        "pii_dek_version",
        "auth_path",
        "reason",
        "expires_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "abuse_bans", column).await,
            "abuse_bans.{column} exists after 0045"
        );
    }
    // The regulated subject is PII (an identifier / IP): it is sealed and blind-indexed,
    // never a plaintext column.
    for forbidden in ["subject", "identifier", "ip", "email", "account_id"] {
        assert!(
            !column_exists(pool, "abuse_bans", forbidden).await,
            "abuse_bans must have no plaintext subject column ({forbidden})"
        );
    }
    assert!(
        rls_enabled_and_forced(pool, "abuse_bans").await,
        "abuse_bans must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "abuse_bans", "abuse_bans_tenant_isolation").await,
        "the (tenant, environment) isolation policy must exist on abuse_bans"
    );
    for constraint in [
        "abuse_bans_scope_nonempty",
        "abuse_bans_subject_kind_known",
        "abuse_bans_auth_path_known",
    ] {
        assert!(
            check_constraint_exists(pool, "abuse_bans", constraint).await,
            "abuse_bans must carry the {constraint} CHECK constraint"
        );
    }

    // ---- 0047 step-up policies (issue #72) ----
    assert!(
        table_exists(pool, "scope_step_up_policies").await,
        "scope_step_up_policies exists after 0047"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "scope",
        "min_acr",
        "max_auth_age_secs",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "scope_step_up_policies", column).await,
            "scope_step_up_policies.{column} exists after 0047"
        );
    }
    // The tenant-scoped-table obligations (migrate.rs checklist): forced row-level
    // security, the (tenant, environment) isolation policy, and the nonempty-scope
    // CHECK.
    assert!(
        rls_enabled_and_forced(pool, "scope_step_up_policies").await,
        "scope_step_up_policies must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(
            pool,
            "scope_step_up_policies",
            "scope_step_up_policies_tenant_isolation"
        )
        .await,
        "the (tenant, environment) isolation policy must exist on scope_step_up_policies"
    );
    for constraint in [
        "scope_step_up_policies_scope_nonempty",
        "scope_step_up_policies_scope_token_nonempty",
        "scope_step_up_policies_requirement_present",
    ] {
        assert!(
            check_constraint_exists(pool, "scope_step_up_policies", constraint).await,
            "scope_step_up_policies must carry the {constraint} CHECK constraint"
        );
    }
    // The additive per-client step-up floor columns (issue #72).
    for column in ["step_up_acr", "step_up_max_age_secs"] {
        assert!(
            column_exists(pool, "clients", column).await,
            "clients.{column} exists after 0047"
        );
    }
    // The frozen auth_time on the refresh family, so a refresh can re-evaluate the
    // max-age window without a new authentication (issue #72).
    assert!(
        column_exists(pool, "refresh_families", "auth_time").await,
        "refresh_families.auth_time exists after 0047"
    );

    // ---- 0048 email OTP + scanner-safe magic links (issue #68) ----
    assert!(
        table_exists(pool, "email_otp_codes").await,
        "email_otp_codes exists after 0048"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "purpose",
        "code_hash",
        "recipient_email_bidx",
        "recipient_email_sealed",
        "pii_dek_version",
        "attempt_count",
        "max_attempts",
        "expires_at",
        "consumed_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "email_otp_codes", column).await,
            "email_otp_codes.{column} exists after 0048"
        );
    }
    // A 6-8 digit code is a low-entropy secret: it lands ONLY as a one-way Argon2id hash,
    // never a plaintext column, and the recipient email is sealed (bytea), never plaintext.
    assert_eq!(
        column_data_type(pool, "email_otp_codes", "recipient_email_sealed").await,
        "bytea",
        "the recipient email must be a sealed bytea, never plaintext"
    );
    for forbidden in [
        "code",
        "code_plaintext",
        "otp",
        "plaintext",
        "email",
        "recipient_email",
    ] {
        assert!(
            !column_exists(pool, "email_otp_codes", forbidden).await,
            "email_otp_codes must have no plaintext code / email column ({forbidden})"
        );
    }
    assert!(
        table_exists(pool, "magic_link_tokens").await,
        "magic_link_tokens exists after 0048"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "purpose",
        "token_digest",
        "short_code_hash",
        "binding_digest",
        "recipient_email_bidx",
        "recipient_email_sealed",
        "pii_dek_version",
        "attempt_count",
        "max_attempts",
        "expires_at",
        "consumed_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "magic_link_tokens", column).await,
            "magic_link_tokens.{column} exists after 0048"
        );
    }
    // The magic-link token is stored ONLY as its SHA-256 digest and the short code as an
    // Argon2id hash, never a plaintext bearer value; the recipient email is sealed.
    assert_eq!(
        column_data_type(pool, "magic_link_tokens", "recipient_email_sealed").await,
        "bytea",
        "the recipient email must be a sealed bytea, never plaintext"
    );
    for forbidden in [
        "token",
        "secret",
        "short_code",
        "plaintext",
        "email",
        "recipient_email",
    ] {
        assert!(
            !column_exists(pool, "magic_link_tokens", forbidden).await,
            "magic_link_tokens must have no plaintext token / code / email column ({forbidden})"
        );
    }
    // The tenant-scoped-table obligations for both new tables.
    for table in ["email_otp_codes", "magic_link_tokens"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_purpose_known")).await,
            "{table} must carry the purpose-known CHECK constraint"
        );
        // Both factors attempt-limit their low-entropy secret (the OTP code; the magic
        // link's cross-device short code), so both carry the attempt-budget CHECK.
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_attempts_nonneg")).await,
            "{table} must carry the attempts-nonneg CHECK constraint"
        );
    }

    // ---- 0049 credential-class policies + attestation config + user-handle (issue #66) ----
    assert!(
        table_exists(pool, "credential_class_policies").await,
        "credential_class_policies exists after 0049"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject_kind",
        "subject_ref",
        "min_class",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "credential_class_policies", column).await,
            "credential_class_policies.{column} exists after 0049"
        );
    }
    assert!(
        table_exists(pool, "attestation_config").await,
        "attestation_config exists after 0049"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "mode",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "attestation_config", column).await,
            "attestation_config.{column} exists after 0049"
        );
    }
    // Neither table carries PII (a class token, a subject discriminator, a mode).
    // The tenant-scoped-table obligations for both new tables.
    for table in ["credential_class_policies", "attestation_config"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
    }
    for constraint in [
        "credential_class_policies_subject_kind_known",
        "credential_class_policies_min_class_known",
        "credential_class_policies_subject_ref_presence",
    ] {
        assert!(
            check_constraint_exists(pool, "credential_class_policies", constraint).await,
            "credential_class_policies must carry the {constraint} CHECK constraint"
        );
    }
    assert!(
        check_constraint_exists(pool, "attestation_config", "attestation_config_mode_known").await,
        "attestation_config must carry the mode-known CHECK constraint"
    );
    // The passkey-only account markers on users (issue #66): the immutable WebAuthn
    // user handle (a bytea) and the passwordless flag.
    for column in ["webauthn_user_handle", "passwordless"] {
        assert!(
            column_exists(pool, "users", column).await,
            "users.{column} exists after 0049"
        );
    }
    assert_eq!(
        column_data_type(pool, "users", "webauthn_user_handle").await,
        "bytea",
        "the WebAuthn user handle is an opaque bytea"
    );
    // The user-handle immutability trigger is the storage-layer half of the guarantee
    // (the other half is the deliberate omission of the column from every GRANT UPDATE).
    let trigger_present: bool = sqlx::query(
        "SELECT EXISTS ( \
            SELECT 1 FROM pg_catalog.pg_trigger \
            WHERE tgrelid = 'users'::regclass AND tgname = 'users_user_handle_immutable' \
              AND NOT tgisinternal \
         ) AS present",
    )
    .fetch_one(pool)
    .await
    .expect("trigger lookup")
    .get("present");
    assert!(
        trigger_present,
        "the users_user_handle_immutable BEFORE UPDATE trigger must exist"
    );

    // ---- 0050 guarded SMS OTP (issue #70) ----
    // The SMS-OTP code store mirrors email_otp_codes; the recipient is a sealed +
    // blind-indexed PHONE, never plaintext, and the code is a one-way Argon2id hash.
    assert!(
        table_exists(pool, "sms_otp_codes").await,
        "sms_otp_codes exists after 0050"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "purpose",
        "code_hash",
        "recipient_phone_bidx",
        "recipient_phone_sealed",
        "pii_dek_version",
        "attempt_count",
        "max_attempts",
        "expires_at",
        "consumed_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "sms_otp_codes", column).await,
            "sms_otp_codes.{column} exists after 0050"
        );
    }
    assert_eq!(
        column_data_type(pool, "sms_otp_codes", "recipient_phone_sealed").await,
        "bytea",
        "the recipient phone must be a sealed bytea, never plaintext"
    );
    for forbidden in [
        "code",
        "otp",
        "plaintext",
        "phone",
        "phone_number",
        "recipient_phone",
    ] {
        assert!(
            !column_exists(pool, "sms_otp_codes", forbidden).await,
            "sms_otp_codes must have no plaintext code / phone column ({forbidden})"
        );
    }
    assert!(
        rls_enabled_and_forced(pool, "sms_otp_codes").await,
        "sms_otp_codes must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "sms_otp_codes", "sms_otp_codes_tenant_isolation").await,
        "the (tenant, environment) isolation policy must exist on sms_otp_codes"
    );
    for constraint in [
        "sms_otp_codes_scope_nonempty",
        "sms_otp_codes_purpose_known",
        "sms_otp_codes_attempts_nonneg",
    ] {
        assert!(
            check_constraint_exists(pool, "sms_otp_codes", constraint).await,
            "sms_otp_codes must carry the {constraint} CHECK constraint"
        );
    }

    // The per-tenant SMS enablement: off by default (enabled DEFAULT false) and the
    // factor-downgrade opt-in (default false). Both are the safe defaults that keep SMS
    // off and non-downgrading everywhere.
    assert!(
        table_exists(pool, "sms_config").await,
        "sms_config exists after 0050"
    );
    for column in [
        "tenant_id",
        "environment_id",
        "enabled",
        "allow_factor_downgrade",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "sms_config", column).await,
            "sms_config.{column} exists after 0050"
        );
    }
    // The country ALLOWLIST (never a blocklist): a per (tenant, environment, country)
    // membership row.
    assert!(
        table_exists(pool, "sms_country_allowlist").await,
        "sms_country_allowlist exists after 0050"
    );
    for column in ["tenant_id", "environment_id", "country_code", "created_at"] {
        assert!(
            column_exists(pool, "sms_country_allowlist", column).await,
            "sms_country_allowlist.{column} exists after 0050"
        );
    }
    // The per-route send-to-verify conversion counters + auto-throttle state.
    assert!(
        table_exists(pool, "sms_route_stats").await,
        "sms_route_stats exists after 0050"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "route_key",
        "send_count",
        "verify_count",
        "window_started_at",
        "throttled_until",
        "alarm_active",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "sms_route_stats", column).await,
            "sms_route_stats.{column} exists after 0050"
        );
    }
    // The tenant-scoped-table obligations for every new SMS table.
    for table in ["sms_config", "sms_country_allowlist", "sms_route_stats"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
    }

    // ---- 0097 email-factor config (issue #267) ----
    // The email-side twin of sms_config's downgrade opt-in: one per-scope row governing
    // whether an email possession proof (an email OTP, a magic link, or the headless
    // recovery journey) may mint a primary session over a passkey or an active TOTP.
    // Safe by default in TWO independent ways: the column DEFAULTs false, and a scope
    // with no row at all resolves to the refusing default in the reader.
    assert!(
        table_exists(pool, "email_factor_config").await,
        "email_factor_config exists after 0097"
    );
    for column in [
        "tenant_id",
        "environment_id",
        "allow_factor_downgrade",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "email_factor_config", column).await,
            "email_factor_config.{column} exists after 0097"
        );
    }
    assert!(
        rls_enabled_and_forced(pool, "email_factor_config").await,
        "email_factor_config must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(
            pool,
            "email_factor_config",
            "email_factor_config_tenant_isolation"
        )
        .await,
        "the (tenant, environment) isolation policy must exist on email_factor_config"
    );
    assert!(
        check_constraint_exists(
            pool,
            "email_factor_config",
            "email_factor_config_scope_nonempty"
        )
        .await,
        "email_factor_config must carry the scope-nonempty CHECK constraint"
    );

    // ---- 0051 passkey attestation (issue #66, PR B) ----
    // The per-scope verified MDS3 BLOB cache: the extracted, trusted authenticator
    // entries the attestation path evaluates against, plus the raw-BLOB digest for
    // byte-identical-refetch change detection. No PII (public authenticator metadata).
    assert!(
        table_exists(pool, "mds3_blob_cache").await,
        "mds3_blob_cache exists after 0051"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "blob_no",
        "next_update",
        "payload_jsonb",
        "blob_digest",
        "fetched_at",
        "verified_at",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "mds3_blob_cache", column).await,
            "mds3_blob_cache.{column} exists after 0051"
        );
    }
    // The per-scope AAGUID allow / deny list: one disposition per pinned model.
    assert!(
        table_exists(pool, "aaguid_rules").await,
        "aaguid_rules exists after 0051"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "aaguid",
        "disposition",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "aaguid_rules", column).await,
            "aaguid_rules.{column} exists after 0051"
        );
    }
    // The tenant-scoped-table obligations for both new tables.
    for table in ["mds3_blob_cache", "aaguid_rules"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
    }
    // The AAGUID rule disposition is a closed set.
    assert!(
        check_constraint_exists(pool, "aaguid_rules", "aaguid_rules_disposition_known").await,
        "aaguid_rules must carry the disposition-known CHECK constraint"
    );
    // The reg-time attestation facts on the passkey credential row: captured once at
    // registration, immutable thereafter (INSERT-only, absent from every GRANT UPDATE).
    for column in [
        "attestation_type",
        "attestation_verified",
        "attestation_fmt",
    ] {
        assert!(
            column_exists(pool, "webauthn_credentials", column).await,
            "webauthn_credentials.{column} exists after 0051"
        );
    }
    for constraint in [
        "webauthn_credentials_attestation_type_known",
        "webauthn_credentials_attestation_fmt_known",
    ] {
        assert!(
            check_constraint_exists(pool, "webauthn_credentials", constraint).await,
            "webauthn_credentials must carry the {constraint} CHECK constraint"
        );
    }

    // ---- 0052 admin sudo elevations (issue #73) ----
    assert!(
        table_exists(pool, "admin_sudo_elevations").await,
        "admin_sudo_elevations exists after 0052"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "actor_kind",
        "actor_id",
        "acr",
        "elevated_at",
        "expires_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "admin_sudo_elevations", column).await,
            "admin_sudo_elevations.{column} exists after 0052"
        );
    }
    // The tenant-scoped-table obligations (migrate.rs checklist): forced row-level
    // security, the (tenant, environment) isolation policy, and the nonempty-scope
    // CHECK.
    assert!(
        rls_enabled_and_forced(pool, "admin_sudo_elevations").await,
        "admin_sudo_elevations must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(
            pool,
            "admin_sudo_elevations",
            "admin_sudo_elevations_tenant_isolation"
        )
        .await,
        "the (tenant, environment) isolation policy must exist on admin_sudo_elevations"
    );
    for constraint in [
        "admin_sudo_elevations_scope_nonempty",
        "admin_sudo_elevations_actor_nonempty",
        "admin_sudo_elevations_acr_nonempty",
    ] {
        assert!(
            check_constraint_exists(pool, "admin_sudo_elevations", constraint).await,
            "admin_sudo_elevations must carry the {constraint} CHECK constraint"
        );
    }

    // ---- 0054 minimal risk engine (issue #79) ----
    // The per-subject last-seen login geo the impossible-travel signal reads: the observed
    // IP, coarse location, and User-Agent are end-user device metadata (PII), each SEALED
    // under the scope DEK (issue #48), never a plaintext column.
    assert!(
        table_exists(pool, "risk_login_geo").await,
        "risk_login_geo exists after 0054"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "ip_sealed",
        "geo_sealed",
        "user_agent_sealed",
        "pii_dek_version",
        "observed_at",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "risk_login_geo", column).await,
            "risk_login_geo.{column} exists after 0054"
        );
    }
    // The observed IP / location / User-Agent are PII, sealed under the scope DEK (issue
    // #48): no plaintext column ever lands.
    for forbidden in ["ip", "geo", "user_agent", "location", "ip_address"] {
        assert!(
            !column_exists(pool, "risk_login_geo", forbidden).await,
            "risk_login_geo must have no plaintext PII column ({forbidden}) after 0054"
        );
    }
    assert_eq!(
        column_data_type(pool, "risk_login_geo", "geo_sealed").await,
        "bytea",
        "the login geo must be a sealed bytea, never plaintext"
    );

    // The persisted decision record: the LOW/MED/HIGH score, the dispatched action, and the
    // enumerated contributing signals (no plaintext PII).
    assert!(
        table_exists(pool, "risk_decisions").await,
        "risk_decisions exists after 0054"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "correlation_id",
        "score",
        "action",
        "signals",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "risk_decisions", column).await,
            "risk_decisions.{column} exists after 0054"
        );
    }

    // The "this wasn't me" disavowal token: the SHA-256 digest of the single-use secret
    // (server-side state), the sessions it revokes, and the single-use consumed_at latch.
    assert!(
        table_exists(pool, "risk_disavowal_tokens").await,
        "risk_disavowal_tokens exists after 0054"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "token_digest",
        "decision_id",
        "session_ids",
        "consumed_at",
        "expires_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "risk_disavowal_tokens", column).await,
            "risk_disavowal_tokens.{column} exists after 0054"
        );
    }
    // The disavowal token is stored ONLY as its SHA-256 digest, never a plaintext bearer
    // value.
    assert_eq!(
        column_data_type(pool, "risk_disavowal_tokens", "token_digest").await,
        "bytea",
        "the disavowal token is stored as a digest, never plaintext"
    );
    for forbidden in ["token", "secret", "plaintext", "raw_token"] {
        assert!(
            !column_exists(pool, "risk_disavowal_tokens", forbidden).await,
            "risk_disavowal_tokens must have no plaintext-token column ({forbidden})"
        );
    }

    // The tenant-scoped-table obligations for every new risk table: forced row-level
    // security, the (tenant, environment) isolation policy, and the nonempty-scope CHECK.
    for table in ["risk_login_geo", "risk_decisions", "risk_disavowal_tokens"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
    }
    // The decision score and action are closed sets: a corrupt or unknown value can never
    // be written.
    for constraint in ["risk_decisions_score_known", "risk_decisions_action_known"] {
        assert!(
            check_constraint_exists(pool, "risk_decisions", constraint).await,
            "risk_decisions must carry the {constraint} CHECK constraint"
        );
    }

    // Federation connectors (issue #75, migration 0056): one new tenant-scoped table.
    assert!(
        table_exists(pool, "connectors").await,
        "connectors exists after 0056"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "connector_slug",
        "definition_json",
        "client_secret_sealed",
        "client_secret_dek_version",
        "cap_refresh",
        "cap_groups",
        "cap_logout_propagation",
        "cap_email_verified_trust",
        "enabled",
    ] {
        assert!(
            column_exists(pool, "connectors", column).await,
            "connectors.{column} exists after 0056"
        );
    }
    // The upstream client secret is SEALED, never a plaintext column.
    assert_eq!(
        column_data_type(pool, "connectors", "client_secret_sealed").await,
        "bytea",
        "the connector client secret must be a sealed bytea column, never plaintext"
    );
    // The definition column is jsonb and SECRET-FREE (the client_secret field is stripped
    // before storage), so a raw plaintext client_secret column can never exist here.
    assert!(
        !column_exists(pool, "connectors", "client_secret").await,
        "connectors must have no plaintext client_secret column after 0056"
    );
    // The tenant-scoped-table obligations: forced RLS, the isolation policy, and the
    // nonempty-scope CHECK, plus the closed email-verified-trust CHECK.
    assert!(
        rls_enabled_and_forced(pool, "connectors").await,
        "connectors must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "connectors", "connectors_tenant_isolation").await,
        "the (tenant, environment) isolation policy must exist on connectors"
    );
    for constraint in [
        "connectors_scope_nonempty",
        "connectors_email_verified_trust_known",
    ] {
        assert!(
            check_constraint_exists(pool, "connectors", constraint).await,
            "connectors must carry the {constraint} CHECK constraint"
        );
    }

    // Federation login state (issue #75, PR B, migration 0058): one new tenant-scoped,
    // single-use correlation table.
    assert!(
        table_exists(pool, "federation_login_states").await,
        "federation_login_states exists after 0058"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "state",
        "nonce",
        "code_verifier_sealed",
        "code_verifier_dek_version",
        "connector_id",
        "return_to",
        "consumed_at",
        "expires_at",
    ] {
        assert!(
            column_exists(pool, "federation_login_states", column).await,
            "federation_login_states.{column} exists after 0058"
        );
    }
    // The PKCE code_verifier is a secret SEALED under the scope DEK: a bytea ciphertext,
    // never a plaintext column.
    assert_eq!(
        column_data_type(pool, "federation_login_states", "code_verifier_sealed").await,
        "bytea",
        "the federation code_verifier must be a sealed bytea column, never plaintext"
    );
    assert!(
        !column_exists(pool, "federation_login_states", "code_verifier").await,
        "federation_login_states must have no plaintext code_verifier column after 0058"
    );
    // The tenant-scoped-table obligations: forced RLS, the isolation policy, and the
    // nonempty-scope CHECK.
    assert!(
        rls_enabled_and_forced(pool, "federation_login_states").await,
        "federation_login_states must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(
            pool,
            "federation_login_states",
            "federation_login_states_tenant_isolation"
        )
        .await,
        "the (tenant, environment) isolation policy must exist on federation_login_states"
    );
    assert!(
        check_constraint_exists(
            pool,
            "federation_login_states",
            "federation_login_states_scope_nonempty"
        )
        .await,
        "federation_login_states must carry the nonempty-scope CHECK constraint"
    );
    // Enterprise inbound routing (issue #77, migration 0059): two new tenant-scoped
    // tables plus additive org-binding columns. The AUTHORIZE leg writes the routed org
    // connection into the correlation row, and the JIT provisioning stamps it on the user.
    assert!(
        column_exists(pool, "federation_login_states", "org_connection_id").await,
        "federation_login_states.org_connection_id exists after 0059"
    );
    assert!(
        column_exists(pool, "users", "org_connection_id").await,
        "users.org_connection_id exists after 0059"
    );

    // The org-connection binding table.
    assert!(
        table_exists(pool, "org_connections").await,
        "org_connections exists after 0059"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "organization_id",
        "connector_id",
        "overlay_min_acr",
        "max_age_secs",
        "overlay_min_class",
        "capture_upstream_tokens",
        "enabled",
    ] {
        assert!(
            column_exists(pool, "org_connections", column).await,
            "org_connections.{column} exists after 0059"
        );
    }
    // A binding holds NO secret column (classified Promotable).
    for forbidden in ["client_secret", "secret", "sealed"] {
        assert!(
            !column_exists(pool, "org_connections", forbidden).await,
            "org_connections must have no secret column ({forbidden}) after 0059"
        );
    }
    assert!(
        rls_enabled_and_forced(pool, "org_connections").await,
        "org_connections must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "org_connections", "org_connections_tenant_isolation").await,
        "the (tenant, environment) isolation policy must exist on org_connections"
    );
    for constraint in [
        "org_connections_scope_nonempty",
        "org_connections_overlay_min_class_known",
        // 0103 (issue #286). 0059 pinned the CLASS ladder and left the ACR column open, so a
        // typo became an unranked floor that the federated context can never reach, making
        // the ceremony unsatisfiable. It fails closed, which is why this is hardening.
        "org_connections_overlay_min_acr_known",
        // 0103. A negative bound is silently dropped by the unsigned conversion at the
        // enforcement read, which is fail OPEN on a nonsense value: the bound reads as
        // absent and nothing is enforced.
        "org_connections_max_age_nonnegative",
    ] {
        assert!(
            check_constraint_exists(pool, "org_connections", constraint).await,
            "org_connections must carry the {constraint} CHECK constraint"
        );
    }

    // 0103 (issue #286): the sibling bound on the per-CLIENT step-up policy. 0047 gave this
    // CHECK to the scope_step_up_policies table it CREATED and did not give it to the column
    // it added to `clients` in the same file; this closes that gap.
    assert!(
        check_constraint_exists(pool, "clients", "clients_step_up_max_age_nonnegative").await,
        "clients must carry the step-up max-age nonnegative CHECK after 0103"
    );

    // 0103 (issue #286): the per-account broker-then-migrate cutover marker, and the
    // column-scoped grant that lets the data plane stamp it and nothing else.
    assert!(
        column_exists(pool, "users", "local_cutover_marked_at").await,
        "users.local_cutover_marked_at exists after 0103"
    );
    assert!(
        role_has_column_privilege(
            pool,
            "ironauth_app",
            "users",
            "local_cutover_marked_at",
            "UPDATE"
        )
        .await,
        "the data plane must be able to stamp the cutover marker"
    );

    // The routing-rule table.
    assert!(
        table_exists(pool, "routing_rules").await,
        "routing_rules exists after 0059"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "rule_kind",
        "domain_norm",
        "client_id",
        "user_bidx",
        "org_connection_id",
        "priority",
        "enabled",
    ] {
        assert!(
            column_exists(pool, "routing_rules", column).await,
            "routing_rules.{column} exists after 0059"
        );
    }
    // The per-user selector is a BLIND INDEX (bytea), never a plaintext identifier.
    assert_eq!(
        column_data_type(pool, "routing_rules", "user_bidx").await,
        "bytea",
        "the routing_rules user selector must be a blind-index bytea column, never plaintext"
    );
    for forbidden in ["user_identifier", "email", "identifier"] {
        assert!(
            !column_exists(pool, "routing_rules", forbidden).await,
            "routing_rules must have no plaintext user selector column ({forbidden}) after 0059"
        );
    }
    assert!(
        rls_enabled_and_forced(pool, "routing_rules").await,
        "routing_rules must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "routing_rules", "routing_rules_tenant_isolation").await,
        "the (tenant, environment) isolation policy must exist on routing_rules"
    );
    for constraint in [
        "routing_rules_scope_nonempty",
        "routing_rules_kind_known",
        "routing_rules_selector_matches_kind",
    ] {
        assert!(
            check_constraint_exists(pool, "routing_rules", constraint).await,
            "routing_rules must carry the {constraint} CHECK constraint"
        );
    }
    // The THREE partial UNIQUE indexes, one per selector scope, are the structural
    // routing-confusion defence: one domain, one app, or one user maps to at most one
    // enabled org connection within a scope.
    for index in [
        "routing_rules_domain_uniq",
        "routing_rules_app_uniq",
        "routing_rules_user_uniq",
    ] {
        assert!(
            partial_unique_index_exists(pool, "routing_rules", index).await,
            "routing_rules must carry the partial unique index {index} after 0059"
        );
    }

    // The upstream token vault (issue #77, migration 0060): the per-session table of
    // SEALED upstream tokens, and the per-client retrieval-grant table.
    assert!(
        table_exists(pool, "upstream_tokens").await,
        "upstream_tokens exists after 0060"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "session_id",
        "connector_id",
        "access_token_sealed",
        "refresh_token_sealed",
        "pii_dek_version",
        "access_expires_at",
        "token_scope",
    ] {
        assert!(
            column_exists(pool, "upstream_tokens", column).await,
            "upstream_tokens.{column} exists after 0060"
        );
    }
    // The captured tokens are envelope ciphertext at rest (issue #48): the two token
    // columns are `bytea`, never a plaintext column.
    for sealed in ["access_token_sealed", "refresh_token_sealed"] {
        assert_eq!(
            column_data_type(pool, "upstream_tokens", sealed).await,
            "bytea",
            "upstream_tokens.{sealed} must be a sealed envelope-ciphertext bytea column"
        );
    }
    for forbidden in ["access_token", "refresh_token", "secret", "token"] {
        assert!(
            !column_exists(pool, "upstream_tokens", forbidden).await,
            "upstream_tokens must have no plaintext token column ({forbidden}) after 0060"
        );
    }
    // The session-scoped lifetime: the session_id FK is ON DELETE CASCADE, so deleting
    // the session destroys its captured tokens.
    assert!(
        fk_on_delete_cascade(pool, "upstream_tokens", "session_id").await,
        "upstream_tokens.session_id must be a FOREIGN KEY with ON DELETE CASCADE from sessions"
    );
    assert!(
        rls_enabled_and_forced(pool, "upstream_tokens").await,
        "upstream_tokens must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "upstream_tokens", "upstream_tokens_tenant_isolation").await,
        "the (tenant, environment) isolation policy must exist on upstream_tokens"
    );
    assert!(
        check_constraint_exists(pool, "upstream_tokens", "upstream_tokens_scope_nonempty").await,
        "upstream_tokens must carry the nonempty-scope CHECK constraint"
    );

    // The retrieval-grant table.
    assert!(
        table_exists(pool, "upstream_token_grants").await,
        "upstream_token_grants exists after 0060"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "client_id",
        "org_connection_id",
        "enabled",
    ] {
        assert!(
            column_exists(pool, "upstream_token_grants", column).await,
            "upstream_token_grants.{column} exists after 0060"
        );
    }
    // A grant holds NO secret column (classified Promotable).
    for forbidden in ["secret", "sealed", "token"] {
        assert!(
            !column_exists(pool, "upstream_token_grants", forbidden).await,
            "upstream_token_grants must have no secret column ({forbidden}) after 0060"
        );
    }
    assert!(
        rls_enabled_and_forced(pool, "upstream_token_grants").await,
        "upstream_token_grants must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(
            pool,
            "upstream_token_grants",
            "upstream_token_grants_tenant_isolation"
        )
        .await,
        "the (tenant, environment) isolation policy must exist on upstream_token_grants"
    );
    assert!(
        check_constraint_exists(
            pool,
            "upstream_token_grants",
            "upstream_token_grants_scope_nonempty"
        )
        .await,
        "upstream_token_grants must carry the nonempty-scope CHECK constraint"
    );

    // The guarded account links table (issue #78, migration 0061): one row per (local
    // user) to (federated identity) binding.
    assert!(
        table_exists(pool, "account_links").await,
        "account_links exists after 0061"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "user_id",
        "connector_id",
        "external_id_bidx",
        "external_id_sealed",
        "external_id_dek_version",
        "email_verified",
        "link_method",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "account_links", column).await,
            "account_links.{column} exists after 0061"
        );
    }
    // The federated identifier lands as a keyed BLIND INDEX and a SEALED ciphertext,
    // never a plaintext queryable column.
    assert_eq!(
        column_data_type(pool, "account_links", "external_id_bidx").await,
        "bytea",
        "the account_links federated selector must be a blind-index bytea column"
    );
    assert_eq!(
        column_data_type(pool, "account_links", "external_id_sealed").await,
        "bytea",
        "the account_links display identifier must be a sealed-ciphertext bytea column"
    );
    for forbidden in ["external_id", "issuer", "subject", "sub", "email"] {
        assert!(
            !column_exists(pool, "account_links", forbidden).await,
            "account_links must have no plaintext federated identifier column ({forbidden}) after \
             0061"
        );
    }
    // The email_verified trust snapshot is a boolean property of the link.
    assert_eq!(
        column_data_type(pool, "account_links", "email_verified").await,
        "boolean",
        "account_links.email_verified must be a boolean trust snapshot"
    );
    // The email_verified trust snapshot is IMMUTABLE (a security property of issue #78):
    // captured at link time and never rewritten. Its immutability is enforced physically,
    // not by convention:
    //   1. the column is NOT NULL DEFAULT false, so a link always carries a definite,
    //      fail-safe (untrusted) snapshot rather than a NULL that could read as trusted;
    //   2. the data-plane app role holds NO UPDATE privilege on account_links at all, so
    //      the snapshot cannot be flipped after the fact even by the application. Asserted
    //      here so a future grant widening (or a dropped NOT NULL / DEFAULT) fails closed.
    assert!(
        column_is_not_null(pool, "account_links", "email_verified").await,
        "account_links.email_verified must be NOT NULL (a link always carries a definite \
         trust snapshot)"
    );
    assert_eq!(
        column_default(pool, "account_links", "email_verified")
            .await
            .as_deref(),
        Some("false"),
        "account_links.email_verified must DEFAULT false (fail-safe untrusted)"
    );
    assert!(
        !role_has_table_privilege(pool, "ironauth_app", "account_links", "UPDATE").await,
        "the app role must hold NO UPDATE on account_links: the email_verified trust \
         snapshot is physically immutable"
    );
    assert!(
        rls_enabled_and_forced(pool, "account_links").await,
        "account_links must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "account_links", "account_links_tenant_isolation").await,
        "the (tenant, environment) isolation policy must exist on account_links"
    );
    for constraint in [
        "account_links_scope_nonempty",
        "account_links_link_method_known",
    ] {
        assert!(
            check_constraint_exists(pool, "account_links", constraint).await,
            "account_links must carry the {constraint} CHECK constraint"
        );
    }
    // The structural anti-takeover invariant: a federated identity resolves to AT MOST
    // one local user per scope. The UNIQUE (tenant, environment, connector,
    // external_id_bidx) constraint is what makes a second local user claiming the same
    // (connector, issuer, sub) a unique violation rather than a silent re-home.
    assert!(
        unique_constraint_exists(pool, "account_links", "account_links_identity_uniq").await,
        "account_links must carry the (connector, external_id_bidx) UNIQUE anti-takeover constraint"
    );
    // The user_id column is a PLAIN foreign key into users(id), exactly like
    // user_identifiers: no ON DELETE CASCADE (users are soft-deleted, so a link is never
    // hard-deleted out from under an account by the users lifecycle).
    assert!(
        fk_references(pool, "account_links", "user_id").await,
        "account_links.user_id must be a FOREIGN KEY into users"
    );

    // The account-linking wiring migration (issue #78, PR 2): two additive nullable
    // columns. The manual-link purpose marker on the single-use correlation row, and the
    // per-environment auto-link posture override on the environments level table.
    assert!(
        column_exists(pool, "federation_login_states", "link_target_user_id").await,
        "federation_login_states.link_target_user_id exists after 0062"
    );
    assert!(
        column_exists(pool, "environments", "auto_link_posture").await,
        "environments.auto_link_posture exists after 0062"
    );
    // The per-environment posture is a nullable override (NULL inherits the deployment
    // default), and its closed vocabulary is pinned by a CHECK.
    assert!(
        !column_is_not_null(pool, "environments", "auto_link_posture").await,
        "environments.auto_link_posture must be nullable (NULL inherits the deployment default)"
    );
    assert!(
        check_constraint_exists(pool, "environments", "environments_auto_link_posture_valid").await,
        "environments must carry the auto_link_posture closed-vocabulary CHECK"
    );
    // The scope-forced guardrail projection (0029) must EXPOSE the new posture column: the
    // data plane reads the per-environment override ONLY through this view, never through a
    // direct grant on the environments level table, so a view replace that dropped the column
    // would silently break the read.
    assert!(
        view_exposes_column(pool, "environment_guardrails", "auto_link_posture").await,
        "the environment_guardrails view must expose the auto_link_posture column"
    );
    // The posture UPDATE grant is COLUMN-scoped to the control role: control may set the
    // per-environment posture, the app (data-plane) role may NEVER update it, and the grant is
    // narrow enough that control cannot rewrite another environment identity column (e.g. kind)
    // through it. A grant that ever widened to the app role would be a data-plane privilege
    // escalation, so this guard fails closed on it.
    assert!(
        role_has_column_privilege(
            pool,
            "ironauth_control",
            "environments",
            "auto_link_posture",
            "UPDATE"
        )
        .await,
        "the control role must hold column-scoped UPDATE on environments.auto_link_posture"
    );
    assert!(
        !role_has_column_privilege(
            pool,
            "ironauth_app",
            "environments",
            "auto_link_posture",
            "UPDATE"
        )
        .await,
        "the app (data-plane) role must NOT hold UPDATE on environments.auto_link_posture"
    );
    assert!(
        !role_has_column_privilege(pool, "ironauth_control", "environments", "kind", "UPDATE")
            .await,
        "the posture grant must stay column-scoped: control must NOT gain UPDATE on other \
         environment identity columns (kind)"
    );

    // ---------------------------------------------------------------------------
    // The organization data model expand (issue #94, 0084).
    //
    // Two additive organizations columns plus a NEW tenant-scoped org_memberships
    // table with RLS, its isolation policy, the nonempty-scope CHECK, and
    // least-privilege column-scoped grants.

    // The tree-capable parent pointer is present and nullable (no organization has a
    // parent until a later PR ever sets one), and is a self-referential foreign key.
    assert!(
        column_exists(pool, "organizations", "parent_id").await,
        "organizations.parent_id exists after 0084"
    );
    assert!(
        !column_is_not_null(pool, "organizations", "parent_id").await,
        "organizations.parent_id must be nullable (schema only, unset in PR-A)"
    );
    assert!(
        fk_references(pool, "organizations", "parent_id").await,
        "organizations.parent_id must be a self-referential FOREIGN KEY into organizations"
    );

    // The lifecycle state is present, NOT NULL (defaulted 'active'), and its closed
    // vocabulary is pinned by a CHECK: an unknown state can never be written.
    assert!(
        column_is_not_null(pool, "organizations", "state").await,
        "organizations.state must be NOT NULL (defaulted 'active') after 0084"
    );
    assert!(
        check_constraint_exists(pool, "organizations", "organizations_state_valid").await,
        "organizations must carry the state closed-vocabulary CHECK"
    );
    // The state UPDATE grant is COLUMN-scoped to the control role, and the data-plane
    // role never gains it (only an admin toggles an organization's state), and it is
    // narrow enough that control cannot rewrite the display_name through it.
    assert!(
        role_has_column_privilege(pool, "ironauth_control", "organizations", "state", "UPDATE")
            .await,
        "the control role must hold column-scoped UPDATE on organizations.state"
    );
    assert!(
        !role_has_column_privilege(pool, "ironauth_app", "organizations", "state", "UPDATE").await,
        "the app (data-plane) role must NOT hold UPDATE on organizations.state"
    );
    assert!(
        !role_has_column_privilege(
            pool,
            "ironauth_control",
            "organizations",
            "display_name",
            "UPDATE"
        )
        .await,
        "the state grant must stay column-scoped: control must NOT gain UPDATE on \
         organizations.display_name through it"
    );
    // The data-plane READ on organizations that 0027 revoked is re-granted (membership
    // resolution and org-context validation need it), and it is SELECT ONLY: the data
    // plane can look an organization up but never mutate one.
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "organizations", "SELECT").await,
        "the data-plane role must regain SELECT on organizations after 0084"
    );
    assert!(
        !role_has_table_privilege(pool, "ironauth_app", "organizations", "INSERT").await,
        "the data-plane re-grant must be SELECT only (no INSERT on organizations)"
    );
    assert!(
        !role_has_table_privilege(pool, "ironauth_app", "organizations", "DELETE").await,
        "the data-plane re-grant must be SELECT only (no DELETE on organizations)"
    );

    // org_memberships is a NEW tenant-scoped table, so it must ENABLE and FORCE
    // row-level security, carry the (tenant, environment) isolation policy, and pin the
    // nonempty-scope CHECK, exactly like every other scoped table.
    assert!(
        rls_enabled_and_forced(pool, "org_memberships").await,
        "org_memberships must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "org_memberships", "org_memberships_tenant_isolation").await,
        "org_memberships must carry the (tenant, environment) isolation policy"
    );
    for constraint in [
        "org_memberships_scope_nonempty",
        "org_memberships_state_valid",
    ] {
        assert!(
            check_constraint_exists(pool, "org_memberships", constraint).await,
            "org_memberships must carry the {constraint} CHECK constraint"
        );
    }
    // The (organization, user) uniqueness is a PARTIAL unique index over LIVE rows
    // (WHERE deleted_at IS NULL), not a table-wide constraint: at most one LIVE
    // membership per (organization, user), so a duplicate add of a live member is a
    // storage-engine conflict, while a removed (soft-deleted) membership does NOT
    // occupy the key and can be revived on re-add.
    assert!(
        partial_unique_index_exists(
            pool,
            "org_memberships",
            "org_memberships_org_user_live_uniq"
        )
        .await,
        "org_memberships must carry the (organization, user) partial unique index over live rows"
    );
    // Both foreign keys are plain (no ON DELETE CASCADE): the organization and the user
    // are soft-deleted, so a membership is never hard-deleted out from under a scope.
    assert!(
        fk_references(pool, "org_memberships", "organization_id").await,
        "org_memberships.organization_id must be a FOREIGN KEY into organizations"
    );
    assert!(
        fk_references(pool, "org_memberships", "user_id").await,
        "org_memberships.user_id must be a FOREIGN KEY into users"
    );

    // Least-privilege grants (the #31 lesson). BOTH planes bind a membership: the
    // control plane owns the admin surface (add + soft-delete remove), and the data
    // plane binds on the invitation-accept path (a revive-or-insert). Both therefore
    // hold SELECT, INSERT, and a COLUMN-scoped UPDATE of ONLY the mutable columns
    // (state, metadata, updated_at, deleted_at) so a removed member can be revived; the
    // grant never reaches the identity columns and neither plane holds table-wide
    // UPDATE or DELETE.
    for role in ["ironauth_control", "ironauth_app"] {
        for privilege in ["SELECT", "INSERT"] {
            assert!(
                role_has_table_privilege(pool, role, "org_memberships", privilege).await,
                "{role} must hold {privilege} on org_memberships"
            );
        }
        for column in ["state", "metadata", "updated_at", "deleted_at"] {
            assert!(
                role_has_column_privilege(pool, role, "org_memberships", column, "UPDATE").await,
                "{role} must hold column-scoped UPDATE on org_memberships.{column} (the revive)"
            );
        }
        // The UPDATE grant stays column-scoped: it must NOT reach the identity columns
        // (a membership's organization or user can never be rewritten in place).
        assert!(
            !role_has_column_privilege(pool, role, "org_memberships", "organization_id", "UPDATE")
                .await,
            "the membership UPDATE grant must stay column-scoped: {role} must NOT gain UPDATE on \
             org_memberships.organization_id"
        );
        // Neither plane may hard-DELETE a membership: removal is a soft delete only.
        assert!(
            !role_has_table_privilege(pool, role, "org_memberships", "DELETE").await,
            "{role} must NOT hold DELETE on org_memberships (removal is a soft delete)"
        );
    }

    // ---------------------------------------------------------------------------
    // Organization roles (issue #97, 0086).
    //
    // A NEW tenant-scoped table: RLS ENABLEd and FORCEd, the (tenant, environment)
    // isolation policy, the nonempty-scope CHECK, the slug and display-name CHECKs,
    // the partial unique index over live rows, the organization foreign key, and
    // least-privilege COLUMN-scoped grants that leave `slug` immutable.

    // EXPAND (issue #97): one new tenant-scoped table with its indexes, policy, and
    // grants. Nothing existing is altered or dropped.
    assert_eq!(phase_of(86).await, "expand");
    assert!(
        table_exists(pool, "org_roles").await,
        "org_roles exists after 0086"
    );
    assert!(
        rls_enabled_and_forced(pool, "org_roles").await,
        "org_roles must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "org_roles", "org_roles_tenant_isolation").await,
        "org_roles must carry the (tenant, environment) isolation policy"
    );
    for constraint in [
        "org_roles_scope_nonempty",
        "org_roles_slug_valid",
        "org_roles_display_name_nonempty",
    ] {
        assert!(
            check_constraint_exists(pool, "org_roles", constraint).await,
            "org_roles must carry the {constraint} CHECK constraint"
        );
    }
    for column in ["tenant_id", "environment_id", "organization_id", "slug"] {
        assert!(
            column_is_not_null(pool, "org_roles", column).await,
            "org_roles.{column} must be NOT NULL"
        );
    }
    // The (organization, slug) uniqueness is a PARTIAL unique index over LIVE rows
    // (WHERE deleted_at IS NULL), so a deleted role frees its slug for a NEW role
    // rather than occupying it forever, and every read (which filters deleted_at IS
    // NULL) agrees with the uniqueness invariant on exactly the live set.
    assert!(
        partial_unique_index_exists(pool, "org_roles", "org_roles_org_slug_live_uniq").await,
        "org_roles must carry the (organization, slug) partial unique index over live rows"
    );
    // The organization foreign key is the backstop that makes a role in a
    // nonexistent or cross-scope organization impossible.
    assert!(
        fk_references(pool, "org_roles", "organization_id").await,
        "org_roles.organization_id must be a FOREIGN KEY into organizations"
    );

    // Least-privilege grants (the #31 lesson). The CONTROL plane owns the whole role
    // lifecycle: SELECT, INSERT, and a COLUMN-scoped UPDATE of ONLY the mutable
    // columns. The DATA plane holds SELECT and nothing else (a later PR resolves
    // effective roles at token issuance under the app role; nothing on that plane
    // ever writes a role).
    for privilege in ["SELECT", "INSERT"] {
        assert!(
            role_has_table_privilege(pool, "ironauth_control", "org_roles", privilege).await,
            "ironauth_control must hold {privilege} on org_roles"
        );
    }
    for column in ["display_name", "metadata", "updated_at", "deleted_at"] {
        assert!(
            role_has_column_privilege(pool, "ironauth_control", "org_roles", column, "UPDATE")
                .await,
            "ironauth_control must hold column-scoped UPDATE on org_roles.{column}"
        );
    }
    // The slug is immutable by GRANT, not merely by convention: NEITHER role may
    // ever UPDATE it, so the stable name a later authorization decision keys on
    // cannot be rewritten by any code path.
    for role in ["ironauth_control", "ironauth_app"] {
        assert!(
            !role_has_column_privilege(pool, role, "org_roles", "slug", "UPDATE").await,
            "org_roles.slug must be immutable by GRANT: {role} must NOT hold UPDATE on it"
        );
        // Nor may the UPDATE grant reach the identity columns: a role can never be
        // moved between organizations or between scopes in place.
        for column in ["organization_id", "tenant_id", "environment_id", "id"] {
            assert!(
                !role_has_column_privilege(pool, role, "org_roles", column, "UPDATE").await,
                "the role UPDATE grant must stay column-scoped: {role} must NOT gain UPDATE \
                 on org_roles.{column}"
            );
        }
        // Removal is a soft delete: neither plane may hard-DELETE a role, which would
        // break the retention that keeps a `organization.role.delete` audit row's
        // target resolvable (an application rule; `audit_log` carries no foreign key
        // here).
        assert!(
            !role_has_table_privilege(pool, role, "org_roles", "DELETE").await,
            "{role} must NOT hold DELETE on org_roles (deletion is a soft delete)"
        );
    }
    // The data plane is READ ONLY on roles.
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "org_roles", "SELECT").await,
        "the data-plane role must hold SELECT on org_roles (the token-issuance read)"
    );
    for privilege in ["INSERT", "UPDATE"] {
        assert!(
            !role_has_table_privilege(pool, "ironauth_app", "org_roles", privilege).await,
            "the data-plane grant on org_roles must be SELECT only (no {privilege})"
        );
    }
    // Those table-wide probes cannot see a COLUMN-scoped grant, which is a real way
    // for the data plane to gain a write on org_roles while every assertion here
    // stays green. That half of the least-privilege argument is closed by
    // `the_data_plane_holds_no_column_scoped_write_grant_on_org_roles` below.
}

/// The data plane holds NO write grant of any shape on `org_roles` (issue #97, 0086).
///
/// The table-wide `has_table_privilege` probes in the production-chain assertions
/// above cannot see a COLUMN-scoped grant: `GRANT INSERT (id, tenant_id,
/// environment_id, organization_id, slug, display_name) ON org_roles TO
/// ironauth_app` leaves every one of them reading false while genuinely letting the
/// token-issuance data plane forge a role in its own scope, which is precisely the
/// least-privilege invariant issue #97 states (nothing on the data plane ever
/// writes a role) and which the token seam later in the issue depends on. Sweeping
/// every column closes that gap, so the invariant is a physical property of the
/// schema rather than a claim about which code paths happen to exist.
///
/// This is its own test rather than more lines in the production-chain test so that
/// a failure names the grant shape it found rather than a line inside that test's
/// long sweep. An earlier note gave that test's stack budget as the reason; the
/// measurement in its doc comment shows the budget is not the constraint.
#[tokio::test]
async fn the_data_plane_holds_no_column_scoped_write_grant_on_org_roles() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // INSERT, UPDATE, and REFERENCES are the write-shaped privileges Postgres can
    // grant per column (DELETE has no column form and is asserted table-wide with
    // the rest of the 0086 grants).
    for privilege in ["INSERT", "UPDATE", "REFERENCES"] {
        assert!(
            !role_has_any_column_privilege(pool, "ironauth_app", "org_roles", privilege).await,
            "the data plane must hold NO column-scoped {privilege} on org_roles"
        );
    }
    // A positive control, so a sweep that simply answered "no" to everything could
    // not pass this test: the data plane DOES hold the column-scoped SELECT that
    // the token-issuance role read needs, and the control plane DOES hold the
    // column-scoped UPDATE that a rename needs.
    assert!(
        role_has_any_column_privilege(pool, "ironauth_app", "org_roles", "SELECT").await,
        "the data plane holds SELECT on org_roles (the token-issuance read)"
    );
    assert!(
        role_has_any_column_privilege(pool, "ironauth_control", "org_roles", "UPDATE").await,
        "the control plane holds the column-scoped UPDATE a rename needs"
    );
}

/// The `org_groups` schema, policy, indexes, and grants (issue #97, migration 0087).
///
/// Its own test rather than more lines in the production-chain assertions so that a
/// failure names this table rather than a line inside that test's long sweep. An
/// earlier note gave that test's stack budget as the reason; the measurement in
/// its doc comment shows the budget is not the constraint.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one table's whole structural contract (phase, columns, constraints, \
              policy, both index shapes, and the full grant matrix on both roles) \
              read as one unit"
)]
async fn org_groups_carries_its_isolation_indexes_and_least_privilege_grants() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // EXPAND: one new tenant-scoped table with its indexes, policy, and grants.
    // Nothing existing is altered or dropped.
    let phase: String = sqlx::query("SELECT phase FROM _schema_migrations WHERE version = 87")
        .fetch_one(pool)
        .await
        .expect("0087 is in the ledger")
        .get("phase");
    assert_eq!(phase, "expand");

    assert!(
        table_exists(pool, "org_groups").await,
        "org_groups exists after 0087"
    );
    assert!(
        rls_enabled_and_forced(pool, "org_groups").await,
        "org_groups must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "org_groups", "org_groups_tenant_isolation").await,
        "org_groups must carry the (tenant, environment) isolation policy"
    );
    for constraint in [
        "org_groups_scope_nonempty",
        "org_groups_slug_valid",
        "org_groups_display_name_nonempty",
        // The one-node cycle guard, enforced by the storage engine. Longer cycles
        // are not expressible as a CHECK and are the repository's job.
        "org_groups_parent_not_self",
    ] {
        assert!(
            check_constraint_exists(pool, "org_groups", constraint).await,
            "org_groups must carry the {constraint} CHECK constraint"
        );
    }
    for column in ["tenant_id", "environment_id", "organization_id", "slug"] {
        assert!(
            column_is_not_null(pool, "org_groups", column).await,
            "org_groups.{column} must be NOT NULL"
        );
    }
    // `parent_id` is NULLABLE and that is load-bearing: NULL is what makes a group a
    // ROOT. A NOT NULL parent would make a forest impossible to express.
    assert!(
        column_exists(pool, "org_groups", "parent_id").await,
        "org_groups.parent_id exists"
    );
    assert!(
        !column_is_not_null(pool, "org_groups", "parent_id").await,
        "org_groups.parent_id must be NULLABLE: NULL is how a root group is expressed"
    );
    // Both foreign keys: the organization (so a group in a nonexistent or
    // cross-scope organization is impossible) and the SELF key on parent_id (so a
    // parent pointer can never dangle).
    assert!(
        fk_references(pool, "org_groups", "organization_id").await,
        "org_groups.organization_id must be a FOREIGN KEY into organizations"
    );
    assert!(
        fk_references(pool, "org_groups", "parent_id").await,
        "org_groups.parent_id must be a self-referential FOREIGN KEY"
    );
    // The (organization, slug) uniqueness is PARTIAL over LIVE rows, so a deleted
    // group frees its slug for a new group rather than occupying it forever.
    assert!(
        partial_unique_index_exists(pool, "org_groups", "org_groups_org_slug_live_uniq").await,
        "org_groups must carry the (organization, slug) partial unique index over live rows"
    );
    // The DOWNWARD traversal index the recursive descendant walk depends on. Its
    // column ORDER is what makes it usable: the walk joins each child's parent_id
    // against the frontier, so parent_id must lead after the scope columns. An index
    // present but ordered wrongly leaves the walk on a sequential scan per level
    // while every functional assertion in the suite stays green.
    assert!(
        partial_index_exists(pool, "org_groups", "org_groups_parent_idx").await,
        "org_groups must carry the downward traversal index over live rows"
    );
    assert_eq!(
        index_columns(pool, "org_groups", "org_groups_parent_idx").await,
        vec![
            "tenant_id".to_owned(),
            "environment_id".to_owned(),
            "parent_id".to_owned()
        ],
        "the descendant walk needs parent_id leading immediately after the scope columns"
    );

    // Least-privilege grants (the #31 lesson). The CONTROL plane owns the whole
    // group lifecycle: SELECT, INSERT, and a COLUMN-scoped UPDATE of ONLY the
    // mutable columns, which for groups INCLUDES parent_id (reparenting is an admin
    // operation). The DATA plane holds SELECT and nothing else.
    for privilege in ["SELECT", "INSERT"] {
        assert!(
            role_has_table_privilege(pool, "ironauth_control", "org_groups", privilege).await,
            "ironauth_control must hold {privilege} on org_groups"
        );
    }
    for column in [
        "display_name",
        "metadata",
        "parent_id",
        "updated_at",
        "deleted_at",
    ] {
        assert!(
            role_has_column_privilege(pool, "ironauth_control", "org_groups", column, "UPDATE")
                .await,
            "ironauth_control must hold column-scoped UPDATE on org_groups.{column}"
        );
    }
    for role in ["ironauth_control", "ironauth_app"] {
        // The slug is immutable by GRANT, not merely by convention.
        assert!(
            !role_has_column_privilege(pool, role, "org_groups", "slug", "UPDATE").await,
            "org_groups.slug must be immutable by GRANT: {role} must NOT hold UPDATE on it"
        );
        // Nor may the UPDATE grant reach the identity columns. This is what makes
        // "a group's organization never changes" a schema property: without it, the
        // same-organization containment the hierarchy check enforces on every write
        // could be undone afterwards by a plain UPDATE.
        for column in ["organization_id", "tenant_id", "environment_id", "id"] {
            assert!(
                !role_has_column_privilege(pool, role, "org_groups", column, "UPDATE").await,
                "the group UPDATE grant must stay column-scoped: {role} must NOT gain \
                 UPDATE on org_groups.{column}"
            );
        }
        // Removal is a soft delete on both planes.
        assert!(
            !role_has_table_privilege(pool, role, "org_groups", "DELETE").await,
            "{role} must NOT hold DELETE on org_groups (deletion is a soft delete)"
        );
    }
    // The data plane is READ ONLY on groups: the ancestor walk that resolves
    // effective roles at token issuance runs there, and nothing on that plane ever
    // writes a group.
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "org_groups", "SELECT").await,
        "the data-plane role must hold SELECT on org_groups (the ancestor walk)"
    );
    for privilege in ["INSERT", "UPDATE"] {
        assert!(
            !role_has_table_privilege(pool, "ironauth_app", "org_groups", privilege).await,
            "the data-plane grant on org_groups must be SELECT only (no {privilege})"
        );
    }
    // The table-wide probes above cannot see a COLUMN-scoped grant, which is a real
    // way for the data plane to gain a write while every one of them stays green.
    // Sweeping every column closes that, so "nothing on the data plane writes a
    // group" is a physical property of the schema rather than a claim about which
    // code paths happen to exist today.
    for privilege in ["INSERT", "UPDATE", "REFERENCES"] {
        assert!(
            !role_has_any_column_privilege(pool, "ironauth_app", "org_groups", privilege).await,
            "the data plane must hold NO column-scoped {privilege} on org_groups"
        );
    }
    // Positive controls, so a sweep that answered "no" to everything could not pass.
    assert!(
        role_has_any_column_privilege(pool, "ironauth_app", "org_groups", "SELECT").await,
        "the data plane holds SELECT on org_groups"
    );
    assert!(
        role_has_any_column_privilege(pool, "ironauth_control", "org_groups", "UPDATE").await,
        "the control plane holds the column-scoped UPDATE a rename and a reparent need"
    );
}

#[tokio::test]
async fn not_sorted_is_rejected_for_descending_and_duplicate_versions() {
    let pool = TestDatabase::fresh_owner_pool().await;

    // Descending: version 1 follows version 2.
    let descending = MigrationRunner::from_migrations(
        &pool,
        vec![
            step(2, Phase::Expand, "CREATE TABLE ns_desc_2 (id int);"),
            step(1, Phase::Expand, "CREATE TABLE ns_desc_1 (id int);"),
        ],
    )
    .run()
    .await
    .expect_err("a descending chain must be refused");
    assert!(
        matches!(descending, MigrationError::NotSorted { version: 1 }),
        "expected NotSorted{{version:1}}, got: {descending:?}"
    );

    // Duplicate: version 1 appears twice (not strictly ascending).
    let duplicate = MigrationRunner::from_migrations(
        &pool,
        vec![
            step(1, Phase::Expand, "CREATE TABLE ns_dup_a (id int);"),
            step(1, Phase::Expand, "CREATE TABLE ns_dup_b (id int);"),
        ],
    )
    .run()
    .await
    .expect_err("a duplicate version must be refused");
    assert!(
        matches!(duplicate, MigrationError::NotSorted { version: 1 }),
        "expected NotSorted{{version:1}}, got: {duplicate:?}"
    );

    // A refused sort check touches no connection: neither table was created.
    assert!(!table_exists(&pool, "ns_desc_1").await);
    assert!(!table_exists(&pool, "ns_dup_a").await);
}

#[tokio::test]
async fn unknown_applied_version_is_rejected_and_nothing_is_applied() {
    // The N/N-1 downgrade guard: a ledger migrated by a newer build (which knows
    // version 3) presented to an older build whose registry stops at version 2.
    let pool = TestDatabase::fresh_owner_pool().await;

    // A "newer build" applies versions 1 to 3.
    MigrationRunner::from_migrations(
        &pool,
        vec![
            step(1, Phase::Expand, "CREATE TABLE dg_1 (id int);"),
            step(2, Phase::Expand, "CREATE TABLE dg_2 (id int);"),
            step(3, Phase::Expand, "CREATE TABLE dg_3 (id int);"),
        ],
    )
    .run()
    .await
    .expect("newer build applies 1 to 3");

    // The "older build" only knows versions 1 and 2, and adds an unapplied
    // version 2b to prove nothing pending is applied either.
    let older = MigrationRunner::from_migrations(
        &pool,
        vec![
            step(1, Phase::Expand, "CREATE TABLE dg_1 (id int);"),
            step(2, Phase::Expand, "CREATE TABLE dg_2 (id int);"),
        ],
    )
    .run()
    .await
    .expect_err("a ledger version unknown to this build must be refused");
    assert!(
        matches!(older, MigrationError::UnknownApplied { version: 3 }),
        "expected UnknownApplied{{version:3}}, got: {older:?}"
    );

    // Nothing changed: the ledger still holds exactly 1, 2, 3.
    assert_eq!(applied_versions(&pool).await, vec![1_i64, 2, 3]);
}

#[tokio::test]
async fn a_failed_migration_records_no_ledger_row_and_stops_the_chain() {
    let pool = TestDatabase::fresh_owner_pool().await;

    // Version 2's DDL is invalid (an undefined column type). It must roll back
    // with no ledger row, and version 3 must never be attempted.
    let err = MigrationRunner::from_migrations(
        &pool,
        vec![
            step(1, Phase::Expand, "CREATE TABLE fdl_1 (id int);"),
            step(
                2,
                Phase::Expand,
                "CREATE TABLE fdl_2 (id int, broken nonexistent_type_xyz);",
            ),
            step(3, Phase::Expand, "CREATE TABLE fdl_3 (id int);"),
        ],
    )
    .run()
    .await
    .expect_err("a migration with invalid DDL must fail");
    assert!(
        matches!(err, MigrationError::Database(_)),
        "expected a Database error, got: {err:?}"
    );

    // Version 1 committed; version 2 rolled back (no table, no ledger row);
    // version 3 was never attempted.
    assert_eq!(
        applied_versions(&pool).await,
        vec![1_i64],
        "only version 1 is recorded"
    );
    assert!(table_exists(&pool, "fdl_1").await, "version 1 committed");
    assert!(
        !table_exists(&pool, "fdl_2").await,
        "the failed migration's DDL rolled back"
    );
    assert!(
        !table_exists(&pool, "fdl_3").await,
        "the chain stopped at the failure"
    );
}

#[tokio::test]
async fn concurrent_runners_serialize_cleanly_via_the_advisory_lock() {
    // Two runners racing on one fresh database (the rolling-upgrade boot race).
    // Without the advisory lock the loser would race to CREATE and fail with a
    // raw "relation already exists" error; with it, the loser waits and finds
    // nothing pending. Both must complete cleanly and the ledger must be [1, 2].
    let pool = TestDatabase::fresh_owner_pool().await;
    let chain = || {
        vec![
            step(1, Phase::Expand, "CREATE TABLE conc_a (id int);"),
            step(2, Phase::Expand, "CREATE TABLE conc_b (id int);"),
        ]
    };

    let runner_a = MigrationRunner::from_migrations(&pool, chain());
    let runner_b = MigrationRunner::from_migrations(&pool, chain());
    let (a, b) = tokio::join!(runner_a.run(), runner_b.run());

    a.expect("runner A completes without a raw error");
    b.expect("runner B completes without a raw error");

    // Exactly one full apply happened; the final ledger is [1, 2].
    assert_eq!(applied_versions(&pool).await, vec![1_i64, 2]);
    assert!(table_exists(&pool, "conc_a").await);
    assert!(table_exists(&pool, "conc_b").await);
}

/// The versions recorded in the ledger, ascending.
async fn applied_versions(pool: &sqlx::PgPool) -> Vec<i64> {
    sqlx::query("SELECT version FROM _schema_migrations ORDER BY version")
        .fetch_all(pool)
        .await
        .expect("read ledger versions")
        .iter()
        .map(|row| row.get::<i64, _>("version"))
        .collect()
}

/// The three JOIN tables' schema, policies, indexes, and grants (issue #97,
/// migrations 0088 and 0089).
///
/// One test over all three because they are one structural contract stated three
/// times: the same scope columns, the same organization denormalization, the same
/// soft delete, the same partial uniqueness over live rows, the same read-only data
/// plane. A per-table copy would let one of the three drift while the other two kept
/// the suite green, which is exactly the defect this shape rules out. Its own test
/// rather than more lines in the production-chain assertions so that a failure names
/// these tables rather than a line inside that test's long sweep.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "three tables' whole structural contract (phase, columns, constraints, \
              policies, index shapes, and the full grant matrix on both roles) read \
              as one unit, precisely so the three cannot drift apart"
)]
async fn the_org_join_tables_carry_their_isolation_indexes_and_least_privilege_grants() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // EXPAND on both: new tenant-scoped tables with their indexes, policies, and
    // grants. Nothing existing is altered or dropped.
    for version in [88_i64, 89] {
        let phase: String = sqlx::query("SELECT phase FROM _schema_migrations WHERE version = $1")
            .bind(version)
            .fetch_one(pool)
            .await
            .unwrap_or_else(|_| panic!("{version:04} is in the ledger"))
            .get("phase");
        assert_eq!(phase, "expand", "migration {version:04} must be an EXPAND");
    }

    // The shape every one of the three shares: RLS enabled AND forced, the isolation
    // policy, the nonempty-scope CHECK, NOT NULL on the scope and organization
    // columns, and a foreign key into organizations.
    for table in [
        "org_group_members",
        "org_group_roles",
        "org_membership_roles",
    ] {
        assert!(table_exists(pool, table).await, "{table} exists");
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "{table} must carry the (tenant, environment) isolation policy"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the nonempty-scope CHECK"
        );
        for column in ["tenant_id", "environment_id", "organization_id"] {
            assert!(
                column_is_not_null(pool, table, column).await,
                "{table}.{column} must be NOT NULL"
            );
        }
        assert!(
            fk_references(pool, table, "organization_id").await,
            "{table}.organization_id must be a FOREIGN KEY into organizations"
        );
        // A soft-delete column, and no DELETE grant on either plane to go with it.
        assert!(
            column_exists(pool, table, "deleted_at").await,
            "{table}.deleted_at exists (removal is a soft delete)"
        );
    }

    // The per-table endpoint columns and their foreign keys. This is what makes
    // "you cannot be in a group of an organization you do not belong to" a schema
    // property rather than a convention: the subject of a group binding and of a
    // direct role grant is an org MEMBERSHIP, not a bare user.
    for (table, endpoints) in [
        ("org_group_members", ["group_id", "membership_id"]),
        ("org_group_roles", ["group_id", "role_id"]),
        ("org_membership_roles", ["membership_id", "role_id"]),
    ] {
        for column in endpoints {
            assert!(
                column_is_not_null(pool, table, column).await,
                "{table}.{column} must be NOT NULL"
            );
            assert!(
                fk_references(pool, table, column).await,
                "{table}.{column} must be a FOREIGN KEY"
            );
        }
    }

    // Uniqueness is PARTIAL over LIVE rows on all three, so removing a binding or
    // withdrawing an assignment frees the pair immediately instead of occupying it
    // forever, and every read (which filters deleted_at IS NULL) agrees with the
    // uniqueness invariant on exactly the live set.
    for index in [
        (
            "org_group_members",
            "org_group_members_group_membership_live_uniq",
        ),
        ("org_group_roles", "org_group_roles_group_role_live_uniq"),
        (
            "org_membership_roles",
            "org_membership_roles_membership_role_live_uniq",
        ),
    ] {
        assert!(
            partial_unique_index_exists(pool, index.0, index.1).await,
            "{} must carry the {} partial unique index over live rows",
            index.0,
            index.1
        );
    }

    // The lookup indexes, and their COLUMN ORDER. Order is the whole point: an index
    // present but ordered wrongly leaves the token-issuance reads on a sequential
    // scan while every functional assertion in the suite stays green. The membership
    // index of org_group_members is the SEED of effective-role resolution and the
    // membership index of org_membership_roles is its DIRECT half, so both are on the
    // mint path.
    for (table, index, leading) in [
        (
            "org_group_members",
            "org_group_members_membership_idx",
            "membership_id",
        ),
        (
            "org_group_members",
            "org_group_members_group_idx",
            "group_id",
        ),
        ("org_group_roles", "org_group_roles_group_idx", "group_id"),
        ("org_group_roles", "org_group_roles_role_idx", "role_id"),
        (
            "org_membership_roles",
            "org_membership_roles_membership_idx",
            "membership_id",
        ),
        (
            "org_membership_roles",
            "org_membership_roles_role_idx",
            "role_id",
        ),
    ] {
        assert_eq!(
            index_columns(pool, table, index).await,
            vec![
                "tenant_id".to_owned(),
                "environment_id".to_owned(),
                leading.to_owned(),
                "created_at".to_owned(),
                "id".to_owned(),
            ],
            "{index} must be (tenant, environment, {leading}, created_at, id): the scope, \
             the filter, then the stable pagination key"
        );
    }

    // Least-privilege grants (the #31 lesson), identical on all three. The CONTROL
    // plane owns the lifecycle: SELECT, INSERT, and a COLUMN-scoped UPDATE of ONLY
    // the soft-delete pair. Nothing may REPOINT an existing row at a different
    // endpoint, organization, or scope, which is what makes the containment checked
    // at write time durable rather than momentary.
    for table in [
        "org_group_members",
        "org_group_roles",
        "org_membership_roles",
    ] {
        for privilege in ["SELECT", "INSERT"] {
            assert!(
                role_has_table_privilege(pool, "ironauth_control", table, privilege).await,
                "ironauth_control must hold {privilege} on {table}"
            );
        }
        for column in ["updated_at", "deleted_at"] {
            assert!(
                role_has_column_privilege(pool, "ironauth_control", table, column, "UPDATE").await,
                "ironauth_control must hold column-scoped UPDATE on {table}.{column}"
            );
        }
        for role in ["ironauth_control", "ironauth_app"] {
            for column in [
                "id",
                "tenant_id",
                "environment_id",
                "organization_id",
                "created_at",
            ] {
                assert!(
                    !role_has_column_privilege(pool, role, table, column, "UPDATE").await,
                    "the {table} UPDATE grant must stay column-scoped: {role} must NOT \
                     gain UPDATE on {table}.{column}"
                );
            }
            assert!(
                !role_has_table_privilege(pool, role, table, "DELETE").await,
                "{role} must NOT hold DELETE on {table} (removal is a soft delete)"
            );
        }
        // The endpoint columns specifically: repointing a live binding or assignment
        // would move authorization between subjects with no audit row naming either.
        for column in ["group_id", "membership_id", "role_id"] {
            if !column_exists(pool, table, column).await {
                continue;
            }
            for role in ["ironauth_control", "ironauth_app"] {
                assert!(
                    !role_has_column_privilege(pool, role, table, column, "UPDATE").await,
                    "{table}.{column} must be immutable by GRANT: {role} must NOT hold \
                     UPDATE on it"
                );
            }
        }
        // Effective-role resolution reads all three at token issuance, so the data
        // plane holds SELECT on all three.
        assert!(
            role_has_table_privilege(pool, "ironauth_app", table, "SELECT").await,
            "the data-plane role must hold SELECT on {table} (the resolution read)"
        );
        // It never CREATES or REPOINTS a row on any of them, in any grant shape. The
        // table-wide probe cannot see a COLUMN-scoped grant, which is a real way for
        // the data plane to gain a write while every table-wide assertion stays
        // green, so every column is swept too.
        for privilege in ["INSERT", "REFERENCES"] {
            assert!(
                !role_has_table_privilege(pool, "ironauth_app", table, privilege).await,
                "the data plane must hold no {privilege} on {table}"
            );
            assert!(
                !role_has_any_column_privilege(pool, "ironauth_app", table, privilege).await,
                "the data plane must hold NO column-scoped {privilege} on {table}"
            );
        }
        // UPDATE is where the three tables deliberately DIFFER, and the asymmetry is
        // the security statement. The invitation-accept side effect runs on the DATA
        // plane and REVIVES a previously removed membership, which must come back
        // holding no groups and no direct roles, so the data plane holds the
        // COLUMN-scoped soft-delete pair on the two MEMBERSHIP-keyed tables and
        // nothing else. `org_group_roles` is keyed on a GROUP, no membership
        // lifecycle reaches it, and the data plane stays strictly READ ONLY there.
        // Asserted in BOTH directions so neither a widening nor a narrowing passes.
        let data_plane_may_revoke = table != "org_group_roles";
        assert!(
            !role_has_table_privilege(pool, "ironauth_app", table, "UPDATE").await,
            "the data-plane UPDATE on {table} must never be table-wide"
        );
        for column in ["updated_at", "deleted_at"] {
            assert_eq!(
                role_has_column_privilege(pool, "ironauth_app", table, column, "UPDATE").await,
                data_plane_may_revoke,
                "the data plane's UPDATE on {table}.{column} must be present exactly \
                 when the membership cascade can reach that table"
            );
        }
        // Positive controls, so a sweep that answered "no" to everything could not
        // pass.
        assert!(
            role_has_any_column_privilege(pool, "ironauth_app", table, "SELECT").await,
            "the data plane holds SELECT on {table}"
        );
        assert_eq!(
            role_has_any_column_privilege(pool, "ironauth_app", table, "UPDATE").await,
            data_plane_may_revoke,
            "the data plane's column-scoped UPDATE on {table} exists exactly when the \
             membership cascade can reach that table"
        );
        assert!(
            role_has_any_column_privilege(pool, "ironauth_control", table, "UPDATE").await,
            "the control plane holds the column-scoped UPDATE a removal needs on {table}"
        );
    }
}

/// The `org_auth_policies` schema, policy, indexes, and grants (issue #95,
/// migration 0090).
///
/// Its own test rather than more lines in the production-chain assertions so that a
/// failure names this table rather than a line inside that test's long sweep. An
/// earlier note gave that test's stack budget as the reason; the measurement in
/// its doc comment shows the budget is not the constraint.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one table's whole structural contract (phase, columns, constraints, \
              policy, both index shapes, and the full grant matrix on both roles) \
              read as one unit"
)]
async fn org_auth_policies_carries_its_isolation_indexes_and_least_privilege_grants() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // EXPAND: one new tenant-scoped table with its indexes, policy, and grants.
    // Nothing existing is altered or dropped.
    let phase: String = sqlx::query("SELECT phase FROM _schema_migrations WHERE version = 90")
        .fetch_one(pool)
        .await
        .expect("0090 is in the ledger")
        .get("phase");
    assert_eq!(phase, "expand");

    assert!(
        table_exists(pool, "org_auth_policies").await,
        "org_auth_policies exists after 0090"
    );
    assert!(
        rls_enabled_and_forced(pool, "org_auth_policies").await,
        "org_auth_policies must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(
            pool,
            "org_auth_policies",
            "org_auth_policies_tenant_isolation"
        )
        .await,
        "org_auth_policies must carry the (tenant, environment) isolation policy"
    );

    // Every CHECK is asserted BY NAME, which is why none of them may be anonymous:
    // an anonymous constraint cannot be pinned, so a later migration could drop or
    // weaken it with nothing failing.
    for constraint in [
        "org_auth_policies_scope_nonempty",
        "org_auth_policies_factors_nonempty",
        "org_auth_policies_domains_nonempty",
        "org_auth_policies_factors_known",
        "org_auth_policies_mfa_reachable",
        "org_auth_policies_session_ttl_positive",
        "org_auth_policies_session_idle_positive",
        "org_auth_policies_idle_within_absolute",
    ] {
        assert!(
            check_constraint_exists(pool, "org_auth_policies", constraint).await,
            "org_auth_policies must carry the {constraint} CHECK constraint"
        );
    }

    // The identity columns are NOT NULL.
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "organization_id",
        "metadata",
    ] {
        assert!(
            column_is_not_null(pool, "org_auth_policies", column).await,
            "org_auth_policies.{column} must be NOT NULL"
        );
    }
    // EVERY policy dimension is NULLABLE, and that is the whole storage model: NULL
    // means UNSET, which the resolution engine reads as "inherit the next level up
    // unchanged". A dimension that acquired a NOT NULL (or a DEFAULT) would turn an
    // empty policy object into one that RESTRICTS, which is the exact opposite of
    // what the issue requires.
    for column in [
        "mfa_required",
        "allowed_factors",
        "allowed_email_domains",
        "jit_provisioning",
        "invitations_enabled",
        "session_ttl_secs",
        "session_idle_ttl_secs",
        "deleted_at",
    ] {
        assert!(
            column_exists(pool, "org_auth_policies", column).await,
            "org_auth_policies.{column} exists"
        );
        assert!(
            !column_is_not_null(pool, "org_auth_policies", column).await,
            "org_auth_policies.{column} must be NULLABLE (NULL means inherit)"
        );
        assert_eq!(
            column_default(pool, "org_auth_policies", column).await,
            None,
            "org_auth_policies.{column} must carry NO default: a default would make an \
             empty policy object restrict something"
        );
    }

    // At most one LIVE policy per organization. PARTIAL over live rows, so a removed
    // policy does not occupy its organization; it is also the conflict target the
    // `set` upsert names, so it must be partial in exactly the shape the reads filter.
    assert!(
        partial_unique_index_exists(pool, "org_auth_policies", "org_auth_policies_org_live_uniq")
            .await,
        "org_auth_policies must carry the per-organization partial unique index over live rows"
    );
    assert_eq!(
        index_columns(pool, "org_auth_policies", "org_auth_policies_org_live_uniq").await,
        vec![
            "tenant_id".to_owned(),
            "environment_id".to_owned(),
            "organization_id".to_owned()
        ],
        "the live uniqueness key is (tenant, environment, organization) and nothing finer"
    );
    assert_eq!(
        index_columns(pool, "org_auth_policies", "org_auth_policies_scope_idx").await,
        vec![
            "tenant_id".to_owned(),
            "environment_id".to_owned(),
            "created_at".to_owned(),
            "id".to_owned()
        ],
        "the scope list index must lead with the scope and then the (created_at, id) \
         pagination key"
    );

    // The organization foreign key is the backstop that makes a policy on a
    // nonexistent or cross-scope organization impossible.
    assert!(
        fk_references(pool, "org_auth_policies", "organization_id").await,
        "org_auth_policies.organization_id must be a FOREIGN KEY into organizations"
    );
    assert!(fk_references(pool, "org_auth_policies", "tenant_id").await);

    // Grants: the control plane owns the surface.
    for privilege in ["SELECT", "INSERT"] {
        assert!(
            role_has_table_privilege(pool, "ironauth_control", "org_auth_policies", privilege)
                .await,
            "ironauth_control must hold {privilege} on org_auth_policies"
        );
    }
    for column in [
        "mfa_required",
        "allowed_factors",
        "allowed_email_domains",
        "jit_provisioning",
        "invitations_enabled",
        "session_ttl_secs",
        "session_idle_ttl_secs",
        "metadata",
        "updated_at",
        "deleted_at",
    ] {
        assert!(
            role_has_column_privilege(
                pool,
                "ironauth_control",
                "org_auth_policies",
                column,
                "UPDATE"
            )
            .await,
            "ironauth_control must hold column-scoped UPDATE on org_auth_policies.{column}"
        );
    }
    // The scope and organization columns are immutable by GRANT on BOTH roles, which
    // is what keeps the containment invariant from being defeatable by an UPDATE
    // after the fact: a policy row can never be moved between scopes or between
    // organizations.
    for role in ["ironauth_control", "ironauth_app"] {
        for column in ["id", "tenant_id", "environment_id", "organization_id"] {
            assert!(
                !role_has_column_privilege(pool, role, "org_auth_policies", column, "UPDATE").await,
                "org_auth_policies.{column} must be immutable by GRANT: {role} must NOT hold \
                 UPDATE on it"
            );
        }
        // DELETE is granted to nobody on either plane: removal is the soft delete.
        assert!(
            !role_has_table_privilege(pool, role, "org_auth_policies", "DELETE").await,
            "{role} must NOT hold DELETE on org_auth_policies (removal is a soft delete)"
        );
    }

    // The data plane reads and NOTHING else. A data plane able to rewrite its own MFA
    // requirement is the whole threat this table's grants exist to prevent.
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "org_auth_policies", "SELECT").await,
        "the data-plane role must hold SELECT on org_auth_policies (the resolution read)"
    );
    for privilege in ["INSERT", "UPDATE", "DELETE"] {
        assert!(
            !role_has_table_privilege(pool, "ironauth_app", "org_auth_policies", privilege).await,
            "the data-plane grant on org_auth_policies must be SELECT only (no {privilege})"
        );
    }
}

/// The data plane holds NO write grant of any shape on `org_auth_policies`
/// (issue #95, 0090).
///
/// The table-wide `has_table_privilege` probes above CANNOT see a COLUMN-scoped
/// grant: `GRANT UPDATE (mfa_required) ON org_auth_policies TO ironauth_app` leaves
/// every one of them reading false while genuinely letting the authorization path
/// rewrite the requirement it is about to evaluate against itself. Sweeping every
/// column through `pg_attribute` closes that gap, so the least-privilege invariant is
/// a PHYSICAL property of the schema rather than a claim about which code paths
/// happen to exist.
#[tokio::test]
async fn the_data_plane_holds_no_column_scoped_write_grant_on_org_auth_policies() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // INSERT, UPDATE, and REFERENCES are the write-shaped privileges Postgres can
    // grant per column (DELETE has no column form and is asserted table-wide with the
    // rest of the 0090 grants).
    for privilege in ["INSERT", "UPDATE", "REFERENCES"] {
        assert!(
            !role_has_any_column_privilege(pool, "ironauth_app", "org_auth_policies", privilege)
                .await,
            "the data plane must hold NO column-scoped {privilege} on org_auth_policies"
        );
    }
    // Positive controls, so a sweep that simply answered "no" to everything could not
    // pass this test.
    assert!(
        role_has_any_column_privilege(pool, "ironauth_app", "org_auth_policies", "SELECT").await,
        "the data plane holds SELECT on org_auth_policies (the resolution read)"
    );
    assert!(
        role_has_any_column_privilege(pool, "ironauth_control", "org_auth_policies", "UPDATE")
            .await,
        "the control plane holds the column-scoped UPDATE a change and a removal need"
    );
}

/// The `permissions` schema, policy, indexes, and grants (issue #98, migration 0091).
///
/// Its own test rather than more lines in the production-chain assertions, following
/// the 0090 precedent, so that a failure names this table rather than a line
/// inside that test's long sweep. An earlier note gave that test's stack budget as
/// the reason; the measurement in its doc comment shows the budget is not the
/// constraint.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one table's whole structural contract (phase, columns, constraints, \
              policy, both index shapes, and the full grant matrix on both roles) \
              read as one unit"
)]
async fn permissions_carries_its_isolation_indexes_and_least_privilege_grants() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // EXPAND: one new tenant-scoped table with its indexes, policy, and grants.
    // Nothing existing is altered or dropped.
    let phase: String = sqlx::query("SELECT phase FROM _schema_migrations WHERE version = 91")
        .fetch_one(pool)
        .await
        .expect("0091 is in the ledger")
        .get("phase");
    assert_eq!(phase, "expand");

    assert!(
        table_exists(pool, "permissions").await,
        "permissions exists after 0091"
    );
    assert!(
        rls_enabled_and_forced(pool, "permissions").await,
        "permissions must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "permissions", "permissions_tenant_isolation").await,
        "permissions must carry the (tenant, environment) isolation policy"
    );

    // Every CHECK is asserted BY NAME, which is why none of them may be anonymous:
    // an anonymous constraint cannot be pinned, so a later migration could drop or
    // weaken it with nothing failing.
    for constraint in [
        "permissions_scope_nonempty",
        "permissions_kind_known",
        "permissions_slug_valid",
        "permissions_display_name_nonempty",
    ] {
        assert!(
            check_constraint_exists(pool, "permissions", constraint).await,
            "permissions must carry the {constraint} CHECK constraint"
        );
    }

    // There is deliberately NO organization column. The vocabulary belongs to the
    // ENVIRONMENT (a permission names an API capability, and one string cannot mean
    // different things to two organizations calling one API), which is what makes
    // the isolation policy this table's COMPLETE fence, unlike every #97 table.
    // Asserted rather than merely written down, because "someone will add it later
    // without reading the header" is exactly how that property is lost.
    assert!(
        !column_exists(pool, "permissions", "organization_id").await,
        "permissions must carry NO organization_id: the vocabulary is per ENVIRONMENT, \
         and the role-to-permission mapping is what carries the organization"
    );

    // The identity and value columns are NOT NULL, and `kind` carries the default
    // that makes issue #98's own writes (which never state a kind) ordinary
    // permissions.
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "kind",
        "slug",
        "display_name",
        "metadata",
    ] {
        assert!(
            column_is_not_null(pool, "permissions", column).await,
            "permissions.{column} must be NOT NULL"
        );
    }
    assert!(
        column_default(pool, "permissions", "kind")
            .await
            .is_some_and(|default| default.contains("'permission'")),
        "permissions.kind must default to the ordinary permission, so a write that \
         states no kind cannot land as something a projection filter excludes"
    );
    assert!(
        !column_is_not_null(pool, "permissions", "deleted_at").await,
        "permissions.deleted_at must be nullable (the soft-delete latch)"
    );

    // At most one LIVE row per (scope, kind, slug), PARTIAL over live rows so a
    // deleted permission does not occupy its slug. `kind` is IN the key, and that is
    // what gives issue #103 its headroom: `plan.enterprise` may exist as an
    // entitlement while a permission of the same slug exists independently. Dropping
    // `kind` from this key would force #103 into a migration on a table the token
    // path reads.
    assert!(
        partial_unique_index_exists(pool, "permissions", "permissions_kind_slug_live_uniq").await,
        "permissions must carry the per-(kind, slug) partial unique index over live rows"
    );
    assert_eq!(
        index_columns(pool, "permissions", "permissions_kind_slug_live_uniq").await,
        vec![
            "tenant_id".to_owned(),
            "environment_id".to_owned(),
            "kind".to_owned(),
            "slug".to_owned()
        ],
        "the live uniqueness key is (tenant, environment, kind, slug)"
    );
    // And the PREDICATE itself, pinned by text the way the parity oracle pins the
    // slug CHECK text. The two probes above cannot see a predicate that was narrowed
    // rather than removed: `WHERE deleted_at IS NULL AND kind = 'permission'` leaves
    // both reading exactly as they do now, while a second LIVE entitlement of one
    // slug stops being refused and issue #103 inherits a table with no uniqueness for
    // the kind it is about to write.
    assert_eq!(
        index_predicate(pool, "permissions", "permissions_kind_slug_live_uniq").await,
        "(deleted_at IS NULL)",
        "the live-uniqueness predicate must be the soft-delete latch ALONE: `kind` is \
         part of the KEY, never part of the predicate"
    );
    assert_eq!(
        index_columns(pool, "permissions", "permissions_scope_idx").await,
        vec![
            "tenant_id".to_owned(),
            "environment_id".to_owned(),
            "created_at".to_owned(),
            "id".to_owned()
        ],
        "the scope list index must lead with the scope and then the (created_at, id) \
         pagination key"
    );

    // The scope foreign keys are the backstop that makes a permission in a
    // nonexistent scope impossible.
    assert!(fk_references(pool, "permissions", "tenant_id").await);
    assert!(fk_references(pool, "permissions", "environment_id").await);

    // Grants: the control plane owns the surface.
    for privilege in ["SELECT", "INSERT"] {
        assert!(
            role_has_table_privilege(pool, "ironauth_control", "permissions", privilege).await,
            "ironauth_control must hold {privilege} on permissions"
        );
    }
    for column in ["display_name", "metadata", "updated_at", "deleted_at"] {
        assert!(
            role_has_column_privilege(pool, "ironauth_control", "permissions", column, "UPDATE")
                .await,
            "ironauth_control must hold column-scoped UPDATE on permissions.{column}"
        );
    }
    // `slug` and `kind` are immutable by GRANT on BOTH roles, and so are the scope
    // columns. A slug is a DIRECT authorization input that lands in a token, so a
    // rename under live mappings would silently repoint every grant that names it; a
    // reclassification would silently move a row into or out of the set a token
    // claim selects. These absences are security properties, and an absence that
    // nothing asserts is an absence a later migration can quietly fill.
    for role in ["ironauth_control", "ironauth_app"] {
        for column in ["id", "tenant_id", "environment_id", "slug", "kind"] {
            assert!(
                !role_has_column_privilege(pool, role, "permissions", column, "UPDATE").await,
                "permissions.{column} must be immutable by GRANT: {role} must NOT hold \
                 UPDATE on it"
            );
        }
        // DELETE is granted to nobody on either plane: removal is the soft delete.
        assert!(
            !role_has_table_privilege(pool, role, "permissions", "DELETE").await,
            "{role} must NOT hold DELETE on permissions (removal is a soft delete)"
        );
    }

    // The data plane reads and NOTHING else. A data plane able to DEFINE the
    // capability names it is about to put into a token is the whole threat this
    // table's grants exist to prevent.
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "permissions", "SELECT").await,
        "the data-plane role must hold SELECT on permissions (the resolution read)"
    );
    for privilege in ["INSERT", "UPDATE", "DELETE"] {
        assert!(
            !role_has_table_privilege(pool, "ironauth_app", "permissions", privilege).await,
            "the data-plane grant on permissions must be SELECT only (no {privilege})"
        );
    }
}

/// The data plane holds NO write grant of any shape on `permissions` (issue #98,
/// 0091).
///
/// The table-wide `has_table_privilege` probes above CANNOT see a COLUMN-scoped
/// grant: `GRANT INSERT (slug) ON permissions TO ironauth_app` leaves every one of
/// them reading false while genuinely letting the token-issuance plane define the
/// capability names it is about to emit. Sweeping every column through `pg_attribute`
/// closes that gap, so the least-privilege invariant is a PHYSICAL property of the
/// schema rather than a claim about which code paths happen to exist.
#[tokio::test]
async fn the_data_plane_holds_no_column_scoped_write_grant_on_permissions() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // INSERT, UPDATE, and REFERENCES are the write-shaped privileges Postgres can
    // grant per column (DELETE has no column form and is asserted table-wide with
    // the rest of the 0091 grants).
    for privilege in ["INSERT", "UPDATE", "REFERENCES"] {
        assert!(
            !role_has_any_column_privilege(pool, "ironauth_app", "permissions", privilege).await,
            "the data plane must hold NO column-scoped {privilege} on permissions"
        );
    }
    // Positive controls, so a sweep that simply answered "no" to everything could not
    // pass this test.
    assert!(
        role_has_any_column_privilege(pool, "ironauth_app", "permissions", "SELECT").await,
        "the data plane holds SELECT on permissions (the resolution read)"
    );
    assert!(
        role_has_any_column_privilege(pool, "ironauth_control", "permissions", "UPDATE").await,
        "the control plane holds the column-scoped UPDATE a relabel and a delete need"
    );
}

/// Migration 0100's control-plane write grants on `environment_secrets` (issue #250).
///
/// Its own test rather than more lines in the production-chain sweep, following the
/// 0091/0092 precedent, so a failure names this grant rather than a line inside that
/// long test. Both directions matter: the control plane must be ABLE to arm, rotate,
/// and disable an environment's outbound-verification credential, and it must be able
/// to do exactly that and no more.
#[tokio::test]
async fn the_control_plane_can_write_an_environment_secret_value_and_nothing_else() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // The three table-wide privileges the management endpoints need. DELETE has no
    // column form, so it is asserted table-wide by definition.
    for privilege in ["SELECT", "INSERT", "DELETE"] {
        assert!(
            role_has_table_privilege(pool, "ironauth_control", "environment_secrets", privilege)
                .await,
            "the control plane needs {privilege} on environment_secrets to manage the \
             outbound-verification credential"
        );
    }

    // The UPDATE is COLUMN SCOPED, which is the whole point: a rotation rewrites the
    // sealed value and its bookkeeping, and nothing else. `has_table_privilege` does
    // not see a column-scoped grant, so the table-wide probe must read FALSE while the
    // four named columns read true.
    assert!(
        !role_has_table_privilege(pool, "ironauth_control", "environment_secrets", "UPDATE").await,
        "the control plane must hold NO table-wide UPDATE on environment_secrets (the #31 \
         lesson): a future column would silently fall under it"
    );
    for column in ["ciphertext", "dek_version", "version", "updated_at"] {
        assert!(
            role_has_column_privilege(
                pool,
                "ironauth_control",
                "environment_secrets",
                column,
                "UPDATE"
            )
            .await,
            "a rotation rewrites {column}, so the control plane needs it"
        );
    }
    // And the identity columns are NOT writable, so the control plane cannot rewrite a
    // secret's name or scope THROUGH AN UPDATE. That is a narrower claim than it looks
    // and the next test is the reason it has to be stated that narrowly.
    for column in ["id", "tenant_id", "environment_id", "name", "created_at"] {
        assert!(
            !role_has_column_privilege(
                pool,
                "ironauth_control",
                "environment_secrets",
                column,
                "UPDATE"
            )
            .await,
            "the control plane must not be able to rewrite {column} on environment_secrets"
        );
    }
}

/// Migration 0100's RESTRICTIVE row-level-security policies on `environment_secrets`
/// (issue #250): the control plane may write exactly the ONE reserved name.
///
/// # Why the column grants above are not the fence, measured rather than argued
///
/// `GRANT INSERT` is table wide and `GRANT DELETE` has no column form at all, so the
/// column-scoped UPDATE says nothing about what the control plane can CREATE. INSERT
/// plus DELETE is a rename, and a replace of any other secret in the bound scope, one
/// statement pair at a time. An earlier draft of 0100's header claimed the grants alone
/// meant the control plane "can neither rename one nor move one between scopes"; that
/// was true of UPDATE and false of the pair, and this test is what would have caught it.
///
/// SELECT is deliberately left unrestricted, and that is asserted here too: 0035 granted
/// the control role SELECT for the config-promotion plan's reference-PRESENCE check,
/// which asks about secrets by whatever name a variable references.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one linear seed -> five-probe walk over one policy set
async fn the_control_plane_can_write_only_the_one_reserved_environment_secret_name() {
    use ironauth_env::Env;

    const RESERVED: &str = "ironauth.outbound_verification_token";
    const FOREIGN: &str = "connector.stripe.api_key";

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();

    // A FOREIGN secret seeded as the OWNER, so the control plane's inability to touch it
    // below is measured against a row that really exists.
    sqlx::query(
        "INSERT INTO environment_secrets \
         (id, tenant_id, environment_id, name, dek_version, ciphertext) \
         VALUES ($1, $2, $3, $4, 1, '\\x00'::bytea)",
    )
    .bind("esec_owner_seeded_foreign")
    .bind(&tenant)
    .bind(&environment)
    .bind(FOREIGN)
    .execute(db.owner_pool())
    .await
    .expect("the owner seeds a foreign secret");

    // Everything below runs as `ironauth_control` inside the scope-bound transaction the
    // repository layer always opens, which is exactly how the management API reaches
    // this table.
    let mut tx = db
        .control_pool()
        .begin()
        .await
        .expect("control transaction");
    for (key, value) in [
        ("ironauth.tenant_id", &tenant),
        ("ironauth.environment_id", &environment),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(key)
            .bind(value)
            .execute(&mut *tx)
            .await
            .expect("bind the scope");
    }

    // 1. The RESERVED name is writable: this is the anti-vacuity control. Without it a
    //    policy that refused EVERYTHING would satisfy every negative below.
    sqlx::query(
        "INSERT INTO environment_secrets \
         (id, tenant_id, environment_id, name, dek_version, ciphertext) \
         VALUES ($1, $2, $3, $4, 1, '\\x01'::bytea)",
    )
    .bind("esec_control_reserved")
    .bind(&tenant)
    .bind(&environment)
    .bind(RESERVED)
    .execute(&mut *tx)
    .await
    .expect("the control plane arms the reserved name");

    // 2. A DIFFERENT name is refused at the INSERT, which is the hole the grants left
    //    wide open: this is how the control plane would have minted a secret under any
    //    name at all.
    let refused = sqlx::query(
        "INSERT INTO environment_secrets \
         (id, tenant_id, environment_id, name, dek_version, ciphertext) \
         VALUES ($1, $2, $3, $4, 1, '\\x02'::bytea)",
    )
    .bind("esec_control_foreign")
    .bind(&tenant)
    .bind(&environment)
    .bind("connector.acme.api_key")
    .execute(&mut *tx)
    .await;
    let message = refused
        .expect_err("the control plane must not create a secret under any other name")
        .to_string();
    assert!(
        message.contains("row-level security"),
        "the refusal must be the restrictive policy rather than an incidental \
         constraint: {message}"
    );

    // A failed statement poisons the transaction, so the remaining probes get a fresh
    // one, bound to the same scope.
    tx.rollback().await.expect("roll back the poisoned probe");
    let mut tx = db
        .control_pool()
        .begin()
        .await
        .expect("control transaction");
    for (key, value) in [
        ("ironauth.tenant_id", &tenant),
        ("ironauth.environment_id", &environment),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(key)
            .bind(value)
            .execute(&mut *tx)
            .await
            .expect("bind the scope");
    }

    // 3. The other half of the rename: DELETE. Without the restrictive DELETE policy the
    //    control plane could destroy any secret in the scope, connector credentials
    //    included, and then INSERT its own row under that name.
    let deleted = sqlx::query("DELETE FROM environment_secrets WHERE name = $1")
        .bind(FOREIGN)
        .execute(&mut *tx)
        .await
        .expect("the delete runs")
        .rows_affected();
    assert_eq!(
        deleted, 0,
        "the control plane must not be able to delete another environment secret"
    );

    // 4. And an UPDATE of a foreign row's VALUE is refused by the policy as well, which
    //    the column grants alone did not cover: they said WHICH columns, never WHICH ROWS.
    let updated =
        sqlx::query("UPDATE environment_secrets SET ciphertext = '\\x03'::bytea WHERE name = $1")
            .bind(FOREIGN)
            .execute(&mut *tx)
            .await
            .expect("the update runs")
            .rows_affected();
    assert_eq!(
        updated, 0,
        "the control plane must not be able to rewrite another environment secret's value"
    );

    // 5. SELECT is UNRESTRICTED, deliberately: 0035's reference-presence check reads
    //    secrets by whatever name a promoted variable references. A policy that broke
    //    that would break config promotion, so it is pinned here rather than discovered
    //    there.
    let (visible,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM environment_secrets WHERE name = $1")
            .bind(FOREIGN)
            .fetch_one(&mut *tx)
            .await
            .expect("the presence read runs");
    assert_eq!(
        visible, 1,
        "the control plane must still SEE a foreign secret's presence (migration 0035)"
    );

    tx.commit().await.expect("commit the probe transaction");
}

/// The `org_role_permissions` schema, policy, indexes, and grants (issue #98,
/// migration 0092).
///
/// Its own test rather than more lines in the production-chain assertions, following
/// the 0090 precedent, so that a failure names this table rather than a line
/// inside that test's long sweep. An earlier note gave that test's stack budget as
/// the reason; the measurement in its doc comment shows the budget is not the
/// constraint.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one table's whole structural contract (phase, columns, constraints, \
              policy, all three index shapes with their predicates, and the full \
              grant matrix on both roles) read as one unit"
)]
async fn org_role_permissions_carries_its_isolation_indexes_and_least_privilege_grants() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // EXPAND: one new tenant-scoped table with its indexes, policy, and grants.
    // Nothing existing is altered or dropped.
    let phase: String = sqlx::query("SELECT phase FROM _schema_migrations WHERE version = 92")
        .fetch_one(pool)
        .await
        .expect("0092 is in the ledger")
        .get("phase");
    assert_eq!(phase, "expand");

    assert!(
        table_exists(pool, "org_role_permissions").await,
        "org_role_permissions exists after 0092"
    );
    assert!(
        rls_enabled_and_forced(pool, "org_role_permissions").await,
        "org_role_permissions must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(
            pool,
            "org_role_permissions",
            "org_role_permissions_tenant_isolation"
        )
        .await,
        "org_role_permissions must carry the (tenant, environment) isolation policy"
    );
    assert!(
        check_constraint_exists(
            pool,
            "org_role_permissions",
            "org_role_permissions_scope_nonempty"
        )
        .await,
        "org_role_permissions must carry the nonempty-scope CHECK by NAME (an anonymous \
         constraint cannot be pinned, so a later migration could drop it silently)"
    );

    // Unlike `permissions` (0091), this table DOES carry an organization, because the
    // ROLE half of the pair has one. Asserted rather than left to the header: without
    // this column the isolation policy would be the whole fence and one
    // organization's mapping would be readable and detachable from a sibling
    // organization's management route inside one environment.
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "organization_id",
        "role_id",
        "permission_id",
    ] {
        assert!(
            column_is_not_null(pool, "org_role_permissions", column).await,
            "org_role_permissions.{column} must be NOT NULL"
        );
        assert_eq!(
            column_default(pool, "org_role_permissions", column).await,
            None,
            "org_role_permissions.{column} must carry NO default: every one of these is \
             a caller-supplied identifier the repository resolves before the write"
        );
    }
    assert!(
        !column_is_not_null(pool, "org_role_permissions", "deleted_at").await,
        "org_role_permissions.deleted_at must be nullable (the soft-delete latch)"
    );

    // The foreign keys. They are the backstop that makes a mapping naming a
    // NONEXISTENT endpoint impossible; they are id-only, so same-scope and
    // same-organization containment is the repository's job and 0092's header says so.
    for column in ["tenant_id", "organization_id", "role_id", "permission_id"] {
        assert!(
            fk_references(pool, "org_role_permissions", column).await,
            "org_role_permissions.{column} must be a FOREIGN KEY"
        );
    }

    // At most one LIVE mapping per (role, permission), PARTIAL over live rows so a
    // detach frees the pair immediately.
    assert!(
        partial_unique_index_exists(
            pool,
            "org_role_permissions",
            "org_role_permissions_pair_live_uniq"
        )
        .await,
        "org_role_permissions must carry the per-(role, permission) partial unique index \
         over live rows"
    );
    // The KEY, pinned as an exact vector. `organization_id` is deliberately NOT in it:
    // adding a column to a unique key WEAKENS it, and the weaker form would admit two
    // live rows for one (role, permission) pair under different organizations, which a
    // role belonging to exactly one organization makes meaningless except as a
    // corruption. This mirrors org_group_roles_group_role_live_uniq, which omits the
    // organization its table likewise carries.
    assert_eq!(
        index_columns(
            pool,
            "org_role_permissions",
            "org_role_permissions_pair_live_uniq"
        )
        .await,
        vec![
            "tenant_id".to_owned(),
            "environment_id".to_owned(),
            "role_id".to_owned(),
            "permission_id".to_owned()
        ],
        "the live uniqueness key is (tenant, environment, role, permission) and nothing \
         wider: organization_id in the key would ADMIT a duplicate pair"
    );
    // And the PREDICATE by text, because the two probes above cannot see a predicate
    // that was NARROWED rather than removed: any extra conjunct leaves both reading
    // exactly as they do now while a second live mapping of one pair stops being
    // refused.
    assert_eq!(
        index_predicate(
            pool,
            "org_role_permissions",
            "org_role_permissions_pair_live_uniq"
        )
        .await,
        "(deleted_at IS NULL)",
        "the live-uniqueness predicate must be the soft-delete latch ALONE"
    );

    // The two lookup indexes, their COLUMN ORDER, and their predicates. Order is the
    // whole point: an index present but ordered wrongly leaves the reads on a
    // sequential scan while every functional assertion stays green. The role index is
    // on the token-issuance path (it is the join the effective-permission
    // resolution performs); the permission index is the blast-radius answer an
    // operator wants before deleting a permission.
    for (index, endpoint) in [
        ("org_role_permissions_role_idx", "role_id"),
        ("org_role_permissions_permission_idx", "permission_id"),
    ] {
        assert_eq!(
            index_columns(pool, "org_role_permissions", index).await,
            vec![
                "tenant_id".to_owned(),
                "environment_id".to_owned(),
                endpoint.to_owned(),
                "created_at".to_owned(),
                "id".to_owned()
            ],
            "{index} must lead with the scope, then the endpoint, then the \
             (created_at, id) pagination key the list orders on"
        );
        assert_eq!(
            index_predicate(pool, "org_role_permissions", index).await,
            "(deleted_at IS NULL)",
            "{index} is partial over live rows, which is what every read filters on"
        );
    }

    // Grants: the control plane owns the surface.
    for privilege in ["SELECT", "INSERT"] {
        assert!(
            role_has_table_privilege(pool, "ironauth_control", "org_role_permissions", privilege)
                .await,
            "ironauth_control must hold {privilege} on org_role_permissions"
        );
    }
    for column in ["updated_at", "deleted_at"] {
        assert!(
            role_has_column_privilege(
                pool,
                "ironauth_control",
                "org_role_permissions",
                column,
                "UPDATE"
            )
            .await,
            "ironauth_control must hold column-scoped UPDATE on org_role_permissions.{column}"
        );
    }
    // Every ADDRESSING column is immutable by GRANT on BOTH roles, which is what keeps
    // the containment the repository resolves at write time from being undone
    // afterwards: a mapping can never be repointed at a different role, permission,
    // organization, or scope. These absences are security properties, and an absence
    // that nothing asserts is an absence a later migration can quietly fill.
    for role in ["ironauth_control", "ironauth_app"] {
        for column in [
            "id",
            "tenant_id",
            "environment_id",
            "organization_id",
            "role_id",
            "permission_id",
        ] {
            assert!(
                !role_has_column_privilege(pool, role, "org_role_permissions", column, "UPDATE")
                    .await,
                "org_role_permissions.{column} must be immutable by GRANT: {role} must NOT \
                 hold UPDATE on it"
            );
        }
        // DELETE is granted to nobody on either plane: removal is the soft delete,
        // which is what keeps a detach audit row's target resolvable (an application
        // rule; `audit_log` carries no foreign key here).
        assert!(
            !role_has_table_privilege(pool, role, "org_role_permissions", "DELETE").await,
            "{role} must NOT hold DELETE on org_role_permissions (removal is a soft delete)"
        );
    }

    // The data plane reads and NOTHING else, and the asymmetry with
    // org_membership_roles (which DOES hold the soft-delete pair, because the
    // invitation-accept cascade runs on the data plane) is the point: no membership
    // lifecycle reaches this table, so it stays strictly read only here.
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "org_role_permissions", "SELECT").await,
        "the data-plane role must hold SELECT on org_role_permissions (the resolution join)"
    );
    for privilege in ["INSERT", "UPDATE", "DELETE"] {
        assert!(
            !role_has_table_privilege(pool, "ironauth_app", "org_role_permissions", privilege)
                .await,
            "the data-plane grant on org_role_permissions must be SELECT only (no {privilege})"
        );
    }
}

/// The data plane holds NO write grant of any shape on `org_role_permissions`
/// (issue #98, 0092).
///
/// The table-wide `has_table_privilege` probes above CANNOT see a COLUMN-scoped
/// grant: `GRANT INSERT (permission_id) ON org_role_permissions TO ironauth_app`
/// leaves every one of them reading false while genuinely letting the token-issuance
/// plane decide which capabilities a role grants, which is the same as letting it
/// write its own claim. Sweeping every column through `pg_attribute` closes that gap,
/// so the least-privilege invariant is a PHYSICAL property of the schema rather than
/// a claim about which code paths happen to exist.
#[tokio::test]
async fn the_data_plane_holds_no_column_scoped_write_grant_on_org_role_permissions() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // INSERT, UPDATE, and REFERENCES are the write-shaped privileges Postgres can
    // grant per column (DELETE has no column form and is asserted table-wide with the
    // rest of the 0092 grants).
    for privilege in ["INSERT", "UPDATE", "REFERENCES"] {
        assert!(
            !role_has_any_column_privilege(pool, "ironauth_app", "org_role_permissions", privilege)
                .await,
            "the data plane must hold NO column-scoped {privilege} on org_role_permissions"
        );
    }
    // Positive controls, so a sweep that simply answered "no" to everything could not
    // pass this test.
    assert!(
        role_has_any_column_privilege(pool, "ironauth_app", "org_role_permissions", "SELECT").await,
        "the data plane holds SELECT on org_role_permissions (the resolution join)"
    );
    assert!(
        role_has_any_column_privilege(pool, "ironauth_control", "org_role_permissions", "UPDATE")
            .await,
        "the control plane holds the column-scoped UPDATE a detach needs"
    );
}

/// The organization DEFAULT ROLE designation: the column, the partial unique index
/// that makes "at most one per organization" structural, and the one new grant
/// (issue #98, migration 0093).
///
/// Its own test rather than more lines in the production-chain assertions, following
/// the 0090 precedent, so that a failure names this table rather than a line
/// inside that test's long sweep. An earlier note gave that test's stack budget as
/// the reason; the measurement in its doc comment shows the budget is not the
/// constraint.
#[tokio::test]
async fn org_roles_carries_the_default_designation_its_live_uniqueness_and_its_grant() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // EXPAND: one additive column with a NOT NULL DEFAULT, one new index, one new
    // grant. No existing column is altered or dropped and no existing grant is
    // revoked.
    let phase: String = sqlx::query("SELECT phase FROM _schema_migrations WHERE version = 93")
        .fetch_one(pool)
        .await
        .expect("0093 is in the ledger")
        .get("phase");
    assert_eq!(phase, "expand");

    assert!(
        column_exists(pool, "org_roles", "is_default").await,
        "org_roles.is_default exists after 0093"
    );
    assert_eq!(
        column_data_type(pool, "org_roles", "is_default").await,
        "boolean",
        "the designation is a boolean flag on the ROLE, not a pointer on the organization"
    );
    // NOT NULL with a false DEFAULT, so every row that existed before 0093 reads
    // false and no backfill is needed. A nullable column would make "no default" and
    // "unknown" two states where the resolution treats them as one.
    assert!(
        column_is_not_null(pool, "org_roles", "is_default").await,
        "org_roles.is_default must be NOT NULL"
    );
    assert_eq!(
        column_default(pool, "org_roles", "is_default").await,
        Some("false".to_owned()),
        "the safe default is false: an organization has no default role until an \
         operator designates one"
    );

    // At most ONE LIVE default role per organization, structurally rather than by
    // convention. This is also the backstop that refuses the loser if two designate
    // requests race, which is why it is a UNIQUE index and not merely an index.
    assert!(
        partial_unique_index_exists(pool, "org_roles", "org_roles_org_default_live_uniq").await,
        "org_roles must carry the per-organization default partial unique index"
    );
    assert_eq!(
        index_columns(pool, "org_roles", "org_roles_org_default_live_uniq").await,
        vec![
            "tenant_id".to_owned(),
            "environment_id".to_owned(),
            "organization_id".to_owned()
        ],
        "the key is the ORGANIZATION address alone: adding any further column would \
         WEAKEN it into admitting two live defaults"
    );
    // And the PREDICATE by text, because neither probe above can see a predicate that
    // was WIDENED rather than removed. Dropping the `is_default` conjunct would make
    // this an at-most-one-live-ROLE-per-organization index, which refuses the second
    // role an organization ever defines; dropping the `deleted_at` conjunct would let
    // a soft-deleted role go on occupying the designation forever.
    assert_eq!(
        index_predicate(pool, "org_roles", "org_roles_org_default_live_uniq").await,
        "(is_default AND (deleted_at IS NULL))",
        "the designation is unique over exactly the rows the resolution can see"
    );

    // The control plane designates and clears; the column-scoped UPDATE grant is
    // ADDITIVE to the one 0086 wrote, so the four columns named there must still be
    // updatable and `slug` must still not be.
    assert!(
        role_has_column_privilege(
            pool,
            "ironauth_control",
            "org_roles",
            "is_default",
            "UPDATE"
        )
        .await,
        "ironauth_control must hold column-scoped UPDATE on org_roles.is_default"
    );
    for column in ["display_name", "metadata", "updated_at", "deleted_at"] {
        assert!(
            role_has_column_privilege(pool, "ironauth_control", "org_roles", column, "UPDATE")
                .await,
            "0086's column-scoped UPDATE on org_roles.{column} must survive 0093 \
             (Postgres unions column grants; a re-GRANT that replaced them would not)"
        );
    }
    assert!(
        !role_has_column_privilege(pool, "ironauth_control", "org_roles", "slug", "UPDATE").await,
        "org_roles.slug must still be immutable by GRANT after 0093"
    );

    // The DATA plane gains nothing. A data plane able to designate the role every
    // member of an organization holds is a data plane able to write its own token
    // claim. `the_data_plane_holds_no_column_scoped_write_grant_on_org_roles` sweeps
    // every column and so covers this one automatically; this is the named assertion
    // for the column 0093 introduces.
    assert!(
        !role_has_column_privilege(pool, "ironauth_app", "org_roles", "is_default", "UPDATE").await,
        "the data plane must NOT hold UPDATE on org_roles.is_default"
    );
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "org_roles", "SELECT").await,
        "the data plane keeps the SELECT the token-issuance resolution reads this \
         column through"
    );
}

/// The per-audience PERMISSION-CLAIM opt-in: the column, and the one column-scoped
/// grant without which a config promotion of a resource server fails 42501 (issue
/// #98, migration 0094).
///
/// Its own test rather than more lines in the production-chain assertions, for the
/// reason the 0090 and 0093 tests record.
#[tokio::test]
async fn resource_servers_carries_the_permission_claim_opt_in_and_its_column_grant() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // EXPAND: one additive column with a NOT NULL DEFAULT (which Postgres applies
    // without rewriting the table) and one new grant.
    let phase: String = sqlx::query("SELECT phase FROM _schema_migrations WHERE version = 94")
        .fetch_one(pool)
        .await
        .expect("0094 is in the ledger")
        .get("phase");
    assert_eq!(phase, "expand");

    assert!(
        column_exists(pool, "resource_servers", "permission_claims_enabled").await,
        "resource_servers.permission_claims_enabled exists after 0094"
    );
    assert_eq!(
        column_data_type(pool, "resource_servers", "permission_claims_enabled").await,
        "boolean",
        "the opt-in is a boolean on the row the mint already reads by audience"
    );
    // NOT NULL with a false DEFAULT, so every row that existed before 0094 reads
    // false and no backfill is needed. A nullable column would make "opted out" and
    // "never decided" two states where the mint treats them as one.
    assert!(
        column_is_not_null(pool, "resource_servers", "permission_claims_enabled").await,
        "resource_servers.permission_claims_enabled must be NOT NULL"
    );
    assert_eq!(
        column_default(pool, "resource_servers", "permission_claims_enabled").await,
        Some("false".to_owned()),
        "the safe default is false: a registered audience is opted OUT until an \
         operator says otherwise"
    );

    // THE grant this migration exists for. 0035's UPDATE on this table is
    // COLUMN-scoped, so without this the promotion engine's Update arm, which names
    // every promotable column in one SET list, is refused with SQLSTATE 42501.
    // `the_promotion_apply_fails_42501_without_the_permission_claims_grant` in
    // tests/config_promotion.rs revokes it and measures that failure end to end;
    // this is the static half.
    assert!(
        role_has_column_privilege(
            pool,
            "ironauth_control",
            "resource_servers",
            "permission_claims_enabled",
            "UPDATE"
        )
        .await,
        "ironauth_control must hold column-scoped UPDATE on \
         resource_servers.permission_claims_enabled"
    );
    // ADDITIVE to 0035: Postgres unions column grants, so a re-GRANT that REPLACED
    // them would leave these two unwritable and break the promotion of a format or a
    // lifetime while the new column worked.
    for column in ["token_format", "access_token_ttl_secs"] {
        assert!(
            role_has_column_privilege(
                pool,
                "ironauth_control",
                "resource_servers",
                column,
                "UPDATE"
            )
            .await,
            "0035's column-scoped UPDATE on resource_servers.{column} must survive 0094"
        );
    }
    // Every ADDRESSING column stays immutable by GRANT. A control plane able to
    // rewrite an `audience` could silently repoint which protected API a live token
    // targets, and one able to rewrite `tenant_id` could move a row across the
    // isolation fence the policy enforces.
    for column in ["id", "tenant_id", "environment_id", "audience"] {
        assert!(
            !role_has_column_privilege(
                pool,
                "ironauth_control",
                "resource_servers",
                column,
                "UPDATE"
            )
            .await,
            "resource_servers.{column} must still be immutable by GRANT after 0094"
        );
    }

    // The DATA plane gains NOTHING. It READS this flag on the token-issuance path,
    // and a data plane able to SET it is a data plane able to widen its own token.
    assert!(
        !role_has_column_privilege(
            pool,
            "ironauth_app",
            "resource_servers",
            "permission_claims_enabled",
            "UPDATE"
        )
        .await,
        "the data plane must NOT hold UPDATE on resource_servers.permission_claims_enabled"
    );
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "resource_servers", "SELECT").await,
        "the data plane keeps the SELECT the mint reads this column through"
    );
}

/// The permission-budget dimensions on the token size event sink: five nullable columns,
/// and the GRANT that did NOT have to be written (issue #98, migration 0095).
///
/// Its own test rather than more lines in the production-chain assertions, for the
/// reason the 0090, 0093, and 0094 tests record.
#[tokio::test]
async fn token_size_events_carries_the_budget_columns_under_the_existing_grants() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // EXPAND: five additive nullable columns, which Postgres adds without rewriting the
    // table, and no grant, no CHECK edit, and no backfill.
    let phase: String = sqlx::query("SELECT phase FROM _schema_migrations WHERE version = 95")
        .fetch_one(pool)
        .await
        .expect("0095 is in the ledger")
        .get("phase");
    assert_eq!(phase, "expand");

    for (column, data_type) in [
        ("reason", "text"),
        ("audience", "text"),
        ("organization_id", "text"),
        ("permission_count", "bigint"),
        ("permission_status", "text"),
    ] {
        assert!(
            column_exists(pool, "token_size_events", column).await,
            "token_size_events.{column} exists after 0095"
        );
        assert_eq!(
            column_data_type(pool, "token_size_events", column).await,
            data_type,
            "token_size_events.{column} is a {data_type}"
        );
        // NULLABLE and DEFAULT-less, deliberately. The ID-token bloat event that has
        // written this table since 0073 has no permission budget to report, so NULL means
        // "not a permission budget event" and there is no value that would be true of the
        // rows already there. A NOT NULL column would have needed a backfill inventing one.
        assert!(
            !column_is_not_null(pool, "token_size_events", column).await,
            "token_size_events.{column} must be nullable (a bloat event has no budget)"
        );
        assert_eq!(
            column_default(pool, "token_size_events", column).await,
            None,
            "token_size_events.{column} carries no DEFAULT"
        );
    }

    // THE POINT OF THIS TEST. 0095 writes no GRANT, and this is why it does not have to:
    // 0073's `GRANT SELECT, INSERT, DELETE ON token_size_events TO ironauth_app` is
    // TABLE-wide, and a table-wide grant covers columns added afterwards, so the data
    // plane's INSERT may name all five with no further grant.
    //
    // Contrast 0094, which DID need one: 0035 had granted the control role a
    // COLUMN-SCOPED `UPDATE (token_format, access_token_ttl_secs)` on `resource_servers`,
    // and a column-scoped grant enumerates columns, so the column it added was invisible
    // to it. The rule is a property of the grants already written, never of the column.
    for column in [
        "reason",
        "audience",
        "organization_id",
        "permission_count",
        "permission_status",
    ] {
        assert!(
            role_has_column_privilege(pool, "ironauth_app", "token_size_events", column, "INSERT")
                .await,
            "0073's TABLE-wide INSERT must already cover token_size_events.{column}, which is \
             why 0095 needs no column-scoped grant of its own"
        );
        assert!(
            role_has_column_privilege(
                pool,
                "ironauth_control",
                "token_size_events",
                column,
                "SELECT"
            )
            .await,
            "0073's TABLE-wide SELECT must already cover token_size_events.{column} for the \
             management warnings read"
        );
    }

    // The sink stays APPEND ONLY: nobody holds UPDATE on it in any shape, so no plane can
    // rewrite a recorded withholding. `has_table_privilege` cannot see a column-scoped
    // grant, so the sweep over live columns is the only probe that proves this.
    for role in ["ironauth_app", "ironauth_control"] {
        assert!(
            !role_has_table_privilege(pool, role, "token_size_events", "UPDATE").await
                && !role_has_any_column_privilege(pool, role, "token_size_events", "UPDATE").await,
            "{role} must hold no UPDATE of any shape on the append-only token_size_events"
        );
    }

    // And the 0073 CHECK that admits the access-token event 0095 exists to serve is
    // UNCHANGED: recording an access-token size event needed no constraint edit.
    assert!(
        check_constraint_exists(pool, "token_size_events", "token_size_events_type_known").await,
        "the 0073 token_type CHECK is untouched by 0095"
    );
    let admits_access_token: bool = sqlx::query(
        "SELECT pg_get_constraintdef(oid) LIKE '%access_token%' AS admits \
         FROM pg_constraint WHERE conname = 'token_size_events_type_known'",
    )
    .fetch_one(pool)
    .await
    .expect("read the token_type CHECK")
    .get("admits");
    assert!(
        admits_access_token,
        "the 0073 CHECK already admits 'access_token', which is why 0095 edits no CHECK"
    );

    // `reason` deliberately carries NO CHECK: the closed set lives in Rust
    // (`TokenSizeReason`, round-trip tested), and the only consumer is an advisory read
    // that skips a value it cannot parse, so a future variant must not cost a migration.
    for column in ["reason", "permission_status"] {
        let vocabulary_checks: i64 = sqlx::query(
            "SELECT count(*) AS n FROM pg_constraint c \
             JOIN pg_class t ON t.oid = c.conrelid \
             WHERE t.relname = 'token_size_events' AND c.contype = 'c' \
             AND pg_get_constraintdef(c.oid) LIKE '%' || $1 || '%'",
        )
        .bind(column)
        .fetch_one(pool)
        .await
        .expect("count vocabulary CHECKs")
        .get("n");
        assert_eq!(
            vocabulary_checks, 0,
            "the {column} vocabulary is pinned in Rust, not by a CHECK"
        );
    }
}

/// The per-client SCOPE allowlist: the column, and the one column-scoped grant
/// without which the management setter fails 42501 (issue #98, migration 0096).
///
/// Its own test rather than more lines in the production-chain assertions, for the
/// reason the 0090, 0093, and 0094 tests record.
#[tokio::test]
async fn clients_carries_the_scope_allowlist_and_its_control_column_grant() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // EXPAND: one additive nullable column, which Postgres adds without rewriting the
    // table, and one new grant.
    let phase: String = sqlx::query("SELECT phase FROM _schema_migrations WHERE version = 96")
        .fetch_one(pool)
        .await
        .expect("0096 is in the ledger")
        .get("phase");
    assert_eq!(phase, "expand");

    assert!(
        column_exists(pool, "clients", "allowed_scopes").await,
        "clients.allowed_scopes exists after 0096"
    );
    assert_eq!(
        column_data_type(pool, "clients", "allowed_scopes").await,
        "jsonb",
        "the allowlist is jsonb, so Postgres refuses a value that is not JSON at all"
    );
    // NULLABLE and DEFAULT-less. NULL is a MEANINGFUL state here ("no allowlist
    // configured"), which is exactly what every client registered before 0096 must
    // read as, so there is no default to apply and nothing to backfill. Contrast
    // 0094, whose boolean needed a NOT NULL DEFAULT precisely because it had no
    // meaningful third state.
    assert!(
        !column_is_not_null(pool, "clients", "allowed_scopes").await,
        "clients.allowed_scopes must be NULLABLE: NULL is the no-allowlist state"
    );
    assert_eq!(
        column_default(pool, "clients", "allowed_scopes").await,
        None,
        "no DEFAULT: an existing client keeps the NULL no-allowlist reading"
    );

    // THE grant this migration exists for. Every UPDATE grant `clients` carries for
    // the control role is COLUMN-scoped (0018's quarantined/verified_at, 0076's
    // first_party) and there has never been a table-wide one, so a column added later
    // is invisible to all of them.
    // `the_control_column_grant_is_load_bearing_for_allowed_scopes` in
    // tests/repository.rs revokes this and measures the 42501 end to end; this is the
    // static half.
    assert!(
        role_has_column_privilege(
            pool,
            "ironauth_control",
            "clients",
            "allowed_scopes",
            "UPDATE"
        )
        .await,
        "ironauth_control must hold column-scoped UPDATE on clients.allowed_scopes"
    );
    // ADDITIVE to 0018 and 0076: Postgres unions column grants, so a re-GRANT that
    // REPLACED them would leave the quarantine lift and the first-party
    // classification unwritable while the new column worked.
    for column in ["quarantined", "verified_at", "first_party"] {
        assert!(
            role_has_column_privilege(pool, "ironauth_control", "clients", column, "UPDATE").await,
            "the earlier column-scoped UPDATE on clients.{column} must survive 0096"
        );
    }
    // Every ADDRESSING column stays immutable by GRANT for the control role: one able
    // to rewrite `tenant_id` could move a client across the isolation fence.
    for column in ["id", "tenant_id", "environment_id", "secret_hash"] {
        assert!(
            !role_has_column_privilege(pool, "ironauth_control", "clients", column, "UPDATE").await,
            "clients.{column} must still be immutable by GRANT for the control role"
        );
    }

    // The DATA plane gains NOTHING, and this is the deliberate divergence from the
    // twin: 0019 granted `UPDATE (allowed_resources)` to ironauth_app, and 0096 grants
    // the scope allowlist to the control role alone. A data plane able to widen the
    // set of scopes the machine token it is about to mint may carry defeats the point
    // of having an allowlist.
    assert!(
        !role_has_column_privilege(pool, "ironauth_app", "clients", "allowed_scopes", "UPDATE")
            .await,
        "the data plane must NOT hold UPDATE on clients.allowed_scopes"
    );
    // It keeps the SELECT the machine-grant paths read the allowlist through. 0018
    // narrowed only UPDATE, so the table-wide SELECT 0001 granted still covers a
    // column added later.
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "clients", "SELECT").await,
        "the data plane keeps the SELECT the mint reads this column through"
    );
    assert!(
        role_has_table_privilege(pool, "ironauth_control", "clients", "SELECT").await,
        "the control plane keeps the SELECT the management read-back needs"
    );
    // And neither role gained a TABLE-wide UPDATE, which is the failure mode 0018's
    // header calls out by name.
    assert!(
        !role_has_table_privilege(pool, "ironauth_control", "clients", "UPDATE").await,
        "0096 must not widen the control role to a table-wide UPDATE on clients"
    );
    assert!(
        !role_has_table_privilege(pool, "ironauth_app", "clients", "UPDATE").await,
        "0096 must not widen the data role to a table-wide UPDATE on clients"
    );
}

/// 0098 names the two relations the management plane reached with no privilege at
/// all, and the two withholdings are the least-privilege statement it makes.
///
/// `live_surface.rs` pins all of this behaviourally, which is the stronger proof
/// because it drives the real role over the real routes. This test exists anyway,
/// for a reason worth stating: a behavioural test goes red for many causes, and a
/// reader who sees it fail cannot tell a lost grant from a broken handler. These
/// assertions name the invariant directly, so the catalog and the wire have to be
/// wrong together before the invariant is silently lost.
#[tokio::test]
async fn the_control_plane_holds_exactly_the_dead_surface_grants_0098_adds() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // The three abuse_bans verbs the management surface actually issues. A lift
    // resolves the row before removing it, so SELECT is not optional.
    for privilege in ["SELECT", "INSERT", "DELETE"] {
        assert!(
            role_has_table_privilege(pool, "ironauth_control", "abuse_bans", privilege).await,
            "the control plane needs {privilege} on abuse_bans; without it listBans, \
             createBan and liftBan answer an opaque server error on every deployment \
             that sets admin.control_database_url"
        );
    }

    // A ban is immutable once placed. Withholding UPDATE means a compromised control
    // path can create one (audited) or remove one (audited) and cannot retarget an
    // existing ban's subject, widen its authentication path, or extend its expiry,
    // which are precisely the edits an audit trail recording only create and lift
    // would never show.
    assert!(
        !role_has_table_privilege(pool, "ironauth_control", "abuse_bans", "UPDATE").await,
        "0098 must not grant the control plane UPDATE on abuse_bans; a ban is immutable"
    );

    // The MDS3 cache backs one management operation, a health read. The blob is the
    // FIDO metadata the passkey attestation gate evaluates against, so a plane able
    // to write it could weaken attestation for an environment by seeding a forged or
    // stale blob. The only writer is the data-plane synchronization task, which
    // verifies the signature and refuses a replayed blob number first.
    assert!(
        role_has_table_privilege(pool, "ironauth_control", "mds3_blob_cache", "SELECT").await,
        "the control plane needs SELECT on mds3_blob_cache for getMds3Health"
    );
    for privilege in ["INSERT", "UPDATE", "DELETE"] {
        assert!(
            !role_has_table_privilege(pool, "ironauth_control", "mds3_blob_cache", privilege).await,
            "0098 must not grant the control plane {privilege} on mds3_blob_cache; a plane \
             that can write the metadata blob can weaken passkey attestation"
        );
    }

    // A positive control, so a catalog lookup that answered "no" to everything could
    // not satisfy the withholdings above: the DATA plane does hold the abuse_bans
    // grants 0046 gave it.
    assert!(
        role_has_table_privilege(pool, "ironauth_app", "abuse_bans", "SELECT").await,
        "the data plane holds the abuse_bans SELECT that enforcement reads"
    );
}

/// The generic outbox table's isolation, its two partial indexes, its terminal-state
/// CHECK, and its least-privilege grants (issue #104, migration 0099).
///
/// Its own test rather than more lines in the production-chain assertions, for the reason
/// the 0090, 0093, and 0094 tests record. What it pins that the chain sweep cannot: the
/// head-of-group index the per-aggregate ordering rule depends on for its cost, and the
/// grant shape that makes a message's ROUTING immutable to the plane that drains it.
#[tokio::test]
async fn outbox_messages_carries_its_isolation_and_its_structural_state_constraints() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // EXPAND: one new table, two new indexes, one policy, two grants. Nothing existing is
    // altered and no data is moved, which is what makes it safe for an old binary still
    // writing the table this consumer moved off.
    let phase: String = sqlx::query("SELECT phase FROM _schema_migrations WHERE version = 99")
        .fetch_one(pool)
        .await
        .expect("0099 is in the ledger")
        .get("phase");
    assert_eq!(phase, "expand");

    // Isolation: enabled AND forced, so the policy binds even for the table owner, plus
    // the (tenant, environment) policy and the nonempty-scope CHECK every scoped table
    // carries.
    assert!(
        rls_enabled_and_forced(pool, "outbox_messages").await,
        "outbox_messages must have row-level security ENABLED and FORCED"
    );
    assert!(
        policy_exists(pool, "outbox_messages", "outbox_messages_tenant_isolation").await,
        "outbox_messages carries its (tenant, environment) isolation policy"
    );
    assert!(
        check_constraint_exists(pool, "outbox_messages", "outbox_messages_scope_nonempty").await,
        "outbox_messages carries the nonempty-scope CHECK"
    );
    // An empty consumer would be claimable by no registered drain and would sit in the
    // queue forever; an empty ordering key would collapse a consumer's whole queue into
    // one ordering group and serialize it.
    assert!(
        check_constraint_exists(pool, "outbox_messages", "outbox_messages_routing_nonempty").await,
        "outbox_messages refuses an empty consumer, idempotency key, or ordering key"
    );
    // The two terminal markers are mutually exclusive. Without this a row could read as
    // completed AND dead-lettered at once, and the "not terminal" predicate the claim and
    // the head-of-group rule SHARE would be satisfied by neither reading.
    assert!(
        check_constraint_exists(
            pool,
            "outbox_messages",
            "outbox_messages_one_terminal_state"
        )
        .await,
        "a message is completed or dead-lettered, never both"
    );
    assert!(
        check_constraint_exists(
            pool,
            "outbox_messages",
            "outbox_messages_attempts_nonnegative"
        )
        .await,
        "the attempts counter cannot go negative"
    );

    // Enqueue idempotency, made structural: one message per (consumer, domain fact).
    let unique_columns = sqlx::query(
        "SELECT a.attname AS name \
         FROM pg_constraint c \
         JOIN unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true \
         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum \
         WHERE c.conrelid = 'outbox_messages'::regclass AND c.contype = 'u' \
         ORDER BY k.ord",
    )
    .fetch_all(pool)
    .await
    .expect("read the unique constraint columns")
    .iter()
    .map(|row| row.get::<String, _>("name"))
    .collect::<Vec<_>>();
    assert_eq!(
        unique_columns,
        vec![
            "tenant_id".to_owned(),
            "environment_id".to_owned(),
            "consumer".to_owned(),
            "idempotency_key".to_owned()
        ],
        "the dedup key is scoped to a consumer: two consumers may reuse one key"
    );

    // The table this consumer moved OFF is left completely intact, which is what makes
    // 0099 old-binary safe: a replica still running the previous binary keeps writing and
    // draining it without error while the rollout completes.
    assert!(
        table_exists(pool, "session_ended_events").await,
        "0099 must not drop or alter the table the session-ended consumer moved off"
    );
}

/// The generic outbox's three indexes (issue #104, migration 0099): two PARTIAL ones over
/// the live tail, and one NON-PARTIAL one over every state.
///
/// Split from the isolation test above only because the combined body outran the
/// readable-length lint. What it pins is not decoration: the head-of-group index is what
/// keeps the per-aggregate ordering rule from turning the claim into a scan of a group,
/// BOTH partial predicates have to name BOTH terminal markers or the anti-join reports a
/// retired message as a blocker, and the third index has to be non-partial or the ordered
/// all-states listing an operator reads the dead-letter tail through sorts the scope's
/// entire history on every page.
#[tokio::test]
async fn outbox_messages_carries_the_three_indexes_the_drain_the_ordering_and_the_listing_need() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // The candidate scan index: a consumer's non-terminal messages in drain order.
    assert!(
        partial_index_exists(pool, "outbox_messages", "outbox_messages_pending_idx").await,
        "the pending drain index is PARTIAL, so the working set is the live tail"
    );
    assert_eq!(
        index_columns(pool, "outbox_messages", "outbox_messages_pending_idx").await,
        vec![
            "tenant_id".to_owned(),
            "environment_id".to_owned(),
            "consumer".to_owned(),
            "sequence".to_owned()
        ],
        "the drain scans one consumer's scope in sequence order"
    );
    // THE index the per-aggregate ordering rule rests on. The claim asks, per candidate,
    // whether its group holds a non-terminal message with a lower sequence; with this
    // index that is one probe of the group's minimum. Without it the ordering guarantee
    // would still be CORRECT and would turn the claim into a scan of the group, which is
    // why the index is pinned here and not left to the planner's luck.
    assert!(
        partial_index_exists(pool, "outbox_messages", "outbox_messages_group_head_idx").await,
        "the head-of-group index is PARTIAL on the non-terminal messages"
    );
    assert_eq!(
        index_columns(pool, "outbox_messages", "outbox_messages_group_head_idx").await,
        vec![
            "tenant_id".to_owned(),
            "environment_id".to_owned(),
            "consumer".to_owned(),
            "ordering_key".to_owned(),
            "sequence".to_owned()
        ],
        "the head-of-group probe is keyed by (scope, consumer, ordering key, sequence)"
    );
    // Both predicates must name BOTH terminal markers. One that mentioned only
    // completed_at would exclude nothing dead-lettered from the index and the anti-join
    // would keep reporting a dead-lettered head as a blocker, wedging its group forever.
    for index in [
        "outbox_messages_pending_idx",
        "outbox_messages_group_head_idx",
    ] {
        let predicate = index_predicate(pool, "outbox_messages", index).await;
        assert!(
            predicate.contains("completed_at IS NULL")
                && predicate.contains("dead_lettered_at IS NULL"),
            "{index} must be partial on BOTH terminal markers, got `{predicate}`"
        );
    }

    // The third index is the one that must NOT be partial, and that is the whole reason
    // it exists: `list` returns a consumer's messages in ANY state, newest first, with a
    // limit, and the completed and dead-lettered rows it is mostly for are exactly what
    // the two partial indexes above exclude. Measured at 205k rows over 100 scopes,
    // without it that read is a bitmap scan of the scope's whole history plus a top-N
    // heapsort (2075 buffers) instead of an index scan backward (53).
    // Existence first: `index_columns` returns an empty vector for an index that is not
    // there, so this comparison is what proves the index exists at all, and the
    // not-partial check below would pass vacuously without it.
    assert_eq!(
        index_columns(pool, "outbox_messages", "outbox_messages_scope_idx").await,
        vec![
            "tenant_id".to_owned(),
            "environment_id".to_owned(),
            "consumer".to_owned(),
            "sequence".to_owned()
        ],
        "the all-states index leads with the scope the RI probe keys on and extends \
         through the consumer and the order the listing sorts by"
    );
    assert!(
        !partial_index_exists(pool, "outbox_messages", "outbox_messages_scope_idx").await,
        "the all-states scope index must NOT be partial: the readers it serves span every \
         state, and a partial index would exclude exactly the rows they are for"
    );
}

/// The generic outbox's grant shape (issue #104, migration 0099): what each plane may do
/// to a queued message, and the much longer list of what it may not.
///
/// Split from the schema test above only because the combined body outran the
/// readable-length lint; the two halves are one obligation. The grant shape is the
/// structural half of the ordering and routing guarantees: a drain that could rewrite
/// `consumer` or `ordering_key` could defeat both without touching a line of Rust.
#[tokio::test]
async fn outbox_messages_holds_its_lifecycle_only_grants_on_both_planes() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // The data plane ENQUEUEs (inside the domain transaction), READs, and mutates the six
    // lifecycle columns.
    for privilege in ["SELECT", "INSERT"] {
        assert!(
            role_has_table_privilege(pool, "ironauth_app", "outbox_messages", privilege).await,
            "the data plane needs {privilege} to enqueue and drain"
        );
    }
    for column in [
        "attempts",
        "next_attempt_at",
        "claimed_at",
        "last_error",
        "completed_at",
        "dead_lettered_at",
    ] {
        assert!(
            role_has_column_privilege(pool, "ironauth_app", "outbox_messages", column, "UPDATE")
                .await,
            "the drain must be able to write the lifecycle column {column}"
        );
    }
    // And NOTHING else. A drain that could rewrite `consumer` could hand another
    // subsystem's message to itself; one that could rewrite `ordering_key` could move a
    // message into another aggregate and jump the queue; one that could rewrite `payload`
    // could change what a consumer is asked to do after the domain write that authorized
    // it committed.
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "consumer",
        "idempotency_key",
        "ordering_key",
        "payload",
        "enqueued_at",
    ] {
        assert!(
            !role_has_column_privilege(pool, "ironauth_app", "outbox_messages", column, "UPDATE")
                .await,
            "outbox_messages.{column} must be immutable by GRANT for the data plane"
        );
    }
    assert!(
        !role_has_table_privilege(pool, "ironauth_app", "outbox_messages", "UPDATE").await,
        "0099 must not grant the data plane a table-wide UPDATE (the #31 lesson)"
    );
    assert!(
        !role_has_table_privilege(pool, "ironauth_app", "outbox_messages", "DELETE").await,
        "a drain retires a message by marking it terminal, never by deleting it. This must \
         hold AFTER 0102 as well as before it: the data plane is the role that writes \
         dead_lettered_at, so DELETE here would let ONE role give up on a message and then \
         erase the record of having given up"
    );

    // The control plane can enqueue (its own domain writes must be able to emit a message
    // in their own transaction) and read (queue depth, the dead-letter tail), and it does
    // not drain, so it holds no UPDATE of any shape and cannot retire another plane's
    // message or extend a lease.
    for privilege in ["SELECT", "INSERT"] {
        assert!(
            role_has_table_privilege(pool, "ironauth_control", "outbox_messages", privilege).await,
            "the control plane needs {privilege} on outbox_messages"
        );
    }
    assert!(
        !role_has_any_column_privilege(pool, "ironauth_control", "outbox_messages", "UPDATE").await,
        "the control plane does not drain, so it holds no UPDATE on outbox_messages: this \
         is what makes it safe for it to hold DELETE, because a role that can retire a row \
         can never have been the role that marked it terminal"
    );
    // DELETE is the ONE grant this shape gained after 0099, in 0102, and it went to the
    // control plane alone. Its POSITIVE half is asserted in
    // `outbox_retention_delete_is_the_control_planes_alone_and_is_bound_by_scope` below,
    // which also measures what bounds it. Nothing about it is repeated here: the assertion
    // that the data plane still holds no DELETE is the one already made above, beside the
    // rest of that role's shape, and a second copy of it here would look like new coverage
    // while guarding a predicate that is already guarded.
}

/// Migration 0102's retention grant on the generic outbox (issue #104, PR 3): the one
/// capability the table gained after 0099, and the three things that bound it.
///
/// 0099 said "no role is granted DELETE, and there is no reaper", and PR 2 multiplied the
/// table's growth by roughly `1 + N_relying_parties` per session end.
///
/// This asserts the grant landed AND that it is bounded in the two ways the migration
/// header claims, both of which are properties of the database rather than of the
/// repository: row-level security confines an in-scope delete to its own scope, and an
/// UNSCOPED delete matches zero rows rather than every row. The second is the one worth
/// measuring, because the intuitive guess about an unscoped statement under FORCE
/// row-level security is that it deletes everything.
///
/// The unscoped case here runs on a connection that has ALSO been used for scoped work, so
/// it exercises the version of it that a pooled connection actually reaches. That
/// distinction is not cosmetic: `current_setting('ironauth.tenant_id', true)` is NULL only
/// on a connection that has never bound a scope, and reads as the EMPTY STRING once a
/// transaction-local binding has committed on it. Both match no row, but for different
/// reasons: NULL because a comparison with NULL is not true, and the empty string because
/// the `outbox_messages_scope_nonempty` CHECK forbids the only row that could match it.
#[tokio::test]
async fn outbox_retention_delete_is_the_control_planes_alone_and_is_bound_by_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let other = db.seed_scope(&env).await;
    assert_ne!(
        scope, other,
        "the isolation half of this test needs two distinct scopes"
    );

    assert!(
        role_has_table_privilege(
            db.owner_pool(),
            "ironauth_control",
            "outbox_messages",
            "DELETE"
        )
        .await,
        "0102 must grant the control plane DELETE on outbox_messages: without it nothing \
         in the system can remove a retired message and the table grows forever"
    );

    // A COMPLETED message in each scope, enqueued and retired through the real repository
    // as the data plane, so the rows under test are rows the production path wrote.
    for target in [scope, other] {
        seed_retired_outbox_message(&db, &env, target).await;
    }

    // ONE connection for all three control-plane steps, taken out of the pool explicitly.
    // The point of (3) is what the SAME connection does after a scoped transaction has run
    // on it, and a pool is free to hand back a different connection each time.
    let control = db.control_pool();
    let mut conn = control
        .acquire()
        .await
        .expect("take one control connection");
    let who: String = sqlx::query("SELECT current_user AS u")
        .fetch_one(&mut *conn)
        .await
        .expect("identify session role")
        .get("u");
    assert_eq!(
        who, "ironauth_control",
        "the delete under test must run as the low-privilege control role"
    );

    // (1) An UNSCOPED delete on a VIRGIN connection, exactly as a reaper that forgot to
    // bind its scope would issue it. Zero rows, not two.
    assert_eq!(
        bound_tenant(&mut conn).await,
        None,
        "a connection that has never bound a scope reports NULL, which is the case the \
         NULL-comparison argument covers"
    );
    assert_eq!(
        unscoped_retention_delete(&mut conn).await,
        0,
        "a DELETE with no scope bound must affect ZERO rows: the policy's USING compares \
         each row against current_setting(...), which is NULL here"
    );

    // (2) The SAME delete inside a scoped transaction removes that scope's row and only
    // that scope's row.
    {
        let mut tx = sqlx::Connection::begin(&mut *conn)
            .await
            .expect("begin scoped delete");
        bind_scope(
            &mut tx,
            &scope.tenant().to_string(),
            &scope.environment().to_string(),
        )
        .await;
        let removed = sqlx::query("DELETE FROM outbox_messages WHERE completed_at IS NOT NULL")
            .execute(&mut *tx)
            .await
            .expect("the control role may delete a retired message in its own scope")
            .rows_affected();
        assert_eq!(removed, 1, "the in-scope completed row is removed");
        tx.commit().await.expect("commit scoped delete");
    }

    // (3) The same unscoped delete AGAIN, on the same connection, now that a
    // transaction-local binding has committed on it. This is the state a pooled connection
    // is actually in, and the NULL argument no longer describes it: the setting reads as
    // the EMPTY STRING. It must still remove nothing, and what refuses it now is the
    // `outbox_messages_scope_nonempty` CHECK, because no row can carry an empty tenant.
    assert_eq!(
        bound_tenant(&mut conn).await.as_deref(),
        Some(""),
        "a transaction-local binding reverts to the EMPTY STRING rather than to NULL, which \
         is why the fail-closed argument cannot rest on NULL alone"
    );
    assert_eq!(
        unscoped_retention_delete(&mut conn).await,
        0,
        "an unscoped delete on a REUSED connection must still remove nothing: the CHECK \
         forbids the only row an empty-string scope could match"
    );
    drop(conn);

    assert_eq!(
        db.store()
            .scoped(other)
            .outbox()
            .list("retention_probe", 10)
            .await
            .expect("list the other scope")
            .len(),
        1,
        "another scope's retired message is untouched: row-level security, not the \
         statement's WHERE clause, is what confines the delete"
    );
}

/// The other half of 0102's grant: the DATA plane is still refused DELETE outright, by
/// GRANT, before any policy runs (issue #104, PR 3).
///
/// A separate test from the one above only because the combined body outran the
/// readable-length lint; the two are one obligation. `ironauth_app` holds the column-scoped
/// UPDATE that writes `dead_lettered_at`, so a data plane with DELETE could give up on a
/// message and then erase the record of having given up, and 0102 must not have widened
/// anything on that role.
#[tokio::test]
async fn outbox_retention_leaves_the_data_plane_refused_delete_by_grant() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    seed_retired_outbox_message(&db, &env, scope).await;

    let mut tx = db.app_pool().begin().await.expect("begin app delete");
    bind_scope(
        &mut tx,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    )
    .await;
    let refused = sqlx::query("DELETE FROM outbox_messages WHERE completed_at IS NOT NULL")
        .execute(&mut *tx)
        .await;
    assert!(
        refused
            .as_ref()
            .err()
            .and_then(sqlx::Error::as_database_error)
            .and_then(sqlx::error::DatabaseError::code)
            .is_some_and(|code| code == "42501"),
        "the data plane must be refused DELETE as insufficient privilege, in the scope it \
         legitimately holds every other grant on: {refused:?}"
    );
    let _ = tx.rollback().await;
}

/// What `current_setting('ironauth.tenant_id', true)` reads as on `conn` right now.
///
/// The three values it can take are the whole of the fail-closed argument: NULL on a
/// connection that never bound a scope, the bound tenant inside a scoped transaction, and
/// the EMPTY STRING on the same connection once that transaction has committed.
async fn bound_tenant(conn: &mut sqlx::PgConnection) -> Option<String> {
    sqlx::query("SELECT current_setting('ironauth.tenant_id', true) AS t")
        .fetch_one(&mut *conn)
        .await
        .expect("read the bound tenant setting")
        .get("t")
}

/// Issue the reaper's DELETE with NO scope bound on `conn`, returning the rows removed.
/// This is exactly what a reaper that forgot to bind its scope would send.
async fn unscoped_retention_delete(conn: &mut sqlx::PgConnection) -> u64 {
    sqlx::query("DELETE FROM outbox_messages WHERE completed_at IS NOT NULL")
        .execute(&mut *conn)
        .await
        .expect("an unscoped delete is permitted by GRANT and matched by no policy row")
        .rows_affected()
}

/// Enqueue one message in `scope` and retire it, through the real repository as the DATA
/// plane, so what the retention test deletes is a row the production path wrote.
async fn seed_retired_outbox_message(db: &TestDatabase, env: &Env, scope: ironauth_store::Scope) {
    let store = db.store();
    let scoped = store.scoped(scope);
    let queue = scoped.outbox();
    queue
        .enqueue(
            env,
            &NewOutboxMessage {
                consumer: "retention_probe",
                idempotency_key: "fact",
                ordering_key: "fact",
                payload: serde_json::json!({}),
            },
        )
        .await
        .expect("enqueue");
    let claimed = queue
        .claim(env, "retention_probe", Duration::from_secs(60), 10)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1, "one message to retire");
    assert!(
        queue
            .complete(env, &claimed[0])
            .await
            .expect("complete the message"),
        "the lease is still ours, so the completion lands"
    );
}

/// Bind the transaction-local row-level-security scope variables, exactly as the repository
/// does. Mirrors the helper in `tests/append_only.rs`.
async fn bind_scope(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    environment: &str,
) {
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(tenant)
        .execute(&mut **tx)
        .await
        .expect("bind tenant scope");
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(environment)
        .execute(&mut **tx)
        .await
        .expect("bind environment scope");
}

/// Migration 0101's control-plane write grants on the migration-run ledger (issue #55).
///
/// Its own test rather than more lines in the production-chain sweep, following the
/// 0100 precedent, so a failure names this grant. BOTH directions matter and both are
/// load bearing here: the control plane must be able to DRIVE a bulk-import run
/// (0043 granted it SELECT alone, which made the whole import surface answer 500), and
/// it must be able to do exactly that and no more. The withheld privileges are the
/// reason the abandon route had to exist: with no `UPDATE (source_total)`, no `UPDATE`
/// on the ledger rows, and no `DELETE`, a run whose invariants cannot be satisfied has
/// exactly one legal exit, and it is the audited one.
#[tokio::test]
async fn the_control_plane_can_drive_a_migration_run_and_nothing_else() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    for table in ["migration_runs", "migration_run_records"] {
        for privilege in ["SELECT", "INSERT"] {
            assert!(
                role_has_table_privilege(pool, "ironauth_control", table, privilege).await,
                "the control plane needs {privilege} on {table} to create a run and account \
                 its records"
            );
        }
        assert!(
            !role_has_table_privilege(pool, "ironauth_control", table, "DELETE").await,
            "the ledger is append-only: nothing on this plane deletes a {table} row"
        );
    }

    // The UPDATE on `migration_runs` is COLUMN SCOPED, which is what keeps a run's
    // declared ground truth out of reach. `has_table_privilege` does not see a
    // column-scoped grant, so the table-wide probe must read FALSE while the three named
    // columns read true.
    assert!(
        !role_has_table_privilege(pool, "ironauth_control", "migration_runs", "UPDATE").await,
        "the control plane must hold NO table-wide UPDATE on migration_runs (the #31 \
         lesson): a future column would silently fall under it"
    );
    // A lifecycle transition writes state and updated_at; an abandonment writes those and
    // the reason. That is the whole of what this plane changes on a run.
    for column in ["state", "updated_at", "abandoned_reason"] {
        assert!(
            role_has_column_privilege(pool, "ironauth_control", "migration_runs", column, "UPDATE")
                .await,
            "a transition or an abandonment writes {column}, so the control plane needs it"
        );
    }
    // And the run's DECLARED GROUND TRUTH is not writable after creation. This is the
    // fence that makes the count invariant mean something: a run that cannot reconcile
    // cannot be made to reconcile by moving the target.
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "kind",
        "source_total",
        "backfill_expected",
        "subject_ref",
        "created_at",
    ] {
        assert!(
            !role_has_column_privilege(
                pool,
                "ironauth_control",
                "migration_runs",
                column,
                "UPDATE"
            )
            .await,
            "the control plane must not be able to rewrite {column} on migration_runs"
        );
    }
    // The reconciliation columns belong to the data plane's triage and backfill passes.
    // The import job only ever INSERTS its accounting.
    assert!(
        !role_has_any_column_privilege(pool, "ironauth_control", "migration_run_records", "UPDATE")
            .await,
        "the control plane does not reconcile, so it holds no UPDATE of any shape on \
         migration_run_records"
    );
}

/// Assert a statement was refused with the PostgreSQL insufficient-privilege error
/// (SQLSTATE 42501), the signal that a column-level grant blocked the write.
fn assert_permission_denied(
    result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>,
    what: &str,
) {
    match result {
        Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("42501") => {}
        other => panic!("expected permission denied (42501) for `{what}`, got: {other:?}"),
    }
}

#[tokio::test]
async fn the_consume_latches_grant_the_data_plane_only_their_consumption_stamp() {
    // Issue #218, the #31 lesson applied to five more tables. A table-wide `GRANT UPDATE`
    // let ironauth_app rewrite ANY column of these tables, including the immutable ones
    // that carry the lineage the rest of the system trusts. Migration 0106 revokes it and
    // re-grants exactly the consumption stamp.
    //
    // The positive half of every one of these grants is already exercised by the suites
    // that consume codes, PAR requests, nonces and login states; if the re-grant were too
    // NARROW those suites would fail with 42501. What nothing else can catch is the grant
    // being too WIDE, because no test tries a write it is not supposed to make. So this
    // drives the refusals directly.
    let db = TestDatabase::start().await;

    // An immutable column on each of the four latches, plus `signing_keys`, which keeps NO
    // update grant at all: nothing in the workspace issues `UPDATE signing_keys`, and a
    // standing capability with no caller is the same thing the #31 lesson objects to.
    //
    // Each probe runs in its OWN transaction. A privilege refusal ABORTS the transaction it
    // happened in, so sharing one makes every probe after the first report 25P02
    // (transaction aborted) instead of the 42501 being measured, and four of the five would
    // then be passing on the wrong error. Measured: that is exactly what the first draft of
    // this test did.
    //
    // No rows need exist: PostgreSQL checks column privileges before it evaluates the
    // predicate, so the refusal is about the GRANT and nothing else.
    for (table, column) in [
        ("authorization_codes", "subject"),
        ("pushed_authorization_requests", "request_params"),
        ("fedcm_assertion_nonces", "nonce"),
        ("federation_login_states", "code_verifier_sealed"),
        ("signing_keys", "key_material"),
    ] {
        let mut tx = db.app_pool().begin().await.expect("begin as the app role");
        let result = sqlx::query(&format!("UPDATE {table} SET {column} = 'forged'"))
            .execute(&mut *tx)
            .await;
        assert_permission_denied(result, &format!("{table}.{column}"));
    }
}

#[tokio::test]
async fn the_data_plane_holds_no_table_wide_update_on_any_table() {
    // Issue #218's actual acceptance, asked of the CATALOG rather than of the migrations.
    // 0018 narrowed `clients`, 0106 the consume latches and 0107 the rest; this asserts the
    // property those three were for, so a future migration that hands ironauth_app a
    // table-wide UPDATE fails here rather than being noticed in a later audit.
    //
    // A table-wide grant appears in `information_schema` as an UPDATE privilege on the
    // TABLE with no matching per-column rows, which is exactly what this looks for.
    let db = TestDatabase::start().await;
    // `information_schema.table_privileges` records a TABLE-wide grant and nothing else: a
    // column-scoped `GRANT UPDATE (col)` does not appear there, it appears only in
    // `column_privileges`. So the presence of a row here IS the defect.
    //
    // The first draft of this query also excluded tables that had any column-level UPDATE
    // row, on the assumption those two catalogs were disjoint. They are not: Postgres
    // expands a table-wide grant into per-column rows as well, so that clause matched every
    // table and the assertion could never fail. Measured, not reasoned about: with the 0107
    // statements removed the query returned nothing while the refusal test below went red.
    let offenders: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.table_privileges \
         WHERE grantee = 'ironauth_app' AND privilege_type = 'UPDATE' \
           AND table_schema = 'public' \
         ORDER BY table_name",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("read the privilege catalog");
    assert!(
        offenders.is_empty(),
        "these tables still grant ironauth_app a TABLE-WIDE UPDATE, which the #31 lesson \
         forbids: {offenders:?}"
    );
}

#[tokio::test]
async fn the_remaining_tables_grant_the_data_plane_only_their_mutable_columns() {
    // Issue #218 second tranche. Same reasoning as the consume-latch test above: the
    // POSITIVE half of each grant is already exercised by the suites that revoke grants,
    // rotate refresh tokens, count DCR registrations, set step-up policies and advance
    // flows, so a re-grant that is too NARROW fails those with 42501. Nothing existing
    // catches a grant that is too WIDE, so the refusals are driven here.
    //
    // One transaction per probe: a privilege refusal aborts its transaction, so sharing one
    // would make every probe after the first report 25P02 instead of the 42501 measured.
    let db = TestDatabase::start().await;
    for (table, column) in [
        // The data plane never updates an organization at all: control-plane only.
        ("organizations", "state"),
        ("grants", "subject"),
        ("refresh_families", "client_id"),
        ("refresh_tokens", "token_digest"),
        ("dcr_rate_counters", "rate_key"),
        ("scope_step_up_policies", "scope"),
        ("flows", "journey"),
    ] {
        let mut tx = db.app_pool().begin().await.expect("begin as the app role");
        let result = sqlx::query(&format!("UPDATE {table} SET {column} = 'forged'"))
            .execute(&mut *tx)
            .await;
        assert_permission_denied(result, &format!("{table}.{column}"));
    }
}

#[tokio::test]
async fn the_retired_queues_grant_the_data_plane_nothing_at_all() {
    // Issue #218, applied to INSERT and DELETE. `session_ended_events` and
    // `backchannel_logout_deliveries` were each a dedicated queue until #104 moved delivery
    // onto the generic outbox, and no statement in the workspace has named either table
    // since. 0108 revokes every data-plane privilege on both, so what is asserted here is
    // the ABSENCE of a standing capability, which is the form of the #31 lesson that a
    // column-scoping sweep cannot reach.
    //
    // The UPDATE probes are the discriminating ones. Their grants were COLUMN scoped, and a
    // table-level REVOKE does not remove a per-column grant, so a migration that revoked
    // only `UPDATE ON <table>` would leave these two writable and every other probe here
    // would still pass. One transaction per probe, because a refusal aborts its own.
    let db = TestDatabase::start().await;
    for statement in [
        "SELECT id FROM session_ended_events",
        "INSERT INTO session_ended_events (id) VALUES (gen_random_uuid())",
        "UPDATE session_ended_events SET delivered_at = now()",
        "SELECT id FROM backchannel_logout_deliveries",
        "INSERT INTO backchannel_logout_deliveries (id) VALUES (gen_random_uuid())",
        "UPDATE backchannel_logout_deliveries SET delivered_at = now()",
    ] {
        let mut tx = db.app_pool().begin().await.expect("begin as the app role");
        let result = sqlx::query(statement).execute(&mut *tx).await;
        assert_permission_denied(result, statement);
    }
}

#[tokio::test]
async fn the_data_plane_can_delete_only_where_a_caller_deletes() {
    // The completeness half, asked of the CATALOG. Four tables carried a DELETE grant that
    // no `DELETE FROM` in the workspace ever used; 0108 revokes those four, and this pins
    // the exact set that remains so a future migration handing ironauth_app a DELETE has to
    // come here and say which caller needs it.
    //
    // A pinned set rather than a count: a count moves for two different reasons and cannot
    // tell them apart, and the failure it produces names no table.
    let db = TestDatabase::start().await;
    // DISTINCT because `table_privileges` carries one row per GRANTOR: the same privilege
    // granted by two roles appears twice and would fail this on a difference that is not a
    // privilege difference. The 0107 query above needs no such guard, since it asserts the
    // result is EMPTY and a duplicate cannot make an empty set non-empty.
    let permitted: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT table_name::text FROM information_schema.table_privileges \
         WHERE grantee = 'ironauth_app' AND privilege_type = 'DELETE' \
           AND table_schema = 'public' \
         ORDER BY table_name",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("read the privilege catalog");
    let expected = [
        "aaguid_rules",
        "abuse_bans",
        "account_credentials",
        "account_links",
        "client_assertion_jtis",
        "client_auth_diagnostics",
        "clients",
        "credential_class_policies",
        "dpop_proof_replay",
        "email_otp_codes",
        "environment_secrets",
        "environment_variables",
        "external_assertion_jtis",
        "magic_link_tokens",
        "policy_decision_traces",
        "pow_challenges",
        "recovery_codes",
        "scope_step_up_policies",
        "sms_country_allowlist",
        "sms_otp_codes",
        "token_size_events",
        "totp_credentials",
        "user_trait_login_index",
        "webauthn_credentials",
    ];
    assert_eq!(
        permitted, expected,
        "the set of tables the data plane may DELETE from changed; if the new grant has a \
         real caller, name it in the migration and add the table here"
    );
}

#[tokio::test]
async fn the_four_reaperless_tables_refuse_a_data_plane_delete() {
    // The other direction of the same change, driven directly rather than read from the
    // catalog: nothing existing attempts these deletes, so nothing existing would notice
    // the grant coming back. One transaction per probe.
    let db = TestDatabase::start().await;
    for table in [
        "sms_config",
        "sms_route_stats",
        "trusted_devices",
        "webauthn_challenges",
    ] {
        let mut tx = db.app_pool().begin().await.expect("begin as the app role");
        let result = sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&mut *tx)
            .await;
        assert_permission_denied(result, table);
    }
}

/// 0153 grants the control plane exactly what the workload-federation surface needs.
///
/// The migration makes two security claims in prose and, before this test, nothing measured
/// either: that UPDATE is narrowed to `enabled` so an operator cannot silently repoint an
/// anchor at a different JWKS while every listing still shows the issuer they expect, and that
/// the DATA plane gains nothing. A later `GRANT UPDATE ON external_assertion_issuers TO
/// ironauth_control` would satisfy every other test in the tree, including the whole-surface
/// live sweep, while handing the control path exactly the edit the narrowing exists to prevent.
///
/// DELETE is asserted PRESENT, which is the half a reader is most likely to think is a mistake.
/// It is what makes a mis-registration correctable: both unique constraints ignore `enabled`,
/// so a parked row keeps its natural key and an issuer that rotated the keys behind a pinned
/// inline `jwks` could otherwise never be repointed.
#[tokio::test]
async fn the_control_plane_holds_exactly_the_federation_grants_0153_adds() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    for table in [
        "external_assertion_issuers",
        "external_assertion_subject_mappings",
    ] {
        // What the eight management routes issue. SELECT covers the two listings plus the
        // by-id reads the PATCH and DELETE handlers make internally (there is no by-id READ
        // route); INSERT the two creates; DELETE the two deletes that free the natural key.
        for privilege in ["SELECT", "INSERT", "DELETE"] {
            assert!(
                role_has_table_privilege(pool, "ironauth_control", table, privilege).await,
                "the control plane needs {privilege} on {table}; without it the issue #126 \
                 management surface answers an opaque server error on every deployment that \
                 sets admin.control_database_url"
            );
        }

        // The narrowing. Table-wide UPDATE would auto-extend to every column this table ever
        // gains, which is how the issue #31 lesson was learned the first time.
        assert!(
            !role_has_table_privilege(pool, "ironauth_control", table, "UPDATE").await,
            "0153 must not grant the control plane table-wide UPDATE on {table}"
        );
        assert!(
            role_has_column_privilege(pool, "ironauth_control", table, "enabled", "UPDATE").await,
            "the control plane needs UPDATE on {table}.enabled: revoking trust in a \
             compromised issuer is the operation an operator needs fastest"
        );

        // And NO OTHER COLUMN is writable, swept over the catalog rather than a hand-written
        // list. The first version of this test probed four columns chosen because they are
        // common to both tables, which happened to exclude every column the migration's
        // security claim is actually about: `jwks`, `jwks_uri`, `signing_alg_allow`,
        // `audience_allow`, `principal`, `external_subject`, `match_claim`, `match_value`. A
        // later `GRANT UPDATE (jwks, jwks_uri) ... TO ironauth_control` would have passed it
        // while handing the control plane exactly the in-place repoint 0153 exists to prevent,
        // and the column-scoped form is the LIKELIER regression, since it is the form 0153 and
        // 0020 both use. So this enumerates the live columns and names the ones that are
        // writable, which cannot go stale as the table grows.
        let writable = writable_columns(pool, "ironauth_control", table).await;
        assert_eq!(
            writable,
            vec!["enabled".to_owned()],
            "the control plane must hold UPDATE on {table}.enabled and on nothing else; an \
             anchor or mapping repointed in place changes who can mint tokens, or as whom, \
             while every listing still shows what an operator expects"
        );

        // The DATA plane is untouched by 0153. 0020 gave it SELECT, INSERT and UPDATE(enabled)
        // and deliberately no DELETE, because a request path must be able to park a compromised
        // anchor and never to erase one.
        assert!(
            !role_has_table_privilege(pool, "ironauth_app", table, "DELETE").await,
            "0153 must not extend DELETE on {table} to the data plane; 0020's \
             'disabled, not deleted' rule is scoped to that plane and stays true"
        );

        // Positive controls, one per HELPER the withholdings above rely on, so neither a
        // table lookup nor a column sweep answering emptily could satisfy them. The first
        // version of this test controlled only the table helper while its sharpest assertions
        // used the column one.
        assert!(
            role_has_table_privilege(pool, "ironauth_app", table, "SELECT").await,
            "the data plane holds the {table} SELECT the JWT bearer grant reads"
        );
        assert_eq!(
            writable_columns(pool, "ironauth_app", table).await,
            vec!["enabled".to_owned()],
            "the column sweep reports a real answer for the data plane too, so an empty \
             result cannot be what satisfied the control-plane assertion above"
        );
    }
}

/// THE VERSION HISTORY'S TIMESTAMP IS READ AT THE INSERT, NOT AT THE TRANSACTION'S START.
///
/// Migration 0165 spends nine lines justifying `clock_timestamp()` over `now()`: the version
/// NUMBERS are ordered by the `token_hooks` row lock, so a losing transaction gets a higher
/// number while it BEGAN earlier, and `now()` is `transaction_timestamp()`. With `now()` the
/// history publishes a higher version carrying an earlier timestamp, and
/// `created_at_unix_micros` is what an operator reads to choose a rollback target.
///
/// Nothing observed that. The only timestamp assertion in the feature is a 2020-2100 window,
/// which both functions satisfy, so the fix could be reverted with the whole suite green --
/// and a fix is the least-reviewed code in any change.
///
/// This reads the DEFAULT OFF THE REAL COLUMN and then evaluates it twice inside ONE
/// transaction. That is the discriminator and it is exact: `now()` is defined to return the
/// same value for every call in a transaction, and `clock_timestamp()` is defined not to. The
/// expression comes from the catalog rather than from a literal here, so the test cannot pass
/// against a default that is no longer the column's.
#[tokio::test]
async fn the_version_timestamp_advances_within_a_transaction() {
    let db = TestDatabase::start().await;

    let default_expression: String = sqlx::query_scalar(
        "SELECT pg_get_expr(d.adbin, d.adrelid) \
         FROM pg_attrdef d \
         JOIN pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum \
         WHERE d.adrelid = 'token_hook_versions'::regclass AND a.attname = 'created_at'",
    )
    .fetch_one(db.owner_pool())
    .await
    .expect("token_hook_versions.created_at must have a default");

    // Two evaluations of the column's own default, in one transaction, with a real pause
    // between them. `pg_sleep` rather than two adjacent calls, because two calls a microsecond
    // apart can land on the same clock tick and the difference this asserts would then be a
    // race rather than a property.
    // As an epoch float, so the test needs no date type and the comparison is a number.
    let sample = format!("SELECT EXTRACT(EPOCH FROM ({default_expression}))::float8");
    let mut tx = db.owner_pool().begin().await.expect("begin");
    let first: f64 = sqlx::query_scalar(&sample)
        .fetch_one(&mut *tx)
        .await
        .expect("first");
    sqlx::query("SELECT pg_sleep(0.05)")
        .execute(&mut *tx)
        .await
        .expect("pause");
    let second: f64 = sqlx::query_scalar(&sample)
        .fetch_one(&mut *tx)
        .await
        .expect("second");
    tx.commit().await.expect("commit");

    assert!(
        second > first,
        "`token_hook_versions.created_at` defaults to `{default_expression}`, which returned \
         the SAME instant twice in one transaction ({first} then {second}). That is `now()` \
         behaviour: it stamps when the transaction began, so the losing side of the deploy \
         race gets the higher version number and the earlier timestamp. 0165 requires \
         clock_timestamp()."
    );
}

/// EVERY COMPONENT BOUND IN THE SCHEMA ADMITS THE HOOK WE ACTUALLY SHIP.
///
/// Migration 0166 raises `token_hooks`' bound from 8 MiB because that number was measured from
/// Rust hooks, and a hook written in a scripting language carries its interpreter: the shipped
/// TypeScript sample is around 10.6 MiB, of which about four kilobytes is the author's code.
/// Under the old bound every TypeScript hook was undeployable through this product's own API.
///
/// The bound is a CHECK constraint, so it is copied wherever a component column is, and a table
/// added later that copies the old number re-introduces the defect on a new door with every
/// existing test still passing. This scans the SCHEMA rather than naming the tables it knows
/// about, which is what catches the one nobody thought to list -- `token_hook_versions` from
/// #1014 is exactly that table, and it landed carrying 0162's number.
///
/// # Why this evaluates the bound instead of reading it
///
/// The first version of this test scanned `pg_get_constraintdef` for the literal `8388608`.
/// That decides the SPELLING of a numeral, not the bound, and Postgres does not fold constants
/// in a stored constraint: measured, `octet_length(component) <= 8 * 1024 * 1024` comes back as
/// `((8 * 1024) * 1024)`, which contains no `8388608` at all. So the scan reported clean on the
/// exact spelling the Rust constant uses, and `8388608::bigint` passed only by accident.
///
/// This substitutes the real artifact's byte count into each constraint's own expression and
/// asks POSTGRES whether it holds. Spelling cannot matter to that, and the number under test is
/// the committed component's actual size rather than a copy of it.
#[tokio::test]
async fn every_component_bound_admits_the_shipped_typescript_hook() {
    // `start` runs the production chain on a fresh database, so what is scanned below is the
    // schema a real deployment gets rather than a hand-built one.
    let db = TestDatabase::start().await;

    // THE REAL ARTIFACT, by path rather than by a number written here. A constant would be a
    // copy of the thing it describes, and the two would drift the first time the sample is
    // rebuilt against a newer componentize-js.
    let sample = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ironauth-hooks/guests-ts/dist/token-customize.wasm"
    );
    let sample_bytes = i64::try_from(
        std::fs::metadata(sample)
            .unwrap_or_else(|error| {
                panic!("the committed TypeScript component ({sample}): {error}")
            })
            .len(),
    )
    .expect("fits");

    // Every CHECK that bounds a component, as its own expression rather than as prose.
    let bounds: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT conrelid::regclass::text, conname, pg_get_expr(conbin, conrelid) \
         FROM pg_constraint \
         WHERE contype = 'c' AND pg_get_expr(conbin, conrelid) LIKE '%octet_length(component)%'",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("scanning constraints");

    assert!(
        !bounds.is_empty(),
        "no component bound was found at all, so everything below is vacuous: the column or \
         the function this scan keys on has been renamed"
    );

    for (table, name, expression) in &bounds {
        // Substitute the size in for the length call, and let Postgres decide. Whatever
        // arithmetic the author wrote, the server evaluates it the same way it does on a write.
        let probe = expression.replace("octet_length(component)", &sample_bytes.to_string());
        let admits: bool = sqlx::query_scalar(&format!("SELECT ({probe})"))
            .fetch_one(db.owner_pool())
            .await
            .unwrap_or_else(|error| panic!("evaluating {table}.{name}: {error}"));
        assert!(
            admits,
            "{table}.{name} REFUSES the TypeScript hook this repository ships \
             ({sample_bytes} bytes). Its bound is `{expression}`. Every TypeScript hook is \
             undeployable through the surface that constraint guards; raise it in a migration, \
             and see 0166_token_hook_component_bound.sql for the reasoning."
        );

        // AND THE CONSTRAINT DISCRIMINATES, or the check above proved nothing: a predicate
        // true of every input returns the same `true` as one that genuinely admits the sample.
        //
        // BOTH ENDS, not just the large one. An earlier version substituted only ten gigabytes
        // and asserted refusal, which quietly required every matched constraint to be an UPPER
        // bound -- and this repository writes lower bounds on their own (`CHECK
        // (octet_length(recipient_bidx) > 0)` in 0157). A perfectly correct component table
        // written that way would have turned this test red and blamed the wrong constraint.
        //
        // That earlier comment also claimed to rule out "a constraint the replacement never
        // touched". It cannot occur: the WHERE clause above already requires the substring, so
        // every row the loop sees is one the replacement reached.
        let mut discriminates = false;
        for probe_value in ["9999999999", "0"] {
            let probe = expression.replace("octet_length(component)", probe_value);
            let holds: bool = sqlx::query_scalar(&format!("SELECT ({probe})"))
                .fetch_one(db.owner_pool())
                .await
                .unwrap_or_else(|error| {
                    panic!("evaluating {table}.{name} at {probe_value}: {error}")
                });
            if !holds {
                discriminates = true;
            }
        }
        assert!(
            discriminates,
            "{table}.{name} admits BOTH a ten-gigabyte component and a zero-byte one, so it \
             bounds nothing and the check above proved nothing about it: `{expression}`"
        );
    }
}

/// A CLIENT CAN HOLD MORE THAN ONE HOOK, AND THEIR ORDER IS TOTAL.
///
/// Migration 0167, issue #114 criterion 5's "explicit ordering of multiple hooks on one event".
/// Before it the primary key was `(tenant_id, environment_id, client_id)`: there was no second
/// hook for an ordering to be an ordering OF, so the criterion could not be met by an admin
/// surface alone.
///
/// # What this asserts that a column list would not
///
/// Four properties, each of which a schema that merely GREW two columns would fail:
///
/// 1. A second hook under a different NAME is accepted. That is the widened identity working.
/// 2. A second hook under the SAME name is refused. That is the identity still being an
///    identity -- a schema that added `name` without moving the primary key would accept both
///    and leave two rows a lookup cannot tell apart.
/// 3. Two hooks at the same ORDINAL are refused. A partial order is not an order: a dispatch
///    chaining them would produce a token that depends on which row Postgres returned first,
///    which is the unordered-cascade defect this repository has already fixed once.
/// 4. A permutation COMMITS. Swapping two hooks passes through an intermediate state with a
///    duplicate ordinal in it, so a non-deferrable constraint would force the caller to
///    sequence its updates through a free slot. Asserting the swap is what pins the constraint
///    as DEFERRABLE rather than merely present.
///
/// The backfill is asserted too, and it is the property an upgrade depends on: the row a client
/// already had is RENAMED in place to `('default', 0)` rather than joined by a new one, so the
/// count of deployed hooks does not change and no client's tokens change shape.
#[tokio::test]
async fn a_client_can_hold_several_named_hooks_whose_order_is_total_and_permutable() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.owner_pool();
    let (tenant, environment) = (scope.tenant().to_string(), scope.environment().to_string());

    let insert = |name: &'static str, ordinal: i32| {
        let (tenant, environment) = (tenant.clone(), environment.clone());
        async move {
            sqlx::query(
                "INSERT INTO token_hooks \
                 (tenant_id, environment_id, client_id, component, payload_version, name, ordinal) \
                 VALUES ($1, $2, 'cli_ordered', '\\x00'::bytea, 1, $3, $4)",
            )
            .bind(&tenant)
            .bind(&environment)
            .bind(name)
            .bind(ordinal)
            .execute(pool)
            .await
        }
    };

    // THE BACKFILL, first: a row written the way the pre-0167 deploy path writes one takes the
    // defaults, so an upgraded install has exactly the hook it had before, under a name.
    sqlx::query(
        "INSERT INTO token_hooks \
         (tenant_id, environment_id, client_id, component, payload_version) \
         VALUES ($1, $2, 'cli_upgraded', '\\x00'::bytea, 1)",
    )
    .bind(&tenant)
    .bind(&environment)
    .execute(pool)
    .await
    .expect("a writer that names no hook still works, or the rollout is a single atomic release");
    let (name, ordinal): (String, i32) = sqlx::query_as(
        "SELECT name, ordinal FROM token_hooks \
         WHERE tenant_id = $1 AND environment_id = $2 AND client_id = 'cli_upgraded'",
    )
    .bind(&tenant)
    .bind(&environment)
    .fetch_one(pool)
    .await
    .expect("read the backfilled row");
    assert_eq!(
        (name.as_str(), ordinal),
        ("default", 0),
        "an existing hook is RENAMED in place, not joined by a new one"
    );

    insert("first", 0).await.expect("the first named hook");
    insert("second", 1)
        .await
        .expect("a SECOND hook on one client, which is the whole point of 0167");

    let duplicate_name = insert("second", 2).await;
    assert!(
        duplicate_name.is_err(),
        "the identity is (scope, client, NAME), so a repeat name is a key collision rather \
         than a second row a lookup cannot tell apart"
    );

    let duplicate_ordinal = insert("third", 1).await;
    assert!(
        duplicate_ordinal.is_err(),
        "two hooks at one position have no order between them, and a partial order is not an \
         order: the database must refuse it rather than let a dispatch pick"
    );

    // AND A PERMUTATION COMMITS. The intermediate state has both hooks at ordinal 0.
    let mut tx = pool.begin().await.expect("begin the swap");
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *tx)
        .await
        .expect("defer");
    for (name, ordinal) in [("first", 1), ("second", 0)] {
        sqlx::query(
            "UPDATE token_hooks SET ordinal = $4 \
             WHERE tenant_id = $1 AND environment_id = $2 AND client_id = 'cli_ordered' \
               AND name = $3",
        )
        .bind(&tenant)
        .bind(&environment)
        .bind(name)
        .bind(ordinal)
        .execute(&mut *tx)
        .await
        .expect("one half of the swap");
    }
    tx.commit()
        .await
        .expect("a reorder is a permutation, so the check has to happen at COMMIT");

    let order: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM token_hooks \
         WHERE tenant_id = $1 AND environment_id = $2 AND client_id = 'cli_ordered' \
         ORDER BY ordinal",
    )
    .bind(&tenant)
    .bind(&environment)
    .fetch_all(pool)
    .await
    .expect("read the order back");
    assert_eq!(
        order,
        vec!["second".to_owned(), "first".to_owned()],
        "and the swap is what the feed reads back, or the reorder wrote nothing"
    );
}

/// THE IDENTITY MOVE LEAVES ONE INDEX ON THE IDENTITY, NOT TWO.
///
/// 0167 adds `token_hooks_named_identity` as a UNIQUE constraint and 0168 drops it in the same
/// statement that adds the primary key over the identical columns. Doing those in the other
/// order, or in two statements, would leave the table carrying two indexes over one column list
/// -- both maintained on every deploy of every hook, on a table whose rows are megabytes.
///
/// A count rather than a name check, because the defect is DUPLICATION and a name check cannot
/// see it: two indexes with different names over the same columns both pass "the primary key
/// exists".
#[tokio::test]
async fn the_hook_identity_carries_exactly_one_index_after_the_move() {
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    for (table, columns) in [
        ("token_hooks", "{tenant_id,environment_id,client_id,name}"),
        (
            "token_hook_versions",
            "{tenant_id,environment_id,client_id,name,version}",
        ),
    ] {
        let indexes: Vec<String> = sqlx::query_scalar(
            "SELECT i.relname \
             FROM pg_index x \
             JOIN pg_class i ON i.oid = x.indexrelid \
             JOIN pg_class t ON t.oid = x.indrelid \
             WHERE t.relname = $1 \
               AND (SELECT array_agg(a.attname ORDER BY k.ord) \
                    FROM unnest(x.indkey) WITH ORDINALITY AS k(attnum, ord) \
                    JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum)::text[] \
                   = $2::text[]",
        )
        .bind(table)
        .bind(columns)
        .fetch_all(pool)
        .await
        .expect("read the index catalogue");
        assert_eq!(
            indexes.len(),
            1,
            "{table} must carry exactly ONE index over its identity columns; found {indexes:?}"
        );
    }
}

/// THE CHAIN READ IS BOUNDED, AND THE BOUND DROPS THE TAIL.
///
/// Before migration 0168 the primary key answered "how many hooks run per login" and the answer
/// was one. Widening the identity removed that answer and nothing replaced it: every hook in a
/// chain is compiled on a cache miss and invoked on every token, so an unbounded chain is an
/// unbounded amount of issuance-path work for a client anyone who can start a login may pick.
///
/// This inserts more hooks than the cap and asserts two things a `LIMIT` alone would not give:
/// that the read stops at `MAX_HOOKS_PER_CLIENT`, and that what survives is the PREFIX in
/// ordinal order. Truncating anywhere but the tail would leave a chain that means something
/// other than what the operator wrote -- dropping the first hook silently changes what every
/// later one is handed.
#[tokio::test]
async fn the_hook_chain_read_is_bounded_and_keeps_the_prefix() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.owner_pool();

    let over = usize::try_from(ironauth_store::MAX_HOOKS_PER_CLIENT).expect("a small cap") + 3;
    for position in 0..over {
        sqlx::query(
            "INSERT INTO token_hooks \
             (tenant_id, environment_id, client_id, name, ordinal, component, payload_version) \
             VALUES ($1, $2, 'cli_longchain', $3, $4, '\\x00'::bytea, 1)",
        )
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(format!("hook{position:02}"))
        .bind(i32::try_from(position).expect("a small position"))
        .execute(pool)
        .await
        .expect("insert a hook into a long chain");
    }

    let chain = db
        .store()
        .scoped(scope)
        .token_hooks()
        .chain("cli_longchain")
        .await
        .expect("read the chain");

    assert_eq!(
        i64::try_from(chain.len()).expect("a small chain"),
        ironauth_store::MAX_HOOKS_PER_CLIENT,
        "the issuance path must not be handed more hooks than it is willing to run"
    );
    let names: Vec<&str> = chain.iter().map(|hook| hook.name.as_str()).collect();
    let expected: Vec<String> = (0..chain.len()).map(|n| format!("hook{n:02}")).collect();
    assert_eq!(
        names, expected,
        "and what survives is the PREFIX in ordinal order: dropping anything but the tail \
         changes what every later hook is handed"
    );
}
