// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-stream audit tamper evidence (issue #109).
//!
//! Two halves. The pure half drives `verify_chain_entries` over hand-built chains, because
//! the interesting cases are the CORRUPTED ones and building those against a live table
//! means defeating the grants that make it append-only. The database half proves the sealer
//! produces a chain that verifies over rows real mutations wrote, and that a tamper applied
//! through the owner connection is caught.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{ChainEntry, ChainFault, ChainedAuditRow, verify_chain_entries};
use ironauth_store::{CorrelationId, ocsf};
use std::collections::BTreeMap;

/// The admin stream's wire name, which is where a client create lands.
const ADMIN: &str = "admin_action";

/// A row with a distinguishable id and event time.
fn row(id: &str, occurred_micros: i64) -> ChainedAuditRow {
    ChainedAuditRow {
        audit_id: id.to_string(),
        action: "client.create".to_string(),
        actor_kind: "service".to_string(),
        actor_id: "svc_1".to_string(),
        target_kind: "cli".to_string(),
        target_id: "cli_1".to_string(),
        correlation_id: "cor_1".to_string(),
        occurred_micros,
        detail: None,
    }
}

/// Seal `rows` into a well-formed chain starting at `first_seq`.
fn seal(rows: &[ChainedAuditRow], first_seq: i64) -> Vec<ChainEntry> {
    let mut prev = String::new();
    let mut out = Vec::new();
    for (offset, row) in rows.iter().enumerate() {
        let record_hash = ocsf::chain_link(&prev, &row.canonical());
        out.push(ChainEntry {
            seq: first_seq + i64::try_from(offset).expect("small"),
            audit_id: row.audit_id.clone(),
            prev_hash: prev.clone(),
            record_hash: record_hash.clone(),
        });
        prev = record_hash;
    }
    out
}

fn map(rows: &[ChainedAuditRow]) -> BTreeMap<String, ChainedAuditRow> {
    rows.iter()
        .map(|row| (row.audit_id.clone(), row.clone()))
        .collect()
}

#[test]
fn a_well_formed_chain_verifies() {
    let rows = [row("aud_1", 10), row("aud_2", 20), row("aud_3", 30)];
    let entries = seal(&rows, 1);
    let verified = verify_chain_entries(&entries, &map(&rows)).expect("must verify");
    assert_eq!(verified.entries, 3, "all three entries must be checked");
}

#[test]
fn modifying_a_sealed_row_is_caught() {
    let rows = [row("aud_1", 10), row("aud_2", 20), row("aud_3", 30)];
    let entries = seal(&rows, 1);
    let mut tampered = map(&rows);
    tampered.get_mut("aud_2").expect("present").action = "client.delete".to_string();
    assert_eq!(
        verify_chain_entries(&entries, &tampered),
        Err(ChainFault::Tampered {
            seq: 2,
            audit_id: "aud_2".to_string()
        }),
        "a modified action must be caught at the row it changed"
    );
}

#[test]
fn deleting_a_sealed_row_is_caught() {
    let rows = [row("aud_1", 10), row("aud_2", 20), row("aud_3", 30)];
    let entries = seal(&rows, 1);
    let mut without = map(&rows);
    without.remove("aud_2");
    assert_eq!(
        verify_chain_entries(&entries, &without),
        Err(ChainFault::MissingRow {
            seq: 2,
            audit_id: "aud_2".to_string()
        })
    );
}

#[test]
fn inserting_a_row_into_the_sealed_past_is_caught() {
    let rows = [row("aud_1", 10), row("aud_3", 30)];
    let entries = seal(&rows, 1);
    let mut with_extra = map(&rows);
    // Slipped in between two sealed rows, so it breaks no link: nothing commits to it.
    with_extra.insert("aud_2".to_string(), row("aud_2", 20));
    assert_eq!(
        verify_chain_entries(&entries, &with_extra),
        Err(ChainFault::Unchained {
            audit_id: "aud_2".to_string()
        }),
        "a row inserted below the watermark must be caught by the completeness check"
    );
}

/// The completeness check must NOT fire on rows the sealer has not reached yet.
///
/// Sealing runs behind the writers, so at any instant the newest rows are legitimately
/// unsealed. An unbounded completeness check would report tampering on ordinary traffic,
/// and the only way to live with it would be to switch it off.
#[test]
fn a_row_newer_than_the_watermark_is_not_yet_sealed_and_is_fine() {
    let sealed_rows = [row("aud_1", 10), row("aud_2", 20)];
    let entries = seal(&sealed_rows, 1);
    let mut all = map(&sealed_rows);
    all.insert("aud_9".to_string(), row("aud_9", 99));
    assert!(
        verify_chain_entries(&entries, &all).is_ok(),
        "a row written after the last sealed one must not read as an insertion"
    );
}

#[test]
fn splicing_two_histories_breaks_the_link() {
    let rows = [row("aud_1", 10), row("aud_2", 20), row("aud_3", 30)];
    let mut entries = seal(&rows, 1);
    // Re-point entry 3 at a predecessor it does not follow.
    entries[2].prev_hash = ocsf::chain_link("", &row("aud_x", 1).canonical());
    assert_eq!(
        verify_chain_entries(&entries, &map(&rows)),
        Err(ChainFault::Link { seq: 3 })
    );
}

#[test]
fn removing_an_entry_from_the_middle_breaks_the_positions() {
    let rows = [row("aud_1", 10), row("aud_2", 20), row("aud_3", 30)];
    let mut entries = seal(&rows, 1);
    entries.remove(1);
    assert_eq!(
        verify_chain_entries(&entries, &map(&rows)),
        Err(ChainFault::Position {
            expected: 2,
            found: 3
        })
    );
}

/// A chain whose PREFIX retention pruned still verifies over what is retained.
///
/// This is the case that makes per-stream retention and tamper evidence able to coexist:
/// pruning is not tampering, so density is checked from the first entry present rather
/// than from position 1.
#[test]
fn a_chain_whose_prefix_was_pruned_still_verifies() {
    let all = [
        row("aud_1", 10),
        row("aud_2", 20),
        row("aud_3", 30),
        row("aud_4", 40),
    ];
    let full = seal(&all, 1);
    // Retention removed positions 1 and 2 and the rows they sealed.
    let retained_entries = full[2..].to_vec();
    let retained_rows = map(&all[2..]);
    let verified = verify_chain_entries(&retained_entries, &retained_rows)
        .expect("a pruned prefix is not a broken chain");
    assert_eq!(verified.entries, 2);
    assert_eq!(
        retained_entries[0].seq, 3,
        "the retained chain starts where the prune stopped, not at 1"
    );
}

#[test]
fn an_empty_chain_with_no_rows_verifies() {
    let verified = verify_chain_entries(&[], &BTreeMap::new()).expect("vacuously fine");
    assert_eq!(verified.entries, 0);
}

// ===========================================================================
// Against a real database.

#[tokio::test]
async fn the_sealer_chains_real_rows_and_a_tamper_is_caught() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    for name in ["chain-a", "chain-b", "chain-c"] {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .clients()
            .create(&env, name)
            .await
            .expect("create a client");
    }

    let chain = db.store().scoped(scope);
    let chain = chain.audit_chain();
    let report = chain.seal_pending(&env, ADMIN, 100).await.expect("seal");
    assert_eq!(report.sealed, 3, "all three admin rows must seal");
    assert_eq!(report.head_seq, 3, "the chain head advances to 3");

    assert!(
        chain.verify(ADMIN).await.expect("verify runs").is_ok(),
        "a freshly sealed chain must verify"
    );

    // Sealing again is a no-op rather than a duplicate: the audit-id unique index is
    // what makes a replaying sealer safe.
    let again = chain.seal_pending(&env, ADMIN, 100).await.expect("reseal");
    assert_eq!(again.sealed, 0, "an already sealed row must not seal twice");
    assert_eq!(again.head_seq, 3, "and the head must not move");

    // Now tamper, through the owner connection, which is the only thing that can:
    // neither application role holds UPDATE on audit_log.
    sqlx::query("UPDATE audit_log SET action = 'client.delete' WHERE action = 'client.create'")
        .execute(db.owner_pool())
        .await
        .expect("owner can rewrite the row");

    let fault = chain
        .verify(ADMIN)
        .await
        .expect("verify runs")
        .expect_err("a rewritten audit row must fail verification");
    assert!(
        matches!(fault, ChainFault::Tampered { .. }),
        "the rewrite must be reported as tampering, got {fault:?}"
    );
}

#[tokio::test]
async fn the_two_streams_chain_independently() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "independent")
        .await
        .expect("create a client");

    let scoped = db.store().scoped(scope);
    let chain = scoped.audit_chain();
    let admin = chain
        .seal_pending(&env, ADMIN, 100)
        .await
        .expect("seal admin");
    assert!(admin.sealed >= 1, "the admin stream has rows to seal");

    // The authentication stream has no rows here, so its chain is empty and verifies
    // on its own. The point is that the two do not share a position space: sealing one
    // must not advance the other.
    let authn = chain
        .seal_pending(&env, "authentication", 100)
        .await
        .expect("seal authn");
    assert_eq!(authn.sealed, 0, "no authentication rows exist yet");
    assert_eq!(
        authn.head_seq, 0,
        "the authentication chain must start at zero regardless of the admin chain"
    );
    assert!(chain.verify(ADMIN).await.expect("verify").is_ok());
    assert!(
        chain
            .verify("authentication")
            .await
            .expect("verify")
            .is_ok()
    );
}

// ===========================================================================
// Per-stream retention (issue #109).

/// A cutoff far in the future, so every existing row falls before it.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// Create a live SSO session, which writes an authentication-stream audit row.
async fn create_session(db: &TestDatabase, env: &Env, scope: ironauth_store::Scope) {
    let id = ironauth_store::SessionId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .sessions()
        .rotate(
            env,
            &id,
            None,
            ironauth_store::NewSession {
                impersonation: None,
                subject: "usr_retention_probe",
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: FAR_FUTURE_MICROS,
                absolute_expires_micros: FAR_FUTURE_MICROS,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("rotate a session");
}

/// Write `count` admin-stream rows and return the scope they landed in.
async fn seed_admin_rows(db: &TestDatabase, env: &Env, scope: ironauth_store::Scope, count: usize) {
    for index in 0..count {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(env), CorrelationId::generate(env))
            .clients()
            .create(env, &format!("retain-{index}"))
            .await
            .expect("create a client");
    }
}

#[tokio::test]
async fn pruning_a_prefix_leaves_a_chain_that_still_verifies() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    seed_admin_rows(&db, &env, scope, 4).await;

    let scoped = db.store().scoped(scope);
    let chain = scoped.audit_chain();
    assert_eq!(
        chain
            .seal_pending(&env, ADMIN, 100)
            .await
            .expect("seal")
            .sealed,
        4
    );
    assert!(chain.verify(ADMIN).await.expect("verify").is_ok());

    // Prune the two oldest, through the retention role: the only one that can.
    let retention = db.audit_retention_store().scoped(scope);
    let report = retention
        .audit_chain()
        .prune_before(ADMIN, FAR_FUTURE_MICROS, 2)
        .await
        .expect("prune");
    assert_eq!(report.rows_removed, 2, "exactly the batch limit is removed");
    assert_eq!(
        report.entries_removed, 2,
        "each pruned row takes its chain entry with it"
    );

    // The retained tail still verifies. Pruning is not tampering.
    let verified = chain
        .verify(ADMIN)
        .await
        .expect("verify runs")
        .expect("a pruned prefix must not read as an attack");
    assert_eq!(verified.entries, 2, "two entries survive");
    let entries = chain.entries(ADMIN).await.expect("entries");
    assert_eq!(
        entries[0].seq, 3,
        "the surviving chain starts where the prune stopped, not renumbered to 1"
    );
}

#[tokio::test]
async fn the_two_streams_are_pruned_independently() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    seed_admin_rows(&db, &env, scope, 2).await;
    create_session(&db, &env, scope).await;

    let before = db.store().scoped(scope);
    let authn_before = before
        .audit_chain()
        .sealed_rows("authentication")
        .await
        .expect("read")
        .len();
    assert!(authn_before > 0, "the session write must have left a row");

    // Prune EVERYTHING from the admin stream.
    let retention = db.audit_retention_store().scoped(scope);
    let removed = retention
        .audit_chain()
        .prune_before(ADMIN, FAR_FUTURE_MICROS, 1_000)
        .await
        .expect("prune admin");
    assert!(removed.rows_removed >= 2, "the admin rows are gone");

    // The authentication stream is untouched. This is the whole point of the split:
    // one window may be short and the other long without either disturbing the other.
    let after = db.store().scoped(scope);
    assert_eq!(
        after
            .audit_chain()
            .sealed_rows("authentication")
            .await
            .expect("read")
            .len(),
        authn_before,
        "pruning the admin stream must not remove an authentication row"
    );
    assert_eq!(
        after
            .audit_chain()
            .sealed_rows(ADMIN)
            .await
            .expect("read")
            .len(),
        0,
        "and the admin stream really was emptied"
    );
}

/// The application role cannot delete an audit row, and that is what makes the
/// retention role meaningful rather than decorative.
#[tokio::test]
async fn only_the_retention_role_can_remove_an_audit_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    seed_admin_rows(&db, &env, scope, 1).await;

    let app = db.store().scoped(scope);
    let refused = app
        .audit_chain()
        .prune_before(ADMIN, FAR_FUTURE_MICROS, 10)
        .await;
    let error = format!(
        "{:?}",
        refused.expect_err("the data-plane role must not prune")
    );
    assert!(
        error.contains("permission denied"),
        "the refusal must come from the GRANT, not from a broken query: {error}"
    );

    // The same call through the retention role succeeds, so the refusal above is the
    // GRANT talking and not a broken query.
    let allowed = db
        .audit_retention_store()
        .scoped(scope)
        .audit_chain()
        .prune_before(ADMIN, FAR_FUTURE_MICROS, 10)
        .await
        .expect("the retention role may prune");
    assert!(allowed.rows_removed >= 1);
}

/// The retention role cannot WRITE an audit row.
///
/// This is the property that separates it from the argument migration 0102 made for
/// the outbox. A role holding both INSERT and DELETE could remove a row and write a
/// replacement, which is exactly the tampering the log exists to make evident.
#[tokio::test]
async fn the_retention_role_cannot_write_an_audit_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let refused = db
        .audit_retention_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "should-not-write")
        .await;
    let error = format!(
        "{:?}",
        refused.expect_err("the retention role must not write an audit row")
    );
    assert!(
        error.contains("permission denied"),
        "the refusal must come from the missing GRANT, not from an absent master key or \
         some other unrelated fault: {error}"
    );
}

/// The reaper honours a window per stream, and a stream with no window is untouched.
///
/// Driven through [`AuditReaper`] rather than through `prune_before` directly, because
/// the mapping from two configured windows onto two streams is the part that can be
/// wired backwards, and a test that calls the prune itself would never see it.
#[tokio::test]
async fn the_reaper_sweeps_one_stream_and_leaves_the_other_forever() {
    use ironauth_store::audit_retention::{AuditReaper, AuditRetentionSettings};
    use std::time::Duration;

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    seed_admin_rows(&db, &env, scope, 3).await;
    create_session(&db, &env, scope).await;

    let reaper = AuditReaper::new(
        db.audit_retention_store().clone(),
        env.clone(),
        AuditRetentionSettings {
            // Zero window: everything already written is older than the cutoff.
            admin_action: Some(Duration::ZERO),
            // None is FOREVER, not "immediately", which is the distinction that keeps an
            // operator who enables the sweeper before choosing a window from erasing the
            // trail.
            authentication: None,
            batch: 1_000,
        },
    );

    let before_authn = db
        .store()
        .scoped(scope)
        .audit_chain()
        .sealed_rows("authentication")
        .await
        .expect("read")
        .len();
    assert!(before_authn > 0, "the session write must have left a row");

    let stats = reaper.reap_once(scope).await.expect("reap");
    assert!(
        stats.admin_action_removed >= 3,
        "the swept stream loses its rows: {stats:?}"
    );
    assert_eq!(
        stats.authentication_removed, 0,
        "a stream with no window must not be swept: {stats:?}"
    );

    let scoped = db.store().scoped(scope);
    assert_eq!(
        scoped
            .audit_chain()
            .sealed_rows(ADMIN)
            .await
            .expect("read")
            .len(),
        0
    );
    assert_eq!(
        scoped
            .audit_chain()
            .sealed_rows("authentication")
            .await
            .expect("read")
            .len(),
        before_authn,
        "the unswept stream is exactly as it was"
    );
}
