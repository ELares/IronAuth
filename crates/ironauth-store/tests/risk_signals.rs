// SPDX-License-Identifier: MIT OR Apache-2.0

//! The third-party risk-signal ingestion store (issue #82, PR 1) against a real Postgres:
//! idempotent single-delivery, the scoped fresh-signal read the #79 engine uses, the
//! blind-index subject binding (no plaintext external subject lands), and cross-tenant
//! isolation through the IDOR harness.

use ironauth_env::Env;
use ironauth_store::idor_harness::IdorHarness;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, NewRiskSignal, Scope, UserId};

const SOURCE: &str = "https://vendor.example";
const RAW_SUBJECT: &str = "alice@example.com";

/// Ingest a signal for `subject` in `scope`, returning whether a fresh row was written.
async fn ingest_signal(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    subject: &UserId,
    jti: &str,
) -> bool {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .risk_signals()
        .ingest(
            env,
            NewRiskSignal {
                source: SOURCE,
                signal_type: "https://schemas.openid.net/secevent/caep/event-type/risk-level-change",
                subject_format: "email",
                subject_raw: RAW_SUBJECT,
                resolved_subject: Some(subject),
                payload_json: r#"{"kind":"verdict","verdict":"deny"}"#,
                event_timestamp_micros: 1_700_000_000 * 1_000_000,
                source_jti: jti,
            },
        )
        .await
        .expect("ingest a verified signal")
}

#[tokio::test]
async fn ingestion_is_idempotent_and_the_engine_read_is_subject_bound() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope);

    // A first delivery ingests the row; a re-delivery of the SAME (source, source_jti) is an
    // idempotent no-op, never a duplicate.
    assert!(
        ingest_signal(&db, &env, scope, &subject, "jti-1").await,
        "the first delivery ingests the row"
    );
    assert!(
        !ingest_signal(&db, &env, scope, &subject, "jti-1").await,
        "a re-delivery of the same source_jti is an idempotent no-op"
    );

    // Exactly one row exists (the dedup UNIQUE held).
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM risk_signals WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count risk_signals");
    assert_eq!(count, 1, "the dedup UNIQUE kept exactly one row");

    // A DISTINCT source_jti from the same source ingests a second row.
    assert!(ingest_signal(&db, &env, scope, &subject, "jti-2").await);

    // The engine's fresh-signal read returns the subject's signals.
    let signals = db
        .store()
        .scoped(scope)
        .risk_signals()
        .fresh_signals_for_subject(&subject, 100)
        .await
        .expect("read fresh signals");
    assert_eq!(signals.len(), 2, "both distinct deliveries are readable");
    assert!(signals.iter().all(|signal| signal.source == SOURCE));

    // A DIFFERENT subject sees none of them (the read is subject-bound).
    let other = UserId::generate(&env, &scope);
    let none = db
        .store()
        .scoped(scope)
        .risk_signals()
        .fresh_signals_for_subject(&other, 100)
        .await
        .expect("read fresh signals for another subject");
    assert!(none.is_empty(), "a signal is bound to its own subject only");
}

#[tokio::test]
async fn the_raw_external_subject_is_never_stored_as_plaintext() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope);
    assert!(ingest_signal(&db, &env, scope, &subject, "jti-1").await);

    // The row carries a keyed blind index of the external subject, never the plaintext. The
    // raw email must appear in NO text column of the row.
    let row: (Vec<u8>, Option<String>) = sqlx::query_as(
        "SELECT subject_bidx, subject FROM risk_signals \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read the ingested row");
    assert!(!row.0.is_empty(), "the subject blind index is present");
    assert_eq!(
        row.1.as_deref(),
        Some(subject.to_string().as_str()),
        "the resolved local subject is the usr_ id, not the external subject"
    );

    // A full-row text dump reveals no occurrence of the raw external subject.
    let dump: String = sqlx::query_scalar(
        "SELECT risk_signals::text FROM risk_signals \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("dump the row");
    assert!(
        !dump.contains(RAW_SUBJECT),
        "the raw external subject must never appear in a queryable column: {dump}"
    );
}

#[tokio::test]
async fn a_signal_never_resolves_across_a_tenant_boundary() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    // Plant a signal for a subject in scope B.
    let victim = UserId::generate(&env, &scope_b);
    assert!(ingest_signal(&db, &env, scope_b, &victim, "jti-b").await);

    // The IDOR harness runs the risk-signal read probe as scope A against scope B's subject:
    // it must resolve to nothing (a uniform cross-scope not-found), never leak the row.
    let mut harness = IdorHarness::new();
    harness.register_risk_signal_probes();
    assert_eq!(
        harness.probe_names(),
        vec!["risk_signals.fresh_signals_for_subject"],
        "the risk-signal read surface is registered with the harness"
    );
    let foreign = [victim.to_string()];
    let refs: Vec<&str> = foreign.iter().map(String::as_str).collect();
    let leaks = harness.run(db.store(), scope_a, &refs).await;
    assert!(leaks.is_empty(), "cross-scope leak detected: {leaks:?}");

    // The row is STILL readable in its OWN scope (the probe never removed it), proving a
    // genuine scope boundary rather than a global miss.
    let own = db
        .store()
        .scoped(scope_b)
        .risk_signals()
        .fresh_signals_for_subject(&victim, 100)
        .await
        .expect("read in own scope");
    assert_eq!(own.len(), 1, "the row survives the cross-scope probe");
}
