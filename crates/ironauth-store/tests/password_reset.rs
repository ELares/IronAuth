// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reset schema isolation and lifecycle constraints, not a reset ceremony.
//! Rows below are metadata fixtures; no user credential is changed by these tests.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{PasswordResetChallengeId, RecipientChallengeId, Scope};
use sqlx::Row;

async fn insert_fixture(
    db: &TestDatabase,
    scope: Scope,
    id: &PasswordResetChallengeId,
    bound: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO password_reset_challenges \
         (id,tenant_id,environment_id,client_id,browser_binding_hash,authorization_return_to,\
          subject,identifier_id,recipient_revision,recovery_id,credential_digest,code_hash,created_at,expires_at) \
         VALUES ($1,$2,$3,'fixture-client',decode(repeat('ab',32),'hex'),'/authorize?fixture=1',\
          $4,$5,$6,$7,$8,'fixture-hash',TIMESTAMPTZ '2026-10-03 00:00:00Z',\
          TIMESTAMPTZ '2026-10-03 00:05:00Z')",
    )
    .bind(id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(bound.then_some("fixture-subject"))
    .bind(bound.then_some("fixture-identifier"))
    .bind(bound.then_some("fixture-revision"))
    .bind(bound.then_some("fixture-recovery"))
    .bind(bound.then_some(vec![1_u8; 32]))
    .execute(db.owner_pool())
    .await?;
    Ok(())
}

fn sqlstate(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()?
        .code()
        .map(|code| code.into_owned())
}

#[tokio::test]
async fn reset_schema_forces_scope_and_refuses_authority_rewrites() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let other = db.seed_scope(&env).await;
    let id = PasswordResetChallengeId::generate(&env, &scope);
    insert_fixture(&db, scope, &id, true).await.unwrap();
    let flags = sqlx::query("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname='password_reset_challenges'")
        .fetch_one(db.owner_pool()).await.unwrap();
    assert!(flags.get::<bool, _>("relrowsecurity"));
    assert!(flags.get::<bool, _>("relforcerowsecurity"));
    let mut tx = db.app_pool().begin().await.unwrap();
    sqlx::query("SELECT set_config('ironauth.tenant_id',$1,true),set_config('ironauth.environment_id',$2,true)")
        .bind(other.tenant().to_string()).bind(other.environment().to_string()).execute(&mut *tx).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM password_reset_challenges")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(count, 0);
    for query in [
        "DELETE FROM password_reset_challenges WHERE id=$1",
        "UPDATE password_reset_challenges SET attempt_count=1 WHERE id=$1",
    ] {
        assert_eq!(
            sqlx::query(query)
                .bind(id.to_string())
                .execute(&mut *tx)
                .await
                .unwrap()
                .rows_affected(),
            0
        );
    }
    tx.commit().await.unwrap();

    let mut tx = db.app_pool().begin().await.unwrap();
    sqlx::query("SELECT set_config('ironauth.tenant_id',$1,true),set_config('ironauth.environment_id',$2,true)")
        .bind(other.tenant().to_string()).bind(other.environment().to_string()).execute(&mut *tx).await.unwrap();
    let forged = PasswordResetChallengeId::generate(&env, &scope);
    let error = sqlx::query("INSERT INTO password_reset_challenges (id,tenant_id,environment_id,client_id,browser_binding_hash,authorization_return_to,code_hash,created_at,expires_at) VALUES ($1,$2,$3,'fixture-client',decode(repeat('ab',32),'hex'),'/authorize?fixture=1','fixture-hash',TIMESTAMPTZ '2026-10-03 00:00:00Z',TIMESTAMPTZ '2026-10-03 00:05:00Z')")
        .bind(forged.to_string()).bind(scope.tenant().to_string()).bind(scope.environment().to_string())
        .execute(&mut *tx).await.expect_err("WITH CHECK rejects foreign insertion");
    assert_eq!(sqlstate(&error).as_deref(), Some("42501"));
    tx.rollback().await.unwrap();
    for column in [
        "subject",
        "identifier_id",
        "recipient_revision",
        "recovery_id",
        "credential_digest",
        "browser_binding_hash",
        "authorization_return_to",
        "client_id",
        "code_hash",
        "expires_at",
        "tenant_id",
        "environment_id",
    ] {
        let error = sqlx::query(&format!(
            "UPDATE password_reset_challenges SET {column}={column}"
        ))
        .execute(db.app_pool())
        .await
        .expect_err("runtime cannot rewrite bound authority");
        assert_eq!(sqlstate(&error).as_deref(), Some("42501"), "{column}");
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM password_reset_challenges WHERE id=$1 AND attempt_count=0",
    )
    .bind(id.to_string())
    .fetch_one(db.owner_pool())
    .await
    .unwrap();
    assert_eq!(
        count, 1,
        "foreign and unprivileged writes left the record intact"
    );
    assert!(PasswordResetChallengeId::parse_in_scope(&id.to_string(), &other).is_err());
    assert!(RecipientChallengeId::parse_in_scope(&id.to_string(), &scope).is_err());
    assert!(!format!("{id:?}").contains(&id.to_string()));
}

#[tokio::test]
async fn reset_schema_rejects_partial_completion_and_unbounded_attempts() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = PasswordResetChallengeId::generate(&env, &scope);
    insert_fixture(&db, scope, &id, true).await.unwrap();
    for change in [
        "attempt_count=6",
        "attempt_count=-1",
        "expires_at=created_at",
        "expires_at=created_at+interval '11 minutes'",
        "browser_binding_hash=decode('ab','hex')",
        "identifier_id=NULL",
        "state='completed'",
        "finished_at=created_at+interval '1 minute'",
        "state='completed',attempt_count=1,finished_at=created_at+interval '1 minute',completion_request_hash=decode(repeat('ab',32),'hex')",
        "state='completed',attempt_count=1,finished_at=expires_at,completion_request_hash=decode(repeat('ab',32),'hex'),completion_credential_digest=decode(repeat('cd',32),'hex')",
    ] {
        let error = sqlx::query(&format!(
            "UPDATE password_reset_challenges SET {change} WHERE id=$1"
        ))
        .bind(id.to_string())
        .execute(db.owner_pool())
        .await
        .expect_err("invalid state refused");
        assert_eq!(sqlstate(&error).as_deref(), Some("23514"), "{change}");
    }
    let next = PasswordResetChallengeId::generate(&env, &scope);
    let error = insert_fixture(&db, scope, &next, true)
        .await
        .expect_err("one pending reset per subject");
    assert_eq!(sqlstate(&error).as_deref(), Some("23505"));
    sqlx::query("UPDATE password_reset_challenges SET state='cancelled',finished_at=created_at+interval '1 minute' WHERE id=$1")
        .bind(id.to_string()).execute(db.owner_pool()).await.unwrap();
    insert_fixture(&db, scope, &next, true).await.unwrap();
    let decoy = PasswordResetChallengeId::generate(&env, &scope);
    insert_fixture(&db, scope, &decoy, false).await.unwrap();
    let error = sqlx::query("UPDATE password_reset_challenges SET state='completed',attempt_count=1,finished_at=created_at+interval '1 minute',completion_request_hash=decode(repeat('ab',32),'hex'),completion_credential_digest=decode(repeat('cd',32),'hex') WHERE id=$1")
        .bind(decoy.to_string()).execute(db.owner_pool()).await.expect_err("decoy cannot become completed authority");
    assert_eq!(sqlstate(&error).as_deref(), Some("23514"));
    sqlx::query("UPDATE password_reset_challenges SET state='completed',attempt_count=1,finished_at=created_at+interval '1 minute',completion_request_hash=decode(repeat('ab',32),'hex'),completion_credential_digest=decode(repeat('cd',32),'hex') WHERE id=$1")
        .bind(next.to_string()).execute(db.owner_pool()).await.expect("complete metadata shape is representable; this is not a credential mutation");
}
