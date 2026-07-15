// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment custom domains with built-in ACME (issue #47, EXPLORATORY),
//! over a real database (`DATABASE_URL`).
//!
//! Proves the persistence-layer acceptance for the exploratory slice: a domain
//! registers with an opened ACME challenge and round-trips through the scoped
//! repository; the challenge lifecycle moves through issued -> validated and
//! issued -> failed with a deterministic backoff schedule under a manual clock;
//! an issued certificate's PRIVATE KEY is stored ONLY as envelope ciphertext (a
//! database dump reveals no key material); one tenant cannot verify a domain
//! another tenant already verified; and an unsafe or malformed domain is refused
//! before it is ever written.

use std::time::{Duration, SystemTime};

use ironauth_env::Env;
use ironauth_jose::MasterKey;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    AcmeChallengeId, ChallengeOutcome, ChallengeStatus, ChallengeType, CorrelationId,
    CustomDomainId, Scope, StoreError, VerificationStatus,
};
use sqlx::Row;

/// A fresh random platform master key from the entropy seam.
fn master_key(env: &Env) -> MasterKey {
    MasterKey::generate("master-cdom-test", env.entropy())
}

/// Register `domain_name` in `scope` with a freshly minted domain id, challenge
/// id, and token. Returns the two ids.
async fn register(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    domain_name: &str,
    challenge_type: ChallengeType,
) -> (CustomDomainId, AcmeChallengeId) {
    let domain = CustomDomainId::generate(env, &scope);
    let challenge = AcmeChallengeId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .custom_domains()
        .register(
            env,
            &domain,
            domain_name,
            challenge_type,
            &challenge,
            "tok-http-01-example",
        )
        .await
        .expect("register custom domain");
    (domain, challenge)
}

#[tokio::test]
async fn register_opens_a_pending_challenge_and_round_trips() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let (domain, challenge) =
        register(&db, &env, scope, "auth.example.com", ChallengeType::Http01).await;

    let read = db
        .store()
        .scoped(scope)
        .custom_domains()
        .get_by_name("auth.example.com")
        .await
        .expect("read by name");
    assert_eq!(read.id, domain);
    assert_eq!(read.domain_name, "auth.example.com");
    assert_eq!(read.challenge_type, ChallengeType::Http01);
    assert_eq!(read.verification_status, VerificationStatus::Pending);
    assert!(
        read.cert_secret_id.is_none(),
        "an unverified domain has no certificate"
    );

    // The opened challenge is pending and belongs to the domain.
    let challenges = db
        .store()
        .scoped(scope)
        .custom_domains()
        .challenges_for(&domain)
        .await
        .expect("list challenges");
    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0].id, challenge);
    assert_eq!(challenges[0].status, ChallengeStatus::Pending);
    assert_eq!(challenges[0].token, "tok-http-01-example");

    // Listing the environment's domains sees exactly the one.
    let listed = db
        .store()
        .scoped(scope)
        .custom_domains()
        .list()
        .await
        .expect("list domains");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, domain);
}

#[tokio::test]
async fn a_second_registration_of_the_same_name_conflicts_in_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    register(&db, &env, scope, "auth.example.com", ChallengeType::Http01).await;

    let domain = CustomDomainId::generate(&env, &scope);
    let challenge = AcmeChallengeId::generate(&env, &scope);
    let err = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .custom_domains()
        .register(
            &env,
            &domain,
            "auth.example.com",
            ChallengeType::Dns01,
            &challenge,
            "tok",
        )
        .await
        .expect_err("a duplicate registration in the same scope must conflict");
    assert!(matches!(err, StoreError::Conflict), "got {err:?}");
}

#[tokio::test]
async fn a_valid_challenge_result_verifies_the_domain() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (domain, challenge) =
        register(&db, &env, scope, "auth.example.com", ChallengeType::Http01).await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .custom_domains()
        .record_challenge_result(&env, &challenge, &domain, ChallengeOutcome::Valid)
        .await
        .expect("record a valid result");

    let read = db
        .store()
        .scoped(scope)
        .custom_domains()
        .get(&domain)
        .await
        .expect("read domain");
    assert_eq!(read.verification_status, VerificationStatus::Verified);
    let challenges = db
        .store()
        .scoped(scope)
        .custom_domains()
        .challenges_for(&domain)
        .await
        .expect("list challenges");
    assert_eq!(challenges[0].status, ChallengeStatus::Valid);
    assert!(
        challenges[0].next_attempt_at_micros.is_none(),
        "a valid challenge clears its retry schedule"
    );
}

#[tokio::test]
async fn a_failed_challenge_fails_the_domain_and_schedules_a_deterministic_backoff() {
    // A manual clock frozen at the epoch: the failed challenge's next-attempt
    // instant is the frozen now plus the deterministic first backoff (60s), so the
    // schedule is reproducible.
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x47);
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    let (domain, challenge) =
        register(&db, &env, scope, "auth.example.com", ChallengeType::Http01).await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .custom_domains()
        .record_challenge_result(&env, &challenge, &domain, ChallengeOutcome::Invalid)
        .await
        .expect("record an invalid result");

    let read = db
        .store()
        .scoped(scope)
        .custom_domains()
        .get(&domain)
        .await
        .expect("read domain");
    assert_eq!(read.verification_status, VerificationStatus::Failed);

    let challenges = db
        .store()
        .scoped(scope)
        .custom_domains()
        .challenges_for(&domain)
        .await
        .expect("list challenges");
    assert_eq!(challenges[0].status, ChallengeStatus::Invalid);
    assert_eq!(challenges[0].attempts, 1, "the attempt count incremented");
    // The clock is frozen at UNIX_EPOCH; the first backoff is 60s, so the next
    // attempt is scheduled at exactly 60_000_000 microseconds since the epoch.
    let expected = i64::try_from(Duration::from_secs(60).as_micros()).unwrap();
    assert_eq!(
        challenges[0].next_attempt_at_micros,
        Some(expected),
        "the retry schedule is the deterministic first backoff after the frozen clock"
    );
}

#[tokio::test]
async fn a_stored_certificate_private_key_is_encrypted_and_never_in_a_dump() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let master = master_key(&env);
    let scope = db.seed_scope(&env).await;
    let (domain, challenge) =
        register(&db, &env, scope, "auth.example.com", ChallengeType::Http01).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .custom_domains()
        .record_challenge_result(&env, &challenge, &domain, ChallengeOutcome::Valid)
        .await
        .expect("verify");

    // A recognizable plaintext private-key marker so the dump assertion is real.
    let private_key_marker =
        b"-----BEGIN PRIVATE KEY-----\nSECRET-CDOM-KEY-MATERIAL\n-----END PRIVATE KEY-----";
    let bundle = private_key_marker.to_vec();
    let not_after = i64::try_from(Duration::from_secs(90 * 24 * 3600).as_micros()).unwrap();

    let secret_id = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .custom_domains()
        .store_certificate(&env, &master, &domain, &bundle, not_after)
        .await
        .expect("store certificate");

    // The domain now points at the sealed bundle and records the not-after.
    let read = db
        .store()
        .scoped(scope)
        .custom_domains()
        .get(&domain)
        .await
        .expect("read domain");
    assert_eq!(read.cert_secret_id.as_ref(), Some(&secret_id));
    assert_eq!(read.cert_not_after_micros, Some(not_after));

    // The sealed bundle round-trips back to the exact plaintext under the master.
    let opened = db
        .store()
        .scoped(scope)
        .envelope()
        .open_secret(&master, &format!("custom_domain_cert:{domain}"))
        .await
        .expect("open sealed cert");
    assert_eq!(opened, bundle);

    // A DATABASE DUMP (as the owner, bypassing row-level security) of the
    // encrypted_secrets ciphertext must NOT contain the plaintext key marker, and
    // the custom_domains row carries only the opaque handle, never key bytes.
    let ciphertext: Vec<u8> = sqlx::query(
        "SELECT ciphertext FROM encrypted_secrets \
         WHERE tenant_id = $1 AND environment_id = $2 AND purpose = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(format!("custom_domain_cert:{domain}"))
    .fetch_one(db.owner_pool())
    .await
    .expect("dump ciphertext")
    .get("ciphertext");
    assert!(
        !contains_subslice(&ciphertext, private_key_marker),
        "the private key must never appear in a dump of the ciphertext"
    );

    // The custom_domains dump carries the handle, not the key.
    let dumped_handle: String = sqlx::query(
        "SELECT cert_secret_id FROM custom_domains \
         WHERE tenant_id = $1 AND environment_id = $2 AND id = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(domain.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("dump domain row")
    .get("cert_secret_id");
    assert_eq!(dumped_handle, secret_id.to_string());
}

#[tokio::test]
async fn one_tenant_cannot_verify_another_tenants_verified_domain() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    // Two DISTINCT tenants (each seed_scope mints its own tenant + environment).
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    assert_ne!(scope_a.tenant(), scope_b.tenant(), "distinct tenants");

    // Tenant A registers and VERIFIES shared.example.com.
    let (domain_a, challenge_a) = register(
        &db,
        &env,
        scope_a,
        "shared.example.com",
        ChallengeType::Http01,
    )
    .await;
    db.store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .custom_domains()
        .record_challenge_result(&env, &challenge_a, &domain_a, ChallengeOutcome::Valid)
        .await
        .expect("tenant A verifies");

    // Tenant B may still REGISTER a pending claim (registration is not globally
    // exclusive), but its attempt to VERIFY the same name is refused by the global
    // verified-domain unique index.
    let (domain_b, challenge_b) = register(
        &db,
        &env,
        scope_b,
        "shared.example.com",
        ChallengeType::Http01,
    )
    .await;
    let err = db
        .store()
        .scoped(scope_b)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .custom_domains()
        .record_challenge_result(&env, &challenge_b, &domain_b, ChallengeOutcome::Valid)
        .await
        .expect_err("tenant B must not verify tenant A's verified domain");
    assert!(matches!(err, StoreError::Conflict), "got {err:?}");

    // The refusal rolled everything back: tenant B's domain is STILL pending, and
    // tenant A keeps its verified domain.
    let b_read = db
        .store()
        .scoped(scope_b)
        .custom_domains()
        .get(&domain_b)
        .await
        .expect("read B domain");
    assert_eq!(b_read.verification_status, VerificationStatus::Pending);
    let a_read = db
        .store()
        .scoped(scope_a)
        .custom_domains()
        .get(&domain_a)
        .await
        .expect("read A domain");
    assert_eq!(a_read.verification_status, VerificationStatus::Verified);
}

#[tokio::test]
async fn an_unsafe_or_malformed_domain_is_refused_before_it_is_written() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    for bad in [
        "localhost",
        "127.0.0.1",
        "http://auth.example.com",
        "auth.example.com:8443",
    ] {
        let domain = CustomDomainId::generate(&env, &scope);
        let challenge = AcmeChallengeId::generate(&env, &scope);
        let err = db
            .store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .custom_domains()
            .register(&env, &domain, bad, ChallengeType::Http01, &challenge, "tok")
            .await
            .expect_err("an unsafe domain must be refused");
        assert!(
            matches!(err, StoreError::InvalidCustomDomain),
            "{bad} should be InvalidCustomDomain, got {err:?}"
        );
    }

    // Nothing was written.
    let listed = db
        .store()
        .scoped(scope)
        .custom_domains()
        .list()
        .await
        .expect("list");
    assert!(listed.is_empty(), "no unsafe domain was persisted");
}

#[tokio::test]
async fn cross_tenant_exclusivity_is_case_and_trailing_dot_insensitive() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    // Three distinct tenants, each with its own environment.
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let scope_c = db.seed_scope(&env).await;
    assert_ne!(scope_a.tenant(), scope_b.tenant(), "distinct tenants");
    assert_ne!(scope_a.tenant(), scope_c.tenant(), "distinct tenants");

    // Tenant A registers with a mixed-case, trailing-dot input; it is stored in
    // the canonical normalized form, then verified.
    let (domain_a, challenge_a) =
        register(&db, &env, scope_a, "Example.COM.", ChallengeType::Http01).await;
    let a_read = db
        .store()
        .scoped(scope_a)
        .custom_domains()
        .get(&domain_a)
        .await
        .expect("read A domain");
    assert_eq!(
        a_read.domain_name, "example.com",
        "the domain is stored normalized (lowercase, no root dot)"
    );
    db.store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .custom_domains()
        .record_challenge_result(&env, &challenge_a, &domain_a, ChallengeOutcome::Valid)
        .await
        .expect("tenant A verifies");

    // A lookup in any case, with surrounding whitespace or a trailing dot, finds
    // the same registered row.
    for query in [
        "example.com",
        "EXAMPLE.COM",
        "Example.Com.",
        "  example.com.  ",
    ] {
        let found = db
            .store()
            .scoped(scope_a)
            .custom_domains()
            .get_by_name(query)
            .await
            .unwrap_or_else(|error| {
                panic!("lookup by {query:?} should find the domain: {error:?}")
            });
        assert_eq!(
            found.id, domain_a,
            "lookup by {query:?} finds the same domain"
        );
    }

    // Tenant B verifying the same DNS domain in a DIFFERENT case is refused by the
    // cross-tenant verified-domain unique index (the byte-exact index can no
    // longer be bypassed by case, because both rows are normalized).
    let (domain_b, challenge_b) =
        register(&db, &env, scope_b, "EXAMPLE.com", ChallengeType::Http01).await;
    assert_eq!(
        db.store()
            .scoped(scope_b)
            .custom_domains()
            .get(&domain_b)
            .await
            .expect("read B domain")
            .domain_name,
        "example.com",
        "tenant B's registration is normalized to the same canonical name"
    );
    let err = db
        .store()
        .scoped(scope_b)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .custom_domains()
        .record_challenge_result(&env, &challenge_b, &domain_b, ChallengeOutcome::Valid)
        .await
        .expect_err("a case-variant cross-tenant claim must be refused");
    assert!(matches!(err, StoreError::Conflict), "got {err:?}");

    // Tenant C claiming the same domain with a trailing root dot is likewise
    // refused: the trailing-dot form normalizes to the one true name.
    let (domain_c, challenge_c) =
        register(&db, &env, scope_c, "example.com.", ChallengeType::Http01).await;
    let err = db
        .store()
        .scoped(scope_c)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .custom_domains()
        .record_challenge_result(&env, &challenge_c, &domain_c, ChallengeOutcome::Valid)
        .await
        .expect_err("a trailing-dot cross-tenant claim must be refused");
    assert!(matches!(err, StoreError::Conflict), "got {err:?}");

    // Tenant A keeps sole ownership.
    assert_eq!(
        db.store()
            .scoped(scope_a)
            .custom_domains()
            .get(&domain_a)
            .await
            .expect("read A domain")
            .verification_status,
        VerificationStatus::Verified
    );
}

#[tokio::test]
async fn record_challenge_result_refuses_a_challenge_domain_mismatch() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    // Two domains in the same scope, each with its own challenge.
    let (domain_one, _challenge_one) =
        register(&db, &env, scope, "one.example.com", ChallengeType::Http01).await;
    let (domain_two, challenge_two) =
        register(&db, &env, scope, "two.example.com", ChallengeType::Http01).await;

    // Pairing domain_two's challenge with domain_one's id is refused for BOTH the
    // valid and the invalid paths, before any state is touched.
    for outcome in [ChallengeOutcome::Valid, ChallengeOutcome::Invalid] {
        let err = db
            .store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .custom_domains()
            .record_challenge_result(&env, &challenge_two, &domain_one, outcome)
            .await
            .expect_err("a challenge/domain mismatch must be refused");
        assert!(matches!(err, StoreError::NotFound), "got {err:?}");
    }

    // Nothing moved: both domains are still pending and the challenge is untouched.
    assert_eq!(
        db.store()
            .scoped(scope)
            .custom_domains()
            .get(&domain_one)
            .await
            .expect("read domain one")
            .verification_status,
        VerificationStatus::Pending
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .custom_domains()
            .get(&domain_two)
            .await
            .expect("read domain two")
            .verification_status,
        VerificationStatus::Pending
    );
    let ch = db
        .store()
        .scoped(scope)
        .custom_domains()
        .get_challenge(&challenge_two)
        .await
        .expect("read challenge two");
    assert_eq!(ch.status, ChallengeStatus::Pending);
    assert_eq!(
        ch.attempts, 0,
        "the mismatched result never bumped attempts"
    );

    // The matching (challenge_two, domain_two) pair still works.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .custom_domains()
        .record_challenge_result(&env, &challenge_two, &domain_two, ChallengeOutcome::Valid)
        .await
        .expect("the correctly-paired result succeeds");
    assert_eq!(
        db.store()
            .scoped(scope)
            .custom_domains()
            .get(&domain_two)
            .await
            .expect("read domain two")
            .verification_status,
        VerificationStatus::Verified
    );
}

#[tokio::test]
async fn store_certificate_refuses_an_unverified_domain() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let master = master_key(&env);
    let scope = db.seed_scope(&env).await;
    // Registered but NOT verified (still pending: no challenge succeeded).
    let (domain, _challenge) = register(
        &db,
        &env,
        scope,
        "pending.example.com",
        ChallengeType::Http01,
    )
    .await;

    let bundle =
        b"-----BEGIN PRIVATE KEY-----\nUNVERIFIED-CDOM-KEY\n-----END PRIVATE KEY-----".to_vec();
    let not_after = i64::try_from(Duration::from_secs(90 * 24 * 3600).as_micros()).unwrap();
    let err = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .custom_domains()
        .store_certificate(&env, &master, &domain, &bundle, not_after)
        .await
        .expect_err("a certificate for an unverified domain must be refused");
    assert!(matches!(err, StoreError::Conflict), "got {err:?}");

    // The domain still carries no certificate handle, and no orphan secret was
    // sealed (the gate rejects BEFORE sealing any key material).
    let read = db
        .store()
        .scoped(scope)
        .custom_domains()
        .get(&domain)
        .await
        .expect("read domain");
    assert!(
        read.cert_secret_id.is_none(),
        "an unverified domain gains no certificate"
    );
    let opened = db
        .store()
        .scoped(scope)
        .envelope()
        .open_secret(&master, &format!("custom_domain_cert:{domain}"))
        .await;
    assert!(opened.is_err(), "no orphan sealed secret should exist");
}

/// Whether `haystack` contains `needle` as a contiguous subslice.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
