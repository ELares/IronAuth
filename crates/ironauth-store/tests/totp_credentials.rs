// SPDX-License-Identifier: MIT OR Apache-2.0

//! TOTP and recovery-code persistence at the store layer (issue #69), against a
//! real database.
//!
//! These pin the security-critical store-side guarantees the endpoints depend on:
//!
//! - the RFC 6238 seed is SEALED at rest (a raw owner probe never sees the
//!   plaintext), and opens back to the exact seed under the tenant DEK;
//! - an abandoned enrollment stays PENDING and never becomes an active factor;
//! - single-use is a hard store invariant: a `(credential, time-step)` verifies at
//!   most once, and a replay at or below the last consumed step is refused;
//! - the drift resync offset is persisted on a successful verification;
//! - recovery codes are stored as one-way hashes, each redeemable exactly once,
//!   and a full regeneration invalidates every prior code;
//! - a TOTP verification and a recovery-code redemption are audited DISTINCTLY;
//! - another subject's credential is the uniform not-found;
//! - the exit export carries the opened seed and the recovery-code hashes.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    Action, CorrelationId, CredentialRemoveOutcome, NewRecoveryCode, NewTotpEnrollment,
    RecoveryRedeemOutcome, RestoredRecoveryCode, RestoredTotp, Scope, TotpActivateOutcome,
    TotpCredentialId, TotpVerifyOutcome, UserId,
};
use sqlx::Row;

const SEED: &[u8] = b"12345678901234567890"; // the RFC 6238 SHA1 test seed
const ARGON_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g";

/// A batch of `n` recovery codes to persist: distinct normalized plaintexts (so each
/// gets its own blind index) paired with the shared test hash. Redemption in these
/// tests is by id, so the hash need not match the normalized string.
fn recovery_batch(n: usize) -> Vec<(String, String)> {
    (0..n)
        .map(|i| (format!("recovery-normalized-{i}"), ARGON_HASH.to_owned()))
        .collect()
}

/// Borrow a [`recovery_batch`] as the `NewRecoveryCode` slice `replace_all` takes.
fn new_codes(batch: &[(String, String)]) -> Vec<NewRecoveryCode<'_>> {
    batch
        .iter()
        .map(|(code, hash)| NewRecoveryCode {
            normalized_code: code,
            code_hash: hash,
        })
        .collect()
}

async fn register_user(db: &TestDatabase, env: &Env, scope: Scope, handle: &str) -> UserId {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register(env, handle, ARGON_HASH)
        .await
        .expect("register user")
}

fn enrollment<'a>(seed: &'a [u8], name: &'a str) -> NewTotpEnrollment<'a> {
    NewTotpEnrollment {
        seed,
        friendly_name: name,
        algorithm: "SHA1",
        digits: 6,
        period_secs: 30,
    }
}

async fn begin(db: &TestDatabase, env: &Env, scope: Scope, subject: &UserId) -> TotpCredentialId {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .totp_credentials()
        .begin_enroll(env, subject, &enrollment(SEED, "my phone"))
        .await
        .expect("begin enroll")
}

#[tokio::test]
async fn enroll_seals_the_seed_and_stays_pending_until_activated() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, "alice@example.test").await;

    let id = begin(&db, &env, scope, &subject).await;

    // The seed is SEALED at rest: a raw owner probe never sees the plaintext seed.
    let raw: Vec<u8> = sqlx::query("SELECT totp_seed FROM totp_credentials WHERE id = $1")
        .bind(id.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("raw probe")
        .get("totp_seed");
    assert_ne!(raw.as_slice(), SEED, "the stored seed must be ciphertext");
    assert!(
        raw.windows(SEED.len()).all(|w| w != SEED),
        "the plaintext seed must not appear anywhere in the sealed column"
    );

    // The status is pending: an abandoned enrollment is NOT an active factor.
    let status: String = sqlx::query("SELECT status FROM totp_credentials WHERE id = $1")
        .bind(id.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("status")
        .get("status");
    assert_eq!(status, "pending");
    // No ACTIVE factor exists yet.
    assert!(
        db.store()
            .scoped(scope)
            .totp_credentials()
            .open_active_material(&subject)
            .await
            .expect("open active")
            .is_none(),
        "a pending enrollment must not resolve as an active factor"
    );

    // The seed opens back to the exact plaintext under the tenant DEK (verify path).
    let material = db
        .store()
        .scoped(scope)
        .totp_credentials()
        .open_material(&subject, &id)
        .await
        .expect("open material")
        .expect("material present");
    assert_eq!(material.seed, SEED, "the seed opens back to the plaintext");
    assert_eq!(material.status, "pending");

    // Activation flips it to active and seeds the single-use step.
    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .totp_credentials()
        .activate(&env, &subject, &id, 100)
        .await
        .expect("activate");
    assert_eq!(outcome, TotpActivateOutcome::Activated);
    assert!(
        db.store()
            .scoped(scope)
            .totp_credentials()
            .open_active_material(&subject)
            .await
            .expect("open active")
            .is_some(),
        "an activated factor resolves as active"
    );
}

#[tokio::test]
async fn single_use_replay_is_rejected_and_drift_offset_is_resynced() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, "bob@example.test").await;
    let id = begin(&db, &env, scope, &subject).await;
    let acting = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };
    acting()
        .totp_credentials()
        .activate(&env, &subject, &id, 100)
        .await
        .expect("activate");

    // A verification at a NEWER step succeeds and records the drift offset.
    let first = acting()
        .totp_credentials()
        .record_verification(&env, &subject, &id, 101, 1)
        .await
        .expect("record 101");
    assert_eq!(first, TotpVerifyOutcome::Verified);
    let offset: i32 = sqlx::query("SELECT last_offset FROM totp_credentials WHERE id = $1")
        .bind(id.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("offset")
        .get("last_offset");
    assert_eq!(offset, 1, "the resync offset is persisted");

    // A REPLAY of the same step is refused (single-use).
    let replay = acting()
        .totp_credentials()
        .record_verification(&env, &subject, &id, 101, 1)
        .await
        .expect("replay 101");
    assert_eq!(replay, TotpVerifyOutcome::Replay);

    // An EARLIER in-window step is also refused (cannot rewind the single-use spine).
    let earlier = acting()
        .totp_credentials()
        .record_verification(&env, &subject, &id, 100, -1)
        .await
        .expect("earlier 100");
    assert_eq!(earlier, TotpVerifyOutcome::Replay);

    // A later step (the drifted client's next code) is accepted, tracking the skew.
    let next = acting()
        .totp_credentials()
        .record_verification(&env, &subject, &id, 102, 2)
        .await
        .expect("record 102");
    assert_eq!(next, TotpVerifyOutcome::Verified);
}

#[tokio::test]
async fn recovery_codes_are_single_use_and_regeneration_invalidates_prior() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, "carol@example.test").await;
    let acting = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };
    // Store a batch of codes (the store persists the one-way hashes and the blind
    // index derived from each normalized code).
    let batch = recovery_batch(10);
    acting()
        .recovery_codes()
        .replace_all(&env, &subject, &new_codes(&batch))
        .await
        .expect("replace");
    assert_eq!(
        db.store()
            .scoped(scope)
            .recovery_codes()
            .remaining_count(&subject)
            .await
            .expect("count"),
        10
    );
    // The codes are stored as HASHES (a raw probe shows the PHC, never a plaintext).
    let stored: String =
        sqlx::query("SELECT code_hash FROM recovery_codes WHERE subject = $1 ORDER BY id LIMIT 1")
            .bind(subject.to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("hash probe")
            .get("code_hash");
    assert!(stored.starts_with("$argon2"), "codes are stored hashed");

    // Redeem one code: single-use. A second redeem of the SAME id is not-found.
    let first_id = db
        .store()
        .scoped(scope)
        .recovery_codes()
        .unconsumed(&subject)
        .await
        .expect("unconsumed")[0]
        .id;
    assert_eq!(
        acting()
            .recovery_codes()
            .redeem(&env, &subject, &first_id)
            .await
            .expect("redeem"),
        RecoveryRedeemOutcome::Redeemed
    );
    assert_eq!(
        acting()
            .recovery_codes()
            .redeem(&env, &subject, &first_id)
            .await
            .expect("redeem twice"),
        RecoveryRedeemOutcome::NotFound
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .recovery_codes()
            .remaining_count(&subject)
            .await
            .expect("count after redeem"),
        9
    );

    // Regeneration invalidates ALL prior codes: the old id is gone entirely.
    acting()
        .recovery_codes()
        .replace_all(&env, &subject, &new_codes(&batch))
        .await
        .expect("regenerate");
    assert_eq!(
        db.store()
            .scoped(scope)
            .recovery_codes()
            .remaining_count(&subject)
            .await
            .expect("count after regen"),
        10,
        "a fresh full batch after regeneration"
    );
    let survivors: i64 = sqlx::query("SELECT count(*) AS n FROM recovery_codes WHERE id = $1")
        .bind(first_id.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("survivor probe")
        .get("n");
    assert_eq!(survivors, 0, "a prior code does not survive regeneration");
}

#[tokio::test]
async fn totp_verify_and_recovery_redeem_are_audited_distinctly() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, "dave@example.test").await;
    let acting = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };
    let id = begin(&db, &env, scope, &subject).await;
    acting()
        .totp_credentials()
        .activate(&env, &subject, &id, 100)
        .await
        .expect("activate");
    acting()
        .totp_credentials()
        .record_verification(&env, &subject, &id, 101, 0)
        .await
        .expect("verify");
    let batch = recovery_batch(1);
    acting()
        .recovery_codes()
        .replace_all(&env, &subject, &new_codes(&batch))
        .await
        .expect("replace");
    let rvc = db
        .store()
        .scoped(scope)
        .recovery_codes()
        .unconsumed(&subject)
        .await
        .expect("unconsumed")[0]
        .id;
    acting()
        .recovery_codes()
        .redeem(&env, &subject, &rvc)
        .await
        .expect("redeem");

    // The two second-factor paths write DISTINCT audit actions.
    for action in [
        Action::TotpActivate,
        Action::TotpVerify,
        Action::RecoveryCodesGenerate,
        Action::RecoveryCodeRedeem,
    ] {
        let count: i64 = sqlx::query("SELECT count(*) AS n FROM audit_log WHERE action = $1")
            .bind(action.as_str())
            .fetch_one(db.owner_pool())
            .await
            .expect("audit count")
            .get("n");
        assert!(count >= 1, "expected an audit row for {}", action.as_str());
    }
    // A TOTP verify is NEVER conflated with a recovery redemption.
    assert_ne!(
        Action::TotpVerify.as_str(),
        Action::RecoveryCodeRedeem.as_str()
    );
}

#[tokio::test]
async fn another_subjects_factor_is_the_uniform_not_found() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let alice = register_user(&db, &env, scope, "alice2@example.test").await;
    let mallory = register_user(&db, &env, scope, "mallory@example.test").await;
    let id = begin(&db, &env, scope, &alice).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .totp_credentials()
        .activate(&env, &alice, &id, 100)
        .await
        .expect("activate");

    // Mallory cannot open, verify against, or remove Alice's factor.
    assert!(
        db.store()
            .scoped(scope)
            .totp_credentials()
            .open_material(&mallory, &id)
            .await
            .expect("open")
            .is_none()
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .totp_credentials()
            .record_verification(&env, &mallory, &id, 200, 0)
            .await
            .expect("verify"),
        TotpVerifyOutcome::NotFound
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .totp_credentials()
            .remove(&env, &mallory, &id)
            .await
            .expect("remove"),
        CredentialRemoveOutcome::NotFound
    );
}

#[tokio::test]
async fn the_exit_export_carries_the_opened_seed_and_recovery_hashes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, "erin@example.test").await;
    let acting = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };
    let id = begin(&db, &env, scope, &subject).await;
    acting()
        .totp_credentials()
        .activate(&env, &subject, &id, 100)
        .await
        .expect("activate");
    let batch = recovery_batch(2);
    acting()
        .recovery_codes()
        .replace_all(&env, &subject, &new_codes(&batch))
        .await
        .expect("replace");

    let page = db
        .store()
        .scoped(scope)
        .users()
        .export_page(None, 100)
        .await
        .expect("export");
    let record = page
        .iter()
        .find(|r| r.id == subject)
        .expect("subject in export");
    // The TOTP factor is exported with its OPENED seed (the covenant secret).
    assert_eq!(record.totp.len(), 1);
    let exported = &record.totp[0];
    assert_eq!(exported.status, "active");
    let decoded = ironauth_jose::base32_decode(&exported.seed_base32).expect("decode seed");
    assert_eq!(decoded, SEED, "the export round-trips the exact seed");
    // The recovery-code hashes are carried (one-way, like a password verifier).
    assert_eq!(record.recovery_codes.len(), 2);
    assert!(
        record
            .recovery_codes
            .iter()
            .all(|c| c.code_hash.starts_with("$argon2")),
        "recovery codes export as hashes, never plaintext"
    );
}

/// LOW-4: the seed seal AAD binds the credential id, so a seed sealed for one row
/// cannot be transplanted into another subject's row and still open. A privileged
/// same-scope DB write that lifts Alice's sealed seed (and its DEK version) into Bob's
/// row must FAIL to open, not silently authenticate under Bob.
#[tokio::test]
async fn a_seed_sealed_for_one_row_does_not_open_in_another() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let alice = register_user(&db, &env, scope, "aad-alice@example.test").await;
    let bob = register_user(&db, &env, scope, "aad-bob@example.test").await;
    let alice_id = begin(&db, &env, scope, &alice).await;
    let bob_id = begin(&db, &env, scope, &bob).await;

    // Alice's sealed seed and the DEK version it was sealed under.
    let alice_row =
        sqlx::query("SELECT totp_seed, pii_dek_version FROM totp_credentials WHERE id = $1")
            .bind(alice_id.to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("alice row");
    let alice_seed: Vec<u8> = alice_row.get("totp_seed");
    let alice_dek: i32 = alice_row.get("pii_dek_version");

    // A privileged same-scope write transplants Alice's sealed seed into Bob's row.
    sqlx::query("UPDATE totp_credentials SET totp_seed = $1, pii_dek_version = $2 WHERE id = $3")
        .bind(&alice_seed)
        .bind(alice_dek)
        .bind(bob_id.to_string())
        .execute(db.owner_pool())
        .await
        .expect("transplant");

    // Opening Bob's row now FAILS: the AAD binds Bob's credential id, but the
    // ciphertext was sealed under Alice's id, so authentication does not match.
    let opened = db
        .store()
        .scoped(scope)
        .totp_credentials()
        .open_material(&bob, &bob_id)
        .await;
    assert!(
        opened.is_err(),
        "a seed sealed for Alice's row must not open in Bob's row: {opened:?}"
    );
}

/// INFO-5: removing a TOTP factor cascades to the subject's recovery codes, so a
/// leaked recovery code is not redeemable after the authenticator is gone.
#[tokio::test]
async fn removing_the_totp_factor_deletes_the_recovery_codes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, "cascade@example.test").await;
    let acting = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };
    let id = begin(&db, &env, scope, &subject).await;
    acting()
        .totp_credentials()
        .activate(&env, &subject, &id, 100)
        .await
        .expect("activate");
    let batch = recovery_batch(8);
    acting()
        .recovery_codes()
        .replace_all(&env, &subject, &new_codes(&batch))
        .await
        .expect("replace");
    assert_eq!(
        db.store()
            .scoped(scope)
            .recovery_codes()
            .remaining_count(&subject)
            .await
            .expect("count"),
        8
    );

    // Remove the factor: the recovery codes go with it, in the same transaction.
    assert_eq!(
        acting()
            .totp_credentials()
            .remove(&env, &subject, &id)
            .await
            .expect("remove"),
        CredentialRemoveOutcome::Removed
    );
    let survivors: i64 = sqlx::query("SELECT count(*) AS n FROM recovery_codes WHERE subject = $1")
        .bind(subject.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("survivor probe")
        .get("n");
    assert_eq!(
        survivors, 0,
        "a prior recovery code must not survive TOTP removal"
    );
}

/// HIGH-1 (store layer): a restored TOTP factor re-seals under the target DEK and
/// OPENS back to the EXACT original seed, so a code from the original authenticator
/// verifies against the re-imported factor (the covenant re-homes the second factor,
/// not a metadata echo). Restored recovery codes stay redeemable.
#[tokio::test]
async fn a_restored_totp_and_recovery_codes_round_trip() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, "restore@example.test").await;
    let acting = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };

    // Restore an ACTIVE factor with the original seed and single-use position.
    let restored = RestoredTotp {
        seed: SEED,
        friendly_name: "imported authenticator",
        algorithm: "SHA1",
        digits: 6,
        period_secs: 30,
        status: "active",
        last_consumed_step: Some(100),
    };
    let id = acting()
        .totp_credentials()
        .restore(&env, &subject, &restored)
        .await
        .expect("restore totp");

    // The seed is sealed at rest but opens back to the EXACT plaintext, so a code from
    // the original authenticator verifies here.
    let raw: Vec<u8> = sqlx::query("SELECT totp_seed FROM totp_credentials WHERE id = $1")
        .bind(id.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("raw probe")
        .get("totp_seed");
    assert_ne!(
        raw.as_slice(),
        SEED,
        "the restored seed is re-sealed at rest"
    );
    let material = db
        .store()
        .scoped(scope)
        .totp_credentials()
        .open_active_material(&subject)
        .await
        .expect("open active")
        .expect("active factor present");
    assert_eq!(
        material.seed, SEED,
        "the restored seed opens to the original"
    );
    assert_eq!(material.status, "active");
    assert_eq!(
        material.last_consumed_step,
        Some(100),
        "the single-use position round-trips"
    );

    // Restore a recovery code (only the one-way hash survives an export; the blind
    // index is NULL). It stays redeemable through the NULL-index fallback.
    acting()
        .recovery_codes()
        .restore_all(
            &env,
            &subject,
            &[RestoredRecoveryCode {
                code_hash: ARGON_HASH.to_owned(),
                consumed: false,
            }],
        )
        .await
        .expect("restore recovery");
    let candidates = db
        .store()
        .scoped(scope)
        .recovery_codes()
        .candidates_for_code(&subject, "any-presented-code")
        .await
        .expect("candidates");
    assert_eq!(
        candidates.len(),
        1,
        "an imported (NULL-index) code is always a redemption candidate"
    );
    assert_eq!(
        acting()
            .recovery_codes()
            .redeem(&env, &subject, &candidates[0].id)
            .await
            .expect("redeem"),
        RecoveryRedeemOutcome::Redeemed,
        "a re-imported recovery code redeems once"
    );
}

/// LOW-3: redemption resolves ONE candidate for a natively generated code via the
/// blind index, so a right code costs a single Argon2 verify and a wrong code costs
/// none, rather than scanning the whole set.
#[tokio::test]
async fn recovery_redemption_narrows_to_a_single_candidate_by_blind_index() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, "bidx@example.test").await;
    let acting = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };
    let batch = recovery_batch(16);
    acting()
        .recovery_codes()
        .replace_all(&env, &subject, &new_codes(&batch))
        .await
        .expect("replace");

    // A code that exists narrows to exactly its ONE row (a single hash to verify),
    // never the full 16-code set.
    let one = db
        .store()
        .scoped(scope)
        .recovery_codes()
        .candidates_for_code(&subject, "recovery-normalized-7")
        .await
        .expect("candidates for a real code");
    assert_eq!(
        one.len(),
        1,
        "a natively generated code resolves to exactly one candidate"
    );
    // A wrong code narrows to NONE (no NULL-index imported codes exist here), so a
    // wrong guess costs zero Argon2 verifications.
    let none = db
        .store()
        .scoped(scope)
        .recovery_codes()
        .candidates_for_code(&subject, "not-a-real-code")
        .await
        .expect("candidates for a wrong code");
    assert!(
        none.is_empty(),
        "a wrong code resolves to no candidate: no Argon2 amplification"
    );
}
