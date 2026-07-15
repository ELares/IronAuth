// SPDX-License-Identifier: MIT OR Apache-2.0

//! Flexible identifiers on the central canonicalization seam (issue #54), over a
//! real database (`DATABASE_URL`).
//!
//! Proves the acceptance criteria at the persistence layer: the
//! canonicalization-mismatch CVE class fails to reproduce (Unicode invisibles,
//! mixed case, and fullwidth homoglyphs behave identically across resolution and
//! uniqueness), all three uniqueness modes behave, a post-canonicalization collision
//! is rejected, identifier-first resolution returns only the methods applicable to
//! the resolved account, the mode-change validation pass reports collisions, and the
//! identifier value never lands in a database dump as plaintext.

use ironauth_env::Env;
use ironauth_store::identifier::{IdentifierType, UniquenessMode};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, CredentialType, LoginMethod, NewAdminUser, NewUserIdentifier, Scope, StoreError,
    UserId, UserState,
};
use sqlx::Row;

const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";

/// Register a bootstrap user with a usable password in `scope`, returning its id.
async fn register_user(db: &TestDatabase, env: &Env, scope: Scope, handle: &str) -> UserId {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register(env, handle, PASSWORD_HASH)
        .await
        .expect("register user")
}

/// Create an ACTIVE user with NO password (credential-less), returning its id. Used
/// to prove passkey-only resolution: `register` always sets a usable password, so a
/// password-free account can only be minted through the admin create path.
async fn register_passwordless_user(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    handle: &str,
) -> UserId {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .admin_create(
            env,
            NewAdminUser {
                id: None,
                identifier: handle,
                password_hash: None,
                claims_json: None,
                external_id: None,
                state: UserState::Active,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits_json: None,
                traits_schema_version: None,
            },
            0,
            None,
        )
        .await
        .expect("admin_create passwordless user")
}

/// Add a typed login identifier to `user` in `scope` under `mode` (org = None).
async fn add_identifier(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    user: &UserId,
    kind: IdentifierType,
    raw: &str,
    mode: UniquenessMode,
) -> Result<(), StoreError> {
    add_identifier_org(db, env, scope, user, kind, raw, mode, None).await
}

/// Add a typed login identifier to `user` in `scope` under `mode` and `org`.
#[allow(clippy::too_many_arguments)]
async fn add_identifier_org(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    user: &UserId,
    kind: IdentifierType,
    raw: &str,
    mode: UniquenessMode,
    org: Option<&str>,
) -> Result<(), StoreError> {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .user_identifiers()
        .add(
            env,
            NewUserIdentifier {
                user_id: user,
                identifier_type: kind,
                raw,
                verified: false,
                mode,
                org,
            },
        )
        .await
        .map(|_| ())
}

/// Apply a uniqueness-mode change to `scope`.
async fn apply_mode(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    mode: UniquenessMode,
) -> Result<(), StoreError> {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .user_identifiers()
        .apply_uniqueness_mode(env, mode)
        .await
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// The canonicalization-mismatch CVE class fails to reproduce.

#[tokio::test]
async fn variants_that_canonicalize_identically_are_one_identifier_for_resolution() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x54);
    let scope = db.seed_scope(&env).await;
    let user = register_user(&db, &env, scope, "u1").await;

    // Register ONE email, in a plain spelling.
    add_identifier(
        &db,
        &env,
        scope,
        &user,
        IdentifierType::Email,
        "Ada.Lovelace@Example.com",
        UniquenessMode::EnvironmentWide,
    )
    .await
    .expect("add email");

    // Every adversarial spelling of that email resolves to the same account: a
    // mixed-case form, a zero-width-space-padded form, a fullwidth-homoglyph form,
    // and a bidi-override form. This is the CVE class (per-endpoint normalization);
    // it must not reproduce.
    let variants = [
        "ada.lovelace@example.com",
        "ADA.LOVELACE@EXAMPLE.COM",
        "ada.lovelace@example.com\u{200B}",
        "\u{FEFF}Ada.Lovelace@Example.com",
        "\u{FF41}\u{FF44}\u{FF41}.lovelace@example.com", // fullwidth "ada"
        "ada.lovelace\u{202E}@example.com",
    ];
    for variant in variants {
        let hits = db
            .store()
            .scoped(scope)
            .user_identifiers()
            .resolve(IdentifierType::Email, variant)
            .await
            .expect("resolve");
        assert_eq!(
            hits.len(),
            1,
            "variant {variant:?} must resolve to exactly the one account"
        );
        assert_eq!(hits[0].user_id, user, "variant {variant:?} resolves to u1");
    }

    // A genuinely different email resolves to nothing.
    let none = db
        .store()
        .scoped(scope)
        .user_identifiers()
        .resolve(IdentifierType::Email, "someone.else@example.com")
        .await
        .expect("resolve");
    assert!(none.is_empty(), "an unregistered email resolves to nothing");
}

#[tokio::test]
async fn a_canonically_equal_variant_collides_on_uniqueness() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x55);
    let scope = db.seed_scope(&env).await;
    let user_a = register_user(&db, &env, scope, "a").await;
    let user_b = register_user(&db, &env, scope, "b").await;

    add_identifier(
        &db,
        &env,
        scope,
        &user_a,
        IdentifierType::Email,
        "grace@example.com",
        UniquenessMode::EnvironmentWide,
    )
    .await
    .expect("first add");

    // A different raw spelling that canonicalizes to the SAME value is a
    // post-canonicalization collision and is rejected with the deterministic
    // conflict, even for a different user.
    let collision = add_identifier(
        &db,
        &env,
        scope,
        &user_b,
        IdentifierType::Email,
        "  GRACE@Example.com\u{200B}  ",
        UniquenessMode::EnvironmentWide,
    )
    .await;
    assert!(
        matches!(collision, Err(StoreError::Conflict)),
        "a canonically-equal identifier must be rejected as a conflict, got {collision:?}"
    );
}

// ---------------------------------------------------------------------------
// Uniqueness as configuration: all three modes.

#[tokio::test]
async fn environment_wide_is_the_default_and_rejects_duplicates() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x56);
    let scope = db.seed_scope(&env).await;
    let a = register_user(&db, &env, scope, "a").await;
    let b = register_user(&db, &env, scope, "b").await;

    add_identifier(
        &db,
        &env,
        scope,
        &a,
        IdentifierType::Username,
        "shared",
        UniquenessMode::EnvironmentWide,
    )
    .await
    .expect("first");
    let dup = add_identifier(
        &db,
        &env,
        scope,
        &b,
        IdentifierType::Username,
        "SHARED",
        UniquenessMode::EnvironmentWide,
    )
    .await;
    assert!(
        matches!(dup, Err(StoreError::Conflict)),
        "environment-wide mode rejects the duplicate, got {dup:?}"
    );
}

#[tokio::test]
async fn org_scoped_with_no_membership_falls_back_to_environment_scope() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x57);
    let scope = db.seed_scope(&env).await;
    let a = register_user(&db, &env, scope, "a").await;
    let b = register_user(&db, &env, scope, "b").await;

    // Under org-scoped mode, membership-free users (org = None, the M10-absent
    // reality) are checked against the environment scope, so a duplicate still
    // conflicts, exactly as the default mode does.
    add_identifier(
        &db,
        &env,
        scope,
        &a,
        IdentifierType::Email,
        "team@example.com",
        UniquenessMode::OrgScoped,
    )
    .await
    .expect("first");
    let dup = add_identifier(
        &db,
        &env,
        scope,
        &b,
        IdentifierType::Email,
        "team@example.com",
        UniquenessMode::OrgScoped,
    )
    .await;
    assert!(
        matches!(dup, Err(StoreError::Conflict)),
        "org-scoped membership-free fallback rejects the duplicate, got {dup:?}"
    );
}

#[tokio::test]
async fn non_unique_mode_allows_duplicates_and_resolves_all_of_them() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x58);
    let scope = db.seed_scope(&env).await;
    let a = register_user(&db, &env, scope, "a").await;
    let b = register_user(&db, &env, scope, "b").await;

    // Two accounts share one email under non-unique mode.
    add_identifier(
        &db,
        &env,
        scope,
        &a,
        IdentifierType::Email,
        "family@example.com",
        UniquenessMode::NonUnique,
    )
    .await
    .expect("first non-unique add");
    add_identifier(
        &db,
        &env,
        scope,
        &b,
        IdentifierType::Email,
        "Family@example.com",
        UniquenessMode::NonUnique,
    )
    .await
    .expect("second non-unique add is allowed");

    // Identifier-first login still resolves deterministically: it returns BOTH
    // accounts (the M7 factor step disambiguates), in a stable order.
    let hits = db
        .store()
        .scoped(scope)
        .user_identifiers()
        .resolve(IdentifierType::Email, "FAMILY@EXAMPLE.COM")
        .await
        .expect("resolve");
    assert_eq!(
        hits.len(),
        2,
        "non-unique mode resolves both shared accounts"
    );
    let mut users: Vec<UserId> = hits.iter().map(|h| h.user_id).collect();
    users.sort_by_key(std::string::ToString::to_string);
    let mut expected = vec![a, b];
    expected.sort_by_key(std::string::ToString::to_string);
    assert_eq!(users, expected, "both shared accounts resolve");
}

// ---------------------------------------------------------------------------
// Identifier-first resolution returns only the applicable methods.

#[tokio::test]
async fn resolution_returns_only_the_methods_the_account_actually_has() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x59);
    let scope = db.seed_scope(&env).await;

    // A user with only a password.
    let pw_only = register_user(&db, &env, scope, "pw").await;
    add_identifier(
        &db,
        &env,
        scope,
        &pw_only,
        IdentifierType::Username,
        "pwuser",
        UniquenessMode::EnvironmentWide,
    )
    .await
    .expect("add");
    let hits = db
        .store()
        .scoped(scope)
        .user_identifiers()
        .resolve(IdentifierType::Username, "pwuser")
        .await
        .expect("resolve");
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].methods,
        vec![LoginMethod::Password],
        "a password-only account offers exactly the password method"
    );

    // Enroll a passkey for the same user; resolution now offers both, in a stable
    // order (password before passkey).
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .account_credentials()
        .enroll(&env, &pw_only, CredentialType::Passkey, "my key", "none")
        .await
        .expect("enroll passkey");
    let hits = db
        .store()
        .scoped(scope)
        .user_identifiers()
        .resolve(IdentifierType::Username, "pwuser")
        .await
        .expect("resolve");
    assert_eq!(
        hits[0].methods,
        vec![LoginMethod::Password, LoginMethod::Passkey],
        "after enrolling a passkey the account offers both methods, in order"
    );
}

// ---------------------------------------------------------------------------
// The mode-change validation pass reports collisions before the change applies.

#[tokio::test]
async fn mode_change_validation_pass_reports_post_canonicalization_collisions() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5A);
    let scope = db.seed_scope(&env).await;
    let a = register_user(&db, &env, scope, "a").await;
    let b = register_user(&db, &env, scope, "b").await;

    // Populate a duplicate under non-unique mode (allowed), so switching to a
    // uniqueness-enforcing mode WOULD collide.
    add_identifier(
        &db,
        &env,
        scope,
        &a,
        IdentifierType::Email,
        "dup@example.com",
        UniquenessMode::NonUnique,
    )
    .await
    .expect("first");
    add_identifier(
        &db,
        &env,
        scope,
        &b,
        IdentifierType::Email,
        "DUP@example.com",
        UniquenessMode::NonUnique,
    )
    .await
    .expect("second");

    // Non-unique mode never collides.
    let none = db
        .store()
        .scoped(scope)
        .user_identifiers()
        .collisions_for_mode(UniquenessMode::NonUnique)
        .await
        .expect("collision scan");
    assert!(none.is_empty(), "non-unique mode reports no collisions");

    // Switching to environment-wide (or org-scoped, which falls back to it) would
    // enforce uniqueness and is reported BEFORE the change applies.
    let collisions = db
        .store()
        .scoped(scope)
        .user_identifiers()
        .collisions_for_mode(UniquenessMode::EnvironmentWide)
        .await
        .expect("collision scan");
    assert_eq!(
        collisions.len(),
        1,
        "one colliding canonical form is reported"
    );
    assert_eq!(collisions[0].identifier_type, IdentifierType::Email);
    assert_eq!(
        collisions[0].count, 2,
        "two accounts share the canonical form"
    );
}

// ---------------------------------------------------------------------------
// The identifier value is sealed and blind-indexed: no plaintext in a dump.

#[tokio::test]
async fn a_database_dump_of_user_identifiers_carries_no_plaintext() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5B);
    let scope = db.seed_scope(&env).await;
    let user = register_user(&db, &env, scope, "u").await;

    let raw = "Secret.Person@example.com";
    add_identifier(
        &db,
        &env,
        scope,
        &user,
        IdentifierType::Email,
        raw,
        UniquenessMode::EnvironmentWide,
    )
    .await
    .expect("add");

    // What a stolen backup sees: the sealed raw value and the canonical blind index,
    // neither of which contains the plaintext handle (or its canonical form) verbatim.
    let row = sqlx::query(
        "SELECT canonical_bidx, raw_sealed FROM user_identifiers \
         WHERE tenant_id = $1 AND environment_id = $2 AND user_id = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(user.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("dump row");
    let bidx: Vec<u8> = row.get("canonical_bidx");
    let sealed: Vec<u8> = row.get("raw_sealed");
    assert!(
        !contains(&sealed, raw.as_bytes()),
        "the sealed raw identifier must not contain the plaintext handle"
    );
    assert!(
        !contains(&sealed, b"secret.person@example.com"),
        "nor the canonical form"
    );
    assert!(
        !contains(&bidx, b"secret.person@example.com"),
        "the blind index must not contain the canonical plaintext"
    );

    // The list read decrypts the RAW value back for display, exactly as typed.
    let list = db
        .store()
        .scoped(scope)
        .user_identifiers()
        .list_for_user(&user)
        .await
        .expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].raw, raw, "the raw value round-trips for display");
    assert_eq!(list[0].identifier_type, IdentifierType::Email);
}

// ---------------------------------------------------------------------------
// Cross-tenant isolation of the blind index.

#[tokio::test]
async fn the_same_identifier_does_not_collide_or_leak_across_tenants() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5C);
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let user_a = register_user(&db, &env, scope_a, "a").await;
    let user_b = register_user(&db, &env, scope_b, "b").await;

    // The SAME identifier in two tenants is two independent rows (no cross-tenant
    // uniqueness collision).
    add_identifier(
        &db,
        &env,
        scope_a,
        &user_a,
        IdentifierType::Email,
        "same@example.com",
        UniquenessMode::EnvironmentWide,
    )
    .await
    .expect("tenant a");
    add_identifier(
        &db,
        &env,
        scope_b,
        &user_b,
        IdentifierType::Email,
        "same@example.com",
        UniquenessMode::EnvironmentWide,
    )
    .await
    .expect("tenant b add is independent");

    // Tenant A resolves only its own account; tenant B resolves only its own.
    let hits_a = db
        .store()
        .scoped(scope_a)
        .user_identifiers()
        .resolve(IdentifierType::Email, "same@example.com")
        .await
        .expect("resolve a");
    assert_eq!(hits_a.len(), 1);
    assert_eq!(hits_a[0].user_id, user_a);
}

// ---------------------------------------------------------------------------
// HIGH 1: the invisible-character survivors of the old curated list now COLLIDE
// end-to-end against Postgres (they canonicalize to the same value, so the partial
// unique index rejects the second one).

#[tokio::test]
async fn invisible_variant_survivors_collide_under_environment_wide() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x60);
    let scope = db.seed_scope(&env).await;

    // Each of these code points made "admin" and an invisibly-padded spelling two
    // DIFFERENT canonical forms under the old curated strip (defeating the default
    // uniqueness mode). Now each is stripped, so the padded spelling collides with the
    // clean "admin" on the partial unique index.
    let survivors = [
        ("cgj", '\u{034F}'),     // U+034F COMBINING GRAPHEME JOINER (Mn, not Cf)
        ("gap", '\u{2065}'),     // U+2065 (the 2060..2064 / 2066..206F list gap, Cn)
        ("linesep", '\u{2028}'), // U+2028 LINE SEPARATOR (Zl, not is_control)
        ("parasep", '\u{2029}'), // U+2029 PARAGRAPH SEPARATOR (Zp, not is_control)
        ("nbsp", '\u{00A0}'),    // internal NO-BREAK SPACE (survives a trim-only pass)
    ];
    for (label, invisible) in survivors {
        // A fresh clean handle per case (a unique username per iteration), and its
        // invisibly-padded spelling: the same characters with the invisible inserted
        // in the middle. They must canonicalize to ONE form.
        let owner = register_user(&db, &env, scope, &format!("owner{label}")).await;
        let intruder = register_user(&db, &env, scope, &format!("intruder{label}")).await;
        let clean = format!("handle{label}");
        let mid = clean.len() / 2;
        let padded = format!("{}{}{}", &clean[..mid], invisible, &clean[mid..]);
        add_identifier(
            &db,
            &env,
            scope,
            &owner,
            IdentifierType::Username,
            &clean,
            UniquenessMode::EnvironmentWide,
        )
        .await
        .unwrap_or_else(|e| panic!("{label}: clean add failed: {e:?}"));
        let collision = add_identifier(
            &db,
            &env,
            scope,
            &intruder,
            IdentifierType::Username,
            &padded,
            UniquenessMode::EnvironmentWide,
        )
        .await;
        assert!(
            matches!(collision, Err(StoreError::Conflict)),
            "{label}: the invisibly-padded spelling must collide with the clean handle, got {collision:?}"
        );
        // And the padded spelling resolves to the clean owner (one identity).
        let hits = db
            .store()
            .scoped(scope)
            .user_identifiers()
            .resolve(IdentifierType::Username, &padded)
            .await
            .expect("resolve");
        assert_eq!(
            hits.len(),
            1,
            "{label}: padded spelling resolves to one account"
        );
        assert_eq!(
            hits[0].user_id, owner,
            "{label}: resolves to the clean owner"
        );
    }
}

// ---------------------------------------------------------------------------
// MEDIUM 3: a degenerate (empty) or malformed canonical form is not a squattable
// identifier.

#[tokio::test]
async fn an_all_invisible_or_empty_identifier_is_refused_at_add() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x61);
    let scope = db.seed_scope(&env).await;
    let user = register_user(&db, &env, scope, "u").await;

    // An all-invisible submission canonicalizes to the EMPTY form and must be refused,
    // so it cannot squat the empty slot and resolve to this account.
    for raw in ["", "   \t  ", "\u{200B}\u{2065}\u{FEFF}\u{2028}"] {
        let rejected = add_identifier(
            &db,
            &env,
            scope,
            &user,
            IdentifierType::Username,
            raw,
            UniquenessMode::EnvironmentWide,
        )
        .await;
        assert!(
            matches!(rejected, Err(StoreError::InvalidIdentifier)),
            "an empty/all-invisible identifier {raw:?} must be refused, got {rejected:?}"
        );
    }

    // Nothing was stored, so a resolve of the empty form returns an empty result
    // (never an error, never an oracle for the empty slot).
    for raw in ["", "\u{200B}\u{FEFF}"] {
        let hits = db
            .store()
            .scoped(scope)
            .user_identifiers()
            .resolve(IdentifierType::Username, raw)
            .await
            .expect("resolve of empty is a clean miss, not an error");
        assert!(
            hits.is_empty(),
            "resolve of an empty canonical form {raw:?} is empty"
        );
    }
}

#[tokio::test]
async fn a_malformed_email_is_refused_at_add() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x62);
    let scope = db.seed_scope(&env).await;
    let user = register_user(&db, &env, scope, "u").await;

    // An email with no usable `@` shape canonicalizes to the empty form and must be
    // refused, never stored as a username-like whole-string fold.
    for raw in ["no-at-sign", "local@", "@domain.test", "   @   "] {
        let rejected = add_identifier(
            &db,
            &env,
            scope,
            &user,
            IdentifierType::Email,
            raw,
            UniquenessMode::EnvironmentWide,
        )
        .await;
        assert!(
            matches!(rejected, Err(StoreError::InvalidIdentifier)),
            "a malformed email {raw:?} must be refused, got {rejected:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// MEDIUM 4: a uniqueness-mode tightening actually recomputes the keys, so a
// pre-existing non-unique duplicate does not stay exempt from the partial index.

#[tokio::test]
async fn apply_uniqueness_mode_refuses_while_dupes_exist_then_recomputes_keys() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x63);
    let scope = db.seed_scope(&env).await;
    let a = register_user(&db, &env, scope, "a").await;
    let b = register_user(&db, &env, scope, "b").await;
    let c = register_user(&db, &env, scope, "c").await;

    // Two NON-unique duplicates of one canonical email (allowed under non-unique).
    add_identifier(
        &db,
        &env,
        scope,
        &a,
        IdentifierType::Email,
        "dup@example.com",
        UniquenessMode::NonUnique,
    )
    .await
    .expect("first non-unique add");
    add_identifier(
        &db,
        &env,
        scope,
        &b,
        IdentifierType::Email,
        "DUP@example.com",
        UniquenessMode::NonUnique,
    )
    .await
    .expect("second non-unique add");

    // Tightening to environment-wide is REFUSED while the duplicates exist, and it
    // changes nothing (the collision must be resolved first).
    let refused = apply_mode(&db, &env, scope, UniquenessMode::EnvironmentWide).await;
    assert!(
        matches!(refused, Err(StoreError::Conflict)),
        "apply must be refused while a collision the new mode would enforce exists, got {refused:?}"
    );

    // Resolve one of the duplicate rows and delete it (the operator resolves the
    // reported collision). The owner pool bypasses RLS for the test-side cleanup.
    let row_id: String = sqlx::query(
        "SELECT id FROM user_identifiers WHERE tenant_id = $1 AND environment_id = $2 AND user_id = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(b.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("find b's identifier row")
    .get("id");
    sqlx::query("DELETE FROM user_identifiers WHERE id = $1")
        .bind(&row_id)
        .execute(db.owner_pool())
        .await
        .expect("delete the duplicate row");

    // Now the tightening applies: it recomputes every remaining row's key to the
    // environment-wide constant, so the survivor participates in the partial index.
    apply_mode(&db, &env, scope, UniquenessMode::EnvironmentWide)
        .await
        .expect("apply succeeds once the collision is resolved");

    // The recompute is what closes the gap: a subsequent environment-wide add of the
    // same identifier is now the deterministic conflict (no three-way "unique"
    // collision against the previously NULL-keyed survivor).
    let dup = add_identifier(
        &db,
        &env,
        scope,
        &c,
        IdentifierType::Email,
        "dup@example.com",
        UniquenessMode::EnvironmentWide,
    )
    .await;
    assert!(
        matches!(dup, Err(StoreError::Conflict)),
        "after apply, a duplicate add must conflict against the recomputed survivor, got {dup:?}"
    );
}

// ---------------------------------------------------------------------------
// MEDIUM 5: collisions_for_mode(OrgScoped) agrees with add() about the org
// discriminator.

#[tokio::test]
async fn org_scoped_different_orgs_are_allowed_and_not_reported_as_a_collision() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x64);
    let scope = db.seed_scope(&env).await;
    let a = register_user(&db, &env, scope, "a").await;
    let b = register_user(&db, &env, scope, "b").await;

    // Two users in DIFFERENT orgs share one canonical identifier: under org-scoped
    // uniqueness this is legitimate, so BOTH adds succeed.
    add_identifier_org(
        &db,
        &env,
        scope,
        &a,
        IdentifierType::Email,
        "team@example.com",
        UniquenessMode::OrgScoped,
        Some("org_a"),
    )
    .await
    .expect("org_a add");
    add_identifier_org(
        &db,
        &env,
        scope,
        &b,
        IdentifierType::Email,
        "TEAM@example.com",
        UniquenessMode::OrgScoped,
        Some("org_b"),
    )
    .await
    .expect("org_b add is allowed (different org)");

    // Both resolve (resolution is org-agnostic; the factor step disambiguates).
    let hits = db
        .store()
        .scoped(scope)
        .user_identifiers()
        .resolve(IdentifierType::Email, "team@example.com")
        .await
        .expect("resolve");
    assert_eq!(hits.len(), 2, "both cross-org accounts resolve");

    // collisions_for_mode(OrgScoped) must NOT report the cross-org pair (the bug was
    // that it grouped by (type, canonical) only, ignoring the org).
    let org_collisions = db
        .store()
        .scoped(scope)
        .user_identifiers()
        .collisions_for_mode(UniquenessMode::OrgScoped)
        .await
        .expect("org collision scan");
    assert!(
        org_collisions.is_empty(),
        "a legitimate cross-org duplicate must NOT be reported under org-scoped, got {org_collisions:?}"
    );

    // But switching to environment-wide WOULD collapse the org keys, so that scan DOES
    // report the pair.
    let env_collisions = db
        .store()
        .scoped(scope)
        .user_identifiers()
        .collisions_for_mode(UniquenessMode::EnvironmentWide)
        .await
        .expect("env collision scan");
    assert_eq!(
        env_collisions.len(),
        1,
        "environment-wide would collapse the org keys and collide"
    );
    assert_eq!(env_collisions[0].count, 2);
}

#[tokio::test]
async fn org_scoped_reports_a_membership_free_duplicate_as_a_collision() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x65);
    let scope = db.seed_scope(&env).await;
    let a = register_user(&db, &env, scope, "a").await;
    let b = register_user(&db, &env, scope, "b").await;

    // Two membership-free duplicates (created non-unique). Under org-scoped they both
    // fall back to the environment key, so they ARE a collision the mode would enforce.
    add_identifier(
        &db,
        &env,
        scope,
        &a,
        IdentifierType::Email,
        "dup@example.com",
        UniquenessMode::NonUnique,
    )
    .await
    .expect("first");
    add_identifier(
        &db,
        &env,
        scope,
        &b,
        IdentifierType::Email,
        "DUP@example.com",
        UniquenessMode::NonUnique,
    )
    .await
    .expect("second");

    let collisions = db
        .store()
        .scoped(scope)
        .user_identifiers()
        .collisions_for_mode(UniquenessMode::OrgScoped)
        .await
        .expect("org collision scan");
    assert_eq!(
        collisions.len(),
        1,
        "two membership-free duplicates are a collision under org-scoped (env fallback)"
    );
    assert_eq!(collisions[0].count, 2);
}

// ---------------------------------------------------------------------------
// Coverage: passkey-only resolution returns only Passkey.

#[tokio::test]
async fn passkey_only_account_resolves_with_only_the_passkey_method() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x66);
    let scope = db.seed_scope(&env).await;

    // A credential-less (no password) user with only an enrolled passkey.
    let user = register_passwordless_user(&db, &env, scope, "pk").await;
    add_identifier(
        &db,
        &env,
        scope,
        &user,
        IdentifierType::Username,
        "pkuser",
        UniquenessMode::EnvironmentWide,
    )
    .await
    .expect("add identifier");
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .account_credentials()
        .enroll(&env, &user, CredentialType::Passkey, "my key", "none")
        .await
        .expect("enroll passkey");

    let hits = db
        .store()
        .scoped(scope)
        .user_identifiers()
        .resolve(IdentifierType::Username, "pkuser")
        .await
        .expect("resolve");
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].methods,
        vec![LoginMethod::Passkey],
        "a passkey-only account offers exactly the passkey method, no password"
    );
}
