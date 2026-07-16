// SPDX-License-Identifier: MIT OR Apache-2.0

//! The exit-friendliness covenant over a real database (issue #58).
//!
//! The acceptance bar is a ROUND-TRIP: a full export of a populated environment
//! imports into a FRESH scope and every user logs in with their original password,
//! including a user still on an imported FOREIGN hash. The other tests pin the rest
//! of the covenant: a field-coverage test fails on an unexported user column, the
//! export is permission-gated and audited, and the outbound credential-verification
//! endpoint is disabled by default and verifies (native and foreign) when enabled.

mod common;

use common::{Harness, OPERATOR_TOKEN};
use ironauth_env::Env;
use ironauth_import::{ForeignHash, ImportContext, import_stream};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, CredentialType, HumanId, NewAdminUser, Scope, Store, UserId,
    UserRecord, UserState,
};

/// A native Argon2id PHC verifier for `password`, exactly what the login path
/// stores for a normally-registered user.
fn argon2_hash(password: &str) -> String {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::encode_b64(b"exit-export-salt").expect("salt");
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hash")
        .to_string()
}

/// Seed one user in `scope` through the audited admin-create path (issue #52/#55/#58),
/// the only path that accepts a foreign hash and verbatim traits.
async fn seed_user(
    store: &Store,
    scope: Scope,
    env: &Env,
    spec: NewAdminUser<'_>,
    created_at: i64,
) {
    let actor = ActorRef::human(HumanId::generate(env));
    store
        .scoped(scope)
        .acting(actor, CorrelationId::generate(env))
        .users()
        .admin_create(env, spec, created_at, None)
        .await
        .expect("seed user");
}

/// Whether `user` would authenticate with `password` on the login path: verify the
/// native Argon2id hash, else the imported foreign hash, through the same
/// `ForeignHash` dispatch the login path uses. Documented-information only.
fn login_ok(user: &UserRecord, password: &str) -> bool {
    let native =
        ForeignHash::parse(&user.password_hash).is_ok_and(|hash| hash.verify(password.as_bytes()));
    native
        || user
            .foreign_password_hash
            .as_deref()
            .and_then(|stored| ForeignHash::parse(stored).ok())
            .is_some_and(|hash| hash.verify(password.as_bytes()))
}

/// The acceptance criterion: a full export imports into a fresh instance and every
/// user logs in with their original password, INCLUDING a user still on an imported
/// foreign hash, with claims, traits, and external ids carried across losslessly.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one linear seed -> export -> import -> assert walk
async fn full_export_reimports_into_a_fresh_instance_with_logins_working() {
    let harness = Harness::start(100).await;
    let env = Env::system();
    let store = harness.control_store();
    let source = harness.seed_scope().await;

    // A user with a NATIVE Argon2id credential (a normally-registered account).
    let native = argon2_hash("correct horse battery");
    seed_user(
        store,
        source,
        &env,
        NewAdminUser {
            id: None,
            identifier: "alice@exit.test",
            password_hash: Some(&native),
            claims_json: Some(r#"{"email":"alice@exit.test","email_verified":true}"#),
            external_id: None,
            state: UserState::Active,
            foreign_password_hash: None,
            foreign_password_algo: None,
            traits_json: None,
            traits_schema_version: None,
        },
        1_000_000,
    )
    .await;

    // A user still on an imported FOREIGN bcrypt hash (never logged in), plus traits
    // and an external id, so the round-trip covers the covenant's hardest case.
    let bcrypt_hash = bcrypt::hash("hunter2", 6).expect("bcrypt hash");
    seed_user(
        store,
        source,
        &env,
        NewAdminUser {
            id: None,
            identifier: "bob@exit.test",
            password_hash: None,
            claims_json: Some(r#"{"email":"bob@exit.test"}"#),
            external_id: Some("crm-77"),
            state: UserState::Active,
            foreign_password_hash: Some(&bcrypt_hash),
            foreign_password_algo: Some("bcrypt"),
            traits_json: Some(r#"{"department":"engineering"}"#),
            traits_schema_version: Some(3),
        },
        2_000_000,
    )
    .await;

    // A credential-less, pending-verification account (no hash at all).
    seed_user(
        store,
        source,
        &env,
        NewAdminUser {
            id: None,
            identifier: "carol@exit.test",
            password_hash: None,
            claims_json: None,
            external_id: None,
            state: UserState::PendingVerification,
            foreign_password_hash: None,
            foreign_password_algo: None,
            traits_json: None,
            traits_schema_version: None,
        },
        3_000_000,
    )
    .await;

    // Export through the management API with the operator credential.
    let path = format!(
        "/v1/tenants/{}/environments/{}/export",
        source.tenant(),
        source.environment()
    );
    let (status, headers, body) = harness.get(&path).await;
    assert_eq!(status, axum::http::StatusCode::OK, "export: {body}");
    assert_eq!(
        headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/x-ndjson"),
        "the export is newline-delimited JSON"
    );
    let lines: Vec<String> = body
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    assert_eq!(lines.len(), 3, "one record per seeded user: {body}");

    // Import the export into a FRESH scope (a fresh instance), consuming only the
    // documented line-delimited format through the real streaming import engine.
    let target = harness.seed_scope().await;
    let actor = harness.test_actor(&env);
    let ctx = ImportContext {
        store,
        scope: target,
        env: &env,
        actor,
    };
    let report = import_stream(&ctx, lines.clone(), |_| {}).await;
    assert_eq!(
        report.succeeded, 3,
        "every exported user re-imports: {report:?}"
    );
    assert_eq!(report.failed, 0, "no record fails to import: {report:?}");

    // Logins work in the fresh instance.
    let alice = store
        .scoped(target)
        .users()
        .by_identifier("alice@exit.test")
        .await
        .expect("lookup")
        .expect("alice imported");
    assert!(
        login_ok(&alice, "correct horse battery"),
        "native login works"
    );
    assert!(!login_ok(&alice, "wrong"), "a wrong password is rejected");

    let bob = store
        .scoped(target)
        .users()
        .by_identifier("bob@exit.test")
        .await
        .expect("lookup")
        .expect("bob imported");
    assert!(
        login_ok(&bob, "hunter2"),
        "a user still on an imported FOREIGN hash logs in after the round-trip"
    );
    assert!(!login_ok(&bob, "nope"), "a wrong password is rejected");

    // Bob's traits round-tripped verbatim, with their source schema version.
    let (schema_version, traits) = store
        .scoped(target)
        .users()
        .traits(&bob.id)
        .await
        .expect("traits read")
        .expect("bob has traits");
    assert_eq!(schema_version, 3, "the source schema version is preserved");
    assert_eq!(
        traits,
        serde_json::json!({"department": "engineering"}),
        "traits round-trip verbatim"
    );

    // Bob's external id round-tripped (resolvable by the blind index in the new scope).
    let by_ext = store
        .scoped(target)
        .users()
        .by_external_id("crm-77")
        .await
        .expect("external-id lookup")
        .expect("external id carried across");
    assert_eq!(by_ext.identifier, "bob@exit.test");

    // Carol is credential-less: she imports but cannot authenticate.
    let carol = store
        .scoped(target)
        .users()
        .by_identifier("carol@exit.test")
        .await
        .expect("lookup")
        .expect("carol imported");
    assert!(
        !login_ok(&carol, "anything"),
        "a credential-less account cannot log in"
    );

    // The export was audited with actor attribution in the SOURCE scope.
    let actions: Vec<String> = store
        .scoped(source)
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .map(|row| row.action)
        .collect();
    assert!(
        actions.iter().any(|action| action == "user.export"),
        "the export writes a user.export audit row: {actions:?}"
    );
}

/// A re-import of the SAME export into the SAME scope is idempotent: the login
/// handle's per-scope uniqueness makes every record a skip, not a duplicate.
#[tokio::test]
async fn re_importing_into_the_same_scope_is_idempotent() {
    let harness = Harness::start(100).await;
    let env = Env::system();
    let store = harness.control_store();
    let scope = harness.seed_scope().await;
    let native = argon2_hash("pw");
    seed_user(
        store,
        scope,
        &env,
        NewAdminUser {
            id: None,
            identifier: "dave@exit.test",
            password_hash: Some(&native),
            claims_json: None,
            external_id: None,
            state: UserState::Active,
            foreign_password_hash: None,
            foreign_password_algo: None,
            traits_json: None,
            traits_schema_version: None,
        },
        1_000_000,
    )
    .await;

    let path = format!(
        "/v1/tenants/{}/environments/{}/export",
        scope.tenant(),
        scope.environment()
    );
    let (_status, _headers, body) = harness.get(&path).await;
    let lines: Vec<String> = body
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();

    let actor = harness.test_actor(&env);
    let ctx = ImportContext {
        store,
        scope,
        env: &env,
        actor,
    };
    let report = import_stream(&ctx, lines, |_| {}).await;
    assert_eq!(report.succeeded, 0, "no new users: {report:?}");
    assert_eq!(
        report.skipped, 1,
        "the re-import is a skip, not a duplicate: {report:?}"
    );
}

/// The export coverage of one identity-carrying table: every column is either
/// EXPORTED (carried losslessly in the record), DERIVED (re-scoped / re-derived /
/// re-sealed against the destination instance), or OPERATIONAL (a lifecycle column
/// intentionally not exported). A column outside all three fails the guard.
struct TableCoverage {
    /// The identity-carrying table name.
    table: &'static str,
    /// Columns the export CARRIES in each record.
    exported: &'static [&'static str],
    /// Columns re-derived at the destination, not carried by design.
    derived: &'static [&'static str],
    /// Lifecycle columns intentionally not exported.
    operational: &'static [&'static str],
}

/// The field-coverage guard (issue #58): enumerate the FULL identity model, not one
/// table, and fail the build on a column of ANY identity-carrying table that is
/// neither EXPORTED nor a documented non-exported field. This is what stops a future
/// migration, including the M7 credential-secret columns (a TOTP seed, a passkey
/// public key on `account_credentials`), from silently escaping the export: a new
/// column is unclassified until it is either exported or explicitly justified here.
///
/// NOTE: the #54 `user_identifiers` table is not on this branch, so it is not
/// covered here; it joins the guard when it merges.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one linear per-table coverage model plus the live-column sweep
async fn every_identity_column_is_exported_or_a_documented_non_exported_field() {
    let model: &[TableCoverage] = &[
        // The users table: the core identity row.
        TableCoverage {
            table: "users",
            exported: &[
                "identifier_sealed",     // -> identifier
                "claims_sealed",         // -> claims
                "traits_sealed",         // -> traits
                "traits_schema_version", // -> traits_schema_version
                "external_id_sealed",    // -> external_id
                "state",                 // -> state
                "password_hash",         // -> the credential (native)
                "foreign_password_hash", // -> the credential (imported foreign)
            ],
            derived: &[
                "id",                      // re-minted per target scope (embeds the source scope)
                "tenant_id",               // the target scope
                "environment_id",          // the target scope
                "identifier_bidx",         // re-derived from the plaintext under the target key
                "external_id_bidx",        // re-derived from the plaintext under the target key
                "pii_dek_version",         // re-sealed under the target active DEK
                "external_id_dek_version", // re-sealed under the target active DEK
                "traits_dek_version",      // re-sealed under the target active DEK
                "foreign_password_algo",   // re-derived from the exported PHC string's tag
                "created_at",              // set fresh at import
                "updated_at",              // set fresh at import
            ],
            operational: &[
                "scheduled_offboarding_at", // an operational overlay; exports as active
                "deleted_at",               // tombstone; deleted users are excluded
            ],
        },
        // The account_credentials registry (issue #61): a user's enrolled MFA / login
        // credentials. Its metadata is exported today; the M7 secret-material columns
        // (a TOTP seed, a passkey public key) will be UNCLASSIFIED here until they are
        // added to the export, which is exactly the guard firing.
        TableCoverage {
            table: "account_credentials",
            exported: &[
                "credential_type",      // -> credentials[].credential_type
                "friendly_name_sealed", // -> credentials[].friendly_name (opened)
                "last_used_at",         // -> credentials[].last_used_at
            ],
            derived: &[
                "id",               // re-minted per target scope (a fresh crd_ id)
                "tenant_id",        // the target scope
                "environment_id",   // the target scope
                "subject",          // re-linked to the imported user's fresh usr_ id
                "pii_dek_version",  // re-sealed under the target active DEK
                "usable_for_login", // re-derived from credential_type at enrollment
                "created_at",       // set fresh at import (re-enrollment time)
            ],
            operational: &[],
        },
        // The webauthn_credentials registry (issue #65): a user's registered
        // passkeys. Unlike a password hash, a WebAuthn credential is device-bound
        // and NOT portable across IdP instances: the private key never leaves the
        // authenticator, and the stored COSE public key is scoped to this
        // deployment's RP ID, so it cannot be re-homed to another provider (an
        // authenticator refuses to sign for a different RP ID; the user re-enrolls
        // passkeys on the new instance). The whole credential-material set is
        // therefore OPERATIONAL device state, not portable identity; only the
        // scope/structural columns are derived. The covenant is honored: the
        // portable identity (the user, the password hash) round-trips; the
        // non-portable device keys are documented as such here and in
        // docs/exit-guide.md.
        TableCoverage {
            table: "webauthn_credentials",
            exported: &[],
            derived: &[
                "id",              // a `pky_` id, re-minted per target scope
                "tenant_id",       // the target scope
                "environment_id",  // the target scope
                "subject",         // would re-link to the imported user's fresh usr_ id
                "pii_dek_version", // the nickname would re-seal under the target DEK
            ],
            operational: &[
                "credential_id",   // device-bound authenticator credential id
                "cose_public_key", // RP-ID-scoped public key; not re-homable
                "sign_count",      // per-authenticator clone-detection counter
                "aaguid",          // authenticator model id
                "transports",      // last-observed client transports
                "backup_eligible", // BE flag, a property of the authenticator
                "backup_state",    // BS flag, live device state
                "discoverable",    // credProps.rk, a property of the credential
                "clone_detected",  // a security overlay on the live credential
                "nickname_sealed", // the user label of a non-portable device key
                "created_at",      // registration time on this instance
                "last_used_at",    // live usage state
            ],
        },
        // The totp_credentials registry (issue #69): a user's enrolled TOTP
        // authenticators. Unlike a passkey, a TOTP seed IS a portable shared secret,
        // exactly the class the exit covenant says to export (like a password hash):
        // it is sealed at rest and OPENED for the gated, audited export, so it
        // round-trips into a fresh instance. The seed, the friendly name, the
        // parameters, the status, and the single-use step are exported; the ids /
        // scope / key version are re-minted / re-sealed at import; the timestamps and
        // the resync offset are live operational state.
        TableCoverage {
            table: "totp_credentials",
            exported: &[
                "totp_seed",            // -> totp[].seed_base32 (opened, the covenant secret)
                "friendly_name_sealed", // -> totp[].friendly_name (opened)
                "algorithm",            // -> totp[].algorithm
                "digits",               // -> totp[].digits
                "period_secs",          // -> totp[].period_secs
                "status",               // -> totp[].status
                "last_consumed_step",   // -> totp[].last_consumed_step (single-use spine)
            ],
            derived: &[
                "id",              // a `tot_` id, re-minted per target scope
                "tenant_id",       // the target scope
                "environment_id",  // the target scope
                "subject",         // re-linked to the imported user's fresh usr_ id
                "pii_dek_version", // the seed and name re-seal under the target DEK
            ],
            operational: &[
                "last_offset",  // resync drift offset, live device state
                "created_at",   // enrollment time on this instance
                "activated_at", // activation time on this instance
                "last_used_at", // live usage state
            ],
        },
        // The recovery_codes store (issue #69): a user's one-time recovery codes.
        // Each code_hash is a one-way Argon2id verifier (never a plaintext code),
        // carried verbatim exactly like a password hash, plus its consumed state, so
        // the covenant round-trips the recovery-code set. The ids / scope are
        // re-minted at import; created_at is set fresh.
        TableCoverage {
            table: "recovery_codes",
            exported: &[
                "code_hash",   // -> recovery_codes[].code_hash (one-way, like a password)
                "consumed_at", // -> recovery_codes[].consumed (single-use state)
            ],
            derived: &[
                "id",             // a `rvc_` id, re-minted per target scope
                "tenant_id",      // the target scope
                "environment_id", // the target scope
                "subject",        // re-linked to the imported user's fresh usr_ id
                "generation",     // the batch marker, re-numbered on a fresh import
            ],
            operational: &[
                "created_at", // set fresh at import
            ],
        },
    ];

    let db = TestDatabase::start().await;
    for coverage in model {
        let columns: Vec<String> = sqlx::query_scalar(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = $1 ORDER BY column_name",
        )
        .bind(coverage.table)
        .fetch_all(db.owner_pool())
        .await
        .expect("read table columns");
        assert!(
            !columns.is_empty(),
            "the {} table has columns",
            coverage.table
        );

        for column in &columns {
            let classified = coverage.exported.contains(&column.as_str())
                || coverage.derived.contains(&column.as_str())
                || coverage.operational.contains(&column.as_str());
            assert!(
                classified,
                "{} column '{column}' is unclassified: the identity model grew a field that the \
                 export does not cover. Add it to the export (EXPORTED) or document why it is not \
                 exported (DERIVED / OPERATIONAL) in crates/ironauth-admin/tests/export.rs and \
                 docs/exit-guide.md.",
                coverage.table
            );
        }
    }
}

/// A cross-environment management key cannot export another environment: the export
/// is permission-gated exactly like every other per-environment read.
#[tokio::test]
async fn export_is_permission_gated_per_environment() {
    let harness = Harness::start(100).await;
    let (tenant_a, env_a) = harness.create_tenant("tenant-a", "k-a").await;
    let (tenant_b, env_b) = harness.create_tenant("tenant-b", "k-b").await;
    // A management key scoped to environment B.
    let key_b = harness.create_key(&tenant_b, &env_b, "key-b", "k-b2").await;

    // Key B exporting environment A is the loud wrong-scope error.
    let path_a = format!("/v1/tenants/{tenant_a}/environments/{env_a}/export");
    let (status, _headers, body) = harness.get_as(&path_a, &key_b).await;
    assert_eq!(
        status,
        axum::http::StatusCode::FORBIDDEN,
        "a cross-environment key cannot export: {body}"
    );

    // Key B exporting its OWN environment B succeeds.
    let path_b = format!("/v1/tenants/{tenant_b}/environments/{env_b}/export");
    let (status, _headers, _body) = harness.get_as(&path_b, &key_b).await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "the environment's own key may export it"
    );

    // An unauthenticated export is unauthorized.
    let (status, _headers, _body) = harness.get_as(&path_b, "not-a-real-token").await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

/// The outbound verification endpoint is DISABLED BY DEFAULT: a uniform not-found
/// even with a well-formed request.
#[tokio::test]
async fn outbound_verification_is_disabled_by_default() {
    let harness = Harness::start(100).await;
    let scope = harness.seed_scope().await;
    let path = format!(
        "/v1/tenants/{}/environments/{}/migration/verify-credential",
        scope.tenant(),
        scope.environment()
    );
    // A request WITH a bearer but against a deployment that never enabled the
    // endpoint is a uniform not-found (its existence is not revealed).
    let (status, _headers, _body) = harness
        .post_as(
            &path,
            OPERATOR_TOKEN,
            "k1",
            r#"{"identifier":"x","password":"y"}"#,
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "the outbound endpoint is off by default"
    );
}

/// When enabled and credentialed, the outbound endpoint verifies a credential
/// (native and foreign) for a successor system and returns the profile, and refuses
/// a wrong token or a wrong password.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one linear seed -> verify-each-case walk
async fn outbound_verification_verifies_native_and_foreign_when_enabled() {
    const OUTBOUND_TOKEN: &str = "successor-shared-secret";
    let harness = Harness::start_with_outbound_verification(Some(OUTBOUND_TOKEN)).await;
    let env = Env::system();
    let store = harness.control_store();
    // The outbound endpoint is bound to this scope; seed the users into it.
    let scope = harness.outbound_scope();

    let native = argon2_hash("s3cret");
    seed_user(
        store,
        scope,
        &env,
        NewAdminUser {
            id: None,
            identifier: "erin@exit.test",
            password_hash: Some(&native),
            claims_json: Some(r#"{"email":"erin@exit.test"}"#),
            external_id: None,
            state: UserState::Active,
            foreign_password_hash: None,
            foreign_password_algo: None,
            traits_json: None,
            traits_schema_version: None,
        },
        1_000_000,
    )
    .await;
    let bcrypt_hash = bcrypt::hash("hunter2", 6).expect("bcrypt hash");
    seed_user(
        store,
        scope,
        &env,
        NewAdminUser {
            id: None,
            identifier: "frank@exit.test",
            password_hash: None,
            claims_json: None,
            external_id: None,
            state: UserState::Active,
            foreign_password_hash: Some(&bcrypt_hash),
            foreign_password_algo: Some("bcrypt"),
            traits_json: None,
            traits_schema_version: None,
        },
        2_000_000,
    )
    .await;

    let path = format!(
        "/v1/tenants/{}/environments/{}/migration/verify-credential",
        scope.tenant(),
        scope.environment()
    );

    // A wrong outbound token is unauthorized (even though the endpoint is enabled).
    let (status, _h, _b) = harness
        .post_as(
            &path,
            "wrong-token",
            "k0",
            r#"{"identifier":"erin@exit.test","password":"s3cret"}"#,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);

    // Native credential verifies, and returns the profile.
    let (status, _h, body) = harness
        .post_as(
            &path,
            OUTBOUND_TOKEN,
            "k1",
            r#"{"identifier":"erin@exit.test","password":"s3cret"}"#,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let verdict: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        verdict["verified"], true,
        "native credential verifies: {body}"
    );
    assert_eq!(
        verdict["profile"]["claims"]["email"], "erin@exit.test",
        "the profile is returned on success: {body}"
    );

    // Foreign credential verifies through the same endpoint.
    let (status, _h, body) = harness
        .post_as(
            &path,
            OUTBOUND_TOKEN,
            "k2",
            r#"{"identifier":"frank@exit.test","password":"hunter2"}"#,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let verdict: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        verdict["verified"], true,
        "foreign credential verifies: {body}"
    );

    // A wrong password does not verify, with no profile leaked.
    let (status, _h, body) = harness
        .post_as(
            &path,
            OUTBOUND_TOKEN,
            "k3",
            r#"{"identifier":"erin@exit.test","password":"wrong"}"#,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let verdict: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        verdict["verified"], false,
        "a wrong password is rejected: {body}"
    );
    assert!(
        verdict.get("profile").is_none(),
        "no profile on a failed verify: {body}"
    );

    // An unknown account does not verify either.
    let (status, _h, body) = harness
        .post_as(
            &path,
            OUTBOUND_TOKEN,
            "k4",
            r#"{"identifier":"nobody@exit.test","password":"x"}"#,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let verdict: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        verdict["verified"], false,
        "an unknown account does not verify: {body}"
    );
}

/// Enroll a credential of `credential_type` named `friendly_name` for the user with
/// `identifier` in `scope`, through the audited, subject-bound self-service path.
async fn enroll_credential(
    store: &Store,
    scope: Scope,
    env: &Env,
    identifier: &str,
    credential_type: CredentialType,
    friendly_name: &str,
) -> UserId {
    let user = store
        .scoped(scope)
        .users()
        .by_identifier(identifier)
        .await
        .expect("lookup")
        .expect("user exists");
    let actor = ActorRef::human(HumanId::generate(env));
    store
        .scoped(scope)
        .acting(actor, CorrelationId::generate(env))
        .account_credentials()
        .enroll(env, &user.id, credential_type, friendly_name, "step_up")
        .await
        .expect("enroll credential");
    user.id
}

/// The MFA / credential-registry round-trip (issue #58, HIGH): a user with enrolled
/// credentials exports and re-imports into a FRESH scope with every enrollment
/// preserved (factor kind and friendly name), so the exit-friendliness covenant
/// carries the credential registry, not merely the password.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one linear seed -> enroll -> export -> import -> assert walk
async fn enrolled_credentials_round_trip_through_the_export() {
    let harness = Harness::start(100).await;
    let env = Env::system();
    let store = harness.control_store();
    let source = harness.seed_scope().await;

    // A user with a native credential AND two enrolled factors (a passkey and a TOTP).
    let native = argon2_hash("pw");
    seed_user(
        store,
        source,
        &env,
        NewAdminUser {
            id: None,
            identifier: "gina@exit.test",
            password_hash: Some(&native),
            claims_json: None,
            external_id: None,
            state: UserState::Active,
            foreign_password_hash: None,
            foreign_password_algo: None,
            traits_json: None,
            traits_schema_version: None,
        },
        1_000_000,
    )
    .await;
    enroll_credential(
        store,
        source,
        &env,
        "gina@exit.test",
        CredentialType::Passkey,
        "my laptop",
    )
    .await;
    enroll_credential(
        store,
        source,
        &env,
        "gina@exit.test",
        CredentialType::Totp,
        "authenticator app",
    )
    .await;

    // Export through the management API.
    let path = format!(
        "/v1/tenants/{}/environments/{}/export",
        source.tenant(),
        source.environment()
    );
    let (status, _headers, body) = harness.get(&path).await;
    assert_eq!(status, axum::http::StatusCode::OK, "export: {body}");
    // The credential registry rides the record.
    assert!(
        body.contains("credentials") && body.contains("my laptop") && body.contains("passkey"),
        "the export line carries the enrolled credential registry: {body}"
    );
    let lines: Vec<String> = body
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();

    // Import into a FRESH scope through the real streaming import engine.
    let target = harness.seed_scope().await;
    let actor = harness.test_actor(&env);
    let ctx = ImportContext {
        store,
        scope: target,
        env: &env,
        actor,
    };
    let report = import_stream(&ctx, lines, |_| {}).await;
    assert_eq!(report.succeeded, 1, "the user re-imports: {report:?}");
    assert_eq!(report.failed, 0, "no record fails: {report:?}");

    // The enrolled credentials are preserved in the fresh instance.
    let gina = store
        .scoped(target)
        .users()
        .by_identifier("gina@exit.test")
        .await
        .expect("lookup")
        .expect("gina imported");
    let credentials = store
        .scoped(target)
        .account_credentials()
        .list(&gina.id, 50, None)
        .await
        .expect("list credentials");
    assert_eq!(
        credentials.len(),
        2,
        "both enrolled credentials round-trip: {credentials:?}"
    );
    let passkey = credentials
        .iter()
        .find(|c| c.credential_type == "passkey")
        .expect("passkey preserved");
    assert_eq!(
        passkey.friendly_name, "my laptop",
        "the friendly name is preserved"
    );
    assert!(
        passkey.usable_for_login,
        "a passkey is re-derived as a primary login factor"
    );
    let totp = credentials
        .iter()
        .find(|c| c.credential_type == "totp")
        .expect("totp preserved");
    assert_eq!(totp.friendly_name, "authenticator app");
    assert!(
        !totp.usable_for_login,
        "a TOTP factor is not a primary login factor"
    );
}

/// The outbound endpoint is SCOPE-BOUND (issue #58, MEDIUM): configured and enabled
/// for one (tenant, environment), a request to a DIFFERENT scope with the CORRECT
/// token is the uniform 404 and verifies nothing, so the shared token can never
/// verify credentials across tenants.
#[tokio::test]
async fn outbound_verification_is_bound_to_its_configured_scope() {
    const OUTBOUND_TOKEN: &str = "successor-shared-secret";
    let harness = Harness::start_with_outbound_verification(Some(OUTBOUND_TOKEN)).await;
    let env = Env::system();
    let store = harness.control_store();
    let configured = harness.outbound_scope();

    // Seed an authenticatable user in the CONFIGURED scope.
    let native = argon2_hash("s3cret");
    seed_user(
        store,
        configured,
        &env,
        NewAdminUser {
            id: None,
            identifier: "hank@exit.test",
            password_hash: Some(&native),
            claims_json: None,
            external_id: None,
            state: UserState::Active,
            foreign_password_hash: None,
            foreign_password_algo: None,
            traits_json: None,
            traits_schema_version: None,
        },
        1_000_000,
    )
    .await;

    // The CONFIGURED scope verifies with the correct token (sanity: the endpoint works).
    let ok_path = format!(
        "/v1/tenants/{}/environments/{}/migration/verify-credential",
        configured.tenant(),
        configured.environment()
    );
    let (status, _h, body) = harness
        .post_as(
            &ok_path,
            OUTBOUND_TOKEN,
            "k1",
            r#"{"identifier":"hank@exit.test","password":"s3cret"}"#,
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "configured scope verifies: {body}"
    );
    let verdict: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(verdict["verified"], true, "the configured scope verifies");

    // A DIFFERENT scope, with the CORRECT token, is the uniform 404: the token cannot
    // verify credentials outside its one configured environment.
    let other = harness.seed_scope().await;
    let other_path = format!(
        "/v1/tenants/{}/environments/{}/migration/verify-credential",
        other.tenant(),
        other.environment()
    );
    let (status, _h, body) = harness
        .post_as(
            &other_path,
            OUTBOUND_TOKEN,
            "k2",
            r#"{"identifier":"hank@exit.test","password":"s3cret"}"#,
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "a request to a non-configured scope is a uniform 404, even with the correct token: {body}"
    );
}

/// The disabled endpoint is indistinguishable from an absent route to an
/// unauthenticated probe (issue #58, LOW): a request carrying no `Authorization`
/// header against a disabled endpoint returns 404, not 401, so the enablement gate is
/// evaluated before the bearer check and the route's existence is not revealed.
#[tokio::test]
async fn disabled_outbound_endpoint_is_404_to_an_unauthenticated_probe() {
    let harness = Harness::start(100).await;
    let scope = harness.seed_scope().await;
    let path = format!(
        "/v1/tenants/{}/environments/{}/migration/verify-credential",
        scope.tenant(),
        scope.environment()
    );
    // No Authorization header at all against the (default-disabled) endpoint.
    let (status, _headers, body) = harness
        .post_unauthenticated(&path, r#"{"identifier":"x","password":"y"}"#)
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "a disabled endpoint is a uniform 404 to an unauthenticated probe, not a 401: {body}"
    );
}
