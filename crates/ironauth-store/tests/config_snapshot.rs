// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical secret-free config snapshot export, over a real database
//! (`DATABASE_URL`) (issue #43).
//!
//! Proves the two load-bearing properties of a snapshot against a live,
//! fully-populated environment:
//!
//! - **Deterministic / canonical.** Two exports of the same environment produce
//!   BYTE-IDENTICAL bytes, and the canonical document round-trips through
//!   parse-and-re-serialize byte-identically.
//! - **Secret-free.** A fixture environment populated with every secret-bearing
//!   promotable resource (a confidential client's secret, a `private_key_jwt`
//!   client's public JWK Set) plus an environment-identity signing key exports
//!   NO secret or key material: the confidential client's stored secret hash, the
//!   signing key's private material, and the signing key's identifier all appear
//!   NOWHERE in the bytes.
//!
//! It also proves cross-scope isolation (a snapshot exports only its own scope's
//! config) and the classification binding (every promotable type is present and
//! the environment-identity signing key is excluded).
//!
//! The export runs through the CONTROL-plane store (the management-plane reader,
//! which after migration 0031 can SELECT all three promotable tables); the fixture
//! is seeded through the roles that actually own each write (the data plane for
//! clients, resource servers, and signing keys; the control plane for DCR
//! policies), exactly as production does.

use std::time::UNIX_EPOCH;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, DcrPolicyId, NewDcrPolicy, NewJwtAuthClient, NewResourceServer, NewSigningKey,
    ResourceServerId, Scope, SigningKeyId, SigningKeyMaterialKind, TokenFormat, export_snapshot,
    validate_document,
};

/// A distinctive stored client-secret hash: the export must NEVER carry it.
const SECRET_HASH_MARKER: &str =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0";

/// Distinctive signing-key private material: the export must NEVER carry it.
const SIGNING_MATERIAL_MARKER: &[u8] = b"SIGNING-KEY-PRIVATE-MATERIAL-DO-NOT-EXPORT";

/// A PUBLIC JWK Set (no private parameter): the export MAY carry it, and the
/// validator must accept it.
const PUBLIC_JWKS: &str =
    r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#;

/// Wall-clock microseconds drawn from the ENVIRONMENT clock seam (the invariant
/// lint forbids reaching for the process wall clock directly). The value never
/// enters the snapshot (the document excludes timestamps), so it is a DCR-policy
/// write timestamp only.
fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("micros fits i64")
}

/// Seed a fully-populated fixture environment in `scope`: a confidential client, a
/// `private_key_jwt` client with a public JWK Set, two resource servers, two DCR
/// policies, and an environment-identity signing key with distinctive private
/// material. Returns the confidential client's id string (for isolation checks).
async fn seed_fixture(db: &TestDatabase, env: &Env, scope: Scope) -> String {
    let app = db.store();
    let control = db.control_store();

    // A confidential client (data plane): its secret hash is stored but must never
    // reach a snapshot; a named reference stands in for it instead.
    let confidential = app
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .clients()
        .create_confidential(env, "billing", "client_secret_basic", SECRET_HASH_MARKER)
        .await
        .expect("create confidential client");

    // Register a redirect URI on the confidential client (promotable config).
    app.scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .clients()
        .register_redirect_uris(env, &confidential, &["https://billing.example/callback"])
        .await
        .expect("register redirect uris");

    // A private_key_jwt client registering a PUBLIC JWK Set inline (data plane).
    app.scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .clients()
        .create_jwt_auth(
            env,
            NewJwtAuthClient {
                display_name: "svc",
                auth_method: "private_key_jwt",
                jwks: Some(PUBLIC_JWKS),
                jwks_uri: None,
                signing_alg: Some("EdDSA"),
            },
        )
        .await
        .expect("create jwt-auth client");

    // Two resource servers, one of each format (data plane).
    for (audience, format, ttl) in [
        ("https://api.example/reports", TokenFormat::AtJwt, None),
        ("https://api.example/orders", TokenFormat::Opaque, Some(120)),
    ] {
        let id = ResourceServerId::generate(env, &scope);
        app.scoped(scope)
            .acting(db.test_actor(env), CorrelationId::generate(env))
            .resource_servers()
            .register(
                env,
                NewResourceServer {
                    id: &id,
                    audience,
                    token_format: format,
                    access_token_ttl_secs: ttl,
                },
            )
            .await
            .expect("register resource server");
    }

    // Two DCR policies (control plane owns the write).
    for (name, primitives) in [
        ("baseline", r#"[{"kind":"require_https"}]"#),
        (
            "strict",
            r#"[{"kind":"require_https"},{"kind":"max_redirect_uris","max":2}]"#,
        ),
    ] {
        let id = DcrPolicyId::generate(env, &scope);
        control
            .scoped(scope)
            .acting(db.test_actor(env), CorrelationId::generate(env))
            .dcr_policies()
            .create(
                env,
                &id,
                now_micros(env),
                NewDcrPolicy { name, primitives },
                None,
            )
            .await
            .expect("create dcr policy");
    }

    // An environment-identity signing key with distinctive private material (data
    // plane): it must be EXCLUDED from the snapshot, material and all.
    let key_id = SigningKeyId::generate(env, &scope);
    app.scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .signing_keys()
        .provision(
            env,
            NewSigningKey {
                id: &key_id,
                algorithm: "EdDSA",
                material_kind: SigningKeyMaterialKind::Ed25519Seed,
                material: SIGNING_MATERIAL_MARKER,
                publish_at_micros: 0,
                activate_at_micros: 0,
                retire_at_micros: None,
                expire_at_micros: None,
            },
        )
        .await
        .expect("provision signing key");

    confidential.to_string()
}

#[tokio::test]
async fn export_is_deterministic_secret_free_and_classification_bound() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let confidential_id = seed_fixture(&db, &env, scope).await;

    let control = db.control_store();

    // Two exports of the same environment are BYTE-IDENTICAL (determinism).
    let first = export_snapshot(&control.scoped(scope))
        .await
        .expect("first export");
    let second = export_snapshot(&control.scoped(scope))
        .await
        .expect("second export");
    let first_bytes = first.to_canonical_bytes().expect("canonical bytes");
    let second_bytes = second.to_canonical_bytes().expect("canonical bytes");
    assert_eq!(
        first_bytes, second_bytes,
        "two exports of the same environment must be byte-identical"
    );

    let text = String::from_utf8(first_bytes.clone()).expect("utf8");

    // SECRET-FREE (the headline): no client secret hash, no signing-key private
    // material, no environment-identity signing-key id, and no secret-marker column
    // name appears in the bytes.
    assert!(
        !text.contains(SECRET_HASH_MARKER),
        "the confidential client's secret hash must not appear in the snapshot"
    );
    let material_marker = std::str::from_utf8(SIGNING_MATERIAL_MARKER).expect("ascii marker");
    assert!(
        !text.contains(material_marker),
        "signing-key private material must not appear in the snapshot"
    );
    for forbidden in ["secret_hash", "key_material", "sik_", "mak_"] {
        assert!(
            !text.contains(forbidden),
            "secret/identity marker {forbidden:?} must not appear in the snapshot"
        );
    }

    // A confidential client carries a named secret REFERENCE, never a secret.
    let confidential = first
        .resources
        .client
        .iter()
        .find(|c| c.client_id == confidential_id)
        .expect("confidential client present");
    let secret_ref = confidential.secret.as_ref().expect("secret reference");
    assert_eq!(secret_ref.reference, "client_secret");

    // Every promotable type is present (classification coverage), and the PUBLIC
    // JWK Set survived (public key material is promotable, not secret).
    assert_eq!(first.resources.client.len(), 2, "both clients exported");
    assert_eq!(
        first.resources.resource_server.len(),
        2,
        "both resource servers exported"
    );
    assert_eq!(
        first.resources.dcr_policy.len(),
        2,
        "both policies exported"
    );
    assert!(
        first.resources.client.iter().any(|c| c.jwks.is_some()),
        "the public JWK Set must be exported"
    );

    // The canonical document round-trips: validate + re-serialize is byte-identical.
    let parsed = validate_document(&first_bytes).expect("exported snapshot validates");
    let reserialized = parsed.to_canonical_bytes().expect("reserialize");
    assert_eq!(
        first_bytes, reserialized,
        "the canonical snapshot must round-trip byte-identically"
    );
}

#[tokio::test]
async fn a_snapshot_exports_only_its_own_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    // Two independent scopes, each with its own fixture.
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let confidential_a = seed_fixture(&db, &env, scope_a).await;
    let confidential_b = seed_fixture(&db, &env, scope_b).await;

    let control = db.control_store();
    let snapshot_a = export_snapshot(&control.scoped(scope_a))
        .await
        .expect("export a");
    let text_a = String::from_utf8(snapshot_a.to_canonical_bytes().expect("bytes")).expect("utf8");

    // Scope A's snapshot contains A's client and NONE of B's.
    assert!(
        text_a.contains(&confidential_a),
        "scope A's snapshot must contain scope A's client"
    );
    assert!(
        !text_a.contains(&confidential_b),
        "scope A's snapshot must NOT contain scope B's client (cross-scope isolation)"
    );
    assert!(
        snapshot_a
            .resources
            .client
            .iter()
            .all(|c| c.client_id != confidential_b),
        "no scope B client may appear in scope A's snapshot"
    );
}
