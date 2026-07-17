// SPDX-License-Identifier: MIT OR Apache-2.0

//! Declarative federation connectors over a real database (`DATABASE_URL`) (issue
//! #75, PR A).
//!
//! Proves the load-bearing properties of the connector data plane against a live
//! database:
//!
//! - **CRUD.** A connector is created (its upstream client secret SEALED inline, its
//!   capability columns written from the definition), read back SECRET-FREE, updated,
//!   and deleted, all on the control-plane role that owns the connector lifecycle.
//! - **Conservative capability default.** A connector whose definition omits the
//!   capability matrix reads back `email_verified_trust = untrusted`.
//! - **Secret never in an export.** A config-snapshot export of the environment
//!   carries the connector definition and a NAMED REFERENCE to its upstream client
//!   secret, and the distinctive secret VALUE appears NOWHERE in the bytes (the #58
//!   proof).
//! - **Cross-tenant isolation.** A raw, RLS-scoped probe as the control role, scoped
//!   to another tenant with the app filter subverted, sees zero of scope A's connector
//!   rows.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ConnectorCapabilities, CorrelationId, NewConnector, export_snapshot, validate_document,
};
use sqlx::Row;

/// A distinctive upstream client-secret value: it is sealed at rest and must NEVER
/// appear in a read record or a config-snapshot export.
const SECRET_MARKER: &str = "UPSTREAM-CLIENT-SECRET-DO-NOT-LEAK-cnr";

/// A minimal, valid secret-free connector definition JSON for `slug`. Mirrors the
/// projection the management API stores (the `client_secret` field is stripped).
fn definition_json(slug: &str) -> String {
    format!(
        r#"{{"connector_id":"{slug}","display_name":"Acme","protocol":"oidc","endpoints":{{"issuer":"https://issuer.example.com"}},"scopes":["openid","email"],"client_id":"ironauth-at-acme","capabilities":{{"refresh":false,"groups":false,"logout_propagation":false,"email_verified_trust":"untrusted"}}}}"#
    )
}

/// The conservative capability set (all off, email-verified trust untrusted).
fn conservative_caps() -> ConnectorCapabilities<'static> {
    ConnectorCapabilities {
        refresh: false,
        groups: false,
        logout_propagation: false,
        email_verified_trust: "untrusted",
    }
}

// One end-to-end CRUD + seal + export walkthrough; splitting it would only obscure
// the single narrative it proves.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn connector_crud_seals_the_secret_and_exports_a_reference() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    // CREATE on the control role (which owns connectors and holds the KEK/DEK grants).
    let definition = definition_json("acme-oidc");
    let id = {
        use ironauth_store::ConnectorId;
        let id = ConnectorId::generate(&env, &scope);
        control
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .connectors()
            .create(
                &env,
                &id,
                1_000_000,
                NewConnector {
                    slug: "acme-oidc",
                    definition_json: &definition,
                    client_secret: SECRET_MARKER.as_bytes(),
                    capabilities: conservative_caps(),
                    enabled: true,
                },
                None,
            )
            .await
            .expect("create connector");
        id
    };

    // READ back: secret-free record, conservative capability default.
    let record = control
        .scoped(scope)
        .connectors()
        .get(&id)
        .await
        .expect("get connector");
    assert_eq!(record.slug, "acme-oidc");
    assert!(record.enabled);
    assert_eq!(
        record.capabilities.email_verified_trust, "untrusted",
        "email_verified_trust must default to untrusted"
    );
    assert!(
        !record.definition_json.contains(SECRET_MARKER),
        "the stored definition must be secret-free"
    );

    // A second connector with NO capability matrix in the definition still reads back
    // untrusted (the conservative default is written from the definition layer).
    let bare_definition = r#"{"connector_id":"bare","display_name":"Bare","protocol":"oidc","endpoints":{"issuer":"https://bare.example.com"},"scopes":["openid"],"client_id":"ic"}"#;
    let bare_id = {
        use ironauth_store::ConnectorId;
        let bare_id = ConnectorId::generate(&env, &scope);
        control
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .connectors()
            .create(
                &env,
                &bare_id,
                2_000_000,
                NewConnector {
                    slug: "bare",
                    definition_json: bare_definition,
                    client_secret: b"another-secret",
                    capabilities: conservative_caps(),
                    enabled: true,
                },
                None,
            )
            .await
            .expect("create bare connector");
        bare_id
    };
    let bare = control
        .scoped(scope)
        .connectors()
        .get(&bare_id)
        .await
        .expect("get bare");
    assert_eq!(bare.capabilities.email_verified_trust, "untrusted");

    // LIST returns both, ordered by (created_at, id).
    let all = control
        .scoped(scope)
        .connectors()
        .list_all()
        .await
        .expect("list_all");
    assert_eq!(all.len(), 2);

    // EXPORT: the connector definition travels, its secret is a REFERENCE, and the
    // distinctive secret VALUE appears NOWHERE (the #58 proof).
    let snapshot = export_snapshot(&control.scoped(scope))
        .await
        .expect("export snapshot");
    let bytes = snapshot.to_canonical_bytes().expect("canonicalize");
    let text = String::from_utf8(bytes.clone()).expect("utf8");
    assert!(
        !text.contains(SECRET_MARKER),
        "the upstream client secret must never appear in a snapshot"
    );
    // The document validates and carries a connector with a secret REFERENCE.
    validate_document(&bytes).expect("snapshot validates");
    let acme = snapshot
        .resources
        .connector
        .iter()
        .find(|c| c.connector_slug == "acme-oidc")
        .expect("connector present in snapshot");
    let secret_ref = acme.secret.as_ref().expect("a secret reference is present");
    assert_eq!(secret_ref.reference, "connector_client_secret");

    // UPDATE reseals and rewrites; the record still reads back secret-free.
    let updated_definition = definition_json("acme-oidc").replace("Acme", "Acme Renamed");
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .connectors()
        .update(
            &env,
            &id,
            NewConnector {
                slug: "acme-oidc",
                definition_json: &updated_definition,
                client_secret: SECRET_MARKER.as_bytes(),
                capabilities: conservative_caps(),
                enabled: true,
            },
        )
        .await
        .expect("update connector");
    let reread = control
        .scoped(scope)
        .connectors()
        .get(&id)
        .await
        .expect("re-get");
    assert!(reread.definition_json.contains("Acme Renamed"));
    assert!(!reread.definition_json.contains(SECRET_MARKER));

    // DELETE removes it (and its sealed secret).
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .connectors()
        .delete(&env, &id)
        .await
        .expect("delete connector");
    let after = control.scoped(scope).connectors().get(&id).await;
    assert!(after.is_err(), "a deleted connector must not resolve");
}

#[tokio::test]
async fn connectors_are_cross_tenant_isolated() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let control = db.control_store();

    // Seed a connector in scope A.
    let id_a = {
        use ironauth_store::ConnectorId;
        let id_a = ConnectorId::generate(&env, &scope_a);
        control
            .scoped(scope_a)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .connectors()
            .create(
                &env,
                &id_a,
                1_000_000,
                NewConnector {
                    slug: "acme-oidc",
                    definition_json: &definition_json("acme-oidc"),
                    client_secret: SECRET_MARKER.as_bytes(),
                    capabilities: conservative_caps(),
                    enabled: true,
                },
                None,
            )
            .await
            .expect("create in A");
        id_a
    };

    // The typed scope guard: scope B's repository cannot resolve A's connector.
    assert!(
        control
            .scoped(scope_b)
            .connectors()
            .get(&id_a)
            .await
            .is_err(),
        "a scope-A connector must be a uniform not-found under scope B"
    );
    // Scope B's export carries no connectors.
    let snapshot_b = export_snapshot(&control.scoped(scope_b))
        .await
        .expect("export B");
    assert!(
        snapshot_b.resources.connector.is_empty(),
        "scope B must export none of scope A's connectors"
    );

    // RAW RLS probe as the low-privilege control role, scoped to B with the app filter
    // SUBVERTED to explicitly target A's rows: row-level security still returns zero.
    let pool = db.control_pool();
    let mut tx = pool.begin().await.expect("begin as scope B");
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(scope_b.tenant().to_string())
        .execute(&mut *tx)
        .await
        .expect("bind tenant B");
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(scope_b.environment().to_string())
        .execute(&mut *tx)
        .await
        .expect("bind env B");
    let leaked: i64 = sqlx::query(
        "SELECT count(*) AS c FROM connectors WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope_a.tenant().to_string())
    .bind(scope_a.environment().to_string())
    .fetch_one(&mut *tx)
    .await
    .expect("cross-scope count")
    .get("c");
    assert_eq!(
        leaked, 0,
        "RLS must hide scope A connectors from a scope B session even with the app filter bypassed"
    );
    tx.commit().await.expect("commit B read");
}
