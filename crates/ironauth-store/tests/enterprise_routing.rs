// SPDX-License-Identifier: MIT OR Apache-2.0

//! Enterprise inbound routing over a real database (`DATABASE_URL`) (issue #77, PR 1).
//!
//! Proves the load-bearing store properties of org connections and routing rules:
//!
//! - **CRUD + lookup.** A binding and a domain / user routing rule are created on the
//!   control plane and resolved on the data plane by their selector (each a single row
//!   through its per-scope unique index).
//! - **The structural routing-confusion defence (the adversarial property).** Two
//!   organizations can never both claim one domain in a scope: a second enabled domain
//!   rule for the same domain is REJECTED by the per-scope partial unique index (a
//!   `Conflict`), not by an application check.
//! - **Secret-free snapshot export.** A config-snapshot export carries the binding and
//!   the rule, and the per-user selector travels only as an OPAQUE blind index.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ConnectorCapabilities, ConnectorId, CorrelationId, NewConnector, NewOrgConnection,
    NewRoutingRule, OrgConnectionId, OrganizationId, RoutingRuleId, RoutingSelector, StoreError,
    export_snapshot,
};

const CONNECTOR_SLUG: &str = "acme-oidc";
const ROUTED_DOMAIN: &str = "acme.example";
const ROUTED_USER: &str = "ceo@acme.example";

/// A minimal secret-free connector definition JSON for `slug`.
fn definition_json(slug: &str) -> String {
    format!(
        r#"{{"connector_id":"{slug}","display_name":"Acme","protocol":"oidc","endpoints":{{"issuer":"https://issuer.example.com"}},"scopes":["openid","email"],"client_id":"ironauth-at-acme"}}"#
    )
}

fn caps() -> ConnectorCapabilities<'static> {
    ConnectorCapabilities {
        refresh: false,
        groups: false,
        logout_propagation: false,
        email_verified_trust: "untrusted",
    }
}

/// Seed an organization, a connector, and a binding between them; return the binding id.
async fn seed_binding(
    db: &TestDatabase,
    env: &Env,
    scope: ironauth_store::Scope,
) -> OrgConnectionId {
    let control = db.control_store();
    let org_id = OrganizationId::generate(env, &scope);
    control
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &org_id, 1_000_000, "Acme Corp", None)
        .await
        .expect("create organization");

    let connector_id = ConnectorId::generate(env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .connectors()
        .create(
            env,
            &connector_id,
            1_000_000,
            NewConnector {
                slug: CONNECTOR_SLUG,
                definition_json: &definition_json(CONNECTOR_SLUG),
                client_secret: b"upstream-secret",
                capabilities: caps(),
                enabled: true,
            },
            None,
        )
        .await
        .expect("create connector");

    let ocn_id = OrgConnectionId::generate(env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .org_connections()
        .create(
            env,
            &ocn_id,
            1_000_000,
            NewOrgConnection {
                organization_id: &org_id,
                connector_id: &connector_id,
                capture_upstream_tokens: false,
                enabled: true,
            },
        )
        .await
        .expect("create org connection");
    ocn_id
}

#[tokio::test]
async fn a_domain_rule_resolves_on_the_data_plane() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let ocn_id = seed_binding(&db, &env, scope).await;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .routing_rules()
        .create(
            &env,
            &RoutingRuleId::generate(&env, &scope),
            1_000_000,
            NewRoutingRule {
                selector: RoutingSelector::Domain(ROUTED_DOMAIN),
                org_connection_id: &ocn_id,
                priority: 0,
                enabled: true,
            },
        )
        .await
        .expect("create domain rule");

    // The data plane resolves the rule by the NORMALIZED domain (a login submitted with
    // a different case still matches).
    let normalized = ironauth_store::normalize_routing_domain("ACME.example").expect("normalize");
    let matched = db
        .store()
        .scoped(scope)
        .routing_rules()
        .by_domain(&normalized)
        .await
        .expect("by_domain")
        .expect("a domain rule matches");
    assert_eq!(matched.org_connection_id, ocn_id.to_string());
    assert_eq!(matched.rule_kind, "domain");
}

#[tokio::test]
async fn a_user_rule_resolves_by_blind_index_never_plaintext() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let ocn_id = seed_binding(&db, &env, scope).await;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .routing_rules()
        .create(
            &env,
            &RoutingRuleId::generate(&env, &scope),
            1_000_000,
            NewRoutingRule {
                selector: RoutingSelector::User(ROUTED_USER),
                org_connection_id: &ocn_id,
                priority: 0,
                enabled: true,
            },
        )
        .await
        .expect("create user rule");

    // The data plane resolves the rule by the CANONICAL form of the submitted handle (a
    // case/whitespace variant maps to the same blind index).
    let matched = db
        .store()
        .scoped(scope)
        .routing_rules()
        .by_user_identifier("CEO@acme.example")
        .await
        .expect("by_user_identifier")
        .expect("a user rule matches");
    assert_eq!(matched.org_connection_id, ocn_id.to_string());
    assert_eq!(matched.rule_kind, "user");
    // The selector at rest is the OPAQUE blind index, never the plaintext identifier.
    let bidx = matched
        .user_bidx
        .expect("a user rule carries a blind index");
    assert!(
        !bidx
            .windows(ROUTED_USER.len())
            .any(|w| w == ROUTED_USER.as_bytes()),
        "the user selector must not carry the plaintext identifier"
    );
}

// One linear two-org seed plus the conflict assertion; splitting it would scatter the
// single adversarial narrative.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn a_second_domain_mapping_is_rejected_by_the_per_scope_unique_index() {
    // The adversarial routing-confusion property: an attacker cannot cause a domain that
    // already maps to org A's connection to ALSO map to org B's. The per-scope partial
    // unique index rejects the second enabled mapping at the storage layer.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Two distinct bindings (two organizations) in the same scope.
    let ocn_a = seed_binding(&db, &env, scope).await;
    // A second binding reuses the connector-seed helper but for a fresh org/connector.
    let ocn_b = {
        let control = db.control_store();
        let org_b = OrganizationId::generate(&env, &scope);
        control
            .management()
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .organizations(scope)
            .create(&env, &org_b, 1_000_000, "Rival Corp", None)
            .await
            .expect("create org b");
        let connector_b = ConnectorId::generate(&env, &scope);
        control
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .connectors()
            .create(
                &env,
                &connector_b,
                1_000_000,
                NewConnector {
                    slug: "rival-oidc",
                    definition_json: &definition_json("rival-oidc"),
                    client_secret: b"rival-secret",
                    capabilities: caps(),
                    enabled: true,
                },
                None,
            )
            .await
            .expect("create connector b");
        let ocn_b = OrgConnectionId::generate(&env, &scope);
        control
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .org_connections()
            .create(
                &env,
                &ocn_b,
                1_000_000,
                NewOrgConnection {
                    organization_id: &org_b,
                    connector_id: &connector_b,
                    capture_upstream_tokens: false,
                    enabled: true,
                },
            )
            .await
            .expect("create org connection b");
        ocn_b
    };

    // org A claims the domain first.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .routing_rules()
        .create(
            &env,
            &RoutingRuleId::generate(&env, &scope),
            1_000_000,
            NewRoutingRule {
                selector: RoutingSelector::Domain(ROUTED_DOMAIN),
                org_connection_id: &ocn_a,
                priority: 0,
                enabled: true,
            },
        )
        .await
        .expect("org A claims the domain");

    // org B attempts to claim the SAME domain: the unique index refuses it.
    let conflict = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .routing_rules()
        .create(
            &env,
            &RoutingRuleId::generate(&env, &scope),
            1_000_000,
            NewRoutingRule {
                selector: RoutingSelector::Domain(ROUTED_DOMAIN),
                org_connection_id: &ocn_b,
                priority: 0,
                enabled: true,
            },
        )
        .await;
    assert!(
        matches!(conflict, Err(StoreError::Conflict)),
        "a second org cannot claim a domain already mapped in the scope, got {conflict:?}"
    );

    // The domain still resolves to org A only (org B never reached it).
    let normalized = ironauth_store::normalize_routing_domain(ROUTED_DOMAIN).expect("normalize");
    let matched = db
        .store()
        .scoped(scope)
        .routing_rules()
        .by_domain(&normalized)
        .await
        .expect("by_domain")
        .expect("the domain still resolves");
    assert_eq!(
        matched.org_connection_id,
        ocn_a.to_string(),
        "the domain routes to org A, never org B"
    );
}

#[tokio::test]
async fn the_snapshot_export_carries_the_binding_and_rule_secret_free() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let ocn_id = seed_binding(&db, &env, scope).await;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .routing_rules()
        .create(
            &env,
            &RoutingRuleId::generate(&env, &scope),
            1_000_000,
            NewRoutingRule {
                selector: RoutingSelector::User(ROUTED_USER),
                org_connection_id: &ocn_id,
                priority: 0,
                enabled: true,
            },
        )
        .await
        .expect("create user rule");

    let snapshot = export_snapshot(&db.control_store().scoped(scope))
        .await
        .expect("export");
    assert_eq!(
        snapshot.resources.org_connection.len(),
        1,
        "the binding is exported"
    );
    assert_eq!(
        snapshot.resources.routing_rule.len(),
        1,
        "the routing rule is exported"
    );
    let rule = &snapshot.resources.routing_rule[0];
    assert_eq!(rule.rule_kind, "user");
    assert!(rule.user_bidx.is_some(), "the user selector travels opaque");

    // The canonical bytes never carry the plaintext user identifier (the opaque blind
    // index is the only user selector on the wire).
    let bytes = snapshot.to_canonical_bytes().expect("canonical bytes");
    let text = String::from_utf8(bytes).expect("utf8");
    assert!(
        !text.contains(ROUTED_USER),
        "the plaintext user identifier must never appear in a snapshot export"
    );
}

#[tokio::test]
async fn an_org_connection_and_routing_rule_and_token_are_cross_scope_isolated() {
    // A cross-scope IDOR probe (issue #77, L3): a binding, a routing rule, AND a routing
    // token minted in scope A must all read empty / fail to verify from a sibling scope B.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    let ocn_a = seed_binding(&db, &env, scope_a).await;
    db.control_store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .routing_rules()
        .create(
            &env,
            &RoutingRuleId::generate(&env, &scope_a),
            1_000_000,
            NewRoutingRule {
                selector: RoutingSelector::Domain(ROUTED_DOMAIN),
                org_connection_id: &ocn_a,
                priority: 0,
                enabled: true,
            },
        )
        .await
        .expect("scope A claims the domain");

    // Scope B must not resolve scope A's domain rule (a cross-tenant selector read).
    let normalized = ironauth_store::normalize_routing_domain(ROUTED_DOMAIN).expect("normalize");
    assert!(
        db.store()
            .scoped(scope_b)
            .routing_rules()
            .by_domain(&normalized)
            .await
            .expect("by_domain")
            .is_none(),
        "scope B must not resolve scope A's routing rule"
    );

    // Scope A's org-connection id is out of scope in B: the uniform not-found.
    assert!(
        matches!(
            db.store()
                .scoped(scope_b)
                .org_connections()
                .parse_id(&ocn_a.to_string()),
            Err(StoreError::NotFound)
        ),
        "scope A's org connection id must be out of scope in B"
    );

    // A routing token minted in scope A verifies in A but NOT in B: the MAC binds the scope
    // (tenant + environment), so a token cannot be replayed cross-scope.
    let token = db
        .store()
        .scoped(scope_a)
        .org_connections()
        .mint_routing_token(&ocn_a.to_string(), CONNECTOR_SLUG, 1_000_000_000)
        .expect("mint token");
    assert!(
        db.store()
            .scoped(scope_a)
            .org_connections()
            .verify_routing_token(&token, CONNECTOR_SLUG, 0)
            .is_some(),
        "the token verifies in its own scope"
    );
    assert!(
        db.store()
            .scoped(scope_b)
            .org_connections()
            .verify_routing_token(&token, CONNECTOR_SLUG, 0)
            .is_none(),
        "the token must not verify in a foreign scope"
    );
}
