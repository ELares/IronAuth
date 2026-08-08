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
    NewRoutingRule, OrgConnectionId, OrganizationId, RoutingRuleId, RoutingSelector, Scope,
    StoreError, export_snapshot,
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
                overlay_min_acr: None,
                max_age_secs: None,
                overlay_min_class: None,
                capture_upstream_tokens: false,
                enabled: true,
            },
        )
        .await
        .expect("create org connection");
    ocn_id
}

/// Mark a domain rule VERIFIED, which since issue #96 is what makes it route at all.
///
/// A fresh claim is `pending` and the router refuses it, so a test that creates a domain rule
/// and expects a match has to prove ownership first. That extra line is the point of the
/// change: claiming a domain and owning it are different acts.
async fn verify_domain(db: &TestDatabase, env: &Env, scope: Scope, id: &RoutingRuleId) {
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .routing_rules()
        .record_domain_verification(env, id, true)
        .await
        .expect("record domain verification");
}

#[tokio::test]
async fn a_domain_rule_resolves_on_the_data_plane() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let ocn_id = seed_binding(&db, &env, scope).await;

    let rule_id = RoutingRuleId::generate(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .routing_rules()
        .create(
            &env,
            &rule_id,
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

    // A fresh claim is `pending` and routes nothing (issue #96); prove ownership.
    verify_domain(&db, &env, scope, &rule_id).await;

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
                    overlay_min_acr: None,
                    max_age_secs: None,
                    overlay_min_class: None,
                    capture_upstream_tokens: false,
                    enabled: true,
                },
            )
            .await
            .expect("create org connection b");
        ocn_b
    };

    // org A claims the domain first.
    let rule_id = RoutingRuleId::generate(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .routing_rules()
        .create(
            &env,
            &rule_id,
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

    // Org A PROVES the claim, which is what makes it route (issue #96). The land grab this
    // test guards against is now two-step: claiming the domain no longer wins it.
    verify_domain(&db, &env, scope, &rule_id).await;

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

#[tokio::test]
async fn the_broker_overlay_columns_round_trip_through_a_binding()
-> Result<(), Box<dyn std::error::Error>> {
    // The overlay policy columns (issue #77 PR 2) are set at INSERT (the control-plane grant
    // is SELECT + INSERT, no UPDATE) and read back on the data plane exactly as stored, so
    // the federation callback and the authorization gate enforce the operator's configured
    // policy.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let control = db.control_store();
    let org_id = OrganizationId::generate(&env, &scope);
    control
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .create(&env, &org_id, 1_000_000, "Acme Corp", None)
        .await?;
    let connector_id = ConnectorId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .connectors()
        .create(
            &env,
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
        .await?;

    let ocn_id = OrgConnectionId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_connections()
        .create(
            &env,
            &ocn_id,
            1_000_000,
            NewOrgConnection {
                organization_id: &org_id,
                connector_id: &connector_id,
                overlay_min_acr: Some("urn:ironauth:acr:mfa"),
                max_age_secs: Some(3_600),
                overlay_min_class: Some("passkey"),
                capture_upstream_tokens: false,
                enabled: true,
            },
        )
        .await?;

    let record = db
        .store()
        .scoped(scope)
        .org_connections()
        .get(&ocn_id)
        .await?;
    assert_eq!(
        record.overlay_min_acr.as_deref(),
        Some("urn:ironauth:acr:mfa")
    );
    assert_eq!(record.max_age_secs, Some(3_600));
    assert_eq!(record.overlay_min_class.as_deref(), Some("passkey"));

    // The overlay_min_class CHECK constraint rejects a value outside the ladder, so a
    // malformed policy can never be persisted.
    let bad_ocn = OrgConnectionId::generate(&env, &scope);
    let result = control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_connections()
        .create(
            &env,
            &bad_ocn,
            1_000_000,
            NewOrgConnection {
                organization_id: &org_id,
                connector_id: &connector_id,
                overlay_min_acr: None,
                max_age_secs: None,
                overlay_min_class: Some("not_a_rung"),
                capture_upstream_tokens: false,
                enabled: true,
            },
        )
        .await;
    assert!(
        result.is_err(),
        "an unknown overlay class must be refused by the CHECK"
    );
    Ok(())
}

#[tokio::test]
async fn an_unverified_domain_claim_routes_nothing_until_ownership_is_proven() {
    // Issue #96. Before this, a domain rule routed the moment it was CREATED, and the
    // per-scope unique index meant the first claimant won the domain outright. Any
    // organization in the environment could claim a domain it did not own and every
    // identifier-first login for that domain would broker to its upstream IdP, while the
    // end user saw an ordinary sign in.
    //
    // The gate lives in `by_domain` rather than in the routing module on purpose: a check in
    // the caller is one the next caller can miss, and missing it is silent. Here an
    // unverified claim is not ignored, it is unreachable.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let ocn_id = seed_binding(&db, &env, scope).await;
    let normalized = ironauth_store::normalize_routing_domain(ROUTED_DOMAIN).expect("normalize");

    let rule_id = RoutingRuleId::generate(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .routing_rules()
        .create(
            &env,
            &rule_id,
            1_000_000,
            NewRoutingRule {
                selector: RoutingSelector::Domain(ROUTED_DOMAIN),
                org_connection_id: &ocn_id,
                priority: 0,
                enabled: true,
            },
        )
        .await
        .expect("claim the domain");

    // ENABLED, and still routing nothing. `enabled` is the operator's own switch and says
    // nothing about ownership, so the two are separate gates and this asserts the new one.
    let pending = db
        .store()
        .scoped(scope)
        .routing_rules()
        .by_domain(&normalized)
        .await
        .expect("by_domain");
    assert!(
        pending.is_none(),
        "a PENDING claim resolved a route: an organization that merely asked for a domain \
         would capture every identifier-first login at it"
    );

    // A probe that RAN and did not find the record is `failed`, which must route no more
    // than `pending` does. The two are distinct states so an operator can tell "not checked
    // yet" from "checked and absent", and neither is a licence to route.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .routing_rules()
        .record_domain_verification(&env, &rule_id, false)
        .await
        .expect("record a failed probe");
    assert!(
        db.store()
            .scoped(scope)
            .routing_rules()
            .by_domain(&normalized)
            .await
            .expect("by_domain")
            .is_none(),
        "a FAILED claim resolved a route"
    );

    // Proving ownership is the only thing that opens it.
    verify_domain(&db, &env, scope, &rule_id).await;
    let matched = db
        .store()
        .scoped(scope)
        .routing_rules()
        .by_domain(&normalized)
        .await
        .expect("by_domain")
        .expect("a verified claim routes");
    assert_eq!(matched.org_connection_id, ocn_id.to_string());
}

/// A domain rule is born with a token to publish; other kinds carry none (issue #96).
///
/// Migration 0117 gave `routing_rules` a `domain_verification_token` column and nothing
/// ever wrote it, so a domain rule landed in `pending` with NOTHING for the operator to
/// put in DNS. The state machine was therefore unreachable past its first state: no
/// token, no TXT record, no path to `verified`, and `by_domain` only routes `verified`
/// rules. A column that cannot be filled is worse than an absent one, because the schema
/// reads as though the mechanism exists.
#[tokio::test]
async fn a_domain_rule_is_born_with_a_publishable_token_and_other_kinds_are_not() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let ocn = seed_binding(&db, &env, scope).await;
    let control = db.control_store();

    let domain_rule = RoutingRuleId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .routing_rules()
        .create(
            &env,
            &domain_rule,
            1_000_000,
            NewRoutingRule {
                selector: RoutingSelector::Domain(ROUTED_DOMAIN),
                org_connection_id: &ocn,
                priority: 10,
                enabled: true,
            },
        )
        .await
        .expect("create the domain rule");

    let app_rule = RoutingRuleId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .routing_rules()
        .create(
            &env,
            &app_rule,
            1_000_000,
            NewRoutingRule {
                selector: RoutingSelector::App("cli_whatever"),
                org_connection_id: &ocn,
                priority: 20,
                enabled: true,
            },
        )
        .await
        .expect("create the app rule");

    let rules = control
        .scoped(scope)
        .routing_rules()
        .list_all()
        .await
        .expect("list the rules");

    let domain = rules
        .iter()
        .find(|r| r.id == domain_rule)
        .expect("the domain rule is listed");
    assert_eq!(
        domain.domain_verification_state.as_deref(),
        Some("pending"),
        "a domain rule starts unverified"
    );
    let token = domain
        .domain_verification_token
        .as_deref()
        .expect("a domain rule must carry a token to publish, or it can never be verified");
    assert!(
        token.starts_with("ironauth-domain-verification="),
        "the token must be publishable as a TXT record value: {token}"
    );
    assert!(
        token.len() > "ironauth-domain-verification=".len() + 32,
        "the token must carry real entropy so a third party cannot pre-publish it for a \
         domain they do not control: {token}"
    );

    let app = rules
        .iter()
        .find(|r| r.id == app_rule)
        .expect("the app rule is listed");
    assert!(
        app.domain_verification_token.is_none() && app.domain_verification_state.is_none(),
        "only a DOMAIN rule has a domain to verify; an app rule carrying a token would \
         imply a ceremony that does not apply to it"
    );
}

/// Two rules do not share a token.
#[tokio::test]
async fn each_domain_rule_gets_its_own_token() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let ocn = seed_binding(&db, &env, scope).await;
    let control = db.control_store();

    let mut tokens = Vec::new();
    for (n, domain) in ["one.example", "two.example"].iter().enumerate() {
        let id = RoutingRuleId::generate(&env, &scope);
        control
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .routing_rules()
            .create(
                &env,
                &id,
                1_000_000,
                NewRoutingRule {
                    selector: RoutingSelector::Domain(domain),
                    org_connection_id: &ocn,
                    priority: i32::try_from(n).expect("fits") + 1,
                    enabled: true,
                },
            )
            .await
            .expect("create the domain rule");
        let rules = control
            .scoped(scope)
            .routing_rules()
            .list_all()
            .await
            .expect("list");
        tokens.push(
            rules
                .iter()
                .find(|r| r.id == id)
                .and_then(|r| r.domain_verification_token.clone())
                .expect("a token"),
        );
    }
    assert_ne!(
        tokens[0], tokens[1],
        "two domains must not share a verification token, or publishing one proves the \
         other"
    );
}

/// Disabling a CONNECTION stops its domain routing, so logins fall back (issue #96).
///
/// The rule's `enabled` flag and the connection's are different switches, and only the
/// rule's was consulted. Disabling a connection is how an operator turns an upstream off;
/// it has to mean users at that verified domain go back to the organization's other
/// methods. Before this, the rule kept matching and routed them into a connection
/// somebody had deliberately switched off, which locks them out rather than falling back.
#[tokio::test]
async fn disabling_the_connection_stops_its_domain_routing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let ocn = seed_binding(&db, &env, scope).await;
    let control = db.control_store();

    let rule = RoutingRuleId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .routing_rules()
        .create(
            &env,
            &rule,
            1_000_000,
            NewRoutingRule {
                selector: RoutingSelector::Domain(ROUTED_DOMAIN),
                org_connection_id: &ocn,
                priority: 10,
                enabled: true,
            },
        )
        .await
        .expect("create the domain rule");
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .routing_rules()
        .record_domain_verification(&env, &rule, true)
        .await
        .expect("verify the domain");

    // The control: while the connection is enabled the domain routes.
    let routed = control
        .scoped(scope)
        .routing_rules()
        .by_domain(ROUTED_DOMAIN)
        .await
        .expect("read");
    assert!(
        routed.is_some(),
        "a verified domain on an ENABLED connection must route, or the assertion below \
         passes for the wrong reason"
    );

    // Disable the connection the way an operator would: the column, nothing else.
    sqlx::query("UPDATE org_connections SET enabled = false WHERE id = $1")
        .bind(ocn.to_string())
        .execute(db.owner_pool())
        .await
        .expect("disable the connection");

    let routed = control
        .scoped(scope)
        .routing_rules()
        .by_domain(ROUTED_DOMAIN)
        .await
        .expect("read");
    assert!(
        routed.is_none(),
        "a DISABLED connection must stop its domain routing so the login falls back to \
         the organization's other methods; routing into a connection an operator turned \
         off locks those users out instead. Got {routed:?}"
    );
}
