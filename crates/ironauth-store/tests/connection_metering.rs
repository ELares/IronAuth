// SPDX-License-Identifier: MIT OR Apache-2.0

//! Connection metering is STRUCTURALLY absent (issue #96, acceptance criterion 2).
//!
//! The criterion is unusual in that it asserts the absence of a feature, and it is worth
//! saying why that needs a test at all. Every competitor in this space meters enterprise
//! connections: the number of upstream identity providers an organization may bind is the
//! standard paywall, and it is the reason "SSO tax" is a phrase. This project's covenant
//! is that no such gate exists, which is only credible if nothing can add one quietly.
//!
//! An absence is easy to assert vacuously, so this drives BOTH halves the criterion
//! names:
//!
//!   * the BEHAVIOUR, by creating many bindings across many organizations in one
//!     environment and requiring every one to succeed. A cap introduced anywhere (a count
//!     constraint, a trigger, an application check) fails this at whatever number it
//!     chose.
//!   * the SCHEMA, by reading the shipped DDL for `org_connections` and requiring that it
//!     declares no counter, quota, or limit. A cap that is merely UNENFORCED today would
//!     pass the behavioural half while sitting in the table waiting to be switched on.
//!
//! Neither half implies the other, which is why both are here.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ConnectorCapabilities, ConnectorId, CorrelationId, NewConnector, NewOrgConnection,
    OrgConnectionId, OrganizationId, Scope,
};

/// Organizations to bind, and connectors to bind them to. The product is the number of
/// bindings created: comfortably past any number somebody would pick as a free-tier cap,
/// and small enough to stay a fast test.
const ORGANIZATIONS: usize = 8;
const CONNECTORS: usize = 3;

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

async fn seed_organization(db: &TestDatabase, env: &Env, scope: Scope, n: usize) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, 1_000_000, &format!("Customer {n}"), None)
        .await
        .expect("create organization");
    id
}

async fn seed_connector(db: &TestDatabase, env: &Env, scope: Scope, n: usize) -> ConnectorId {
    let id = ConnectorId::generate(env, &scope);
    let slug = format!("upstream-{n}");
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .connectors()
        .create(
            env,
            &id,
            1_000_000,
            NewConnector {
                slug: &slug,
                definition_json: &definition_json(&slug),
                client_secret: b"upstream-secret",
                capabilities: caps(),
                enabled: true,
            },
            None,
        )
        .await
        .expect("create connector");
    id
}

/// The behavioural half: a large number of bindings across organizations all succeed.
#[tokio::test]
async fn many_connections_across_many_organizations_all_succeed() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let mut organizations = Vec::new();
    for n in 0..ORGANIZATIONS {
        organizations.push(seed_organization(&db, &env, scope, n).await);
    }
    let mut connectors = Vec::new();
    for n in 0..CONNECTORS {
        connectors.push(seed_connector(&db, &env, scope, n).await);
    }

    let mut created = 0_usize;
    for organization_id in &organizations {
        for connector_id in &connectors {
            let id = OrgConnectionId::generate(&env, &scope);
            db.control_store()
                .scoped(scope)
                .acting(db.test_actor(&env), CorrelationId::generate(&env))
                .org_connections()
                .create(
                    &env,
                    &id,
                    1_000_000,
                    NewOrgConnection {
                        organization_id,
                        connector_id,
                        overlay_min_acr: None,
                        max_age_secs: None,
                        overlay_min_class: None,
                        capture_upstream_tokens: false,
                        enabled: true,
                    },
                )
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "binding {} of {} was refused, which is what a connection cap looks \
                         like from here: {error:?}",
                        created + 1,
                        ORGANIZATIONS * CONNECTORS
                    )
                });
            created += 1;
        }
    }

    assert_eq!(
        created,
        ORGANIZATIONS * CONNECTORS,
        "every binding across every organization must be creatable"
    );
}

/// The schema half: the shipped DDL declares no counter, quota, or limit.
///
/// Read from the migration TEXT rather than from `information_schema`, deliberately. The
/// question is what the project SHIPS, and a column added by a future migration is
/// exactly what this is meant to catch; a live-database check would also pass on a
/// deployment that had been altered by hand, which is a different question.
#[test]
fn the_connections_table_declares_no_counter_or_limit() {
    let migration = include_str!("../migrations/0059_enterprise_inbound_routing.sql");
    let start = migration.find("CREATE TABLE org_connections").expect(
        "the org_connections DDL must be in this migration; if it moved, this test \
                 is reading the wrong file and is no longer checking anything",
    );
    let ddl = &migration[start..];
    let end = ddl.find("\n);").expect("a terminated CREATE TABLE");
    let ddl = &ddl[..end].to_ascii_lowercase();

    // Shapes a cap would take. `max_age_secs` is deliberately NOT among them: it bounds a
    // session's age, not a count of anything, and matching on "max" alone would flag it
    // and make this test a nuisance that gets deleted.
    for forbidden in [
        "quota",
        "limit",
        "counter",
        "seat",
        "max_connections",
        "connection_count",
        "check (count",
    ] {
        assert!(
            !ddl.contains(forbidden),
            "the org_connections DDL mentions {forbidden:?}. Metering enterprise \
             connections is the standard paywall in this market and this project's \
             covenant is that it has none, so a counter appearing here is a product \
             decision that must be made deliberately rather than arrive in a migration. \
             DDL: {ddl}"
        );
    }

    // Non-vacuity: prove the slice really is the table body rather than an empty string
    // that trivially contains none of the above.
    assert!(
        ddl.contains("organization_id") && ddl.contains("connector_id"),
        "the extracted DDL does not look like the org_connections body, so the scan above \
         proved nothing. Extracted: {ddl}"
    );
}

/// A REAL connection open is metered, and a duplicate is not (issue #107 criterion 4).
///
/// `UsageTally` counts connections per tenant off `connection.opened`, and nothing emitted
/// it: the type was named by a constant, registered nowhere, produced by nothing, so the
/// count was zero on every deployment regardless of how many connections existed.
///
/// The second half is the guard. A duplicate open is a typed conflict, and the enqueue sits
/// after that guard, so a connection a concurrent create already opened is not metered twice
/// -- which for a per-connection count is the difference between a correct invoice and an
/// inflated one.
#[tokio::test]
async fn a_real_connection_open_is_metered_once() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_organization(&db, &env, scope, 0).await;
    let connector = seed_connector(&db, &env, scope, 0).await;
    let id = ironauth_store::OrgConnectionId::generate(&env, &scope);

    let spec = || NewOrgConnection {
        organization_id: &org,
        connector_id: &connector,
        overlay_min_acr: None,
        max_age_secs: None,
        overlay_min_class: None,
        capture_upstream_tokens: false,
        enabled: true,
    };

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_connections()
        .create(&env, &id, 1_000_000, spec())
        .await
        .expect("open the connection");

    let events = match db
        .store()
        .scoped(scope)
        .outbox()
        .events_page_after(ironauth_store::EventCursor::beginning(), 100)
        .await
        .expect("read the feed")
    {
        ironauth_store::EventPage::Page(events) => events,
        ironauth_store::EventPage::Gone { .. } => panic!("nothing was pruned"),
    };
    let opened: Vec<_> = events
        .iter()
        .filter(|m| m.payload["type"] == "connection.opened")
        .collect();
    assert_eq!(
        opened.len(),
        1,
        "a real connection open must put exactly one event on the feed, or metering counts \
         nothing: {events:?}"
    );
    assert_eq!(
        opened[0].payload["payload"]["connection_id"],
        id.to_string()
    );
    ironauth_store::event_catalog::validate_event(&opened[0].payload)
        .expect("it validates against the registry the fan-out enforces");

    let mut tally = ironauth_store::UsageTally::new();
    tally.absorb(&events);
    assert_eq!(tally.connections(), 1, "one open is one connection");

    // A duplicate open is refused, and the enqueue sits after that guard.
    let duplicate = ironauth_store::OrgConnectionId::generate(&env, &scope);
    let error = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_connections()
        .create(&env, &duplicate, 2_000_000, spec())
        .await
        .expect_err("the same organization and connector is a conflict");
    assert!(
        matches!(error, ironauth_store::StoreError::Conflict),
        "got {error:?}"
    );

    let after = match db
        .store()
        .scoped(scope)
        .outbox()
        .events_page_after(ironauth_store::EventCursor::beginning(), 100)
        .await
        .expect("read the feed")
    {
        ironauth_store::EventPage::Page(events) => events,
        ironauth_store::EventPage::Gone { .. } => panic!("nothing was pruned"),
    };
    let mut after_tally = ironauth_store::UsageTally::new();
    after_tally.absorb(&after);
    assert_eq!(
        after_tally.connections(),
        1,
        "a refused duplicate must not be metered; billing a conflict is an inflated invoice"
    );
}
