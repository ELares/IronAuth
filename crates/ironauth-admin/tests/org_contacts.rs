// SPDX-License-Identifier: MIT OR Apache-2.0

//! The organization contact surface, driven through the router (issue #141).
//!
//! # Why this file exists
//!
//! The store suite owns what the table guarantees. What it cannot own is anything the HANDLER
//! decides, and one of those decisions shipped wrong: the removal handler learned the event's
//! category by reading a PAGE of the live listing, so a contact past that page had its removal
//! tombstoned, audited and answered 204 while announcing nothing.
//!
//! A store-level test cannot see that. It calls `remove_with_event` and hands over an event of
//! its own, which is exactly the step the handler gets wrong -- so the store test passes against
//! the paged read and against the point lookup alike. The defect lives at this layer and so does
//! the test that holds it.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use ironauth_store::{EnvironmentId, Scope, TenantId};
use std::time::Duration;

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

/// Claim and complete everything currently in the outbox, returning each event's type.
///
/// LOOPS TO EMPTY rather than claiming once, for the reason the sibling drain in
/// `config_write_events.rs` records: the outbox serializes per ordering key, so a second event
/// about one object is not claimable until the first is COMPLETED. A single pass silently stops
/// being a drain the moment a test makes two writes about one object.
async fn drain(harness: &Harness, scope: Scope) -> Vec<String> {
    drain_full(harness, scope)
        .await
        .into_iter()
        .map(|(kind, _)| kind)
        .collect()
}

/// [`drain`] keeping each event's payload as well as its type.
async fn drain_full(harness: &Harness, scope: Scope) -> Vec<(String, serde_json::Value)> {
    let mut seen = Vec::new();
    loop {
        let claimed = harness
            .store()
            .scoped(scope)
            .outbox()
            .claim(
                &Env::system(),
                ironauth_store::WEBHOOK_EVENT_CONSUMER,
                Duration::from_secs(30),
                100,
            )
            .await
            .expect("claim from the outbox");
        if claimed.is_empty() {
            return seen;
        }
        for message in claimed {
            seen.push((
                message.payload["type"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                message.payload["payload"].clone(),
            ));
            harness
                .store()
                .scoped(scope)
                .outbox()
                .complete(&Env::system(), &message)
                .await
                .expect("complete a claimed event");
        }
    }
}

#[tokio::test]
async fn removing_a_contact_past_the_first_page_still_announces_it() {
    // THE DEFECT, EXACTLY. With a page ceiling of one, the SECOND contact is past the first page.
    // The handler that read a page to learn the category found nothing for it, passed no event,
    // and still removed the row and answered 204 -- so a consumer counting `org_contact.removed`
    // undercounted, silently, and a subscriber that keeps notifying the removed person never
    // learns to stop.
    //
    // THE CEILING IS THE POINT, NOT THE NUMBER. At the shipped ceiling of 200 this needs 201
    // contacts; at a ceiling of one it needs two. Same property, two orders of magnitude cheaper.
    let harness = Harness::start_with_max_page_size(10, 1).await;
    let (tenant, environment) = harness.create_tenant("Acme", "k-tenant").await;
    let scope = scope_of(&tenant, &environment);
    let orgs = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let (status, _, created) = harness
        .post(
            &orgs,
            "k-org",
            &serde_json::json!({ "display_name": "Globex" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create org: {created}");
    let org: serde_json::Value = serde_json::from_str(&created).expect("json");
    let org = org["id"].as_str().expect("an organization id");
    let contacts = format!("{orgs}/{org}/contacts");

    // DRAIN AFTER THE ORGANIZATION, not before it: creating one is itself an audited domain
    // write and announces `organization.created`, so draining any earlier leaves the seed's own
    // event in the batch the assertions below are about.
    drain(&harness, scope).await;

    let mut ids = Vec::new();
    for (index, category) in ["technical", "security"].into_iter().enumerate() {
        let (status, _, body) = harness
            .post(
                &contacts,
                &format!("k-contact-{index}"),
                &serde_json::json!({
                    "display_name": format!("Person {index}"),
                    "email": format!("person{index}@acme.example"),
                    "category": category,
                })
                .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create contact: {body}");
        let view: serde_json::Value = serde_json::from_str(&body).expect("json");
        ids.push(view["id"].as_str().expect("a contact id").to_owned());
    }

    // The two adds announced; drain them so what follows is only the removal.
    let added = drain(&harness, scope).await;
    assert_eq!(
        added,
        vec![
            "org_contact.added".to_owned(),
            "org_contact.added".to_owned()
        ],
        "the adds announced {added:?}"
    );

    // THE SECOND CONTACT IS PAST THE PAGE, which is what makes this fixture able to see the bug.
    let (status, _, listed) = harness.get(&contacts).await;
    assert_eq!(status, StatusCode::OK, "list: {listed}");
    assert!(
        listed.contains(&ids[0]) && !listed.contains(&ids[1]),
        "the first page did not hold exactly the first contact, so this cannot see the bug: \
         {listed}"
    );

    // AND ITS REMOVAL ANNOUNCES.
    let (status, _, body) = harness.delete(&format!("{contacts}/{}", ids[1])).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete: {body}");
    let announced = drain_full(&harness, scope).await;
    assert_eq!(
        announced.len(),
        1,
        "a removal past the first page announced {announced:?}"
    );
    assert_eq!(announced[0].0, "org_contact.removed");
    // AND IT CARRIES THAT CONTACT'S OWN CATEGORY. Comparing only the TYPE would pass against a
    // handler that reached for any contact's category it could find -- which is close to what
    // the paged scan did. The second contact is the `security` one; the first is `technical`,
    // so a handler that took the first page's row would announce the wrong word here.
    assert_eq!(
        announced[0].1["category"], "security",
        "the removal announced another contact's category: {announced:?}"
    );
}
