// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OUTBOUND SCIM connection management surface (issue #137).
//!
//! # What is different from the inbound file next door, and why each test exists
//!
//! The inbound surface's hardest property is that a minted token appears exactly once. This one
//! has no token to appear: a connection NAMES an environment secret and the value never crosses
//! the API, so `no_response_carries_a_credential` is checking a property of the model rather
//! than care taken in a handler. It is here because "there is nothing to leak" is the kind of
//! claim that stops being true when somebody adds a convenience field.
//!
//! The rest is about REFUSING AT CONFIGURATION TIME what the push worker could never use. A
//! plaintext base URL and an unparseable scope filter both fail on every pass forever, and the
//! only moment an operator can fix either is while they are looking at the field they typed.

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

/// Create an organization through the management API and return its id.
async fn create_org(h: &Harness, tenant: &str, environment: &str, key: &str) -> String {
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let body = serde_json::json!({ "display_name": "Globex" }).to_string();
    let (status, _, response) = h.post(&base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create org: {response}");
    serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

fn push_path(tenant: &str, environment: &str, org: &str) -> String {
    format!(
        "/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/scim-push-connections"
    )
}

/// The body of a well formed create.
fn create_body() -> String {
    serde_json::json!({
        "display_name": "Downstream SaaS",
        "base_url": "https://downstream.example/scim/v2",
        "credential_secret_name": "scim_push_downstream",
    })
    .to_string()
}

/// The value written under the connection's secret name, so the "no credential on the wire"
/// assertions have something they could actually find. A distinctive literal rather than a
/// realistic token: what matters is that a substring search separates present from absent.
const DOWNSTREAM_TOKEN: &str = "downstream-token-must-not-appear-on-the-wire";

/// A connection is created, listed and deleted, and NOTHING in any response is a credential.
#[tokio::test]
async fn a_connection_round_trips_and_no_response_carries_a_credential() {
    // START_WITH_SIGNING_REGISTRY, not `start`: writing an environment secret needs the
    // data-plane store, which this surface reaches through the signing registry, and the plain
    // harness has none. Without a REAL secret under the connection's name the credential
    // assertions below have no value to look for and pass by absence, which is what the first
    // version of this test did.
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let path = push_path(&tenant, &environment, &org);

    // The named secret is REAL, written through the route an operator uses. Without it the
    // credential assertions below have no value to look for and pass by absence.
    let secret_path =
        format!("/v1/tenants/{tenant}/environments/{environment}/secrets/scim_push_downstream");
    let (status, _, body) = h
        .put_with_key(
            &secret_path,
            "k-secret",
            &serde_json::json!({ "value": DOWNSTREAM_TOKEN }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "write the secret: {body}");

    let (status, _, created) = h.post(&path, "k2", &create_body()).await;
    assert_eq!(status, StatusCode::CREATED, "create: {created}");
    let handle = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();
    assert!(
        handle.starts_with("spc_"),
        "the handle is an spc_ id: {handle}"
    );

    let (status, _, listed) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "list: {listed}");
    let items = serde_json::from_str::<Value>(&listed).expect("json")["items"]
        .as_array()
        .expect("items")
        .clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"].as_str(), Some(handle.as_str()));
    assert_eq!(
        items[0]["credential_secret_name"].as_str(),
        Some("scim_push_downstream"),
        "the secret NAME is what the row holds and what the view shows"
    );
    assert_eq!(items[0]["active"].as_bool(), Some(true));
    assert_eq!(items[0]["write_mode"].as_str(), Some("patch"));
    assert_eq!(items[0]["deletion_policy"].as_str(), Some("deactivate"));
    assert_eq!(items[0]["backfill_state"].as_str(), Some("pending"));

    // NOTHING SECRET, ANYWHERE. Not in the create, not in the listing.
    //
    // The FIRST assertion is the one that can actually fail. The named secret is REAL here --
    // written through the operator's own route above -- so `DOWNSTREAM_TOKEN` is a value that
    // exists and that a convenience field resolving the secret would put on the wire. The first
    // version of this test named a secret that was never created, so there was no value any
    // response could have carried and the scan was satisfied by absence.
    for (what, body) in [("the create", &created), ("the listing", &listed)] {
        assert!(
            !body.contains(DOWNSTREAM_TOKEN),
            "{what} resolved the secret it only names: {body}"
        );
    }
    // The SECOND is the weaker field-name scan, kept because it catches a field added under a
    // credential-shaped NAME before anyone wires a value into it. It is not what proves the
    // secret does not leak; the assertion above is.
    for (what, body) in [("the create", &created), ("the listing", &listed)] {
        let lowered = body.to_lowercase();
        for forbidden in ["secret_value", "bearer", "password", "credential\":"] {
            assert!(
                !lowered.contains(forbidden),
                "{what} carries a credential-shaped field {forbidden}: {body}"
            );
        }
    }

    let (status, _, response) = h.delete(&format!("{path}/{handle}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete: {response}");
    let (_, _, listed) = h.get(&path).await;
    assert!(
        serde_json::from_str::<Value>(&listed).expect("json")["items"]
            .as_array()
            .expect("items")
            .is_empty()
    );
}

/// A base URL the push worker could never use is refused HERE, not on every pass forever.
#[tokio::test]
async fn a_plaintext_base_url_is_refused_at_configuration_time() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let path = push_path(&tenant, &environment, &org);

    for (what, url) in [
        ("plaintext http", "http://downstream.example/scim/v2"),
        ("a bare host", "downstream.example/scim/v2"),
        ("another scheme", "ftp://downstream.example/scim/v2"),
    ] {
        let body = serde_json::json!({
            "display_name": "Downstream SaaS",
            "base_url": url,
            "credential_secret_name": "scim_push_downstream",
        })
        .to_string();
        let (status, _, response) = h.post(&path, "k2", &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {response}");
        assert!(
            response.contains("invalid_base_url"),
            "{what} must name the field: {response}"
        );
    }

    // CONTROL: https works, so the refusals above are about the scheme.
    let (status, _, response) = h.post(&path, "k9", &create_body()).await;
    assert_eq!(status, StatusCode::CREATED, "https: {response}");
}

/// A scope filter the push worker could never evaluate is refused, by the SAME parser it uses.
#[tokio::test]
async fn an_unparseable_scope_filter_is_refused() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let path = push_path(&tenant, &environment, &org);

    for (field, filter) in [
        ("user_scope_filter", "userName eq"),
        ("user_scope_filter", "((((("),
        ("group_scope_filter", "displayName pr and"),
    ] {
        let mut body = serde_json::json!({
            "display_name": "Downstream SaaS",
            "base_url": "https://downstream.example/scim/v2",
            "credential_secret_name": "scim_push_downstream",
        });
        body[field] = serde_json::Value::String(filter.to_owned());
        let (status, _, response) = h.post(&path, "k2", &body.to_string()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{field}={filter}: {response}"
        );
        assert!(response.contains("invalid_scope_filter"), "{response}");
    }

    // CONTROL: a filter that DOES parse is accepted and stored, so the refusals are about the
    // grammar rather than about the field being present at all.
    let mut body = serde_json::json!({
        "display_name": "Downstream SaaS",
        "base_url": "https://downstream.example/scim/v2",
        "credential_secret_name": "scim_push_downstream",
    });
    body["user_scope_filter"] = serde_json::Value::String("userType eq \"employee\"".to_owned());
    let (status, _, response) = h.post(&path, "k9", &body.to_string()).await;
    assert_eq!(status, StatusCode::CREATED, "a valid filter: {response}");
    let (_, _, listed) = h.get(&path).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["items"][0]["user_scope_filter"]
            .as_str(),
        Some("userType eq \"employee\"")
    );
}

/// A value outside a stored vocabulary is refused by the HANDLER, not by the column.
///
/// # Why that distinction is worth a test
///
/// A handler that let the database refuse would map every `StoreError::Database` onto a 400
/// naming the field -- so a revoked grant, or a full disk, would tell the caller their input was
/// wrong. The sibling inbound module shipped exactly that and a reviewer drove it by revoking
/// `INSERT`. The sweep that looks for missing grants expects a 500, and a handler answering 400
/// passes it while being broken.
#[tokio::test]
async fn a_value_outside_a_vocabulary_is_refused_before_the_write() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let path = push_path(&tenant, &environment, &org);

    for (field, value, code) in [
        ("write_mode", "PATCH", "invalid_write_mode"),
        ("write_mode", "upsert", "invalid_write_mode"),
        ("deletion_policy", "purge", "invalid_deletion_policy"),
    ] {
        let mut body = serde_json::json!({
            "display_name": "Downstream SaaS",
            "base_url": "https://downstream.example/scim/v2",
            "credential_secret_name": "scim_push_downstream",
        });
        body[field] = serde_json::Value::String(value.to_owned());
        let (status, _, response) = h.post(&path, "k2", &body.to_string()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{field}={value}: {response}"
        );
        assert!(response.contains(code), "{response}");
    }

    // AND NOTHING LANDED. This is what makes the refusals above "before the write" rather than
    // merely "a 400": reconstruct the broken shape the doc describes -- pass the raw string to
    // the store and map the column's refusal to a 400 with the same code -- and every assertion
    // above still passes, because a status and an error string cannot tell the two apart. An
    // EMPTY listing can.
    let (status, _, listed) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["items"]
            .as_array()
            .expect("items")
            .len(),
        0,
        "a refused create left a row behind, so the refusal came from the column rather than \
         from the handler: {listed}"
    );

    // CONTROL: every word the vocabulary DOES contain is accepted.
    for (mode, policy) in [("patch", "deactivate"), ("put", "delete")] {
        let body = serde_json::json!({
            "display_name": "Downstream SaaS",
            "base_url": "https://downstream.example/scim/v2",
            "credential_secret_name": "scim_push_downstream",
            "write_mode": mode,
            "deletion_policy": policy,
        })
        .to_string();
        let (status, _, response) = h.post(&path, &format!("k-{mode}-{policy}"), &body).await;
        assert_eq!(status, StatusCode::CREATED, "{mode}/{policy}: {response}");
    }
}

/// Pausing a connection keeps it, and the listing says so.
#[tokio::test]
async fn a_connection_pauses_and_resumes() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let path = push_path(&tenant, &environment, &org);
    let (_, _, created) = h.post(&path, "k2", &create_body()).await;
    let handle = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let active_path = format!("{path}/{handle}/active");

    let (status, _, response) = h
        .put(
            &active_path,
            &serde_json::json!({ "active": false }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "pause: {response}");
    let (_, _, listed) = h.get(&path).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["items"][0]["active"].as_bool(),
        Some(false),
        "a paused connection is still listed, and says it is paused"
    );

    let (status, _, response) = h
        .put(
            &active_path,
            &serde_json::json!({ "active": true }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "resume: {response}");
    assert_eq!(
        serde_json::from_str::<Value>(&h.get(&path).await.2).expect("json")["items"][0]["active"]
            .as_bool(),
        Some(true)
    );
}

/// A connection handle from another organization is a 404, not somebody else's row.
#[tokio::test]
async fn a_handle_from_another_organization_is_not_found() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let mine = create_org(&h, &tenant, &environment, "k1").await;
    let theirs = create_org(&h, &tenant, &environment, "k2").await;
    let (_, _, created) = h
        .post(
            &push_path(&tenant, &environment, &theirs),
            "k3",
            &create_body(),
        )
        .await;
    let handle = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // The OTHER organization's path, their connection's handle -- through BOTH mutating doors,
    // because a fence on one door is a fence with a door beside it. The first version of this
    // test drove only DELETE, and DELETE was also the only handler I checked by hand.
    let (status, _, response) = h
        .delete(&format!(
            "{}/{handle}",
            push_path(&tenant, &environment, &mine)
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a handle must not be reachable through another organization's path: {response}"
    );
    let (status, _, response) = h
        .put(
            &format!(
                "{}/{handle}/active",
                push_path(&tenant, &environment, &mine)
            ),
            &serde_json::json!({ "active": false }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "nor may it be paused through another organization's path: {response}"
    );
    // AND IT IS UNTOUCHED -- still present, and still ACTIVE. Presence alone would pass while the
    // PUT had gone through and paused it.
    let items =
        serde_json::from_str::<Value>(&h.get(&push_path(&tenant, &environment, &theirs)).await.2)
            .expect("json")["items"]
            .as_array()
            .expect("items")
            .clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["active"], serde_json::json!(true));
}

/// A base URL that is not a usable https URL is refused at configuration time.
///
/// # Both were accepted, and both had a doc saying otherwise
///
/// `check_base_url` was `starts_with("https://")` and nothing else, so the literal string
/// `https://` -- no host at all -- was stored, which is precisely the deferral the function's own
/// doc says it exists to prevent. And `attribute_mapping` went to the column unexamined, so
/// `[1, 2, 3]` was stored under a column documented as a mapping whose empty value is an object.
///
/// The mapping arm matters twice over now that the column carries a
/// `jsonb_typeof(...) = 'object'` CHECK: without the surface check a caller meets that
/// constraint as a database error rendered 500, and a malformed body deserves a 400.
#[tokio::test]
async fn a_malformed_base_url_is_refused_before_the_write() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let path = push_path(&tenant, &environment, &org);

    for (label, base_url) in [
        ("no host at all", "https://"),
        // A PORT makes the authority non-empty while leaving no host, which the first version
        // of the check accepted: it tested the authority, and `:8080` is not empty.
        ("a port and no host", "https://:8080/scim/v2"),
        // An EMPTY IPv6 literal, which the bracket branch has to refuse for the same reason the
        // bare authority does: brackets with nothing inside are an authority with no host.
        ("empty brackets", "https://[]/scim/v2"),
        (
            "userinfo smuggled into the authority",
            "https://user:pw@downstream.example/scim/v2",
        ),
        ("a space", "https://downstream.example/scim v2"),
    ] {
        let body = serde_json::json!({
            "display_name": "Downstream SaaS",
            "base_url": base_url,
            "credential_secret_name": "scim_push_downstream",
        })
        .to_string();
        let (status, _, response) = h.post(&path, &format!("k-{label}"), &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {response}");
        assert!(response.contains("invalid_base_url"), "{label}: {response}");
    }

    // A JSON `null` is NOT in this list, and the omission is deliberate rather than an
    // oversight: serde maps `null` onto `None` for an `Option<Value>`, so an explicit null means
    // ABSENT on every optional field this surface has, not "a value of the wrong type". It is
    // driven as a CONTROL below instead, because asserting it is refused would have pinned this
    // one field behaving unlike the rest of the API.
    // CONTROL: the same body with a usable URL and an object mapping is accepted, so the
    // refusals are about those two fields rather than about the create being broken.
    let body = serde_json::json!({
        "display_name": "Downstream SaaS",
        "base_url": "https://downstream.example/scim/v2",
        "credential_secret_name": "scim_push_downstream",
        "attribute_mapping": { "userName": "email" },
    })
    .to_string();
    let (status, _, response) = h.post(&path, "k-ok", &body).await;
    assert_eq!(status, StatusCode::CREATED, "{response}");

    // AND THE NULL CONTROL, pinning what an explicit null actually means here. It is ACCEPTED
    // and resolves to the documented empty mapping, exactly as omitting the field does. Driven
    // rather than merely asserted in the comment above, because "null means absent" is the kind
    // of claim this repository keeps finding to be false where nothing runs it.
    let with_null = serde_json::json!({
        "display_name": "Downstream SaaS",
        "base_url": "https://downstream.example/scim/v2",
        "credential_secret_name": "scim_push_downstream",
        "attribute_mapping": serde_json::Value::Null,
    })
    .to_string();
    let (status, _, response) = h.post(&path, "k-null", &with_null).await;
    assert_eq!(status, StatusCode::CREATED, "an explicit null: {response}");

    let (_, _, listed) = h.get(&path).await;
    let items = serde_json::from_str::<Value>(&listed).expect("json")["items"]
        .as_array()
        .expect("items")
        .clone();
    assert_eq!(items.len(), 2, "{listed}");
    for item in &items {
        assert!(
            item["attribute_mapping"].is_object(),
            "every stored mapping is an object: {listed}"
        );
    }
    // The null one specifically resolved to the EMPTY mapping rather than to the other row's.
    assert!(
        items
            .iter()
            .any(|item| item["attribute_mapping"] == serde_json::json!({})),
        "an explicit null did not resolve to the documented empty mapping: {listed}"
    );
}

/// Every one of the three writes puts its domain event on the feed, with the payload the
/// catalog publishes.
///
/// # Why this test exists, measured
///
/// `scripts/producer-coverage.py` is a TEXT SCAN over the handler's frame: it asks whether the
/// source builds a `*_event(` value, not whether one ever reaches `outbox_messages`.
///
/// It is a real gate and it does real work: a mutation replacing
/// `let pending = created_event(..)` with `None` makes it exit 1, MEASURED, so the claim once
/// written here that "the gate stayed green" on that mutation was simply wrong. What was true is
/// that no TEST caught it -- every test in this file passed -- and that is the gap this closes.
///
/// The gap matters because a text scan cannot see three things this test asserts: that the
/// envelope reaches the feed at all, what its payload SAYS, and that a write which changed no
/// row announces nothing. A handler that built the right envelope and dropped it, or built one
/// naming the wrong connection, satisfies the scan exactly as well as a correct one.
///
/// It also pins the property the catalog's `deleted` entry claims: a delete that changes NO ROW
/// announces nothing. That is the store's `rows_affected() == 0` guard sitting above the
/// enqueue, and reaching it needs a handle that PARSES and matches nothing -- an unparseable one
/// is refused by the id parser before an envelope is ever built, which is a different guard and
/// what the first version of this test actually measured.
#[tokio::test]
async fn each_write_puts_its_event_on_the_feed() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let path = push_path(&tenant, &environment, &org);

    let payloads = |kind: &'static str| {
        let pool = h.db().owner_pool().clone();
        async move {
            let rows: Vec<(serde_json::Value,)> = sqlx::query_as(
                "SELECT payload FROM outbox_messages /* query-audit-allow: owner test read */ \
                 WHERE payload ->> 'type' = $1 ORDER BY sequence",
            )
            .bind(kind)
            .fetch_all(&pool)
            .await
            .expect("read the feed");
            rows.into_iter().map(|(p,)| p).collect::<Vec<_>>()
        }
    };

    // A DELETE OF A WELL-FORMED HANDLE THAT NAMES NO ROW, so the guard being measured is the
    // store's `rows_affected() == 0` and not the id parser.
    //
    // The first version used the literal `spc_absent`, which fails `parse_in_scope` -- a scoped
    // id is 48 bytes and that decodes to four -- so the handler returned 404 one line BEFORE
    // `deleted_event(..)` was built and long before any statement ran. The assertion was true
    // before the request was sent and could not distinguish a correct implementation from one
    // that enqueued the event ahead of the rows-affected check.
    //
    // A handle minted in this scope and then deleted is the honest input: it parses, it reaches
    // the DELETE, and the DELETE matches nothing.
    let (status, _, seed) = h.post(&path, "k-seed-absent", &create_body()).await;
    assert_eq!(status, StatusCode::CREATED, "{seed}");
    let doomed = serde_json::from_str::<Value>(&seed).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let (status, _, _) = h.delete(&format!("{path}/{doomed}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        payloads("scim_push_connection.deleted").await.len(),
        1,
        "the delete that DID remove a row announced it"
    );
    // NOW the same handle again. It parses, it reaches the statement, and the statement matches
    // nothing.
    let (status, _, _) = h.delete(&format!("{path}/{doomed}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        payloads("scim_push_connection.deleted").await.len(),
        1,
        "a delete that changed no row announced one anyway"
    );
    // And the same for the pause, which is a separate handler over a separate statement.
    let (status, _, _) = h
        .put(
            &format!("{path}/{doomed}/active"),
            &serde_json::json!({ "active": false }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        payloads("scim_push_connection.active_changed")
            .await
            .is_empty(),
        "a pause that changed no row announced one anyway"
    );

    let (status, _, created) = h.post(&path, "k2", &create_body()).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let handle = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let events = payloads("scim_push_connection.created").await;
    // TWO creates have happened: the seed above, which was deleted, and this one. The payload
    // assertions below read the LAST, which is this one.
    assert_eq!(events.len(), 2, "{events:?}");
    // THE PAYLOAD, field by field, against what the catalog publishes. Asserting only that an
    // event exists would pass while it named the wrong connection. Index 1 is THIS create;
    // index 0 belongs to the seed, and the count above is what keeps the two from being
    // confused for one another.
    let events = [events[1].clone()];
    assert_eq!(
        events[0]["payload"]["scim_push_connection_id"],
        Value::from(handle.clone())
    );
    assert_eq!(
        events[0]["payload"]["organization_id"],
        Value::from(org.clone())
    );
    assert_eq!(
        events[0]["payload"]["base_url"],
        Value::from("https://downstream.example/scim/v2")
    );
    assert!(
        events[0]["payload"].get("credential_secret_name").is_none(),
        "the event names the secret it must not name: {:?}",
        events[0]
    );

    let (status, _, body) = h
        .put(
            &format!("{path}/{handle}/active"),
            &serde_json::json!({ "active": false }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let events = payloads("scim_push_connection.active_changed").await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["payload"]["active"], Value::from(false));
    assert_eq!(
        events[0]["payload"]["scim_push_connection_id"],
        Value::from(handle.clone())
    );

    let (status, _, body) = h.delete(&format!("{path}/{handle}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    // TWO deletes have removed a row across this test: the seed at the top, whose lifecycle
    // exists so the no-row arm has a handle that PARSES, and this one. The count is asserted
    // rather than the last element read blindly, so a run that emitted a third would fail here
    // instead of quietly reading the right one out of the wrong set.
    let events = payloads("scim_push_connection.deleted").await;
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(
        events[1]["payload"]["scim_push_connection_id"],
        Value::from(handle)
    );
    assert_eq!(events[1]["payload"]["organization_id"], Value::from(org));
}

/// The length bounds the column carries are refused at the SURFACE, in the same unit.
///
/// # Its own test, and why
///
/// Appended to its neighbour first, which pushed that function past `clippy::too_many_lines`
/// (130/100). A targeted `cargo test` does not see that ceiling; only clippy does, which means
/// the gate. The split is also the honest shape: this pins the BOUNDS, and the function it came
/// from pins malformed VALUES.
///
/// # Why the surface refuses at all
///
/// Migration 0189 bounds `display_name` and `credential_secret_name` with `octet_length`. A
/// CHECK violation is SQLSTATE 23514, which `is_unique_violation` does not match, so it falls
/// through to `ApiError::Internal`. Adding a constraint without the matching surface check turns
/// a 400 into a 500, which is what the inbound mirror was caught by with an EMPTY name.
///
/// BYTES ON BOTH SIDES. The column originally counted characters while this counts bytes, which
/// leaves a band -- a 200-character string of three-byte characters -- where one refuses and the
/// other does not.
#[tokio::test]
async fn an_over_long_label_is_refused_at_the_surface_rather_than_by_the_column() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let path = push_path(&tenant, &environment, &org);

    // THE LENGTH BOUNDS, which the column also carries. Refused HERE, in bytes, so a caller
    // meets a 400 rather than the CHECK's SQLSTATE 23514 rendered 500. Driven at 253 bytes
    // rather than at something enormous, because the bound is what is being pinned and a
    // megabyte would pass a bound set anywhere below it.
    for (field, value) in [
        ("display_name", "n".repeat(253)),
        // MULTI-BYTE, which is the case the unit actually matters for. 100 three-byte characters
        // is 300 BYTES and 100 CHARACTERS: a byte bound refuses it and a character bound accepts
        // it, so it is the only shape that can tell the two apart.
        //
        // IT PINS THE SURFACE'S UNIT, NOT THE COLUMN'S. The refusal happens before any SQL, so
        // this observes that `check_label` counts bytes and says nothing about whether 0189's
        // `octet_length` agrees. The two are read together by a person and by nothing else; the
        // earlier ASCII-only version could not observe either, and the sentence claiming it
        // pinned "bytes on both sides" was false in a way this one is only half of.
        ("display_name", "\u{4e16}".repeat(100)),
    ] {
        let mut body = serde_json::json!({
            "display_name": "Downstream SaaS",
            "base_url": "https://downstream.example/scim/v2",
            "credential_secret_name": "scim_push_downstream",
        });
        body[field] = serde_json::Value::String(value);
        let (status, _, response) = h
            .post(&path, &format!("k-long-{field}"), &body.to_string())
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{field} at 253 bytes: {response}"
        );
        assert!(response.contains(&format!("invalid_{field}")), "{response}");
    }
    // CONTROL at exactly the bound, so the refusals above are the bound rather than any long
    // string being refused.
    let mut body = serde_json::json!({
        "base_url": "https://downstream.example/scim/v2",
        "credential_secret_name": "scim_push_downstream",
    });
    body["display_name"] = serde_json::Value::String("n".repeat(252));
    let (status, _, response) = h.post(&path, "k-at-bound", &body.to_string()).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "252 bytes is within the bound: {response}"
    );
    let (status, _, body) = h
        .delete(&format!(
            "{path}/{}",
            serde_json::from_str::<Value>(&response).expect("json")["id"]
                .as_str()
                .expect("id")
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

/// The listing pages, and the cursor it publishes actually walks.
///
/// # Why this exists
///
/// Round one added `Pagination::resolve` to a listing that had published `limit` and `cursor`
/// into the contract and honoured neither. It added NO TEST, and a mutation dropping the cursor
/// back to a fixed page size survived the whole suite: the fix and the defect it replaced were
/// indistinguishable to every assertion in this file.
///
/// So the walk is driven end to end. The page size is 2 against 5 rows, which is three pages
/// with a short last one, and the assertion is that the pages cover exactly what was created, in
/// creation order, WITH NO REPEATS. A cursor that did not advance would repeat; one that skipped
/// would come up short; a listing that ignored `limit` would finish in one page.
#[tokio::test]
async fn the_listing_pages_and_its_cursor_walks() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let path = push_path(&tenant, &environment, &org);

    let mut created = Vec::new();
    for n in 0..5 {
        let body = serde_json::json!({
            "display_name": format!("Downstream {n}"),
            "base_url": "https://downstream.example/scim/v2",
            "credential_secret_name": "scim_push_downstream",
        })
        .to_string();
        let (status, _, response) = h.post(&path, &format!("k-page-{n}"), &body).await;
        assert_eq!(status, StatusCode::CREATED, "{response}");
        created.push(
            serde_json::from_str::<Value>(&response).expect("json")["id"]
                .as_str()
                .expect("id")
                .to_owned(),
        );
    }

    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let uri = match &cursor {
            Some(after) => format!("{path}?limit=2&cursor={after}"),
            None => format!("{path}?limit=2"),
        };
        let (status, _, body) = h.get(&uri).await;
        assert_eq!(status, StatusCode::OK, "page {pages}: {body}");
        let parsed: Value = serde_json::from_str(&body).expect("json");
        let items = parsed["items"].as_array().expect("items");
        assert!(
            items.len() <= 2,
            "a page exceeded the limit it asked for: {body}"
        );
        for item in items {
            seen.push(item["id"].as_str().expect("id").to_owned());
        }
        pages += 1;
        assert!(pages <= 10, "the walk did not terminate: {seen:?}");
        match parsed["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }

    assert_eq!(
        seen, created,
        "the pages must cover exactly what was created, in creation order, with no repeats"
    );
    assert_eq!(
        pages, 3,
        "five rows two at a time is three pages, the last one short"
    );

    // A MALFORMED CURSOR IS A 400, and the contract documents it. It was undocumented: this is
    // the only reachable status the published operation did not list, which is the
    // advertise-then-differ shape in its other direction.
    let (status, _, body) = h.get(&format!("{path}?cursor=not-a-cursor")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// The credential's secret NAME must be a name an environment secret can have.
///
/// # A label bound is the wrong rule for a key
///
/// This field was bounded at 252 bytes with any characters, which is the operator-facing LABEL
/// rule. It is an `environment_secrets` key, and `esv::name_is_valid` caps a name at 128 bytes
/// of ASCII letters, digits, underscore, dot or hyphen. A name outside that alphabet could be
/// stored on a connection and then never resolve, so every push would fail for a reason
/// configured long before and visible nowhere near the failure.
///
/// The surface calls the store's own predicate rather than restating the alphabet, so there is
/// one place for the rule to live and no second copy to drift.
#[tokio::test]
async fn a_secret_name_the_secret_store_could_not_hold_is_refused() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let path = push_path(&tenant, &environment, &org);

    for (label, name) in [
        ("a space", "scim push downstream".to_owned()),
        ("a slash", "scim/push".to_owned()),
        ("a dollar", "${secret:x}".to_owned()),
        ("non-ascii", "sc\u{4e16}m".to_owned()),
        ("over 128 bytes", "s".repeat(129)),
    ] {
        let mut body = serde_json::json!({
            "display_name": "Downstream SaaS",
            "base_url": "https://downstream.example/scim/v2",
        });
        body["credential_secret_name"] = serde_json::Value::String(name);
        let (status, _, response) = h
            .post(&path, &format!("k-name-{label}"), &body.to_string())
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {response}");
        assert!(
            response.contains("invalid_credential_secret_name"),
            "{label}: {response}"
        );
    }

    // CONTROL: the name the rest of this file uses is accepted, so the refusals are the grammar
    // rather than the field being unusable.
    let (status, _, response) = h.post(&path, "k-name-ok", &create_body()).await;
    assert_eq!(status, StatusCode::CREATED, "{response}");

    // AND NOTHING FROM THE REFUSED SET LANDED.
    let (_, _, listed) = h.get(&path).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["items"]
            .as_array()
            .expect("items")
            .len(),
        1,
        "{listed}"
    );
}

/// The Idempotency-Key actually replays, and a key reused with a different body is refused.
///
/// # Why this exists
///
/// Round two made this POST idempotent because `idempotency.rs` opens with the invariant that
/// the header is required on every POST, and a lost 201 otherwise means a retry creates a second
/// connection pointed at the same downstream. It added NO TEST: nothing in the repository posted
/// the same key twice against this route, so the entire addition was unverified and a handler
/// that dropped the record on the floor would have looked identical.
///
/// Three properties, because the header buys three different things and each can fail alone:
/// the SAME key with the SAME body returns the ORIGINAL response and creates nothing new; the
/// same key with a DIFFERENT body is refused rather than silently replayed; and a DIFFERENT key
/// creates a second connection, which is the control that stops the first two passing against a
/// route that simply refuses every repeat.
#[tokio::test]
async fn an_idempotency_key_replays_and_a_reused_key_with_a_different_body_is_refused() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let path = push_path(&tenant, &environment, &org);

    let (status, _, first) = h.post(&path, "idem-1", &create_body()).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");

    // THE SAME KEY, THE SAME BODY: the original response, byte for byte, and no second row.
    let (status, _, replayed) = h.post(&path, "idem-1", &create_body()).await;
    assert_eq!(status, StatusCode::CREATED, "{replayed}");
    assert_eq!(
        replayed, first,
        "a replay must return the ORIGINAL response rather than a fresh one: a caller that \
         retried a lost 201 has to learn the id the first attempt minted"
    );

    let (_, _, listed) = h.get(&path).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["items"]
            .as_array()
            .expect("items")
            .len(),
        1,
        "the replay created a second connection: {listed}"
    );

    // THE SAME KEY, A DIFFERENT BODY: refused, because replaying the stored response for a
    // request that was not the stored one would tell the caller a write happened that did not.
    let mut other = serde_json::from_str::<Value>(&create_body()).expect("json");
    other["display_name"] = serde_json::Value::String("Something else".to_owned());
    let (status, _, response) = h.post(&path, "idem-1", &other.to_string()).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a key reused with a different request must be refused: {response}"
    );
    assert!(
        response.contains("idempotency_key_conflict"),
        "the refusal names the reason: {response}"
    );

    // CONTROL: a DIFFERENT key creates a second connection. Without this the two assertions
    // above would also pass against a route that refused every repeat for any reason.
    let (status, _, second) = h.post(&path, "idem-2", &create_body()).await;
    assert_eq!(status, StatusCode::CREATED, "{second}");
    assert_ne!(
        serde_json::from_str::<Value>(&second).expect("json")["id"],
        serde_json::from_str::<Value>(&first).expect("json")["id"],
        "a fresh key must mint a fresh connection"
    );
    let (_, _, listed) = h.get(&path).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["items"]
            .as_array()
            .expect("items")
            .len(),
        2,
        "{listed}"
    );
}

/// An attribute mapping that is not an object, or that jsonb cannot store, is refused before the
/// write.
///
/// # Its own test, and why
///
/// It lived in the base-URL test until that function reached 113 lines against the crate's
/// 100-line ceiling. A targeted `cargo test` does not see that ceiling; only clippy does, which
/// means the gate. The split is also the honest shape: one function pins malformed URLS and this
/// one pins malformed MAPPINGS.
#[tokio::test]
async fn a_malformed_attribute_mapping_is_refused_before_the_write() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let path = push_path(&tenant, &environment, &org);

    for (label, mapping) in [
        ("an array", serde_json::json!([1, 2, 3])),
        ("a number", serde_json::json!(3)),
        ("a string", serde_json::json!("userName=email")),
        // VALID JSON THAT JSONB WILL NOT STORE. `is_object` passes it and Postgres raises
        // 22P05, which reaches the caller as a 500 -- the exact failure the object check was
        // added to prevent, one level deeper.
        (
            "a NUL escape",
            serde_json::json!({ "userName": "e\u{0}mail" }),
        ),
    ] {
        let body = serde_json::json!({
            "display_name": "Downstream SaaS",
            "base_url": "https://downstream.example/scim/v2",
            "credential_secret_name": "scim_push_downstream",
            "attribute_mapping": mapping,
        })
        .to_string();
        let (status, _, response) = h.post(&path, &format!("k-map-{label}"), &body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} reached the column, where the CHECK would answer 500: {response}"
        );
        assert!(
            response.contains("invalid_attribute_mapping"),
            "{label}: {response}"
        );
    }

    // NOTHING LANDED, so every refusal above happened before the write rather than after it.
    let (_, _, listed) = h.get(&path).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["items"]
            .as_array()
            .expect("items")
            .len(),
        0,
        "{listed}"
    );

    // AND AN IPv6 LITERAL IS ACCEPTED, which is the other half of the bracket branch: refusing
    // it would be a defect, and the first version reached the right answer only because
    // splitting on the first colon happened to leave a non-empty `[`.
    let body = serde_json::json!({
        "display_name": "Downstream SaaS",
        "base_url": "https://[2001:db8::1]:8443/scim/v2",
        "credential_secret_name": "scim_push_downstream",
    })
    .to_string();
    let (status, _, response) = h.post(&path, "k-v6", &body).await;
    assert_eq!(status, StatusCode::CREATED, "an IPv6 literal: {response}");
    let (status, _, body) = h
        .delete(&format!(
            "{path}/{}",
            serde_json::from_str::<Value>(&response).expect("json")["id"]
                .as_str()
                .expect("id")
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // NOTHING LANDED, so every refusal happened before the write rather than after it.
    let (_, _, listed) = h.get(&path).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["items"]
            .as_array()
            .expect("items")
            .len(),
        0,
        "{listed}"
    );

    // CONTROL: an object mapping is accepted, so the refusals are about the shape rather than
    // about the field being unusable.
    let body = serde_json::json!({
        "display_name": "Downstream SaaS",
        "base_url": "https://downstream.example/scim/v2",
        "credential_secret_name": "scim_push_downstream",
        "attribute_mapping": { "userName": "email" },
    })
    .to_string();
    let (status, _, response) = h.post(&path, "k-map-ok", &body).await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
}

/// An explicit `null` attribute mapping means ABSENT, and resolves to the documented empty
/// mapping.
///
/// # Why it is its own test rather than a control beside the refusals
///
/// Two reasons, and the second is the one that matters. It kept the refusal test over the
/// crate's 100-line clippy ceiling, which a targeted `cargo test` does not see. And it pins a
/// DIFFERENT property: the arms beside it pin what is refused, and this pins what a null MEANS.
///
/// serde maps `null` onto `None` for an `Option<Value>`, so an explicit null means absent on
/// every optional field this surface has, not a value of the wrong type. Driven rather than
/// asserted in a comment, because "null means absent" is the kind of claim this repository keeps
/// finding to be false wherever nothing runs it.
#[tokio::test]
async fn an_explicit_null_attribute_mapping_means_absent() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let path = push_path(&tenant, &environment, &org);

    // AND AN EXPLICIT NULL IS ACCEPTED, resolving to the documented empty mapping exactly as
    // omitting the field does: serde maps `null` onto `None` for an `Option<Value>`, so it means
    // ABSENT on every optional field this surface has, not a value of the wrong type. Driven
    // rather than asserted in a comment, because "null means absent" is the kind of claim this
    // repository keeps finding to be false where nothing runs it.
    let with_null = serde_json::json!({
        "display_name": "Downstream SaaS",
        "base_url": "https://downstream.example/scim/v2",
        "credential_secret_name": "scim_push_downstream",
        "attribute_mapping": serde_json::Value::Null,
    })
    .to_string();
    let (status, _, response) = h.post(&path, "k-map-null", &with_null).await;
    assert_eq!(status, StatusCode::CREATED, "an explicit null: {response}");

    // ONE connection, and its mapping is the EMPTY OBJECT rather than a null, a missing key or
    // anything else. Asserting only that the create succeeded would pass while the column held
    // something the doc does not describe.
    let (_, _, listed) = h.get(&path).await;
    let items = serde_json::from_str::<Value>(&listed).expect("json")["items"]
        .as_array()
        .expect("items")
        .clone();
    assert_eq!(items.len(), 1, "{listed}");
    assert_eq!(
        items[0]["attribute_mapping"],
        serde_json::json!({}),
        "an explicit null did not resolve to the documented empty mapping: {listed}"
    );

    // AND OMITTING THE FIELD ENTIRELY REACHES THE SAME PLACE, which is what "null means absent"
    // asserts: the two spellings are indistinguishable in the row they produce. Without this
    // arm the test would pin only that a null is accepted, not that it means what absent means.
    let omitted = serde_json::json!({
        "display_name": "Downstream SaaS",
        "base_url": "https://downstream.example/scim/v2",
        "credential_secret_name": "scim_push_downstream",
    })
    .to_string();
    let (status, _, response) = h.post(&path, "k-map-omitted", &omitted).await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    let (_, _, listed) = h.get(&path).await;
    let items = serde_json::from_str::<Value>(&listed).expect("json")["items"]
        .as_array()
        .expect("items")
        .clone();
    assert_eq!(items.len(), 2, "{listed}");
    assert_eq!(
        items[0]["attribute_mapping"], items[1]["attribute_mapping"],
        "an explicit null and an omitted field must produce the SAME mapping: {listed}"
    );
}
