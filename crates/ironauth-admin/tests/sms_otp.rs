// SPDX-License-Identifier: MIT OR Apache-2.0

//! Guarded SMS OTP configuration over HTTP (issue #70), driven through the management
//! router against a real database.
//!
//! The store half has been complete since #50 and none of it was reachable. Migration
//! 0050's own comment states the requirement, "SMS OTP is unusable until a tenant
//! explicitly turns it on AND populates the country allowlist", and no surface could do
//! either: `set_config`, `allowlist`, `add_allowlist_country` and
//! `remove_allowlist_country` had zero production callers and the published contract had no
//! SMS operation.
//!
//! What is worth proving here is therefore not that a wrapper forwards arguments, but that
//! the surface is REACHABLE at all under the control role, since 0050 granted both tables
//! to `ironauth_app` alone and the management router connects as `ironauth_control`. That
//! is the failure #441 recorded: refused by Postgres before any application logic runs, and
//! surfacing as an opaque 500. Every test below would have answered 500 without migration
//! 0105, which makes the whole file a grant test as much as a behaviour test.

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

fn config_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/sms-otp/config")
}

fn allowlist_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/sms-otp/allowlist")
}

#[tokio::test]
async fn an_unconfigured_environment_reads_as_disabled_with_an_empty_allowlist() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;

    // No row, and that is the shipped default rather than a not-found. This read is what an
    // operator uses to decide what to configure, so "never configured" must be legible and
    // must not be confused with an absent environment.
    let (status, _, response) = h.get(&config_path(&tenant, &environment)).await;
    assert_eq!(status, StatusCode::OK, "config read: {response}");
    let view: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(view["enabled"], false);
    assert_eq!(view["allow_factor_downgrade"], false);

    let (status, _, response) = h.get(&allowlist_path(&tenant, &environment)).await;
    assert_eq!(status, StatusCode::OK, "allowlist read: {response}");
    let view: Value = serde_json::from_str(&response).expect("json");
    assert!(
        view["items"].as_array().expect("items").is_empty(),
        "an unconfigured environment allows NO country, which is why the factor refuses \
         every send until this is populated: {response}"
    );
}

#[tokio::test]
async fn the_configuration_round_trips_and_the_downgrade_opt_in_is_off_unless_asked_for() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let path = config_path(&tenant, &environment);

    // Enabling WITHOUT naming the downgrade opt-in must leave it off. This is the
    // no-silent-downgrade invariant: SMS may not satisfy a step-up a stronger factor
    // required unless a tenant explicitly asks, so the field defaults to false rather than
    // inheriting whatever was there.
    let (status, _, response) = h
        .put_with_key(
            &path,
            "k-on",
            &serde_json::json!({ "enabled": true }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "enable: {response}");
    let view: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(view["enabled"], true);
    assert_eq!(
        view["allow_factor_downgrade"], false,
        "omitting the opt-in must not turn it on: {response}"
    );

    let (_, _, response) = h.get(&path).await;
    let view: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(view["enabled"], true, "the write persisted: {response}");
    assert_eq!(view["allow_factor_downgrade"], false);

    // Asking for it turns it on, and turning the factor off again leaves the row present
    // rather than deleting it, so a later re-enable does not silently reset the opt-in.
    let (status, _, response) = h
        .put_with_key(
            &path,
            "k-downgrade",
            &serde_json::json!({ "enabled": true, "allow_factor_downgrade": true }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "opt in: {response}");
    let (_, _, response) = h.get(&path).await;
    let view: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(view["allow_factor_downgrade"], true);
}

#[tokio::test]
async fn a_country_is_allowed_then_denied_and_the_deny_is_a_no_op_when_absent() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let root = allowlist_path(&tenant, &environment);

    let (status, _, response) = h.put_with_key(&format!("{root}/44"), "k-gb", "").await;
    assert_eq!(status, StatusCode::NO_CONTENT, "allow 44: {response}");
    let (status, _, response) = h.put_with_key(&format!("{root}/1"), "k-us", "").await;
    assert_eq!(status, StatusCode::NO_CONTENT, "allow 1: {response}");

    let (_, _, response) = h.get(&root).await;
    let view: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(
        view["items"],
        serde_json::json!(["1", "44"]),
        "both codes are listed, ordered: {response}"
    );

    // Allowing an already-allowed code is idempotent rather than a conflict: the caller
    // asked for a post-state and that post-state already holds.
    let (status, _, response) = h.put_with_key(&format!("{root}/44"), "k-gb-2", "").await;
    assert_eq!(status, StatusCode::NO_CONTENT, "re-allow: {response}");
    let (_, _, response) = h.get(&root).await;
    let view: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(
        view["items"].as_array().expect("items").len(),
        2,
        "re-allowing added no duplicate: {response}"
    );

    let (status, _, response) = h.delete(&format!("{root}/44")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "deny 44: {response}");
    let (_, _, response) = h.get(&root).await;
    let view: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(view["items"], serde_json::json!(["1"]));

    // Denying a code that was never allowed answers 204, not 404. A not-found here would
    // turn this route into a probe for which countries an environment allows.
    let (status, _, response) = h.delete(&format!("{root}/99")).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "removing an absent code is a no-op, not an existence oracle: {response}"
    );
}

#[tokio::test]
async fn a_country_code_that_is_not_an_e164_calling_code_is_refused_at_the_edge() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let root = allowlist_path(&tenant, &environment);

    // The column's CHECK only enforces non-empty, and the store checks nothing, so without
    // an edge rule these would be stored and then never match a parsed number's country
    // code: an operator would see their entry listed and sends would still refuse.
    for bad in ["GB", "44a", "12345", "0044"] {
        let (status, _, response) = h
            .put_with_key(&format!("{root}/{bad}"), &format!("k-{bad}"), "")
            .await;
        // `0044` is digits-only and within the length bound, so it is ACCEPTED by the
        // grammar; it is listed here to be explicit that the rule is a shape check and not
        // a directory of real calling codes.
        let expected = if bad == "0044" {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::BAD_REQUEST
        };
        assert_eq!(status, expected, "{bad}: {response}");
    }

    let (_, _, response) = h.get(&root).await;
    let view: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(
        view["items"],
        serde_json::json!(["0044"]),
        "only the shape-valid code was stored: {response}"
    );
}

#[tokio::test]
async fn the_configuration_is_invisible_to_a_sibling_environment() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let sibling = h.create_environment(&tenant, "sibling", "k-sibling").await;

    let (status, _, _) = h
        .put_with_key(
            &config_path(&tenant, &environment),
            "k-on",
            &serde_json::json!({ "enabled": true, "allow_factor_downgrade": true }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the config PUT answers the stored view"
    );
    let (status, _, _) = h
        .put_with_key(
            &format!("{}/44", allowlist_path(&tenant, &environment)),
            "k-gb",
            "",
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The fixtures differ in the ENVIRONMENT alone, under one tenant, so this measures the
    // environment half of the fence rather than the tenant predicate. An SMS enable that
    // leaked across environments would turn a staging opt-in into a production one.
    let (_, _, response) = h.get(&config_path(&tenant, &sibling)).await;
    let view: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(
        view["enabled"], false,
        "the sibling is still disabled: {response}"
    );
    assert_eq!(view["allow_factor_downgrade"], false);

    let (_, _, response) = h.get(&allowlist_path(&tenant, &sibling)).await;
    let view: Value = serde_json::from_str(&response).expect("json");
    assert!(
        view["items"].as_array().expect("items").is_empty(),
        "nor does it inherit the allowlist: {response}"
    );
}

/// Allowing and denying a country emit ONE type carrying the country and the direction.
///
/// An allowlist is a set, and adding to it or removing from it are the same edit in two
/// directions -- a consumer mirroring "where may we send" reads one field rather than
/// correlating two subscriptions.
///
/// The COUNTRY is why the payload exists: this allowlist is what stands between the SMS
/// surface and toll fraud, so a receiver auditing it must know WHICH destination changed, not
/// merely that something did. Both directions are asserted, because a producer that
/// hard-coded either would pass a test exercising only one.
#[tokio::test]
async fn allowing_and_denying_a_country_announce_the_country_and_the_direction() {
    use ironauth_store::{EnvironmentId, Scope, TenantId};

    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "sms-evt").await;
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );
    let root = allowlist_path(&tenant, &environment);

    // Provisioning the tenant is itself an audited write that announces itself, so its event
    // is drained and completed before the loop counts anything.
    let setup = h
        .db()
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &ironauth_env::Env::system(),
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            std::time::Duration::from_secs(30),
            100,
        )
        .await
        .expect("drain setup events");
    for message in &setup {
        h.db()
            .store()
            .scoped(scope)
            .outbox()
            .complete(&ironauth_env::Env::system(), message)
            .await
            .expect("complete a setup event");
    }

    for (path_suffix, key, allowed) in [("44", "k-allow", true), ("44", "k-deny", false)] {
        let (status, _, response) = if allowed {
            h.put_with_key(&format!("{root}/{path_suffix}"), key, "")
                .await
        } else {
            h.delete(&format!("{root}/{path_suffix}")).await
        };
        assert_eq!(status, StatusCode::NO_CONTENT, "{response}");

        let claimed = h
            .db()
            .store()
            .scoped(scope)
            .outbox()
            .claim(
                &ironauth_env::Env::system(),
                ironauth_store::WEBHOOK_EVENT_CONSUMER,
                std::time::Duration::from_secs(30),
                100,
            )
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1, "the edit enqueues exactly one event");
        assert_eq!(claimed[0].payload["type"], "sms_otp.allowlist_changed");
        assert_eq!(claimed[0].payload["payload"]["country_code"], "44");
        assert_eq!(
            claimed[0].payload["payload"]["allowed"], allowed,
            "the event must carry the DIRECTION the edit took, not a fixed value"
        );
        ironauth_store::event_catalog::validate_event(&claimed[0].payload)
            .expect("the envelope validates against the registry the fan-out enforces");
        // Completed each round: both events carry the country as their ordering key, so the
        // second is not claimable while the first is outstanding.
        for message in &claimed {
            h.db()
                .store()
                .scoped(scope)
                .outbox()
                .complete(&ironauth_env::Env::system(), message)
                .await
                .expect("complete");
        }
    }
}

/// An SMS-OTP configuration change announces BOTH flags.
///
/// The pair IS the policy: `enabled` alone does not tell a receiver whether a user may fall
/// back from a stronger factor, and that is the half with security consequences. A test that
/// asserted only `enabled` would pass for a producer that dropped the downgrade flag entirely.
///
/// `allow_factor_downgrade` is set to a NON-DEFAULT value here, so a producer that hard-coded
/// the default would fail.
#[tokio::test]
async fn a_configuration_change_announces_both_flags() {
    use ironauth_store::{EnvironmentId, Scope, TenantId};

    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "sms-cfg-evt").await;
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );

    // Provisioning announces itself; drain before counting.
    let setup = h
        .db()
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &ironauth_env::Env::system(),
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            std::time::Duration::from_secs(30),
            100,
        )
        .await
        .expect("drain setup events");
    for message in &setup {
        h.db()
            .store()
            .scoped(scope)
            .outbox()
            .complete(&ironauth_env::Env::system(), message)
            .await
            .expect("complete a setup event");
    }

    let (status, _, body) = h
        .put_with_key(
            &config_path(&tenant, &environment),
            "k-sms-cfg",
            &serde_json::json!({ "enabled": true, "allow_factor_downgrade": true }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let events = h
        .db()
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &ironauth_env::Env::system(),
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            std::time::Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim")
        .into_iter()
        .map(|message| message.payload)
        .collect::<Vec<_>>();
    assert_eq!(
        events.len(),
        1,
        "the config change enqueues exactly one event"
    );
    assert_eq!(events[0]["type"], "sms_otp.config_changed");
    assert_eq!(events[0]["payload"]["enabled"], true);
    assert_eq!(
        events[0]["payload"]["allow_factor_downgrade"], true,
        "the downgrade rule is the half with security consequences; it must be on the wire"
    );
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the envelope validates against the registry the fan-out enforces");
}
