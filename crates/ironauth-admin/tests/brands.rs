// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment brand management endpoints over HTTP (issue #475).
//!
//! Issue #475 measured that `brands` shipped with a store-level writer and NO management
//! endpoint, so a brand could not be created through the public API at all: the only asset
//! endpoints (`.../brands/{slug}/logo`, `.../brands/{slug}/favicon`) both 404 when the brand row
//! is absent, and the only non-store callers of `Brands::set` were tests. These drive the
//! list / set / get / delete lifecycle over HTTP, plus the two ingest walls that make branding
//! safe by construction (the closed typed token grammar and the allowlist slot sanitizer), and
//! the birth-path property the promotion asset transport depends on: create the brand, then
//! upload its logo.
//!
//! Sudo mode is off in the default harness, so these isolate the endpoint behavior.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_store::{EnvironmentId, Scope, TenantId};

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

fn brands_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/brands")
}

fn brand_path(tenant: &str, environment: &str, slug: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/brands/{slug}")
}

#[tokio::test]
async fn list_set_get_delete_lifecycle_for_a_brand() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = brand_path(&tenant, &env, "acme");

    // The environment starts with no brands.
    let (status, _, body) = harness.get(&brands_path(&tenant, &env)).await;
    assert_eq!(status, StatusCode::OK, "list brands: {body}");
    assert!(body.contains("\"items\":[]"), "no brands yet: {body}");

    // SET with only the required field: the tokens default to the neutral block, so a brand
    // that overrides nothing renders exactly today's unbranded pages.
    let (status, _, body) = harness.put(&path, r#"{"product_name":"Acme"}"#).await;
    assert_eq!(status, StatusCode::OK, "set brand: {body}");
    assert!(body.contains("\"slug\":\"acme\""), "{body}");
    assert!(
        body.contains("\"show_wordmark\":true"),
        "defaults on: {body}"
    );
    assert!(body.contains("color_bg"), "neutral tokens stored: {body}");

    // GET reads it back, and the list now carries it.
    let (status, _, body) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "get brand: {body}");
    assert!(body.contains("\"product_name\":\"Acme\""), "{body}");
    let (_, _, body) = harness.get(&brands_path(&tenant, &env)).await;
    assert!(body.contains("\"slug\":\"acme\""), "listed: {body}");

    // An OVERWRITE is idempotent on the slug and updates in place.
    let (status, _, body) = harness
        .put(
            &path,
            r#"{"product_name":"Acme Corp","is_default":true,"host_pattern":"LOGIN.Acme.Test:8443"}"#,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "overwrite: {body}");
    assert!(body.contains("\"product_name\":\"Acme Corp\""), "{body}");
    assert!(body.contains("\"is_default\":true"), "{body}");
    // The host key is CANONICALIZED at ingest (lowercased, port stripped), so the response
    // shows the stored key rather than echoing the request.
    assert!(
        body.contains("\"host_pattern\":\"login.acme.test\""),
        "the host key is canonicalized at ingest: {body}"
    );
    let (_, _, body) = harness.get(&brands_path(&tenant, &env)).await;
    assert_eq!(
        body.matches("\"slug\"").count(),
        1,
        "still one brand: {body}"
    );

    // DELETE removes it, and a subsequent GET is a uniform not-found.
    let (status, _, _) = harness.delete(&path).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete brand");
    let (status, _, _) = harness.get(&path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the brand is gone");
    let (status, _, _) = harness.delete(&path).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a repeated delete is the uniform not-found"
    );
}

/// The brand's BIRTH PATH, which is the whole reason this endpoint exists: a logo upload 404s
/// while the brand row is absent and succeeds once it is created.
///
/// This is also the operator remedy the promotion asset transport depends on. A promotion
/// resolves an asset by content reference against bytes the TARGET already holds, so an
/// operator must be able to create the target brand and upload the bytes before promoting. That
/// was impossible before this endpoint.
#[tokio::test]
async fn a_logo_upload_is_a_not_found_until_the_brand_is_created() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let logo_path = format!("{}/logo", brand_path(&tenant, &env, "acme"));
    // The 8-byte PNG signature is enough: the upload path decides the media type by a
    // MAGIC-BYTE sniff of the actual bytes, never the declared header.
    let png: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    let (status, _, _) = harness.put_bytes(&logo_path, png).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "no brand row, so no asset can be installed"
    );

    let (status, _, body) = harness
        .put(
            &brand_path(&tenant, &env, "acme"),
            r#"{"product_name":"Acme"}"#,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "create the brand: {body}");

    let (status, _, body) = harness.put_bytes(&logo_path, png).await;
    assert_eq!(status, StatusCode::OK, "now the logo installs: {body}");
    assert!(body.contains("\"kind\":\"logo\""), "{body}");

    // And deleting the brand takes its assets with it, so no orphaned bytes survive to be
    // inherited by a later brand of the same slug.
    let (status, _, _) = harness.delete(&brand_path(&tenant, &env, "acme")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, body) = harness
        .put(
            &brand_path(&tenant, &env, "acme"),
            r#"{"product_name":"Acme"}"#,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "recreate the slug: {body}");
    let (status, _, _) = harness.delete(&logo_path).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the recreated brand inherits no asset from its deleted namesake"
    );
}

/// A hostile design token is a loud 400 and NOTHING is stored: the closed typed grammar is the
/// wall that keeps the served stylesheet free of a CSS breakout.
#[tokio::test]
async fn a_hostile_design_token_is_a_precise_bad_request_and_stores_nothing() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = brand_path(&tenant, &env, "acme");

    let body = r##"{"product_name":"Acme","tokens":{"color_bg":"#fff; } body { background: url(javascript:alert(1)) } .x {","color_fg":"#1a1a1a","color_accent":"#2f5bde","color_accent_fg":"#ffffff","color_error":"#b00020","color_surface":"#ffffff","color_border":"#bbbbbb","font_family":"system_ui","radius":6,"space":16}}"##;
    let (status, _, response) = harness.put(&path, body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a CSS breakout in a color slot: {response}"
    );
    assert!(
        response.contains("design-token"),
        "names the fault: {response}"
    );

    // Nothing was stored.
    let (status, _, _) = harness.get(&path).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a refused write stores nothing"
    );
}

/// A rich-text slot is SANITIZED at ingest, and an unknown slot key is a loud 400 rather than a
/// silent drop.
#[tokio::test]
async fn a_slot_is_sanitized_at_ingest_and_an_unknown_slot_key_is_refused() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = brand_path(&tenant, &env, "acme");

    let body = r#"{"product_name":"Acme","slots":{"footer_legal":"<p>Terms<script>alert(1)</script></p>"}}"#;
    let (status, _, response) = harness.put(&path, body).await;
    assert_eq!(status, StatusCode::OK, "set with a slot: {response}");
    assert!(
        !response.to_ascii_lowercase().contains("<script"),
        "the echoed slot is sanitizer output: {response}"
    );
    assert!(
        response.contains("Terms"),
        "the safe text survives: {response}"
    );

    // The two assertions above are NOT enough on their own, and knowing why is the point:
    // `view_of` RE-SANITIZES on read (defense in depth), so the echoed body would be clean even
    // if the ingest wall were removed entirely. MEASURED: replacing the ingest sanitizer with a
    // verbatim serialization left both of them green. What follows reads the STORED ROW, the
    // only place the ingest wall is observable, so this is the assertion that actually pins it.
    let record = harness
        .store()
        .scoped(scope_of(&tenant, &env))
        .brands()
        .get("acme")
        .await
        .expect("read the stored brand")
        .expect("the brand exists");
    assert!(
        !record.slots_json.to_ascii_lowercase().contains("<script"),
        "the slot is SANITIZED AT INGEST, so the stored row can never hold active markup: {}",
        record.slots_json
    );
    assert!(record.slots_json.contains("Terms"), "{}", record.slots_json);

    // A misspelled slot key would otherwise render nothing and look like a server fault.
    let body = r#"{"product_name":"Acme","slots":{"footer_lega":"<b>x</b>"}}"#;
    let (status, _, response) = harness.put(&path, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert!(
        response.contains("footer_lega"),
        "names the key: {response}"
    );
}

/// A slug outside the grammar is the UNIFORM not-found, never a distinguishable error: such a
/// slug can name no installed brand, so it must answer exactly what an absent one does.
#[tokio::test]
async fn a_slug_outside_the_grammar_is_the_uniform_not_found() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;

    for bad in ["Acme", "a%20b", "acme.test"] {
        let path = brand_path(&tenant, &env, bad);
        let (status, _, body) = harness.put(&path, r#"{"product_name":"Acme"}"#).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "PUT {bad}: {body}");
        let (status, _, body) = harness.get(&path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "GET {bad}: {body}");
    }
}

/// The per-CLIENT selection key must name a client of THIS environment.
///
/// It was the only new ingest field with no wall: tokens, slots, the slug and the host key all
/// have one. A `client_id` embeds its `(tenant, environment)`, so a foreign one stored here
/// matches no authorize request that could ever reach this environment. That is dead config an
/// operator has no way to notice, in the column that decides which brand a named relying party
/// renders. A malformed or cross-scope id answers the uniform not-found, exactly as the
/// signup-form key (the same `ClientId`) already does.
///
/// The control at the other end is the in-scope id, which is ACCEPTED even though it names no
/// installed client: the wall is scope parsing, not existence. A brand may legitimately be
/// authored before its client is registered, and an existence check here would also turn the
/// selection column into an oracle for which client ids exist.
#[tokio::test]
async fn a_brand_client_id_from_another_environment_is_the_uniform_not_found() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let (other_tenant, other_env) = harness.create_tenant("Other", "k2").await;
    let path = brand_path(&tenant, &env, "acme");

    let foreign = Harness::fresh_client_id(scope_of(&other_tenant, &other_env));
    let (status, _, body) = harness
        .put(
            &path,
            &format!(r#"{{"product_name":"Acme","client_id":"{foreign}"}}"#),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "another environment's client id names no client here: {body}"
    );
    let (status, _, _) = harness.get(&path).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the refused write stored nothing"
    );

    // A syntactically bogus id is the same uniform not-found.
    let (status, _, _) = harness
        .put(
            &path,
            r#"{"product_name":"Acme","client_id":"not-a-client-id"}"#,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // THE CONTROL: an in-scope id is accepted and stored.
    let local = Harness::fresh_client_id(scope_of(&tenant, &env));
    let (status, _, body) = harness
        .put(
            &path,
            &format!(r#"{{"product_name":"Acme","client_id":"{local}"}}"#),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "an in-scope selection key: {body}");
    assert!(
        body.contains(&format!("\"client_id\":\"{local}\"")),
        "{body}"
    );
}

/// THE SECOND DOOR INTO `brands`, over HTTP: a config-promotion source carrying a brand this
/// crate would refuse to store is a 400 at PLAN and at APPLY, and stores nothing.
///
/// The promotion apply is a full writer of the `brands` table, and snapshot validation checks
/// only that a brand's `tokens` and `slots` are JSON OBJECTS. So without this wall a submitted
/// document stored an unknown slot key, unsanitized markup, and a CSS breakout in a color token,
/// none of which `PUT .../brands/{slug}` accepts. This drives the WIRING rather than the rules
/// (the rules are unit tested in `crate::brands`): removing the wall from either endpoint turns
/// exactly one half of this red.
///
/// The document is built by EXPORTING a real brand and then editing it, so the shape is
/// unquestionably a legal snapshot and the hostile fields are the only difference. The
/// unedited export is planned first, as the control that rules out a wall that refuses
/// everything.
#[tokio::test]
async fn a_promotion_source_carrying_an_unstorable_brand_is_refused_at_plan_and_apply() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let (target_tenant, target_env) = harness.create_tenant("Target", "k2").await;
    let plan_path =
        format!("/v1/tenants/{target_tenant}/environments/{target_env}/config/promotion/plan");
    let apply_path =
        format!("/v1/tenants/{target_tenant}/environments/{target_env}/config/promotion/apply");
    let target_brands = brands_path(&target_tenant, &target_env);

    let (status, _, body) = harness
        .put(
            &brand_path(&tenant, &env, "acme"),
            r#"{"product_name":"Acme","slots":{"footer_legal":"<strong>Legal</strong>"}}"#,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "seed the source brand: {body}");
    let (status, _, exported) = harness
        .get(&format!(
            "/v1/tenants/{tenant}/environments/{env}/config/snapshot"
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "export: {exported}");

    // THE CONTROL: the export itself plans clean. A sanitized slot is its own sanitizer output
    // (the sanitizer is idempotent), so a genuine promotion is not collateral damage.
    let (status, _, plan) = harness.post(&plan_path, "p1", &exported).await;
    assert_eq!(status, StatusCode::OK, "the unedited export plans: {plan}");

    let mut document: serde_json::Value =
        serde_json::from_str(&exported).expect("the export is JSON");
    document["resources"]["brand"][0]["slots"] = serde_json::json!({
        "not_a_slot": "<b>x</b>",
        "footer_legal": "<p>Terms<script>alert(1)</script></p>"
    });
    document["resources"]["brand"][0]["tokens"] = serde_json::json!({
        "color_bg": "#fff; } body { background: url(javascript:alert(1)) } .x {"
    });
    let hostile = serde_json::to_string(&document).expect("serializes");

    let (status, _, body) = harness.post(&plan_path, "p2", &hostile).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the plan must refuse a document the apply could not legally store: {body}"
    );
    assert!(body.contains("not_a_slot"), "the fault is named: {body}");

    // The APPLY carries the same wall independently, so a caller that skips the plan is not a
    // way around it. The revision is irrelevant: the refusal is ahead of the drift gate.
    let apply_body = serde_json::to_string(&serde_json::json!({
        "source": document,
        "base_revision": "0".repeat(64),
    }))
    .expect("serializes");
    let (status, _, body) = harness.post(&apply_path, "a1", &apply_body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the apply must refuse it too: {body}"
    );
    assert!(
        body.contains("design-token") || body.contains("not_a_slot"),
        "{body}"
    );

    let (status, _, body) = harness.get(&target_brands).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("\"items\":[]"),
        "the refused promotion stored nothing: {body}"
    );
}
