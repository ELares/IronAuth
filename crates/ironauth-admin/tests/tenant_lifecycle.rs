// SPDX-License-Identifier: MIT OR Apache-2.0

//! The tenant lifecycle API and residency attributes over HTTP (issue #46).
//!
//! Drives the operator-plane endpoints through the real management router: create
//! with a validated residency region, suspend and resume with the state machine and
//! Idempotency-Key discipline, invalid transitions refused with a loud 409, the
//! plane guard (a data-plane management key cannot drive an operator-plane
//! lifecycle action), and the restore 200 reporting the status the write COMMITTED
//! rather than a post-condition the handler predicted (issue #438).

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

/// Parse a JSON response body.
fn json(body: &str) -> Value {
    serde_json::from_str(body).expect("json body")
}

#[tokio::test]
async fn create_records_and_reads_back_residency_and_status() {
    let harness =
        Harness::start_with_regions(50, vec!["eu-west".to_owned(), "us-east".to_owned()]).await;

    let body = serde_json::json!({
        "display_name": "Acme, Inc.",
        "home_region": "eu-west",
    })
    .to_string();
    let (status, _, response) = harness.post("/v1/tenants", "k-create", &body).await;
    assert_eq!(status, StatusCode::CREATED, "create: {response}");
    let created = json(&response);
    assert_eq!(created["tenant"]["status"], "active");
    assert_eq!(created["tenant"]["home_region"], "eu-west");

    // A read returns the same status and residency.
    let tenant_id = created["tenant"]["id"].as_str().expect("id");
    let (status, _, response) = harness.get(&format!("/v1/tenants/{tenant_id}")).await;
    assert_eq!(status, StatusCode::OK, "get: {response}");
    let view = json(&response);
    assert_eq!(view["status"], "active");
    assert_eq!(view["home_region"], "eu-west");
}

#[tokio::test]
async fn create_rejects_a_region_outside_the_configured_set() {
    let harness = Harness::start_with_regions(50, vec!["eu-west".to_owned()]).await;
    let body = serde_json::json!({ "display_name": "Acme", "home_region": "mars-1" }).to_string();
    let (status, _, response) = harness.post("/v1/tenants", "k1", &body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a region outside the configured set is refused: {response}"
    );
}

#[tokio::test]
async fn create_rejects_any_region_when_none_configured() {
    // The default harness configures no region set, so residency pinning is
    // unavailable and any home_region is refused fail closed.
    let harness = Harness::start(50).await;
    let body = serde_json::json!({ "display_name": "Acme", "home_region": "eu-west" }).to_string();
    let (status, _, response) = harness.post("/v1/tenants", "k1", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no region set: {response}");

    // A create WITHOUT a region still succeeds.
    let ok = serde_json::json!({ "display_name": "Acme" }).to_string();
    let (status, _, response) = harness.post("/v1/tenants", "k2", &ok).await;
    assert_eq!(status, StatusCode::CREATED, "no region is fine: {response}");
    assert!(json(&response)["tenant"]["home_region"].is_null());
}

#[tokio::test]
async fn suspend_then_resume_roundtrips_and_the_tenant_stays_visible() {
    let harness = Harness::start(50).await;
    let (tenant_id, _env) = harness.create_tenant("Acme", "k-create").await;

    let (status, _, response) = harness
        .post(&format!("/v1/tenants/{tenant_id}/suspend"), "k-susp", "{}")
        .await;
    assert_eq!(status, StatusCode::OK, "suspend: {response}");
    assert_eq!(json(&response)["status"], "suspended");

    // A suspended tenant remains visible to control-plane reads, as suspended.
    let (status, _, response) = harness.get(&format!("/v1/tenants/{tenant_id}")).await;
    assert_eq!(status, StatusCode::OK, "get suspended: {response}");
    assert_eq!(json(&response)["status"], "suspended");

    let (status, _, response) = harness
        .post(&format!("/v1/tenants/{tenant_id}/resume"), "k-res", "{}")
        .await;
    assert_eq!(status, StatusCode::OK, "resume: {response}");
    assert_eq!(json(&response)["status"], "active");

    let (_, _, response) = harness.get(&format!("/v1/tenants/{tenant_id}")).await;
    assert_eq!(json(&response)["status"], "active");
}

#[tokio::test]
async fn invalid_transitions_are_refused_with_409() {
    let harness = Harness::start(50).await;
    let (tenant_id, _env) = harness.create_tenant("Acme", "k-create").await;

    // Resume an active tenant: invalid.
    let (status, _, _) = harness
        .post(&format!("/v1/tenants/{tenant_id}/resume"), "k1", "{}")
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "resume of an active tenant is 409"
    );

    // Suspend (valid), then suspend again with a DIFFERENT key: invalid.
    let (status, _, _) = harness
        .post(&format!("/v1/tenants/{tenant_id}/suspend"), "k2", "{}")
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = harness
        .post(&format!("/v1/tenants/{tenant_id}/suspend"), "k3", "{}")
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "suspend of an already-suspended tenant is 409"
    );
}

#[tokio::test]
async fn a_suspend_replays_idempotently_on_the_same_key() {
    let harness = Harness::start(50).await;
    let (tenant_id, _env) = harness.create_tenant("Acme", "k-create").await;

    let path = format!("/v1/tenants/{tenant_id}/suspend");
    let (status, _, first) = harness.post(&path, "same-key", "{}").await;
    assert_eq!(status, StatusCode::OK);
    // A replay with the SAME key returns the original response, NOT a 409, even
    // though the tenant is now already suspended.
    let (status, _, replay) = harness.post(&path, "same-key", "{}").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "same-key replay is the original 200"
    );
    assert_eq!(first, replay, "the replay body is byte-identical");
}

#[tokio::test]
async fn lifecycle_endpoints_require_the_operator_plane() {
    let harness = Harness::start(50).await;
    let (tenant_id, environment_id) = harness.create_tenant("Acme", "k-create").await;
    // A data-plane-scoped management key is NOT an operator credential.
    let mgmt_token = harness
        .create_key(&tenant_id, &environment_id, "ci", "k-key")
        .await;

    // Every lifecycle endpoint (the IDOR harness extension for issue #46): a
    // data-plane key fails structurally with a 403 on suspend, resume, AND restore,
    // never reaching the state machine.
    for (suffix, key) in [
        ("suspend", "k-susp"),
        ("resume", "k-res"),
        ("restore", "k-rest"),
    ] {
        let (status, _, response) = harness
            .post_as(
                &format!("/v1/tenants/{tenant_id}/{suffix}"),
                &mgmt_token,
                key,
                "{}",
            )
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a management key cannot drive the operator-plane {suffix}: {response}"
        );
    }
}

#[tokio::test]
async fn a_grace_deleted_tenant_is_restorable_inside_the_window() {
    let harness = Harness::start(50).await;
    let (tenant_id, _env) = harness.create_tenant("Acme", "k-create").await;

    // Offboard into the grace stage: the tenant reads as absent (soft-deleted).
    let (status, _, _) = harness.delete(&format!("/v1/tenants/{tenant_id}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "grace delete");
    let (status, _, _) = harness.get(&format!("/v1/tenants/{tenant_id}")).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a grace tenant reads as absent"
    );

    // Restore inside the (default 30-day) retention window: the tenant is live and
    // active again, visible to reads.
    let (status, _, response) = harness
        .post(&format!("/v1/tenants/{tenant_id}/restore"), "k-rest", "{}")
        .await;
    assert_eq!(status, StatusCode::OK, "restore in window: {response}");
    assert_eq!(json(&response)["status"], "active");
    let (status, _, response) = harness.get(&format!("/v1/tenants/{tenant_id}")).await;
    assert_eq!(status, StatusCode::OK, "restored tenant is visible again");
    assert_eq!(json(&response)["status"], "active");
}

#[tokio::test]
async fn a_restore_200_reports_the_status_it_committed_and_replays_the_same_bytes() {
    // A restore is not a status TRANSITION: it undoes the delete and leaves the
    // lifecycle status alone. The 200 said `active` regardless, because the body was
    // asserted before the store call and stored as the Idempotency-Key replay body, so
    // a suspended tenant's restore reported a status the row never held and every
    // replay of that key served it again (issue #438).
    let harness = Harness::start(50).await;

    // The SUBJECT: suspended, then grace-deleted, then restored. It comes back
    // suspended (issue #432), so that is what the 200 must say.
    let (suspended, _env) = harness.create_tenant("Suspended Co", "k-create-s").await;
    let (status, _, _) = harness
        .post(&format!("/v1/tenants/{suspended}/suspend"), "k-susp", "{}")
        .await;
    assert_eq!(status, StatusCode::OK, "suspend");
    let (status, _, _) = harness.delete(&format!("/v1/tenants/{suspended}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "grace delete");

    let path = format!("/v1/tenants/{suspended}/restore");
    let (status, _, first) = harness.post(&path, "k-rest-s", "{}").await;
    assert_eq!(status, StatusCode::OK, "restore in window: {first}");
    assert_eq!(
        json(&first)["status"],
        "suspended",
        "the 200 reports the status the restore COMMITTED, not a wished-for active"
    );

    // The 200 agrees with a subsequent READ. This is the disagreement the defect
    // produced, so it is asserted directly rather than inferred.
    let (status, _, read) = harness.get(&format!("/v1/tenants/{suspended}")).await;
    assert_eq!(status, StatusCode::OK, "get restored: {read}");
    assert_eq!(
        json(&read)["status"],
        json(&first)["status"],
        "the restore 200 and a subsequent GET report the same status"
    );

    // The Idempotency-Key record was rendered from the same committed value, inside
    // the restore's own transaction, so a replay is the ORIGINAL BYTES rather than the
    // stale literal. A replay is also the only way to read that stored record back.
    let (status, _, replay) = harness.post(&path, "k-rest-s", "{}").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "same-key replay is the original 200"
    );
    assert_eq!(first, replay, "the replay body is byte-identical");

    // The CONTROL, in the same test, so `suspended` above is attributable to the
    // tenant's status rather than to a report hardwired the other way: an ACTIVE
    // tenant's restore still reports active, and still replays its own bytes.
    let (active, _env) = harness.create_tenant("Active Co", "k-create-a").await;
    let (status, _, _) = harness.delete(&format!("/v1/tenants/{active}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "grace delete control");
    let path = format!("/v1/tenants/{active}/restore");
    let (status, _, first) = harness.post(&path, "k-rest-a", "{}").await;
    assert_eq!(status, StatusCode::OK, "restore control: {first}");
    assert_eq!(json(&first)["status"], "active");
    let (_, _, replay) = harness.post(&path, "k-rest-a", "{}").await;
    assert_eq!(first, replay, "the control's replay body is byte-identical");
}

#[tokio::test]
async fn restoring_a_live_tenant_is_a_uniform_not_found() {
    // A tenant that was never offboarded has nothing to restore: the uniform
    // anti-oracle 404 (not a 409, which is reserved for a window-elapsed grace
    // tenant).
    let harness = Harness::start(50).await;
    let (tenant_id, _env) = harness.create_tenant("Acme", "k-create").await;
    let (status, _, _) = harness
        .post(&format!("/v1/tenants/{tenant_id}/restore"), "k-rest", "{}")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn environment_create_records_and_validates_a_region_pin() {
    let harness =
        Harness::start_with_regions(50, vec!["eu-west".to_owned(), "us-east".to_owned()]).await;
    let (tenant_id, _env) = harness.create_tenant("Acme", "k-create").await;

    // A valid per-environment region is stored and returned on the create and on a
    // subsequent read.
    let path = format!("/v1/tenants/{tenant_id}/environments");
    let body = serde_json::json!({ "display_name": "staging", "kind": "dev", "region": "us-east" })
        .to_string();
    let (status, _, response) = harness.post(&path, "k-env", &body).await;
    assert_eq!(status, StatusCode::CREATED, "create env: {response}");
    let created = json(&response);
    assert_eq!(created["region"], "us-east");
    let environment_id = created["id"].as_str().expect("env id");
    let (status, _, response) = harness
        .get(&format!(
            "/v1/tenants/{tenant_id}/environments/{environment_id}"
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "get env: {response}");
    assert_eq!(json(&response)["region"], "us-east");

    // An invalid region is refused, before any write.
    let bad = serde_json::json!({ "display_name": "prod", "kind": "dev", "region": "mars-1" })
        .to_string();
    let (status, _, response) = harness.post(&path, "k-bad", &bad).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a region outside the configured set is refused: {response}"
    );
}

#[tokio::test]
async fn environment_create_is_refused_under_a_suspended_tenant() {
    // A suspended tenant is fenced off the data plane; it must not gain a fresh,
    // unfenced environment (issue #46). Adding an environment to a suspended tenant is
    // a loud 409, and the ability returns after a resume.
    let harness = Harness::start(50).await;
    let (tenant_id, _env) = harness.create_tenant("Acme", "k-create").await;
    let path = format!("/v1/tenants/{tenant_id}/environments");

    // Under the ACTIVE tenant, a create works.
    let body = serde_json::json!({ "display_name": "staging", "kind": "dev" }).to_string();
    let (status, _, response) = harness.post(&path, "k-env-active", &body).await;
    assert_eq!(status, StatusCode::CREATED, "active create: {response}");

    // Suspend the tenant.
    let (status, _, _) = harness
        .post(&format!("/v1/tenants/{tenant_id}/suspend"), "k-susp", "{}")
        .await;
    assert_eq!(status, StatusCode::OK);

    // A create under the suspended tenant is refused with a loud 409, not the
    // anti-oracle 404 (the tenant is visible to the control plane) and not a silent
    // 201 that would hand the tenant an unfenced serving surface.
    let (status, _, response) = harness.post(&path, "k-env-susp", &body).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "creating an environment under a suspended tenant is 409: {response}"
    );

    // Resume restores the ability to add environments.
    let (status, _, _) = harness
        .post(&format!("/v1/tenants/{tenant_id}/resume"), "k-res", "{}")
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, response) = harness.post(&path, "k-env-resumed", &body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a resumed tenant can add environments again: {response}"
    );
}

#[tokio::test]
async fn the_grace_window_gates_the_purge_and_the_purge_is_terminal() {
    // `TenantRepo::hard_delete` shipped with the offboarding pipeline and NOTHING called
    // it: measured with `grep -rn hard_delete crates/ironauth-admin crates/ironauth/src
    // crates/ironauth-oidc crates/ironauth-server`, which returned nothing. So a
    // soft-deleted tenant sat in grace forever, its platform KEK was never destroyed, and
    // the erasure half of the exit covenant could not happen at all. This is the caller.
    //
    // Two properties, and the first is what makes the second safe: the window GATES the
    // purge, and past the window the purge is terminal.
    let harness = Harness::start_with_offboarding_retention(50, 0).await;
    let (tenant_id, _env) = harness.create_tenant("Acme", "k-create").await;

    // A LIVE tenant cannot be purged. Purge acts only on a tenant already in grace, so
    // this is the uniform not-found rather than a 409: nothing was ever offboarded.
    let (status, _, response) = harness
        .post(&format!("/v1/tenants/{tenant_id}/purge"), "k-p0", "")
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a live tenant is not purgeable: {response}"
    );

    let (status, _, _) = harness.delete(&format!("/v1/tenants/{tenant_id}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "grace delete");

    // Past the window (zero here, chosen by this harness rather than bypassed), the purge
    // is accepted and is TERMINAL: the tenant can no longer be restored.
    let (status, _, response) = harness
        .post(&format!("/v1/tenants/{tenant_id}/purge"), "k-p1", "")
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "purge past window: {response}"
    );

    let (status, _, response) = harness
        .post(&format!("/v1/tenants/{tenant_id}/restore"), "k-r1", "")
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a purged tenant cannot be restored: {response}"
    );

    // REPLAYING the purge key returns the original 204, not a 404. This is what the
    // Idempotency-Key is for on an irreversible operation: an operator whose response was
    // lost to a network timeout must be able to retry and learn that it succeeded, rather
    // than being told the tenant is absent and left unable to tell "I purged it" from
    // "someone else did" or "it never existed".
    let (status, _, response) = harness
        .post(&format!("/v1/tenants/{tenant_id}/purge"), "k-p1", "")
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the same key replays the original success: {response}"
    );

    // A DIFFERENT key is the uniform not-found, not a second destruction.
    let (status, _, response) = harness
        .post(&format!("/v1/tenants/{tenant_id}/purge"), "k-p2", "")
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an already-purged tenant is absent: {response}"
    );
}

#[tokio::test]
async fn a_purge_inside_the_retention_window_is_refused_loudly() {
    // The gate itself, on its own, because the test above runs with a ZERO window and so
    // could never see it. With the shipped default the grace period must run first, and
    // the refusal is a loud 409 rather than the anti-oracle 404: the caller is an
    // authenticated operator acting on a tenant they can already see, and "not yet" is the
    // entire point of a retention window.
    //
    // Without this, a purge that ignored the window would pass the test above unchanged.
    let harness = Harness::start(50).await;
    let (tenant_id, _env) = harness.create_tenant("Acme", "k-create").await;
    let (status, _, _) = harness.delete(&format!("/v1/tenants/{tenant_id}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "grace delete");

    let (status, _, response) = harness
        .post(&format!("/v1/tenants/{tenant_id}/purge"), "k-early", "")
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the grace period must run first: {response}"
    );

    // And the tenant is still restorable, which is what the window is FOR.
    let (status, _, response) = harness
        .post(&format!("/v1/tenants/{tenant_id}/restore"), "k-r", "")
        .await;
    assert_eq!(status, StatusCode::OK, "still restorable: {response}");
}
