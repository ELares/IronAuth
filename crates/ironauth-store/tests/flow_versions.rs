// SPDX-License-Identifier: MIT OR Apache-2.0

//! The custom-journey version registry over a real database (`DATABASE_URL`) (issue #92, PR 5).
//!
//! Proves the load-bearing properties of the flow-versions data plane against a live database:
//!
//! - **Append-only versioning.** Two creates of the same journey mint versions 1 then 2; a
//!   version's content is immutable and there is no overwrite.
//! - **Control-plane authoring, data-plane read.** A version is created and pinned on the
//!   control-plane role that owns authoring, and read back on the data-plane role the custom-flow
//!   engine path uses; the data-plane role can read but never write (the grant split).
//! - **Pinning.** A pin resolves a journey to its active version; moving the pin changes which
//!   version `get_pinned` returns, and clears the `pinned` flag on the previously pinned version.
//! - **Fail-fast write validation.** A load-invalid artifact is refused before it is stored.
//! - **Promotable round-trip.** A config-snapshot export carries every version (its artifact as
//!   embedded JSON and its pin flag), and `validate_document` accepts the exported bytes.
//! - **Cross-scope isolation.** A version authored in scope A never appears in scope B.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewFlowVersion, StoreError, export_snapshot, validate_document,
};

/// A minimal load-valid journey artifact: an identifier/password step routing to a terminal.
fn artifact(id: &str) -> String {
    serde_json::json!({
        "schema_version": "ironauth.journey/v1",
        "id": id,
        "engine_version": 1,
        "entry": "primary",
        "steps": [
            {"id": "primary", "kind": "identifier_password", "node_group": "password"},
            {"id": "done", "kind": "terminal"}
        ],
        "transitions": [{"from": "primary", "to": "done"}]
    })
    .to_string()
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn create_is_append_only_and_pin_moves_the_active_version() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();
    let app = db.store();

    let journey = "login_basic";

    // Create v1 and v2: the version number increments (append-only).
    let v1 = control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .flow_versions()
        .create_next_version(
            &env,
            NewFlowVersion {
                journey_id: journey,
                artifact_json: &artifact(journey),
            },
            1_000_000,
        )
        .await
        .expect("create v1");
    assert_eq!(v1.version, 1);
    assert!(!v1.pinned, "a fresh version is not pinned");

    let v2 = control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .flow_versions()
        .create_next_version(
            &env,
            NewFlowVersion {
                journey_id: journey,
                artifact_json: &artifact(journey),
            },
            2_000_000,
        )
        .await
        .expect("create v2");
    assert_eq!(v2.version, 2, "the version number increments");

    // Read back a version by its flv_ id on the DATA-plane role (the custom-flow engine's role).
    let read = app
        .scoped(scope)
        .flow_versions()
        .get_by_id(&v1.id)
        .await
        .expect("get by id")
        .expect("v1 exists");
    assert_eq!(read.version, 1);
    assert!(read.artifact_json.contains("identifier_password"));

    // Pin v1: get_pinned resolves the journey to v1, and v1's pinned flag is set.
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .flow_versions()
        .pin(&env, journey, 1, 3_000_000, None)
        .await
        .expect("pin v1");
    let pinned = app
        .scoped(scope)
        .flow_versions()
        .get_pinned(journey)
        .await
        .expect("get pinned")
        .expect("a pin exists");
    assert_eq!(pinned.version, 1);
    assert_eq!(pinned.id, v1.id);
    assert!(pinned.pinned);

    // Move the pin to v2: get_pinned now resolves v2, and v1's pinned flag clears.
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .flow_versions()
        .pin(&env, journey, 2, 4_000_000, None)
        .await
        .expect("pin v2");
    let pinned = app
        .scoped(scope)
        .flow_versions()
        .get_pinned(journey)
        .await
        .expect("get pinned")
        .expect("a pin exists");
    assert_eq!(pinned.version, 2, "the pin moved to v2");
    let v1_after = app
        .scoped(scope)
        .flow_versions()
        .get_version(journey, 1)
        .await
        .expect("get v1")
        .expect("v1 exists");
    assert!(!v1_after.pinned, "v1 is no longer the active pin");

    // The data-plane role can read but never write (the grant split): a create on the app role is
    // refused by the missing INSERT privilege.
    let denied = app
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .flow_versions()
        .create_next_version(
            &env,
            NewFlowVersion {
                journey_id: journey,
                artifact_json: &artifact(journey),
            },
            5_000_000,
        )
        .await;
    assert!(
        matches!(denied, Err(StoreError::Database(_))),
        "the data-plane role must not be able to author a version: {denied:?}"
    );
}

#[tokio::test]
async fn pinning_an_unknown_version_is_a_uniform_not_found() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    // No version exists for this journey, so a pin names no version: a uniform not-found.
    let result = control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .flow_versions()
        .pin(&env, "ghost", 1, 1_000_000, None)
        .await;
    assert!(matches!(result, Err(StoreError::NotFound)), "{result:?}");
}

#[tokio::test]
async fn a_load_invalid_artifact_is_refused_before_it_is_stored() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    // A journey whose transition targets an undeclared step does not compile.
    let invalid = serde_json::json!({
        "schema_version": "ironauth.journey/v1",
        "id": "broken",
        "engine_version": 1,
        "entry": "primary",
        "steps": [
            {"id": "primary", "kind": "identifier_password", "node_group": "password"},
            {"id": "done", "kind": "terminal"}
        ],
        "transitions": [{"from": "primary", "to": "nowhere"}]
    })
    .to_string();
    let result = control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .flow_versions()
        .create_next_version(
            &env,
            NewFlowVersion {
                journey_id: "broken",
                artifact_json: &invalid,
            },
            1_000_000,
        )
        .await;
    assert!(
        matches!(result, Err(StoreError::JourneyInvalid(ref e)) if !e.is_empty()),
        "a load-invalid artifact must be refused with its errors: {result:?}"
    );
    // Nothing was stored.
    assert!(
        control
            .scoped(scope)
            .flow_versions()
            .list_for_journey("broken")
            .await
            .expect("list")
            .is_empty(),
        "a rejected artifact leaves no row"
    );
}

#[tokio::test]
async fn versions_round_trip_through_a_config_snapshot_and_stay_scoped() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let control = db.control_store();

    let journey = "login_basic";
    control
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .flow_versions()
        .create_next_version(
            &env,
            NewFlowVersion {
                journey_id: journey,
                artifact_json: &artifact(journey),
            },
            1_000_000,
        )
        .await
        .expect("create v1 in A");
    control
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .flow_versions()
        .pin(&env, journey, 1, 2_000_000, None)
        .await
        .expect("pin v1 in A");

    // The version appears in scope A's config-snapshot export, its pin flag set, and the exported
    // bytes validate (the snapshot both-sides binding). The export is deterministic.
    let snapshot = export_snapshot(&control.scoped(scope_a))
        .await
        .expect("export A");
    assert_eq!(
        snapshot.resources.flow_version.len(),
        1,
        "one version exported"
    );
    assert_eq!(snapshot.resources.flow_version[0].journey_id, journey);
    assert!(snapshot.resources.flow_version[0].pinned, "the pin travels");
    let bytes = snapshot.to_canonical_bytes().expect("canonical bytes");
    validate_document(&bytes).expect("the exported version must validate");
    let again = export_snapshot(&control.scoped(scope_a))
        .await
        .expect("re-export")
        .to_canonical_bytes()
        .expect("canonical bytes");
    assert_eq!(bytes, again, "a re-export is byte-identical");

    // Scope B sees no version and an empty export (cross-scope isolation under RLS).
    assert!(
        control
            .scoped(scope_b)
            .flow_versions()
            .get_pinned(journey)
            .await
            .expect("get pinned in B")
            .is_none(),
        "scope B has no pinned version"
    );
    let snapshot_b = export_snapshot(&control.scoped(scope_b))
        .await
        .expect("export B");
    assert!(
        snapshot_b.resources.flow_version.is_empty(),
        "scope B export carries no version"
    );
}
