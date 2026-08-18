// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment locale bundles over a real database (`DATABASE_URL`) (issue #86, PR 2).
//!
//! Proves the load-bearing properties of the localization data plane against a live database:
//!
//! - **Control-plane set, data-plane read.** A bundle is set on the control-plane role that
//!   owns the locale lifecycle and read back on the data-plane role the renderer and discovery
//!   use; the data-plane role can read (get, list, installed locales, env default) but never
//!   write (the grant split).
//! - **One env-default locale per scope.** Setting a second default demotes the first, so a
//!   scope always resolves exactly one default (the partial unique index backs it structurally).
//! - **Promotable round-trip.** A config-snapshot export carries the bundle (its entries map as
//!   embedded JSON), and `validate_document` accepts the exported bytes BYTE-IDENTICALLY on a
//!   re-export (the snapshot both-sides binding, acceptance criterion g).
//! - **Delete and cross-tenant isolation.** A delete removes the bundle; a bundle set in scope A
//!   never appears in scope B's export, installed-locales, or default read.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, LocaleBundleId, NewLocaleBundle, export_snapshot, validate_document,
};

/// A validated entries blob (numeric message id string to plain-text render, as the admin
/// locales path stores it after validation).
const FR_ENTRIES: &str = r#"{"1010001":"Se connecter","1010002":"Identifiant"}"#;

fn set_locale<'a>(
    locale: &'a str,
    is_env_default: bool,
    entries_json: &'a str,
) -> NewLocaleBundle<'a> {
    NewLocaleBundle {
        locale,
        is_env_default,
        entries_json,
    }
}

#[tokio::test]
async fn locale_set_reads_back_on_the_data_plane_and_round_trips_through_a_snapshot() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();
    let app = db.store();

    // SET on the control role (which owns the locale lifecycle).
    let id = LocaleBundleId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .locale_bundles()
        .set(&env, &id, 1_000_000, set_locale("fr", true, FR_ENTRIES))
        .await
        .expect("set locale");

    // READ back on the DATA-plane role (the renderer's / discovery's role).
    let record = app
        .scoped(scope)
        .locale_bundles()
        .env_default()
        .await
        .expect("read env default")
        .expect("an env default exists");
    assert_eq!(record.locale, "fr");
    assert!(record.is_env_default);
    assert!(
        record.entries_json.contains("Se connecter"),
        "entries round-trip"
    );

    // The installed-locales projection (the discovery read) lists exactly the tag.
    let installed = app
        .scoped(scope)
        .locale_bundles()
        .installed_locales()
        .await
        .expect("installed locales");
    assert_eq!(installed, vec!["fr".to_owned()]);

    // The bundle appears in the config-snapshot export, and the exported bytes validate
    // (the snapshot both-sides binding, acceptance criterion g).
    let snapshot = export_snapshot(&control.scoped(scope))
        .await
        .expect("export snapshot");
    assert_eq!(
        snapshot.resources.locale_bundle.len(),
        1,
        "one bundle exported"
    );
    assert_eq!(snapshot.resources.locale_bundle[0].locale, "fr");
    assert!(snapshot.resources.locale_bundle[0].is_env_default);
    let bytes = snapshot.to_canonical_bytes().expect("canonical bytes");
    validate_document(&bytes).expect("the exported bundle must validate");
    // The export is deterministic (byte-identical on a re-export).
    let again = export_snapshot(&control.scoped(scope))
        .await
        .expect("re-export")
        .to_canonical_bytes()
        .expect("canonical bytes");
    assert_eq!(bytes, again, "a re-export is byte-identical");
}

#[tokio::test]
async fn a_second_default_demotes_the_first_so_one_default_holds() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let first = LocaleBundleId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .locale_bundles()
        .set(&env, &first, 1_000_000, set_locale("fr", true, FR_ENTRIES))
        .await
        .expect("set first default");

    // A second default: the first is demoted, so the partial unique index (one default per
    // scope) is never violated and the scope resolves the new default.
    let second = LocaleBundleId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .locale_bundles()
        .set(&env, &second, 2_000_000, set_locale("es", true, "{}"))
        .await
        .expect("set second default");

    let default_locale = control
        .scoped(scope)
        .locale_bundles()
        .env_default()
        .await
        .expect("read default")
        .expect("a default exists");
    assert_eq!(default_locale.locale, "es", "the new default wins");

    // The first bundle still exists but is no longer the default.
    let first_bundle = control
        .scoped(scope)
        .locale_bundles()
        .get("fr")
        .await
        .expect("get fr")
        .expect("fr still exists");
    assert!(!first_bundle.is_env_default, "the first locale was demoted");

    // Exactly two bundles, exactly one default.
    let all = control
        .scoped(scope)
        .locale_bundles()
        .list_all()
        .await
        .expect("list");
    assert_eq!(all.len(), 2);
    assert_eq!(all.iter().filter(|b| b.is_env_default).count(), 1);
}

#[tokio::test]
async fn an_overwrite_is_idempotent_on_the_tag_and_delete_removes_it() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let id = LocaleBundleId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .locale_bundles()
        .set(&env, &id, 1_000_000, set_locale("fr", false, FR_ENTRIES))
        .await
        .expect("first set");

    // A repeat write to the same tag (a fresh id) overwrites in place: still one row.
    let id2 = LocaleBundleId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .locale_bundles()
        .set(
            &env,
            &id2,
            2_000_000,
            set_locale("fr", false, r#"{"1010001":"Connexion"}"#),
        )
        .await
        .expect("overwrite");

    let all = control
        .scoped(scope)
        .locale_bundles()
        .list_all()
        .await
        .expect("list");
    assert_eq!(all.len(), 1, "an overwrite keeps a single row per tag");
    assert!(all[0].entries_json.contains("Connexion"));

    // Delete by the stored id (reused across the overwrite): the bundle is gone.
    let stored_id = LocaleBundleId::parse_in_scope(&all[0].id, &scope).expect("parse stored id");
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .locale_bundles()
        .delete(&env, &stored_id)
        .await
        .expect("delete");
    assert!(
        control
            .scoped(scope)
            .locale_bundles()
            .get("fr")
            .await
            .expect("get after delete")
            .is_none(),
        "the bundle is deleted"
    );
}

#[tokio::test]
async fn a_locale_is_scoped_and_never_leaks_across_environments() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let control = db.control_store();

    let id = LocaleBundleId::generate(&env, &scope_a);
    control
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .locale_bundles()
        .set(&env, &id, 1_000_000, set_locale("fr", true, FR_ENTRIES))
        .await
        .expect("set locale in scope A");

    // Scope B sees no default, no installed locales, and an empty export.
    assert!(
        control
            .scoped(scope_b)
            .locale_bundles()
            .env_default()
            .await
            .expect("read default in B")
            .is_none(),
        "scope B has no locale"
    );
    assert!(
        control
            .scoped(scope_b)
            .locale_bundles()
            .installed_locales()
            .await
            .expect("installed in B")
            .is_empty(),
        "scope B has no installed locales"
    );
    let snapshot_b = export_snapshot(&control.scoped(scope_b))
        .await
        .expect("export B");
    assert!(
        snapshot_b.resources.locale_bundle.is_empty(),
        "scope B's export carries no locale bundle"
    );
}

/// Deleting a locale bundle emits `locale_bundle.deleted`, carrying its tag (issue #108).
///
/// Removing a bundle changes what language a user is addressed in: the hosted pages and the
/// messages fall back to the default. The TAG is what carries that meaning -- "fr went away"
/// is actionable, an opaque bundle id is not -- and after the delete there is no row left to
/// look it up in.
#[tokio::test]
async fn deleting_a_locale_bundle_emits_the_registered_event_with_its_tag() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = LocaleBundleId::generate(&env, &scope);

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .locale_bundles()
        .set(&env, &id, 1_000_000, set_locale("fr", true, FR_ENTRIES))
        .await
        .expect("set locale bundle");

    assert_eq!(
        queued_events(&db, scope).await.len(),
        0,
        "this set passed no event, so the delete's event below is unambiguous. The \
         un-suffixed method staying silent IS the paired-negative guarantee; it is not a \
         claim that setting never announces"
    );

    let envelope = ironauth_store::event_catalog::envelope(
        "evt_locale_deleted",
        "locale_bundle.deleted",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({ "locale_bundle_id": id.to_string(), "tag": "fr" }),
    )
    .expect("locale_bundle.deleted is registered");

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .locale_bundles()
        .delete_with_event(
            &env,
            &id,
            Some(&ironauth_store::DomainEvent {
                id: "evt_locale_deleted",
                subject: &id.to_string(),
                envelope: &envelope,
            }),
        )
        .await
        .expect("delete with event");

    let events = queued_events(&db, scope).await;
    assert_eq!(events.len(), 1, "the delete enqueues exactly one event");
    assert_eq!(events[0]["type"], "locale_bundle.deleted");
    assert_eq!(
        events[0]["payload"]["tag"], "fr",
        "the tag survives the row it came from"
    );
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the envelope validates against the registry the fan-out enforces");
}

/// A delete carrying no event enqueues nothing.
#[tokio::test]
async fn deleting_a_locale_bundle_without_an_event_enqueues_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = LocaleBundleId::generate(&env, &scope);

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .locale_bundles()
        .set(&env, &id, 1_000_000, set_locale("fr", true, FR_ENTRIES))
        .await
        .expect("set locale bundle");

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .locale_bundles()
        .delete(&env, &id)
        .await
        .expect("delete");

    assert_eq!(
        queued_events(&db, scope).await.len(),
        0,
        "a delete with no event must not invent one"
    );
}

/// Every webhook-event envelope queued in `scope`.
async fn queued_events(db: &TestDatabase, scope: ironauth_store::Scope) -> Vec<serde_json::Value> {
    use std::time::Duration;

    db.store()
        .scoped(scope)
        .outbox()
        .claim(
            &Env::system(),
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim webhook events")
        .into_iter()
        .map(|message| message.payload)
        .collect()
}

/// Setting a locale bundle emits `locale_bundle.set`, addressed by TAG.
///
/// The tag rather than the bundle id, and the OVERWRITE is what proves why: `set` is an
/// upsert, and the store reuses the EXISTING row's id when the tag is already present. A
/// caller-minted id would therefore name a row that does not exist on every overwrite. The
/// second write below mints a fresh id and the event still addresses the same bundle.
#[tokio::test]
async fn setting_a_locale_bundle_emits_an_event_addressed_by_tag() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let envelope = ironauth_store::event_catalog::envelope(
        "evt_locale_set",
        "locale_bundle.set",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({ "tag": "fr" }),
    )
    .expect("locale_bundle.set is registered");
    let domain_event = ironauth_store::DomainEvent {
        id: "evt_locale_set",
        subject: "fr",
        envelope: &envelope,
    };

    let first = LocaleBundleId::generate(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .locale_bundles()
        .set_with_event(
            &env,
            &first,
            1_000_000,
            set_locale("fr", true, FR_ENTRIES),
            Some(&domain_event),
        )
        .await
        .expect("set bundle");

    // Claimed as MESSAGES rather than payloads, because completing the first is what
    // releases its ordering key for the overwrite below.
    let claimed = claim_messages(&db, scope).await;
    assert_eq!(claimed.len(), 1, "the set enqueues exactly one event");
    assert_eq!(claimed[0].payload["type"], "locale_bundle.set");
    assert_eq!(claimed[0].payload["tag"], serde_json::Value::Null);
    assert_eq!(claimed[0].payload["payload"]["tag"], "fr");
    ironauth_store::event_catalog::validate_event(&claimed[0].payload)
        .expect("the envelope validates against the registry the fan-out enforces");

    // THE OVERWRITE: a DIFFERENT minted id, the same tag. The event still addresses the
    // bundle that exists, which a payload carrying the caller's id could not do.
    //
    // A FRESH event id, as a real producer mints per emit: the outbox is unique on
    // (tenant, environment, consumer, idempotency_key) and the key IS the event id, so
    // reusing it is refused by the queue rather than silently duplicated.
    let second_envelope = ironauth_store::event_catalog::envelope(
        "evt_locale_set_again",
        "locale_bundle.set",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        2,
        &serde_json::json!({ "tag": "fr" }),
    )
    .expect("locale_bundle.set is registered");
    let second_event = ironauth_store::DomainEvent {
        id: "evt_locale_set_again",
        subject: "fr",
        envelope: &second_envelope,
    };
    let second = LocaleBundleId::generate(&env, &scope);
    assert_ne!(first, second, "the fixture must mint a distinct id");
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .locale_bundles()
        .set_with_event(
            &env,
            &second,
            2_000_000,
            set_locale("fr", true, FR_ENTRIES),
            Some(&second_event),
        )
        .await
        .expect("overwrite bundle");

    // The overwrite is NOT deliverable yet, and that is the subject choice working: both
    // events carry the tag as their ordering key, and the outbox refuses to hand out a
    // message whose predecessor on the same key is still outstanding. A consumer therefore
    // cannot see the second state of a bundle before the first.
    assert!(
        queued_events(&db, scope).await.is_empty(),
        "the overwrite must wait behind the set it follows on the same tag"
    );

    // Complete the first, and the second becomes available -- in order.
    for message in &claimed {
        db.store()
            .scoped(scope)
            .outbox()
            .complete(&env, message)
            .await
            .expect("complete the first");
    }
    let after = queued_events(&db, scope).await;
    assert_eq!(
        after.len(),
        1,
        "the overwrite announces itself once released"
    );
    assert_eq!(after[0]["payload"]["tag"], "fr");
}

/// Claim the webhook consumer's outstanding messages, keeping the HANDLES so a caller can
/// complete them (which is what releases an ordering key for the next message on it).
async fn claim_messages(
    db: &TestDatabase,
    scope: ironauth_store::Scope,
) -> Vec<ironauth_store::OutboxMessage> {
    use std::time::Duration;

    db.store()
        .scoped(scope)
        .outbox()
        .claim(
            &Env::system(),
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim webhook events")
}
