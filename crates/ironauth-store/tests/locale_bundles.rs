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
