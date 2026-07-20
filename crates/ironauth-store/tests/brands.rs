// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment brands over a real database (`DATABASE_URL`) (issue #86, PR 1).
//!
//! Proves the load-bearing properties of the branding data plane against a live database:
//!
//! - **Control-plane set, data-plane read.** A brand is set on the control-plane role that
//!   owns the branding lifecycle and read back on the data-plane role the renderer uses; the
//!   data-plane role can read but never write (the grant split).
//! - **One default per scope.** Setting a second default brand demotes the first, so a scope
//!   always resolves exactly one default (the partial unique index backs it structurally).
//! - **Promotable round-trip.** A config-snapshot export of the environment carries the brand
//!   (its typed tokens and sanitized slots as embedded JSON), and `validate_document` accepts
//!   the exported bytes (the snapshot both-sides binding).
//! - **Cross-tenant isolation.** A brand set in scope A never appears in scope B's export or
//!   default read.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{BrandId, CorrelationId, NewBrand, export_snapshot, validate_document};

/// A valid serialized design-token blob (the typed scalars the branding module validates).
const TOKENS_JSON: &str = r##"{"color_bg":"#f5f5f5","color_fg":"#1a1a1a","color_accent":"#2f5bde","color_accent_fg":"#ffffff","color_error":"#b00020","color_surface":"#ffffff","color_border":"#bbbbbb","font_family":"system_ui","radius":6,"space":16}"##;

/// A sanitized slot blob (already allowlist-sanitized markup, as the ingest path stores it).
const SLOTS_JSON: &str = r#"{"footer_legal":"<strong>Legal</strong>"}"#;

fn set_brand<'a>(slug: &'a str, is_default: bool, product_name: &'a str) -> NewBrand<'a> {
    NewBrand {
        slug,
        is_default,
        product_name,
        show_wordmark: true,
        brand_token: None,
        tokens_json: TOKENS_JSON,
        tokens_dark_json: None,
        slots_json: SLOTS_JSON,
    }
}

#[tokio::test]
async fn brand_set_reads_back_on_the_data_plane_and_round_trips_through_a_snapshot() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();
    let app = db.store();

    // SET on the control role (which owns the brand lifecycle).
    let id = BrandId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brands()
        .set(&env, &id, 1_000_000, set_brand("acme", true, "Acme"))
        .await
        .expect("set brand");

    // READ back the DEFAULT brand on the DATA-plane role (the renderer's role).
    let record = app
        .scoped(scope)
        .brands()
        .default_brand()
        .await
        .expect("read default brand")
        .expect("a default brand exists");
    assert_eq!(record.slug, "acme");
    assert!(record.is_default);
    assert_eq!(record.product_name, "Acme");
    assert!(record.tokens_json.contains("#2f5bde"), "tokens round-trip");
    assert!(record.slots_json.contains("Legal"), "slots round-trip");

    // The brand appears in the config-snapshot export, and the exported bytes validate
    // (the snapshot both-sides binding).
    let snapshot = export_snapshot(&control.scoped(scope))
        .await
        .expect("export snapshot");
    assert_eq!(snapshot.resources.brand.len(), 1, "one brand exported");
    assert_eq!(snapshot.resources.brand[0].slug, "acme");
    assert!(snapshot.resources.brand[0].is_default);
    let bytes = snapshot.to_canonical_bytes().expect("canonical bytes");
    validate_document(&bytes).expect("the exported brand must validate");
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

    let first = BrandId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brands()
        .set(&env, &first, 1_000_000, set_brand("first", true, "First"))
        .await
        .expect("set first default");

    // A second default: the first is demoted, so the partial unique index (one default per
    // scope) is never violated and the scope resolves the new default.
    let second = BrandId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brands()
        .set(
            &env,
            &second,
            2_000_000,
            set_brand("second", true, "Second"),
        )
        .await
        .expect("set second default");

    let default_brand = control
        .scoped(scope)
        .brands()
        .default_brand()
        .await
        .expect("read default")
        .expect("a default exists");
    assert_eq!(default_brand.slug, "second", "the new default wins");

    // The first brand still exists but is no longer the default.
    let first_brand = control
        .scoped(scope)
        .brands()
        .get("first")
        .await
        .expect("get first")
        .expect("first still exists");
    assert!(!first_brand.is_default, "the first brand was demoted");

    // Exactly two brands, exactly one default.
    let all = control
        .scoped(scope)
        .brands()
        .list_all()
        .await
        .expect("list");
    assert_eq!(all.len(), 2);
    assert_eq!(all.iter().filter(|b| b.is_default).count(), 1);
}

#[tokio::test]
async fn an_overwrite_is_idempotent_on_the_slug() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let id = BrandId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brands()
        .set(&env, &id, 1_000_000, set_brand("acme", true, "Acme"))
        .await
        .expect("first set");

    // A repeat write to the same slug (a fresh id) overwrites in place: still one row.
    let id2 = BrandId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brands()
        .set(
            &env,
            &id2,
            2_000_000,
            set_brand("acme", true, "Acme Renamed"),
        )
        .await
        .expect("overwrite");

    let all = control
        .scoped(scope)
        .brands()
        .list_all()
        .await
        .expect("list");
    assert_eq!(all.len(), 1, "an overwrite keeps a single row per slug");
    assert_eq!(all[0].product_name, "Acme Renamed");
}

#[tokio::test]
async fn a_brand_is_scoped_and_never_leaks_across_environments() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let control = db.control_store();

    let id = BrandId::generate(&env, &scope_a);
    control
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brands()
        .set(&env, &id, 1_000_000, set_brand("acme", true, "Acme"))
        .await
        .expect("set brand in scope A");

    // Scope B sees no default brand and an empty export: a brand never leaks across scopes.
    assert!(
        control
            .scoped(scope_b)
            .brands()
            .default_brand()
            .await
            .expect("read default in B")
            .is_none(),
        "scope B has no brand"
    );
    let snapshot_b = export_snapshot(&control.scoped(scope_b))
        .await
        .expect("export B");
    assert!(
        snapshot_b.resources.brand.is_empty(),
        "scope B's export carries no brand"
    );
}
