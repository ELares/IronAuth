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
use ironauth_store::{
    BrandAssetKind, BrandId, CorrelationId, NewBrand, NewBrandAsset, export_snapshot,
    validate_document,
};

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
        host_pattern: None,
        client_id: None,
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
async fn a_brand_with_selection_and_an_asset_round_trips_through_a_snapshot() {
    // Issue #86, PR 3 (AC #4): a brand carrying a host_pattern + client_id + an installed asset
    // (metadata only) round-trips export -> validate byte-identically, and a re-export is
    // byte-identical. The asset BYTES stay in the store (by-reference in the snapshot).
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    // A brand with per-domain AND per-client selection set.
    let id = BrandId::generate(&env, &scope);
    let brand = NewBrand {
        slug: "acme",
        is_default: true,
        product_name: "Acme",
        show_wordmark: true,
        brand_token: None,
        tokens_json: TOKENS_JSON,
        tokens_dark_json: None,
        slots_json: SLOTS_JSON,
        host_pattern: Some("login.acme.test"),
        client_id: Some("cli_acme"),
    };
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brands()
        .set(&env, &id, 1_000_000, brand)
        .await
        .expect("set brand with selection");

    // Upload a PNG logo asset (the bytes ride the store; the metadata rides the snapshot).
    let png_bytes = [
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x01, 0x02, 0x03,
    ];
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brand_assets()
        .set(
            &env,
            &id,
            2_000_000,
            NewBrandAsset {
                brand_slug: "acme",
                kind: BrandAssetKind::Logo,
                content_type: "image/png",
                bytes: &png_bytes,
                sha256: "abc123",
                size_bytes: 11,
            },
        )
        .await
        .expect("upload logo asset");

    // Export: the brand carries its selection fields and the asset metadata by reference.
    let snapshot = export_snapshot(&control.scoped(scope))
        .await
        .expect("export snapshot");
    assert_eq!(snapshot.resources.brand.len(), 1);
    let exported = &snapshot.resources.brand[0];
    assert_eq!(exported.host_pattern.as_deref(), Some("login.acme.test"));
    assert_eq!(exported.client_id.as_deref(), Some("cli_acme"));
    assert_eq!(exported.assets.len(), 1, "one asset metadata carried");
    assert_eq!(exported.assets[0].kind, "logo");
    assert_eq!(exported.assets[0].content_type, "image/png");
    assert_eq!(exported.assets[0].sha256, "abc123");
    assert_eq!(exported.assets[0].size_bytes, 11);

    // The exported bytes validate, and a re-export is byte-identical (deterministic).
    let bytes = snapshot.to_canonical_bytes().expect("canonical bytes");
    validate_document(&bytes).expect("the exported brand must validate");
    let again = export_snapshot(&control.scoped(scope))
        .await
        .expect("re-export")
        .to_canonical_bytes()
        .expect("canonical bytes");
    assert_eq!(bytes, again, "a re-export is byte-identical");
}

#[tokio::test]
async fn a_brand_asset_reads_back_on_the_data_plane_and_deletes() {
    // Issue #86, PR 3: an asset uploaded on the control plane reads back on the data-plane role
    // (the serve read), and a delete removes it (a subsequent read is absent).
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();
    let app = db.store();

    let id = BrandId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brands()
        .set(&env, &id, 1_000_000, set_brand("acme", true, "Acme"))
        .await
        .expect("set brand");

    let favicon_bytes = [0x00, 0x00, 0x01, 0x00, 0x10, 0x20];
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brand_assets()
        .set(
            &env,
            &id,
            2_000_000,
            NewBrandAsset {
                brand_slug: "acme",
                kind: BrandAssetKind::Favicon,
                content_type: "image/x-icon",
                bytes: &favicon_bytes,
                sha256: "deadbeef",
                size_bytes: 6,
            },
        )
        .await
        .expect("upload favicon");

    // The DATA-plane role reads the serve projection (sniffed type, bytes, sha256).
    let record = app
        .scoped(scope)
        .brands()
        .get_asset("acme", BrandAssetKind::Favicon)
        .await
        .expect("read asset")
        .expect("asset exists");
    assert_eq!(record.content_type, "image/x-icon");
    assert_eq!(record.bytes, favicon_bytes.to_vec());
    assert_eq!(record.sha256, "deadbeef");

    // Delete removes it (audited); a subsequent read is absent.
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brand_assets()
        .delete(&env, &id, "acme", BrandAssetKind::Favicon)
        .await
        .expect("delete asset");
    assert!(
        app.scoped(scope)
            .brands()
            .get_asset("acme", BrandAssetKind::Favicon)
            .await
            .expect("read after delete")
            .is_none(),
        "the asset is gone after delete"
    );
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

#[tokio::test]
async fn two_brands_cannot_claim_the_same_host_after_canonicalization() {
    // Issue #86, PR 3: the per-scope unique index on host_pattern is the routing-confusion
    // structural defense. Because the store canonicalizes host_pattern at ingest, two brands whose
    // host patterns differ only in case or port (both canonicalizing to "acme.test") cannot both
    // claim it in one scope: the second set is a unique violation, and the stored form is the
    // canonical one the selection matcher compares against.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let brand = |slug: &'static str, host: &'static str| NewBrand {
        slug,
        is_default: false,
        product_name: "Acme",
        show_wordmark: true,
        brand_token: None,
        tokens_json: TOKENS_JSON,
        tokens_dark_json: None,
        slots_json: SLOTS_JSON,
        host_pattern: Some(host),
        client_id: None,
    };

    let id_a = BrandId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brands()
        .set(&env, &id_a, 1_000_000, brand("acme", "acme.test"))
        .await
        .expect("the first brand claims acme.test");

    // A DIFFERENT slug whose host_pattern canonicalizes to the SAME "acme.test".
    let id_b = BrandId::generate(&env, &scope);
    let collision = control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brands()
        .set(&env, &id_b, 2_000_000, brand("beta", "ACME.test:443"))
        .await;
    assert!(
        collision.is_err(),
        "a second brand cannot claim the same canonical host"
    );

    // The stored host is the canonical form, matching what the selection matcher normalizes to.
    let stored = control
        .scoped(scope)
        .brands()
        .get("acme")
        .await
        .expect("get brand")
        .expect("brand present");
    assert_eq!(stored.host_pattern.as_deref(), Some("acme.test"));
}

/// Deleting a brand asset emits `brand_asset.deleted`, naming WHICH asset (issue #108).
///
/// A brand asset is addressed by (brand slug, kind) -- there is one logo and one favicon per
/// brand -- so both are needed to say what went. A receiver mirroring the hosted pages has to
/// know whether the favicon or the logo disappeared; either field alone identifies nothing it
/// could act on.
#[tokio::test]
async fn deleting_a_brand_asset_emits_the_registered_event_naming_the_kind() {
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
        .expect("set brand");

    let png_bytes = [
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x01, 0x02, 0x03,
    ];
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brand_assets()
        .set(
            &env,
            &id,
            2_000_000,
            NewBrandAsset {
                brand_slug: "acme",
                kind: BrandAssetKind::Logo,
                content_type: "image/png",
                bytes: &png_bytes,
                sha256: "abc123",
                size_bytes: 11,
            },
        )
        .await
        .expect("upload logo asset");

    assert_eq!(
        queued_events(&db, scope).await.len(),
        0,
        "this upload passed no event, so the delete's event below is unambiguous. Uploads DO \
         announce themselves now (`brand_asset.set`); what stays silent is the un-suffixed \
         `set`, which is the paired-negative guarantee"
    );

    let envelope = ironauth_store::event_catalog::envelope(
        "evt_brand_asset_deleted",
        "brand_asset.deleted",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({
            "brand_id": id.to_string(),
            "brand_slug": "acme",
            "kind": "logo",
        }),
    )
    .expect("brand_asset.deleted is registered");

    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brand_assets()
        .delete_with_event(
            &env,
            &id,
            "acme",
            BrandAssetKind::Logo,
            Some(&ironauth_store::DomainEvent {
                id: "evt_brand_asset_deleted",
                subject: &id.to_string(),
                envelope: &envelope,
            }),
        )
        .await
        .expect("delete with event");

    let events = queued_events(&db, scope).await;
    assert_eq!(events.len(), 1, "the delete enqueues exactly one event");
    assert_eq!(events[0]["type"], "brand_asset.deleted");
    assert_eq!(
        events[0]["payload"]["kind"], "logo",
        "the KIND says which asset went; the brand alone would not"
    );
    assert_eq!(events[0]["payload"]["brand_slug"], "acme");
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the envelope validates against the registry the fan-out enforces");
}

/// A delete carrying no event enqueues nothing.
#[tokio::test]
async fn deleting_a_brand_asset_without_an_event_enqueues_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();
    let id = BrandId::generate(&env, &scope);

    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brands()
        .set(&env, &id, 1_000_000, set_brand("quiet", true, "Quiet"))
        .await
        .expect("set brand");

    let png_bytes = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brand_assets()
        .set(
            &env,
            &id,
            2_000_000,
            NewBrandAsset {
                brand_slug: "quiet",
                kind: BrandAssetKind::Favicon,
                content_type: "image/png",
                bytes: &png_bytes,
                sha256: "def456",
                size_bytes: 8,
            },
        )
        .await
        .expect("upload favicon");

    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brand_assets()
        .delete(&env, &id, "quiet", BrandAssetKind::Favicon)
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

/// An asset upload emits `brand_asset.set`, carrying the digest but never the bytes.
///
/// SET rather than created-or-updated: the write is an upsert (one asset per brand and kind),
/// so distinguishing the two would need the store to read the row back first, and a receiver
/// acts identically either way by refetching.
///
/// The sha256 is the reason this carries more than the ids -- a consumer can decide whether
/// the bytes it cached are stale without refetching them. The BYTES are asserted absent: a
/// webhook is not a CDN, and an image on every subscriber's queue would dwarf every other
/// event in the system.
#[tokio::test]
async fn uploading_a_brand_asset_emits_the_digest_and_never_the_bytes() {
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
        .expect("set brand");

    // A recognisable byte pattern, so "the bytes are not on the wire" is a real assertion
    // rather than one that would pass for any payload.
    let png_bytes = [
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xDE, 0xAD, 0xBE, 0xEF,
    ];
    let envelope = ironauth_store::event_catalog::envelope(
        "evt_brand_asset_set",
        "brand_asset.set",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({
            "brand_id": id.to_string(),
            "brand_slug": "acme",
            "kind": "logo",
            "sha256": "sha-of-the-logo",
        }),
    )
    .expect("brand_asset.set is registered");
    let subject = id.to_string();
    let domain_event = ironauth_store::DomainEvent {
        id: "evt_brand_asset_set",
        subject: &subject,
        envelope: &envelope,
    };

    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brand_assets()
        .set_with_event(
            &env,
            &id,
            2_000_000,
            NewBrandAsset {
                brand_slug: "acme",
                kind: BrandAssetKind::Logo,
                content_type: "image/png",
                bytes: &png_bytes,
                sha256: "sha-of-the-logo",
                size_bytes: 12,
            },
            Some(&domain_event),
        )
        .await
        .expect("upload logo asset");

    let events = queued_events(&db, scope).await;
    assert_eq!(events.len(), 1, "the upload enqueues exactly one event");
    assert_eq!(events[0]["type"], "brand_asset.set");
    assert_eq!(events[0]["payload"]["kind"], "logo");
    assert_eq!(events[0]["payload"]["sha256"], "sha-of-the-logo");
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the envelope validates against the registry the fan-out enforces");

    // The image itself never reaches a subscriber's queue.
    let rendered = events[0].to_string();
    assert!(
        !rendered.contains("deadbeef") && !rendered.contains("DEADBEEF"),
        "the event carried the asset BYTES: {rendered}"
    );
    assert!(
        !rendered.contains("iVBORw0K"),
        "the event carried the asset bytes base64-encoded: {rendered}"
    );
}

/// Everything queued in `scope`, claimed AND completed, so a caller can drain twice.
///
/// [`queued_events`] leaves what it claims in flight, which is right for a one-shot count and
/// wrong here: both brand events share the slug as their ordering key, and a second event on
/// one key is not claimable until the first completes.
async fn drain_events(db: &TestDatabase, scope: ironauth_store::Scope) -> Vec<serde_json::Value> {
    use std::time::Duration;

    let env = Env::system();
    let claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim webhook events");
    for message in &claimed {
        db.store()
            .scoped(scope)
            .outbox()
            .complete(&env, message)
            .await
            .expect("complete");
    }
    claimed.into_iter().map(|message| message.payload).collect()
}

/// Setting and deleting a brand emit distinct types, carrying the identity but not the
/// design document, and a delete of nothing announces nothing.
///
/// A brand is what an end user SEES at the login surface, so a consumer mirroring branding
/// needs both transitions. What it does not need is the tokens, the slots, or the host
/// pattern: those are a config document rather than a fact, and a document on the wire is one
/// every consumer then has to version. The test asserts their ABSENCE.
///
/// `is_default` is the exception and travels, because flipping it changes which brand serves
/// a request that matched no other -- something a consumer cannot learn by re-reading only
/// the brand it was told about.
#[tokio::test]
async fn setting_and_deleting_a_brand_emit_distinct_types() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();
    let id = BrandId::generate(&env, &scope);

    let set = ironauth_store::event_catalog::envelope(
        "evt_brand_set",
        "brand.set",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({
            "brand_id": id.to_string(),
            "brand_slug": "acme",
            "is_default": true,
        }),
    )
    .expect("brand.set is registered");

    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brands()
        .set_with_event(
            &env,
            &id,
            1_000_000,
            set_brand("acme", true, "Acme"),
            Some(&ironauth_store::DomainEvent {
                id: "evt_brand_set",
                subject: "acme",
                envelope: &set,
            }),
        )
        .await
        .expect("set the brand");

    let created = drain_events(&db, scope).await;
    assert_eq!(created.len(), 1, "the set announced {created:?}");
    assert_eq!(created[0]["type"], "brand.set");
    assert_eq!(created[0]["payload"]["brand_slug"], "acme");
    assert_eq!(
        created[0]["payload"]["is_default"], true,
        "the default flag changes which brand serves an unmatched request, so it travels"
    );
    let rendered = serde_json::to_string(&created[0]).expect("json");
    assert!(
        !rendered.contains("color_accent") && !rendered.contains("footer_legal"),
        "the design document reached the wire; a document there is one every consumer has \
         to version: {rendered}"
    );

    let deleted = ironauth_store::event_catalog::envelope(
        "evt_brand_deleted",
        "brand.deleted",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        2,
        &serde_json::json!({ "brand_id": id.to_string(), "brand_slug": "acme" }),
    )
    .expect("brand.deleted is registered");

    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brands()
        .delete_with_event(
            &env,
            &id,
            "acme",
            Some(&ironauth_store::DomainEvent {
                id: "evt_brand_deleted",
                subject: "acme",
                envelope: &deleted,
            }),
        )
        .await
        .expect("delete the brand");

    let removed = drain_events(&db, scope).await;
    assert_eq!(removed.len(), 1, "the delete announced {removed:?}");
    assert_eq!(
        removed[0]["type"], "brand.deleted",
        "the delete takes the brand's ASSETS with it, so a consumer told nothing would keep \
         serving logos from a brand that no longer exists"
    );
    assert_eq!(removed[0]["payload"]["brand_id"], id.to_string());

    // The guard sits before the enqueue: deleting what is already gone destroys nothing,
    // records no audit row, and announces nothing.
    let repeat = ironauth_store::event_catalog::envelope(
        "evt_brand_deleted_again",
        "brand.deleted",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        3,
        &serde_json::json!({ "brand_id": id.to_string(), "brand_slug": "acme" }),
    )
    .expect("brand.deleted is registered");
    let error = control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .brands()
        .delete_with_event(
            &env,
            &id,
            "acme",
            Some(&ironauth_store::DomainEvent {
                id: "evt_brand_deleted_again",
                subject: "acme",
                envelope: &repeat,
            }),
        )
        .await
        .expect_err("an already-deleted brand is not found");
    assert!(
        matches!(error, ironauth_store::StoreError::NotFound),
        "got {error:?}"
    );
    let quiet = drain_events(&db, scope).await;
    assert!(
        quiet.is_empty(),
        "a delete that destroyed nothing must announce nothing: {quiet:?}"
    );
}
