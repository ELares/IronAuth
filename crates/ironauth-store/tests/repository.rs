// SPDX-License-Identifier: MIT OR Apache-2.0

//! Repository round-trip and non-recycling, against a real database.

use std::collections::HashSet;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewPolicyDecisionTrace, NewTokenSizeEvent, PolicyDecisionInputs,
    PolicyDecisionTraceQuery, PolicyKind, PolicyOutcome, PolicyTraceSignal, StoreError,
    TokenSizeKind,
};

#[tokio::test]
async fn create_get_list_delete_round_trip() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Reads need no actor; writes go through an acting context.
    let reader = db.store().scoped(scope).clients();
    let actor = db.test_actor(&env);
    let writer = db
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(&env))
        .clients();

    // Create returns a typed identifier that round-trips through the scoped
    // parser (the request-layer boundary).
    let id = writer.create(&env, "acme web").await.expect("create");
    let parsed = reader.parse_id(&id.to_string()).expect("parse in scope");
    assert_eq!(parsed, id);
    assert_eq!(id.scope(), scope, "the identifier embeds its scope");

    // Get.
    let record = reader.get(&id).await.expect("get");
    assert_eq!(record.id, id);
    assert_eq!(record.display_name, "acme web");

    // List.
    let all = reader.list().await.expect("list");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, id);

    // Delete, then the row is gone and the outcome is the uniform not-found.
    writer.delete(&env, &id).await.expect("delete");
    assert!(matches!(reader.get(&id).await, Err(StoreError::NotFound)));
    assert!(matches!(
        writer.delete(&env, &id).await,
        Err(StoreError::NotFound)
    ));
    assert!(reader.list().await.expect("list").is_empty());
}

#[tokio::test]
async fn identifiers_are_never_recycled_after_deletion() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let writer = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients();

    // Create then delete many; remember every identifier ever issued.
    let mut ever_issued = HashSet::new();
    for _ in 0..200 {
        let id = writer.create(&env, "ephemeral").await.expect("create");
        writer.delete(&env, &id).await.expect("delete");
        assert!(
            ever_issued.insert(id.to_string()),
            "an identifier was issued twice"
        );
    }

    // A fresh batch never collides with any deleted identifier: no serial
    // reuse, no recycled-identifier leakage.
    for _ in 0..200 {
        let id = writer.create(&env, "fresh").await.expect("create");
        assert!(
            !ever_issued.contains(&id.to_string()),
            "a deleted identifier was recycled"
        );
    }
}

/// A management list at the hard cap keeps its has-next sentinel: with
/// `HARD_CAP + 1` rows present, a fetch of `HARD_CAP + 1` (the page size at the
/// cap, plus one for the sentinel) returns all `HARD_CAP + 1`. Before the store
/// clamped the fetch to `HARD_CAP + 1` (rather than `HARD_CAP`), the sentinel was
/// dropped and the final page hidden.
#[tokio::test]
async fn management_list_at_the_hard_cap_keeps_the_has_next_sentinel() {
    use ironauth_store::{MANAGEMENT_LIST_HARD_CAP, ManagementKeyId};

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Insert HARD_CAP + 1 credentials as the owner (a superuser, so it bypasses
    // row-level security), in one bulk statement via UNNEST.
    let n = usize::try_from(MANAGEMENT_LIST_HARD_CAP).expect("cap fits usize") + 1;
    let ids: Vec<String> = (0..n)
        .map(|_| ManagementKeyId::generate(&env, &scope).to_string())
        .collect();
    let tenants = vec![scope.tenant().to_string(); n];
    let environments = vec![scope.environment().to_string(); n];
    let hashes: Vec<String> = (0..n).map(|i| format!("hash-{i}")).collect();
    let names: Vec<String> = (0..n).map(|i| format!("key-{i}")).collect();
    sqlx::query(
        "INSERT INTO management_credentials \
         (id, tenant_id, environment_id, key_hash, display_name) \
         SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[])",
    )
    .bind(ids)
    .bind(tenants)
    .bind(environments)
    .bind(hashes)
    .bind(names)
    .execute(db.owner_pool())
    .await
    .expect("bulk insert credentials");

    // The admin layer fetches page_size + 1; at a page size of HARD_CAP that is
    // HARD_CAP + 1. The store must return all of them (the extra row is the
    // sentinel that tells the admin layer a further page exists).
    let rows = db
        .control_store()
        .management()
        .credentials(scope)
        .list(MANAGEMENT_LIST_HARD_CAP + 1, None)
        .await
        .expect("list at the hard cap");
    assert_eq!(
        rows.len(),
        n,
        "the has-next sentinel survives at a page size equal to the hard cap"
    );
}

/// Scope-aware consent (issue #196): `granted_ref` returns the granted scope, and a
/// re-consent to a BROADER scope UPSERTs the scope in place, keeping the row's
/// ORIGINAL id rather than inserting a second row or dropping the broadened scope.
#[tokio::test]
async fn consent_grant_upserts_the_scope_and_keeps_the_original_id() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // The consents table keys on (subject, client_id) text with no FK to users or
    // clients, so literal ids exercise the grant/read contract directly.
    let subject = "usr_example-subject";
    let client_id = "cli_example-client";

    // A first consent for a NARROW scope records the granted scope and returns its id.
    let first = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid"))
        .await
        .expect("first grant");
    let recorded = db
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(subject, client_id)
        .await
        .expect("granted_ref read")
        .expect("a consent is recorded");
    assert_eq!(recorded.id, first.to_string(), "granted_ref returns the id");
    assert_eq!(
        recorded.granted_scope.as_deref(),
        Some("openid"),
        "granted_ref returns the granted scope"
    );

    // Re-consent to a BROADER scope UPDATEs granted_scope in place and returns the
    // ORIGINAL row id (the upsert keeps it), not a fresh id or a second row.
    let second = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid profile email"))
        .await
        .expect("re-grant");
    assert_eq!(
        second, first,
        "the upsert returns the original consent id on re-consent"
    );
    let updated = db
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(subject, client_id)
        .await
        .expect("granted_ref read")
        .expect("a consent is recorded");
    assert_eq!(
        updated.id,
        first.to_string(),
        "the row keeps its original id"
    );
    assert_eq!(
        updated.granted_scope.as_deref(),
        Some("openid profile email"),
        "the broadened scope is persisted rather than dropped"
    );
}

/// Re-consent audit attribution (issue #196): the `consent.grant` audit row's
/// `target_id` joins to the ACTUAL `consents` row on BOTH a first insert and a
/// scope-broadening re-consent. The upsert's UPDATE branch keeps the row's ORIGINAL
/// id, so a freshly generated (never-persisted) audit target would be a phantom an
/// investigator could not pivot from; this proves the audit target is the real id.
#[tokio::test]
async fn consent_grant_audit_target_joins_the_persisted_consent_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let subject = "usr_example-subject";
    let client_id = "cli_example-client";

    // A first consent (narrow), then a scope-BROADENING re-consent (the
    // security-relevant event): the second takes the upsert's UPDATE branch and keeps
    // the original id, which is exactly where a phantom audit target would show up.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid"))
        .await
        .expect("first grant");
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid profile email"))
        .await
        .expect("re-grant");

    // Exactly two consent.grant audit rows, and EACH one's target_id must join to a
    // real consents row (the broaden's target is NOT a phantom fresh id).
    let audit = db
        .store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit");
    let grants: Vec<_> = audit
        .iter()
        .filter(|row| row.action == "consent.grant")
        .collect();
    assert_eq!(
        grants.len(),
        2,
        "each grant writes exactly one consent.grant audit row"
    );
    for row in grants {
        assert_eq!(row.target_kind, "con", "the audit target is a consent id");
        let joined: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM consents \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(&row.target_id)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("count consents by audit target id");
        assert_eq!(
            joined, 1,
            "the consent.grant audit target_id ({}) joins to exactly one consents row",
            row.target_id
        );
    }

    // And the upsert updated in place: exactly ONE consents row exists, so the
    // broaden's audit target is the same row the first grant's target named.
    let consent_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM consents")
        .fetch_one(db.owner_pool())
        .await
        .expect("count consents");
    assert_eq!(
        consent_rows, 1,
        "the re-consent updated in place rather than inserting a second row"
    );
}

#[tokio::test]
async fn post_logout_redirect_uris_register_read_and_validate() {
    // RP-Initiated Logout (issue #33): a client's post_logout_redirect_uris are an
    // exact-match set the end_session endpoint checks against. Default empty, registered
    // wholesale, validated as registrable targets, and scope-fenced.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let reader = db.store().scoped(scope).clients();
    let writer = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .clients()
    };

    let id = writer()
        .create(&env, "logout client")
        .await
        .expect("create");

    // Default: a fresh client registers NO post-logout redirect URIs.
    let record = reader.get(&id).await.expect("get");
    assert!(
        record.post_logout_redirect_uris.is_empty(),
        "a fresh client has an empty post-logout redirect set"
    );

    // Register a set; it reads back verbatim (exact-string, no normalization).
    writer()
        .register_post_logout_redirect_uris(
            &env,
            &id,
            &["https://client.test/after", "https://client.test/home"],
        )
        .await
        .expect("register post-logout uris");
    let record = reader.get(&id).await.expect("get");
    assert_eq!(
        record.post_logout_redirect_uris,
        vec![
            "https://client.test/after".to_owned(),
            "https://client.test/home".to_owned()
        ],
        "the registered set reads back exactly"
    );

    // Re-registering REPLACES the set wholesale.
    writer()
        .register_post_logout_redirect_uris(&env, &id, &["https://client.test/only"])
        .await
        .expect("re-register");
    assert_eq!(
        reader
            .get(&id)
            .await
            .expect("get")
            .post_logout_redirect_uris,
        vec!["https://client.test/only".to_owned()]
    );

    // A malformed (non-registrable) target rejects the WHOLE set; nothing is stored.
    assert!(matches!(
        writer()
            .register_post_logout_redirect_uris(
                &env,
                &id,
                &["https://client.test/good", "javascript:alert(1)"]
            )
            .await,
        Err(StoreError::InvalidRedirectUri)
    ));
    assert_eq!(
        reader
            .get(&id)
            .await
            .expect("get")
            .post_logout_redirect_uris,
        vec!["https://client.test/only".to_owned()],
        "a rejected registration leaves the prior set untouched"
    );

    // A client id from another scope is the uniform not-found (never a cross-tenant write).
    let other_scope = db.seed_scope(&env).await;
    let foreign = db
        .store()
        .scoped(other_scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "other-tenant client")
        .await
        .expect("create foreign");
    assert!(matches!(
        writer()
            .register_post_logout_redirect_uris(&env, &foreign, &["https://client.test/x"])
            .await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn frontchannel_logout_register_read_and_validate() {
    // Front-Channel Logout (issue #39): a client's frontchannel_logout_uri and
    // session_required flag are the per-client opt-in the end_session flow reads.
    // Default absent, registered as one https URI, https-validated, clearable, and
    // scope-fenced.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let reader = db.store().scoped(scope).clients();
    let writer = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .clients()
    };

    let id = writer()
        .create(&env, "frontchannel client")
        .await
        .expect("create");

    // Default: a fresh client has registered no front-channel logout URI, and its
    // session_required flag is false.
    let record = reader.get(&id).await.expect("get");
    assert_eq!(record.frontchannel_logout_uri, None);
    assert!(!record.frontchannel_logout_session_required);

    // Register a URI with session_required; it reads back verbatim.
    writer()
        .register_frontchannel_logout(&env, &id, Some("https://rp.test/frontchannel"), true)
        .await
        .expect("register frontchannel logout");
    let record = reader.get(&id).await.expect("get");
    assert_eq!(
        record.frontchannel_logout_uri.as_deref(),
        Some("https://rp.test/frontchannel")
    );
    assert!(record.frontchannel_logout_session_required);

    // A non-https URI rejects the registration; the prior value is untouched.
    assert!(matches!(
        writer()
            .register_frontchannel_logout(&env, &id, Some("http://rp.test/insecure"), false)
            .await,
        Err(StoreError::InvalidRedirectUri)
    ));
    let record = reader.get(&id).await.expect("get");
    assert_eq!(
        record.frontchannel_logout_uri.as_deref(),
        Some("https://rp.test/frontchannel"),
        "a rejected registration leaves the prior value untouched"
    );

    // Security hardening (issue #89): the origin of a registered URI becomes a
    // frame-src source on the front-channel logout page, so an authority carrying a
    // space, a `;`, a control character, or userinfo (which could smuggle extra CSP
    // sources or directives) is refused BEFORE it is stored. The prior value stands.
    for smuggle in [
        "https://rp.test frame-src *",
        "https://rp.test;script-src 'unsafe-inline'",
        "https://rp.test\u{0009}/fc",
        "https://user:pass@rp.test/fc",
        "https://",
    ] {
        assert!(
            matches!(
                writer()
                    .register_frontchannel_logout(&env, &id, Some(smuggle), false)
                    .await,
                Err(StoreError::InvalidRedirectUri)
            ),
            "a malformed https authority is rejected: {smuggle:?}"
        );
    }
    let record = reader.get(&id).await.expect("get");
    assert_eq!(
        record.frontchannel_logout_uri.as_deref(),
        Some("https://rp.test/frontchannel"),
        "a rejected malformed registration leaves the prior value untouched"
    );

    // Passing None clears the registration wholesale.
    writer()
        .register_frontchannel_logout(&env, &id, None, false)
        .await
        .expect("clear frontchannel logout");
    let record = reader.get(&id).await.expect("get");
    assert_eq!(record.frontchannel_logout_uri, None);
    assert!(!record.frontchannel_logout_session_required);

    // A client id from another scope is the uniform not-found.
    let other_scope = db.seed_scope(&env).await;
    let foreign = db
        .store()
        .scoped(other_scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "other-tenant client")
        .await
        .expect("create foreign");
    assert!(matches!(
        writer()
            .register_frontchannel_logout(&env, &foreign, Some("https://rp.test/x"), false)
            .await,
        Err(StoreError::NotFound)
    ));
}

const TRACE_RETENTION_MICROS: i64 = 7 * 24 * 60 * 60 * 1_000_000;

#[tokio::test]
async fn policy_decision_traces_round_trip_and_filter() {
    // The M9 flow inspector sink (issue #91): record the three traced policy decisions and read
    // them back, newest first, filtered by policy and subject, with the redacted safe field
    // projection round-tripping through the jsonb column.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let traces = db.store().scoped(scope).policy_decision_traces();

    // A step up trace for one subject.
    traces
        .record(
            &env,
            TRACE_RETENTION_MICROS,
            &NewPolicyDecisionTrace {
                policy: PolicyKind::StepUp,
                subject: Some("usr_alice".to_owned()),
                outcome: PolicyOutcome::StepUpRequired,
                reason: Some("acr_unmet".to_owned()),
                inputs: PolicyDecisionInputs::StepUp {
                    required_acr: Some("urn:ironauth:acr:mfa".to_owned()),
                    achieved_acr: "urn:ironauth:acr:pwd".to_owned(),
                    max_auth_age_secs: Some(300),
                    auth_age_secs: Some(9000),
                    acr_unmet: true,
                    age_lapsed: false,
                },
            },
        )
        .await
        .expect("record step up trace");

    // A risk trace for the SAME subject, with enumerated signals.
    traces
        .record(
            &env,
            TRACE_RETENTION_MICROS,
            &NewPolicyDecisionTrace {
                policy: PolicyKind::Risk,
                subject: Some("usr_alice".to_owned()),
                outcome: PolicyOutcome::Deny,
                reason: Some("block".to_owned()),
                inputs: PolicyDecisionInputs::Risk {
                    level: "high".to_owned(),
                    signals: vec![PolicyTraceSignal {
                        name: "new_device".to_owned(),
                        level: "med".to_owned(),
                    }],
                },
            },
        )
        .await
        .expect("record risk trace");

    // A claim mapping trace for NO subject (evaluated before provisioning), another subject key.
    traces
        .record(
            &env,
            TRACE_RETENTION_MICROS,
            &NewPolicyDecisionTrace {
                policy: PolicyKind::ClaimMapping,
                subject: None,
                outcome: PolicyOutcome::Satisfied,
                reason: None,
                inputs: PolicyDecisionInputs::ClaimMapping {
                    connector: "octa".to_owned(),
                    mapped_trait_count: Some(3),
                    failure_kind: None,
                },
            },
        )
        .await
        .expect("record claim mapping trace");

    // Newest first over the whole scope: three rows, most recent (the claim mapping) first.
    let all = traces
        .query(PolicyDecisionTraceQuery {
            newest_first: true,
            ..Default::default()
        })
        .await
        .expect("query all");
    assert_eq!(all.len(), 3, "all three traces are readable");
    assert_eq!(all[0].policy, "claim_mapping", "newest first ordering");

    // Filter by policy narrows to the one risk trace, with its signals in the jsonb.
    let risk = traces
        .query(PolicyDecisionTraceQuery {
            policy: Some("risk"),
            newest_first: true,
            ..Default::default()
        })
        .await
        .expect("query risk");
    assert_eq!(risk.len(), 1, "the policy filter narrows to risk");
    assert_eq!(risk[0].outcome, "deny");
    assert!(
        risk[0].decision_inputs_json.contains("new_device"),
        "the redacted safe field projection round-trips through jsonb"
    );

    // Filter by subject narrows to the two traces bound to usr_alice (never the subjectless one).
    let alice = traces
        .query(PolicyDecisionTraceQuery {
            subject: Some("usr_alice"),
            ..Default::default()
        })
        .await
        .expect("query alice");
    assert_eq!(
        alice.len(),
        2,
        "the subject filter narrows to alice's traces"
    );
}

#[tokio::test]
async fn token_size_events_round_trip() {
    // The one materialized operational warning (issue #91): record two oversized token events and
    // read them back newest first for the M9 warnings read.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let events = db.store().scoped(scope).token_size_events();

    for byte_size in [4096_i64, 5120] {
        events
            .record(
                &env,
                TRACE_RETENTION_MICROS,
                NewTokenSizeEvent {
                    token_type: TokenSizeKind::IdToken,
                    byte_size,
                    claim_count: Some(40),
                    client_id: "cli_bloat",
                },
            )
            .await
            .expect("record token size event");
    }

    let recent = events.recent(50).await.expect("read recent");
    assert_eq!(recent.len(), 2, "both events are readable");
    assert!(
        recent.iter().all(|event| event.client_id == "cli_bloat"),
        "the events carry the non secret client id"
    );
    assert!(
        recent.iter().any(|event| event.byte_size == 5120),
        "the byte size round-trips"
    );
}
