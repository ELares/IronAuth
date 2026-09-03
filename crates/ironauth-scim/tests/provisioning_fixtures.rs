// SPDX-License-Identifier: MIT OR Apache-2.0

//! Replaying provisioning traffic through the SCIM parsers (issue #135, criteria 1 and 2).
//!
//! # What a green run here means, and what it does not
//!
//! `tests/fixtures/PROVENANCE.md` says it plainly and this header repeats it because a test
//! file is where somebody will look: these bodies are DERIVED FROM SPECIFICATIONS AND VENDOR
//! DOCUMENTATION, not captured from a live tenant. A green run means the parsers accept the
//! shapes the specs describe. It does NOT mean they accept what Okta and Entra actually send.
//!
//! That gap is the whole reason issue #135 asks for recorded traffic: a fixture the
//! implementer writes proves the parser agrees with the implementer. This suite is therefore
//! the HARNESS, ready for real captures, plus a spec-derived corpus that is worth having in
//! the meantime because it catches shape regressions.
//!
//! The harness is deliberately data-driven: a real capture is dropped in as a file, with no
//! test code to change.
//!
//! # Every fixture is REPLAYED, not just parsed
//!
//! An audit caught this file doing far less than its name: it fed the `path`, `patch_path` and
//! `filter` STRINGS to three parsers and never read the `body` key at all, which five of the
//! seven fixtures carry. It passed in 0.00s with no database, which was the tell. A corpus
//! whose request bodies nothing executes is a corpus that cannot fail for any reason a
//! provisioning client would notice.
//!
//! So each fixture now declares `expect_status`, and `every_fixture_replays_against_the_real_
//! surface` drives its method, path and body through `scim_router` against a real database and
//! holds the server to that number. The placeholder ids in the corpus (`usr_...`, `grp_...`)
//! are substituted for the seeded ones at replay time, which is what keeps a fixture a
//! verbatim-ish document rather than something the harness has to be taught about.
//!
//! An `expect_status` of 400 is a STATED GAP, not a pass -- and `entra_enterprise_user` was
//! the one that carried it, recording that the enterprise extension was published in the schema
//! document and not parsed onto the resource. It expects 200 now: the extension is parsed and
//! stored per organization (migration 0187).
//!
//! Worth keeping in view, because a review caught it: the fixture NAMED FOR the extension was
//! asserting the extension was refused, and the suite passed. A criterion can stay unmet
//! indefinitely while the suite that exists to measure it is green, if the number it holds the
//! server to is the number the defect produces.

use std::fs;
use std::path::Path;

use ironauth_scim::{Filter, parse_filter, parse_patch_path, parse_resource_path};
use serde_json::Value;

/// Every fixture in the directory, so a file added and never wired up is impossible.
fn fixtures() -> Vec<(String, Value)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).expect("the fixture directory exists") {
        let path = entry.expect("a directory entry").path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let name = path
                .file_name()
                .expect("a file name")
                .to_string_lossy()
                .into_owned();
            let text = fs::read_to_string(&path).expect("readable fixture");
            let value: Value = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{name} is not valid JSON: {error}"));
            out.push((name, value));
        }
    }
    out.sort_by(|left, right| left.0.cmp(&right.0));
    out
}

/// Every fixture states where it came from.
///
/// The provenance IS the finding here. A fixture with no stated source is one somebody will
/// later mistake for a capture, and the difference between "the parser agrees with the spec"
/// and "the parser agrees with Okta" is the entire value of this suite.
#[test]
fn every_fixture_states_its_provenance() {
    let all = fixtures();
    assert!(!all.is_empty(), "the fixture directory is not empty");
    for (name, fixture) in all {
        let source = fixture
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(
            !source.trim().is_empty(),
            "{name} must state where it came from"
        );
    }
}

/// Every fixture's resource path parses, and to the collection it names.
#[test]
fn every_fixture_path_parses() {
    let mut seen_collection = 0_usize;
    let mut seen_resource = 0_usize;
    for (name, fixture) in fixtures() {
        let Some(path) = fixture.get("path").and_then(Value::as_str) else {
            continue;
        };
        let parsed = parse_resource_path(path)
            .unwrap_or_else(|error| panic!("{name}: {path:?} must parse: {error}"));
        // A create posts to the collection and everything else addresses a resource, which is
        // the difference the id carries. Asserting only "it parsed" would pass on a parser
        // that dropped the id entirely.
        let expects_id = fixture.get("method").and_then(Value::as_str) != Some("POST")
            && fixture.get("method").and_then(Value::as_str) != Some("GET");
        assert_eq!(
            parsed.id().is_some(),
            expects_id,
            "{name}: {path:?} addresses the wrong thing"
        );
        if expects_id {
            seen_resource += 1;
        } else {
            seen_collection += 1;
        }
    }
    // The guard the loop needs to mean anything. Every `continue` above is silent, so a
    // corpus that lost its `path` keys, or a `fixtures()` that returned nothing, would run
    // zero iterations and report success. Both SHAPES are required, not just a nonzero
    // count: a corpus of only collection paths would never exercise the id branch, which is
    // the half that distinguishes `/Users` from `/Users/usr_a`.
    assert!(
        seen_collection > 0,
        "at least one fixture addresses a collection"
    );
    assert!(
        seen_resource > 0,
        "at least one fixture addresses an individual resource"
    );
}

/// Every fixture's PATCH path parses, including both provisioning dialects.
#[test]
fn every_fixture_patch_path_parses() {
    let mut seen_selector = false;
    let mut seen_bare = false;
    for (name, fixture) in fixtures() {
        let Some(path) = fixture.get("patch_path").and_then(Value::as_str) else {
            continue;
        };
        let parsed = parse_patch_path(path)
            .unwrap_or_else(|error| panic!("{name}: {path:?} must parse: {error:?}"));
        if parsed.selector().is_some() {
            seen_selector = true;
        } else {
            seen_bare = true;
        }
    }
    // BOTH dialects are actually exercised. Without this the suite could pass having only
    // ever seen one of them, which is how a dialect stops being covered without anyone
    // editing a test.
    assert!(
        seen_selector,
        "the Okta dialect (a filtered path) is covered"
    );
    assert!(seen_bare, "the Entra dialect (a bare path) is covered");
}

/// Every fixture's filter parses.
#[test]
fn every_fixture_filter_parses() {
    let mut checked = 0;
    let mut seen_value_path = false;
    for (name, fixture) in fixtures() {
        let Some(filter) = fixture.get("filter").and_then(Value::as_str) else {
            continue;
        };
        let parsed = parse_filter(filter)
            .unwrap_or_else(|error| panic!("{name}: {filter:?} must parse: {error}"));
        if matches!(parsed, Filter::ValuePath { .. }) {
            seen_value_path = true;
        }
        checked += 1;
    }
    assert!(checked > 0, "at least one fixture exercises a filter");
    // The bracketed form specifically. It is the one a server can omit and still pass every
    // simple-filter test while refusing what Okta and Entra actually send, so the corpus has
    // to hold one and this has to notice if it goes away.
    assert!(
        seen_value_path,
        "the corpus exercises a valuePath filter (RFC 7644 section 3.4.2.2)"
    );
}

/// The corpus covers the operations criterion 1 enumerates.
///
/// Pinned by NAME rather than by counting files, so adding a fixture does not make this pass
/// while one of the operations the criterion names is quietly missing.
#[test]
fn the_corpus_covers_every_operation_the_criterion_names() {
    let names: Vec<String> = fixtures().into_iter().map(|(name, _)| name).collect();
    for required in [
        "okta_create_user.json",
        "okta_deactivate_user.json",
        "okta_group_membership.json",
        "entra_patch_dialect.json",
        "entra_enterprise_user.json",
        "okta_filter_lookup.json",
        "entra_value_path_filter.json",
    ] {
        assert!(
            names.iter().any(|name| name == required),
            "the corpus is missing {required}; it covers {names:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------
// THE REPLAY. Everything above this line reads strings; everything below executes requests.
// ---------------------------------------------------------------------------------------

/// The placeholder ids the corpus uses, substituted for real ones at replay time.
const USER_PLACEHOLDER: &str = "usr_2c9a8b";
const GROUP_PLACEHOLDER: &str = "grp_7f31";

#[tokio::test]
async fn every_fixture_replays_against_the_real_surface() {
    let (db, env, token) = seeded_connection().await;
    let _ = &token;
    replay_all(&db, &env, &token).await;
}

/// Seed a scope, an organization and a SCIM connection, returning the token that reaches them.
async fn seeded_connection() -> (
    ironauth_store::test_support::TestDatabase,
    ironauth_env::Env,
    String,
) {
    use ironauth_env::Env;
    use ironauth_scim::server::{digest_of, mint_token};
    use ironauth_store::test_support::TestDatabase;
    use ironauth_store::{CorrelationId, NewScimConnection, OrganizationId, ScimConnectionId};

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let now = i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64");

    let org = OrganizationId::generate(&env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .create(&env, &org, now, "Globex", None)
        .await
        .expect("create organization");
    let connection = ScimConnectionId::generate(&env, &scope);
    let token = mint_token(&connection, "s3cret-provisioning-material");
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .create(
            &env,
            NewScimConnection {
                id: &connection,
                organization_id: &org,
                display_name: "Okta production",
                provider: "okta",
                token_digest: &digest_of(&token),
                expires_at_unix_micros: None,
            },
            None,
        )
        .await
        .expect("create connection");
    (db, env, token)
}

/// Replay every fixture in the corpus against the real router.
async fn replay_all(
    db: &ironauth_store::test_support::TestDatabase,
    env: &ironauth_env::Env,
    token: &str,
) {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use ironauth_scim::ScimLimits;
    use ironauth_scim::server::{ScimState, scim_router};
    use tower::ServiceExt as _;

    let token = token.to_owned();
    let send = |method: String, path: String, body: Option<String>| {
        let token = token.clone();
        async move {
            let state = ScimState::new(
                db.store().clone(),
                env.clone(),
                ScimLimits::default(),
                ironauth_store::identifier::UniquenessMode::EnvironmentWide,
            );
            let builder = Request::builder()
                .method(method.as_str())
                .uri(path.as_str())
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/scim+json");
            let request = match body {
                Some(body) => builder.body(Body::from(body)),
                None => builder.body(Body::empty()),
            }
            .expect("request builds");
            let response = scim_router(state)
                .oneshot(request)
                .await
                .expect("router answers");
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .expect("body");
            (status, String::from_utf8_lossy(&bytes).into_owned())
        }
    };

    // Seed the two resources the corpus addresses, through the surface itself, so the replay
    // exercises the same doors a real sync would have used to create them.
    let (status, body) = send(
        "POST".to_owned(),
        "/scim/v2/Users".to_owned(),
        Some(r#"{"userName":"replay@example.test"}"#.to_owned()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let user_id = serde_json::from_str::<Value>(&body).expect("a resource")["id"]
        .as_str()
        .expect("an id")
        .to_owned();
    let (status, body) = send(
        "POST".to_owned(),
        "/scim/v2/Groups".to_owned(),
        Some(r#"{"displayName":"Replay Team"}"#.to_owned()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let group_id = serde_json::from_str::<Value>(&body).expect("a resource")["id"]
        .as_str()
        .expect("an id")
        .to_owned();

    let mut replayed = 0;
    for (name, fixture) in fixtures() {
        assert!(
            fixture.get("expect_status").is_some(),
            "{name} declares no expect_status; a fixture nothing holds the server to is a \
             fixture that cannot fail"
        );
        let method = fixture["method"].as_str().expect("a method").to_owned();
        // Substitution over the RENDERED text, so a placeholder is replaced wherever it
        // appears -- in the path and inside a member value alike.
        let swap = |text: &str| {
            text.replace(USER_PLACEHOLDER, &user_id)
                .replace(GROUP_PLACEHOLDER, &group_id)
        };
        let path = format!(
            "/scim/v2{}",
            swap(fixture["path"].as_str().expect("a path"))
        );
        let body = fixture
            .get("body")
            .map(|body| swap(&serde_json::to_string(body).expect("a body")));

        let (status, answer) = send(method.clone(), path.clone(), body).await;
        assert_replay(&name, &fixture, &method, &path, status.as_u16(), &answer);
        replayed += 1;
    }

    // A COUNT, so a corpus that silently stopped being walked is caught. `fixtures()` reads a
    // directory, and a directory that fails to read as expected would otherwise replay nothing
    // and pass.
    assert_eq!(
        replayed,
        fixtures().len(),
        "every fixture in the directory must have been replayed"
    );
    assert!(replayed >= 8, "the corpus must not have shrunk: {replayed}");
}

/// Hold one replayed fixture to what it declared.
fn assert_replay(name: &str, fixture: &Value, method: &str, path: &str, status: u16, answer: &str) {
    let expected = fixture["expect_status"].as_u64().expect("expect_status");
    let why = fixture
        .get("expect_why")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert_eq!(
        u64::from(status),
        expected,
        "{name}: {method} {path} -- {why}: {answer}"
    );
    // THE EFFECT, where the fixture declares one. A status alone cannot tell a deactivate that
    // worked from one that answered 200 and did nothing, which is the failure mode this whole
    // corpus exists to catch: with only statuses asserted, removing the Entra stringly-boolean
    // arm left every fixture green.
    let Some(fragments) = fixture.get("expect_body_contains") else {
        return;
    };
    let fragments = fragments
        .as_array()
        .unwrap_or_else(|| panic!("{name}: expect_body_contains must be an array"));
    // Compared against the body with whitespace squeezed out, so a fragment is written the way
    // a person reads JSON rather than the way serde happens to print it.
    let compact: String = answer.chars().filter(|c| !c.is_whitespace()).collect();
    for fragment in fragments {
        let fragment = fragment.as_str().expect("a string fragment");
        assert!(
            compact.contains(fragment),
            "{name}: {method} {path} answered {status} but not {fragment}: {answer}"
        );
    }
}
