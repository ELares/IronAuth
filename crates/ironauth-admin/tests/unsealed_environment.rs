// SPDX-License-Identifier: MIT OR Apache-2.0

//! Addressing an ABSENT user in a LIVE environment that has never sealed any PII is the
//! uniform not-found on every user-scoped route (issue #442).
//!
//! # What was measured
//!
//! A freshly created environment holds ZERO envelope keys. Nothing provisions them at
//! environment create: the KEK and DEK pair is minted lazily by the first write that
//! actually seals something, which is the right design and is not what this file
//! changes.
//!
//! `PUT .../users/{user_id}/external-id` seals its argument, so it resolved that key
//! BEFORE it looked the user up. In an environment with no key that resolution failed
//! and the failure rendered as an opaque `500`. The sharpest form of the defect is
//! that the SAME absent user, on the SAME resource, answered two different things
//! depending only on whether the verb happens to seal:
//!
//! ```text
//! PUT    .../users/{absent}/external-id  ->  500 {"error":"internal"}
//! DELETE .../users/{absent}/external-id  ->  404 {"error":"not_found"}
//! ```
//!
//! # Why the fix is ORDERING and not a new error mapping
//!
//! The issue offers three candidate answers: mint the key on demand, refuse with a typed
//! precondition, or answer the uniform not-found. The third is right, and the reason the
//! other two are not is that `StoreError::Encryption` deliberately COLLAPSES three
//! causes: no platform master key is wired, this scope has no envelope key, and a
//! ciphertext did not authenticate. Two of those are genuine faults. Any typed answer
//! given to the variant as a whole would therefore assert something false for them, and
//! a not-found in particular would tell an operator whose key management is misconfigured
//! that their user does not exist.
//!
//! So the addressing check is ordered AHEAD of the key resolution, inside the same
//! transaction and under the row lock. An absent user is then the uniform not-found
//! whatever the scope's key state is, and `Encryption` keeps meaning only what it should.
//! This is the same instrument issue #433 used: an oracle closed by ordering rather than
//! by teaching two different answers to look alike.
//!
//! # Why the sweep is derived from the committed contract
//!
//! [`every_documented_user_scoped_route_answers_an_absent_user_uniformly`] reads
//! `docs/openapi/management.json`, enumerates every operation published under the
//! user-scoped prefix, and fails when its own case list disagrees with that inventory in
//! EITHER direction. A new user-scoped route fails this file the moment it is documented,
//! rather than joining `external-id` as the one nobody drove against a fresh environment.

mod common;

use std::collections::BTreeSet;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use common::Harness;
use ironauth_admin::ApiError;
use ironauth_env::Env;
use ironauth_store::{ClientId, Scope, UserId};

/// The COMMITTED management contract, embedded at compile time: the same artifact and
/// the same idiom `tests/absent_environment.rs` uses.
const COMMITTED_SPEC: &str = include_str!("../../../docs/openapi/management.json");

/// The templated prefix every user-scoped route hangs off.
const USER_PREFIX: &str = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}";

/// One documented user-scoped operation, as the committed contract publishes it.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DocumentedOperation {
    operation_id: String,
    method: String,
}

/// Every operation the committed contract publishes under the user-scoped prefix.
fn documented_user_operations() -> BTreeSet<DocumentedOperation> {
    let doc: serde_json::Value =
        serde_json::from_str(COMMITTED_SPEC).expect("the committed spec parses");
    let mut operations = BTreeSet::new();
    for (template, methods) in doc["paths"].as_object().expect("paths") {
        if !template.starts_with(USER_PREFIX) {
            continue;
        }
        for (method, operation) in methods.as_object().expect("operations") {
            operations.insert(DocumentedOperation {
                operation_id: operation["operationId"]
                    .as_str()
                    .expect("every operation carries an id")
                    .to_owned(),
                method: method.to_uppercase(),
            });
        }
    }
    operations
}

/// What a user-scoped route answers for an absent user.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// The uniform not-found: the request ADDRESSED the user, so failing to find it is
    /// an addressing verdict.
    UniformNotFound,
    /// An empty page. A collection UNDER a user is not an addressing verdict on the user:
    /// a present user with nothing in the collection answers the same empty page, so
    /// answering it for an absent one reveals nothing and is not the defect this file is
    /// about. It is asserted rather than skipped so that a route which QUIETLY started
    /// answering a fault here would still fail.
    EmptyPage,
    /// An IDEMPOTENT no-op that succeeds. Revoking something an absent user does not
    /// have removes nothing and reports that it removed nothing, which is the same
    /// answer a present user with nothing to revoke gets, so it is not an addressing
    /// verdict and not an oracle. Asserted, again, so that a fault here would fail.
    IdempotentNoOp,
}

/// One user-scoped request driven at an absent user in a key-free environment.
struct Case {
    /// The `operationId` this case drives, which is how it resolves against the
    /// committed contract: a name that drifts matches no operation and fails coverage.
    operation_id: &'static str,
    method: &'static str,
    /// The path suffix AFTER the user id, empty for the user resource itself.
    suffix: String,
    body: Option<&'static str>,
    expect: Expect,
}

fn cases(client: &str) -> Vec<Case> {
    vec![
        Case {
            operation_id: "getUser",
            method: "GET",
            suffix: String::new(),
            body: None,
            expect: Expect::UniformNotFound,
        },
        Case {
            // The traits read (issue #53) resolves the user through the SAME fence and then
            // proves the row exists before it reads the sealed document, so an absent user
            // is the uniform not-found rather than an honest-looking `{"traits":null}` (a
            // 200 there would report an identity that is not present as one with no traits)
            // and never the envelope fault a key-free environment would otherwise produce.
            operation_id: "getUserTraits",
            method: "GET",
            suffix: "/traits".to_owned(),
            body: None,
            expect: Expect::UniformNotFound,
        },
        Case {
            operation_id: "deleteUser",
            method: "DELETE",
            suffix: String::new(),
            body: None,
            expect: Expect::UniformNotFound,
        },
        Case {
            operation_id: "updateUser",
            method: "PATCH",
            suffix: String::new(),
            body: Some(r#"{"external_id":"patched"}"#),
            expect: Expect::UniformNotFound,
        },
        Case {
            operation_id: "listUserConsents",
            method: "GET",
            suffix: "/consents".to_owned(),
            body: None,
            expect: Expect::EmptyPage,
        },
        Case {
            operation_id: "revokeUserConsent",
            method: "POST",
            suffix: format!("/consents/{client}/revoke"),
            body: None,
            expect: Expect::IdempotentNoOp,
        },
        Case {
            // Both identifier operations (issue #54, epic #514) prove the user row exists
            // BEFORE they touch anything sealed. That ordering is the whole point here: the
            // list decrypts each raw value for display and the add seals one, so either
            // would answer the envelope fault of a key-free environment if it reached the
            // store first, and a caller would learn from a 500 that the user is real.
            operation_id: "listUserIdentifiers",
            method: "GET",
            suffix: "/identifiers".to_owned(),
            body: None,
            expect: Expect::UniformNotFound,
        },
        Case {
            operation_id: "addUserIdentifier",
            method: "POST",
            suffix: "/identifiers".to_owned(),
            body: Some(r#"{"type":"email","value":"sweep@example.test"}"#),
            expect: Expect::UniformNotFound,
        },
        Case {
            operation_id: "removeUserIdentifier",
            method: "DELETE",
            suffix: "/identifiers/uid_unsealedprobe0000000000000".to_owned(),
            body: None,
            expect: Expect::UniformNotFound,
        },
        Case {
            operation_id: "linkUserExternalId",
            method: "PUT",
            suffix: "/external-id".to_owned(),
            body: Some(r#"{"external_id":"sweep-external-id"}"#),
            expect: Expect::UniformNotFound,
        },
        Case {
            operation_id: "unlinkUserExternalId",
            method: "DELETE",
            suffix: "/external-id".to_owned(),
            body: None,
            expect: Expect::UniformNotFound,
        },
        Case {
            operation_id: "revokeUserSessions",
            method: "POST",
            suffix: "/sessions/revoke".to_owned(),
            body: None,
            expect: Expect::IdempotentNoOp,
        },
        Case {
            operation_id: "setUserState",
            method: "POST",
            suffix: "/state".to_owned(),
            body: Some(r#"{"state":"disabled"}"#),
            expect: Expect::UniformNotFound,
        },
    ]
}

/// How many envelope keys the scope holds, read as the database OWNER so row-level
/// security cannot hide one.
async fn envelope_key_count(harness: &Harness, scope: &Scope) -> i64 {
    let (deks,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM tenant_deks WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("count the scope's data encryption keys");
    deks
}

/// The uniform not-found EXACTLY as the wire carries it, rendered from the one type that
/// produces it rather than transcribed into a literal here.
async fn uniform_not_found() -> (StatusCode, String) {
    let response = ApiError::NotFound.into_response();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the not-found body is finite");
    (
        status,
        String::from_utf8(bytes.to_vec()).expect("the not-found body is utf-8"),
    )
}

#[tokio::test]
async fn every_documented_user_scoped_route_answers_an_absent_user_uniformly() {
    let harness = Harness::start(20).await;
    // A LIVE environment, created through the ordinary seeding path and then left
    // alone: no user, no invitation, no credential, so nothing has ever sealed anything.
    let scope = harness.seed_scope().await;

    // THE PRECONDITION, measured rather than assumed. If this environment did hold an
    // envelope key the whole file would pass while exercising nothing: `external-id`
    // only ever answered 500 BECAUSE the key was absent.
    assert_eq!(
        envelope_key_count(&harness, &scope).await,
        0,
        "a freshly created environment must hold no envelope key, or this file is not \
         driving the state issue #442 is about"
    );

    let base = format!(
        "/v1/tenants/{}/environments/{}",
        scope.tenant(),
        scope.environment()
    );
    let env = Env::system();
    // In scope by construction, so the ONLY thing wrong with each request is that the
    // user is not there.
    let absent_user = UserId::generate(&env, &scope).to_string();
    let client = ClientId::generate(&env, &scope).to_string();
    let (expected_status, expected_body) = uniform_not_found().await;

    let mut driven = BTreeSet::new();
    for case in cases(&client) {
        driven.insert(DocumentedOperation {
            operation_id: case.operation_id.to_owned(),
            method: case.method.to_owned(),
        });
        let path = format!("{base}/users/{absent_user}{}", case.suffix);
        let (status, _headers, body) = match (case.method, case.body) {
            ("GET", _) => harness.get(&path).await,
            ("DELETE", _) => harness.delete(&path).await,
            ("PATCH", Some(body)) => harness.patch(&path, body).await,
            ("PUT", Some(body)) => harness.put(&path, body).await,
            ("POST", body) => {
                harness
                    .post(&path, case.operation_id, body.unwrap_or("{}"))
                    .await
            }
            other => panic!("unsupported case shape: {other:?}"),
        };
        match case.expect {
            Expect::UniformNotFound => assert_eq!(
                (status, body.as_str()),
                (expected_status, expected_body.as_str()),
                "{} {path} must answer the uniform not-found for an absent user in an \
                 environment that has never sealed anything, byte for byte, and never a \
                 server fault",
                case.operation_id
            ),
            Expect::EmptyPage => assert_eq!(
                (status, body.as_str()),
                (StatusCode::OK, r#"{"items":[]}"#),
                "{} {path} must answer the same empty page a present user with an empty \
                 collection answers, and never a server fault",
                case.operation_id
            ),
            Expect::IdempotentNoOp => assert_eq!(
                status,
                StatusCode::OK,
                "{} {path} must report its idempotent no-op as a success, and never a \
                 server fault: {body}",
                case.operation_id
            ),
        }
    }

    // COVERAGE, in both directions, against the committed contract rather than against a
    // list maintained here.
    let documented = documented_user_operations();
    let undriven: Vec<&DocumentedOperation> = documented
        .iter()
        .filter(|op| !driven.contains(op))
        .collect();
    assert!(
        undriven.is_empty(),
        "every documented user-scoped operation must be driven at an absent user in a \
         key-free environment: {undriven:#?}"
    );
    let unknown: Vec<&DocumentedOperation> = driven
        .iter()
        .filter(|op| !documented.contains(op))
        .collect();
    assert!(
        unknown.is_empty(),
        "every driven case must name an operation the committed contract publishes: \
         {unknown:#?}"
    );
}

#[tokio::test]
async fn the_sealing_and_the_non_sealing_verb_answer_the_same_absent_user_alike() {
    // THE DIFFERENTIAL that made the defect unarguable, kept as its own assertion so it
    // survives any reshaping of the sweep above. Both verbs address the SAME resource and
    // the SAME absent user; the only difference between them is that one seals and the
    // other does not, and that difference used to be worth a `500` against a `404`.
    let harness = Harness::start(20).await;
    let scope = harness.seed_scope().await;
    assert_eq!(
        envelope_key_count(&harness, &scope).await,
        0,
        "the environment must hold no envelope key"
    );
    let absent_user = UserId::generate(&Env::system(), &scope).to_string();
    let path = format!(
        "/v1/tenants/{}/environments/{}/users/{absent_user}/external-id",
        scope.tenant(),
        scope.environment()
    );

    let (link_status, link_headers, link_body) = harness
        .put(&path, r#"{"external_id":"sweep-external-id"}"#)
        .await;
    let (unlink_status, unlink_headers, unlink_body) = harness.delete(&path).await;

    assert_eq!(
        link_status, unlink_status,
        "the sealing PUT and the non-sealing DELETE must answer the same absent user \
         with the same status: {link_body} against {unlink_body}"
    );
    // And they must agree ON THE NOT-FOUND, not merely with each other. Agreement alone
    // is satisfied by a total collapse: mapping the store's uniform not-found to an
    // opaque 500 across the whole management plane makes both verbs answer `500`, and
    // the equality above stays green. That was MEASURED, and this line is what turns it
    // red.
    assert_eq!(
        link_status,
        StatusCode::NOT_FOUND,
        "and the answer they agree on must be the uniform not-found, not whatever \
         opaque status they happen to share: {link_body}"
    );
    assert_eq!(
        link_body, unlink_body,
        "and with the same body, which is what stops the verb's implementation detail \
         from being visible on the wire"
    );
    assert_eq!(
        link_headers.get(axum::http::header::CONTENT_TYPE),
        unlink_headers.get(axum::http::header::CONTENT_TYPE),
        "and the same content type"
    );

    // THE CONTROL: the route really does work when the user IS there, so the equality
    // above is two correct not-founds rather than two broken ones. This also proves the
    // reordered addressing check did not simply break the write: linking still seals,
    // which requires the envelope key the environment did not have a moment ago and
    // mints on the way through.
    let (created_status, _headers, created_body) = harness
        .post(
            &format!(
                "/v1/tenants/{}/environments/{}/users",
                scope.tenant(),
                scope.environment()
            ),
            "unsealed-environment-control",
            r#"{"identifier":"control@example.test","password":"correct horse battery staple"}"#,
        )
        .await;
    assert_eq!(
        created_status,
        StatusCode::CREATED,
        "the control user must be created: {created_body}"
    );
    let created: serde_json::Value =
        serde_json::from_str(&created_body).expect("the created user parses");
    let live_user = created["id"].as_str().expect("the created user has an id");
    let live_path = format!(
        "/v1/tenants/{}/environments/{}/users/{live_user}/external-id",
        scope.tenant(),
        scope.environment()
    );
    let (status, _headers, body) = harness
        .put(&live_path, r#"{"external_id":"control-external-id"}"#)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a PRESENT user must still have an external id linked, or the reordered check \
         has broken the write it was meant to leave alone: {body}"
    );
}
