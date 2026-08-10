// SPDX-License-Identifier: MIT OR Apache-2.0

//! Logging in with an ANNOTATED trait value (issue #624), end to end over the real
//! `POST /login` surface.
//!
//! The store layer is pinned in `ironauth-store`'s `trait_login_index.rs`: the blind index,
//! the ambiguity refusal, the annotation-change behaviour, the tag separation. This file is
//! about what the HTTP layer adds, which is the part issue #624 states as its first
//! acceptance criterion ("an annotated trait value signs a user in, driven end to end") and
//! its fifth (anti-enumeration parity with the existing identifier lookup).
//!
//! The negative assertions carry most of the weight. A login that succeeds through a trait
//! is easy to build and easy to build wrongly: the ways it goes wrong are that an
//! UNANNOTATED field also works (a search over sealed PII for anyone who can post a form),
//! that an AMBIGUOUS value picks somebody (an account-takeover primitive), or that the trait
//! route is DISTINGUISHABLE from the handle route in its response (an oracle for which trait
//! values exist).

mod common;

use common::{Harness, PKCE_CHALLENGE, REDIRECT_URI, form, form_field};
use ironauth_env::Env;
use ironauth_store::{CorrelationId, Scope, TraitSchema};
use serde_json::json;

const PASSWORD: &str = "correct-horse-battery-staple";

fn authorize_query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI}&scope=openid&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256&state=xyz"
    )
}

/// Drive an unauthenticated authorize to obtain a valid `return_to` for the login page.
async fn return_to(harness: &Harness) -> String {
    let client_id = harness.client_id().to_string();
    let (_, headers, _) = harness.authorize(&authorize_query(&client_id)).await;
    let login_location = common::location(&headers).expect("login redirect");
    let (_, _, login_html) = harness.get_with_cookie(&login_location, None).await;
    form_field(&login_html, "return_to").expect("return_to field")
}

/// Activate a schema annotating `handle` as a login identifier and leaving `nickname` bare.
async fn activate_schema(harness: &Harness, env: &Env, scope: Scope) {
    let schema = json!({
        "type": "object",
        "properties": {
            "handle": {"type": "string", "x-ironauth": {"identifier": true}},
            "nickname": {"type": "string"}
        }
    })
    .to_string();
    let repo = harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(env), CorrelationId::generate(env));
    let version = repo
        .trait_schemas()
        .create_version(env, &schema, 1_000_000)
        .await
        .expect("create schema version")
        .1;
    repo.trait_schemas()
        .activate_version(env, version)
        .await
        .expect("activate schema version");
    // The schema really does annotate what this file assumes; a fixture whose annotation
    // silently failed to parse would make every negative assertion below pass for free.
    let compiled = TraitSchema::compile(&schema).expect("the fixture schema compiles");
    assert_eq!(
        compiled.annotations().login_identifiers,
        vec!["handle".to_string()],
        "the fixture must annotate exactly `handle`, or the unannotated-field assertions \
         are vacuous"
    );
}

/// Activate a schema annotating BOTH `handle` and `nickname` as login identifiers.
///
/// The cross-FIELD ambiguity case needs two annotated fields, which the single-annotation
/// fixture above cannot produce. This is a different ambiguity from the store's: there, two
/// users share one field's value and the store refuses; here, two DIFFERENT annotated fields
/// each resolve a different user, and only the login seam can see it.
async fn activate_schema_annotating_both(harness: &Harness, env: &Env, scope: Scope) {
    let schema = json!({
        "type": "object",
        "properties": {
            "handle": {"type": "string", "x-ironauth": {"identifier": true}},
            "nickname": {"type": "string", "x-ironauth": {"identifier": true}}
        }
    })
    .to_string();
    let repo = harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(env), CorrelationId::generate(env));
    let version = repo
        .trait_schemas()
        .create_version(env, &schema, 1_000_000)
        .await
        .expect("create schema version")
        .1;
    repo.trait_schemas()
        .activate_version(env, version)
        .await
        .expect("activate schema version");
    let compiled = TraitSchema::compile(&schema).expect("the fixture schema compiles");
    assert_eq!(
        compiled.annotations().login_identifiers.len(),
        2,
        "this fixture must annotate BOTH fields or the cross-field case cannot arise"
    );
}

/// Give a seeded user a traits document.
async fn set_traits(
    harness: &Harness,
    env: &Env,
    scope: Scope,
    user: &str,
    traits: &serde_json::Value,
) {
    let id = ironauth_store::UserId::parse_in_scope(user, &scope).expect("user id");
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(env), CorrelationId::generate(env))
        .users()
        .set_traits(env, &id, &traits.to_string())
        .await
        .expect("set traits");
}

/// Submit `POST /login` and return the status and the `Location` header, if any.
async fn login(harness: &Harness, identifier: &str, password: &str) -> (u16, Option<String>) {
    let return_to = return_to(harness).await;
    let body = form(&[
        ("identifier", identifier),
        ("password", password),
        ("return_to", &return_to),
    ]);
    let (status, headers, _) = harness.post_form("/login", &body, None).await;
    (status.as_u16(), common::location(&headers))
}

/// Whether a login attempt signed the caller in: the interaction path answers a successful
/// login with a redirect back to the authorize it resumed, and a failure by re-rendering.
fn signed_in(status: u16, location: Option<&str>) -> bool {
    (300..400).contains(&status) && location.is_some_and(|l| l.contains("/authorize"))
}

/// Issue #624 criterion 1: an annotated trait value signs a user in, end to end.
///
/// The same password against the same account through the ordinary login HANDLE is asserted
/// too, so a failure here distinguishes "the trait route is broken" from "this fixture could
/// never log in at all".
#[tokio::test]
async fn an_annotated_trait_value_signs_a_user_in() {
    let harness = Harness::start().await;
    let env = Env::system();
    let scope = harness.scope();
    activate_schema(&harness, &env, scope).await;

    let user = harness
        .seed_user("handle-owner@example.test", PASSWORD)
        .await;
    set_traits(
        &harness,
        &env,
        scope,
        &user,
        &json!({"handle": "ada", "nickname": "countess"}),
    )
    .await;

    let (status, location) = login(&harness, "handle-owner@example.test", PASSWORD).await;
    assert!(
        signed_in(status, location.as_deref()),
        "the ordinary login handle must work, or nothing below is about traits: \
         {status} {location:?}"
    );

    let (status, location) = login(&harness, "ada", PASSWORD).await;
    assert!(
        signed_in(status, location.as_deref()),
        "the ANNOTATED trait value must sign the user in, which is issue #624 criterion 1: \
         {status} {location:?}"
    );
}

/// An UNANNOTATED trait value never signs anyone in.
///
/// This is the assertion that keeps the login form from being a search over sealed traits.
/// The user holds `nickname = countess` and the schema does not annotate `nickname`, so the
/// value must be as good as unknown.
#[tokio::test]
async fn an_unannotated_trait_value_never_signs_anyone_in() {
    let harness = Harness::start().await;
    let env = Env::system();
    let scope = harness.scope();
    activate_schema(&harness, &env, scope).await;

    let user = harness.seed_user("owner@example.test", PASSWORD).await;
    set_traits(
        &harness,
        &env,
        scope,
        &user,
        &json!({"handle": "ada", "nickname": "countess"}),
    )
    .await;

    let (status, location) = login(&harness, "countess", PASSWORD).await;
    assert!(
        !signed_in(status, location.as_deref()),
        "an unannotated trait value signed a user in, so anyone who can post the login form \
         can test for the presence of any trait value in the environment: {status}"
    );
}

/// Two users sharing an annotated value sign in NEITHER, with the correct password.
///
/// The password is right and the account exists; what refuses is the resolution. Asserted
/// after proving the value worked while only one user held it, so the refusal is the
/// SECOND holder's doing and not a broken fixture.
#[tokio::test]
async fn an_ambiguous_annotated_value_signs_in_neither_user() {
    let harness = Harness::start().await;
    let env = Env::system();
    let scope = harness.scope();
    activate_schema(&harness, &env, scope).await;

    let alice = harness.seed_user("alice@example.test", PASSWORD).await;
    let bob = harness.seed_user("bob@example.test", PASSWORD).await;
    set_traits(&harness, &env, scope, &alice, &json!({"handle": "shared"})).await;

    let (status, location) = login(&harness, "shared", PASSWORD).await;
    assert!(
        signed_in(status, location.as_deref()),
        "one holder must sign in, or the refusal below proves nothing: {status}"
    );

    set_traits(&harness, &env, scope, &bob, &json!({"handle": "shared"})).await;

    let (status, location) = login(&harness, "shared", PASSWORD).await;
    assert!(
        !signed_in(status, location.as_deref()),
        "an ambiguous annotated value signed somebody in; whichever it picked, setting that \
         value is then a way to be handed another account's login: {status}"
    );

    // And each user still signs in through their own handle: the ambiguity is confined to
    // the trait route and does not lock either account out.
    for handle in ["alice@example.test", "bob@example.test"] {
        let (status, location) = login(&harness, handle, PASSWORD).await;
        assert!(
            signed_in(status, location.as_deref()),
            "{handle} lost their ordinary login because somebody else copied their trait, \
             which turns a collision into a denial of service: {status}"
        );
    }
}

/// The LOGIN HANDLE wins over a trait that names a different user.
///
/// A deployment that adds a trait annotation must not thereby change who an existing handle
/// resolves to. Bob's `handle` trait is Alice's login address; posting that address must
/// sign in ALICE.
#[tokio::test]
async fn the_login_handle_wins_over_a_trait_naming_someone_else() {
    let harness = Harness::start().await;
    let env = Env::system();
    let scope = harness.scope();
    activate_schema(&harness, &env, scope).await;

    let alice = harness.seed_user("alice@example.test", PASSWORD).await;
    let bob = harness
        .seed_user("bob@example.test", "a-different-password")
        .await;
    set_traits(
        &harness,
        &env,
        scope,
        &bob,
        &json!({"handle": "alice@example.test"}),
    )
    .await;
    let _ = alice;

    // Alice's OWN password against her own address: the handle route, which must win.
    let (status, location) = login(&harness, "alice@example.test", PASSWORD).await;
    assert!(
        signed_in(status, location.as_deref()),
        "Bob claiming Alice's address as a trait took her login away from her: {status}"
    );

    // And Bob's password against that address must NOT sign anyone in, which is what says
    // the handle won rather than that both routes happened to agree.
    let (status, location) = login(&harness, "alice@example.test", "a-different-password").await;
    assert!(
        !signed_in(status, location.as_deref()),
        "Bob's password signed in through Alice's address, so a trait can be used to take \
         over an account by claiming its login handle: {status}"
    );
}

/// Issue #624 criterion 5: the trait route is indistinguishable from an unknown value.
///
/// Three submissions with the same wrong password: a value nobody holds, an annotated value
/// somebody holds, and an unannotated value somebody holds. All three must answer the same
/// status and the same page, or the difference tells a prober which trait values exist.
#[tokio::test]
async fn a_failed_trait_login_is_indistinguishable_from_an_unknown_value() {
    let harness = Harness::start().await;
    let env = Env::system();
    let scope = harness.scope();
    activate_schema(&harness, &env, scope).await;

    let user = harness.seed_user("owner@example.test", PASSWORD).await;
    set_traits(
        &harness,
        &env,
        scope,
        &user,
        &json!({"handle": "known-handle", "nickname": "known-nickname"}),
    )
    .await;

    let mut seen: Vec<(String, u16, String)> = Vec::new();
    for value in ["absent-value12", "known-handle", "known-nickname"] {
        let return_to = return_to(&harness).await;
        let body = form(&[
            ("identifier", value),
            ("password", "wrong-password-guess"),
            ("return_to", &return_to),
        ]);
        let (status, _headers, page) = harness.post_form("/login", &body, None).await;
        // The page reflects the submitted value as a prefill, so it is normalized out before
        // comparison; every value here is the same length, but normalizing is what makes the
        // comparison about the MESSAGE rather than about that coincidence.
        seen.push((value.to_string(), status.as_u16(), page.replace(value, "X")));
    }

    let (baseline_value, baseline_status, baseline_page) = seen[0].clone();
    for (value, status, page) in &seen[1..] {
        assert_eq!(
            *status, baseline_status,
            "`{value}` answered a different status from the unknown `{baseline_value}`, so \
             the status distinguishes a trait value that exists from one that does not"
        );
        assert_eq!(
            *page, baseline_page,
            "`{value}` answered a different page from the unknown `{baseline_value}`, which \
             is an oracle for which trait values the environment holds"
        );
    }
}

/// A scope with NO active trait schema logs in exactly as it did before this feature.
///
/// The absence path is the one every existing deployment is on, so it is asserted rather
/// than assumed: a resolution seam that failed closed when no schema was active would break
/// login for every environment that never adopted traits.
#[tokio::test]
async fn a_scope_with_no_trait_schema_logs_in_through_the_handle_as_before() {
    let harness = Harness::start().await;
    harness.seed_user("plain@example.test", PASSWORD).await;

    let (status, location) = login(&harness, "plain@example.test", PASSWORD).await;
    assert!(
        signed_in(status, location.as_deref()),
        "a scope with no active trait schema must log in through the handle exactly as \
         before; this is the state every existing deployment is in: {status}"
    );
}

/// Two DIFFERENT annotated fields resolving two DIFFERENT users signs in neither.
///
/// This ambiguity is invisible to the store: each field's index holds exactly one row for
/// the value, so `by_annotated_trait` resolves cleanly for each. It is only when the login
/// seam consults both fields that the conflict appears, so this is the seam's own refusal
/// and the only test that can see it.
///
/// Both users have the SAME password here, so a seam that picked one would sign somebody in
/// and the assertion would catch it. With different passwords a wrong pick could fail for
/// the wrong reason and the test would pass while the defect stood.
#[tokio::test]
async fn two_annotated_fields_naming_two_users_sign_in_neither() {
    let harness = Harness::start().await;
    let env = Env::system();
    let scope = harness.scope();
    activate_schema_annotating_both(&harness, &env, scope).await;

    let alice = harness.seed_user("alice@example.test", PASSWORD).await;
    let bob = harness.seed_user("bob@example.test", PASSWORD).await;
    // Alice holds the value under `handle`; Bob holds the SAME value under `nickname`.
    set_traits(
        &harness,
        &env,
        scope,
        &alice,
        &json!({"handle": "contested"}),
    )
    .await;

    let (status, location) = login(&harness, "contested", PASSWORD).await;
    assert!(
        signed_in(status, location.as_deref()),
        "one holder must sign in first, or the refusal below proves nothing: {status}"
    );

    set_traits(
        &harness,
        &env,
        scope,
        &bob,
        &json!({"nickname": "contested"}),
    )
    .await;

    let (status, location) = login(&harness, "contested", PASSWORD).await;
    assert!(
        !signed_in(status, location.as_deref()),
        "one annotated field named Alice and another named Bob, and the login picked one;          whoever can set the second field is then handed the first user's account: {status}"
    );

    // Neither loses their ordinary login.
    for handle in ["alice@example.test", "bob@example.test"] {
        let (status, location) = login(&harness, handle, PASSWORD).await;
        assert!(
            signed_in(status, location.as_deref()),
            "{handle} lost their handle login to a cross-field collision: {status}"
        );
    }
}

/// The SAME user reached through two annotated fields is not ambiguity.
///
/// A user who puts one value in both annotated fields must still log in. A seam that treated
/// "two fields matched" as a conflict without comparing WHO they matched would lock out the
/// most ordinary configuration there is.
#[tokio::test]
async fn one_user_matching_through_two_fields_still_signs_in() {
    let harness = Harness::start().await;
    let env = Env::system();
    let scope = harness.scope();
    activate_schema_annotating_both(&harness, &env, scope).await;

    let user = harness.seed_user("owner@example.test", PASSWORD).await;
    set_traits(
        &harness,
        &env,
        scope,
        &user,
        &json!({"handle": "same", "nickname": "same"}),
    )
    .await;

    let (status, location) = login(&harness, "same", PASSWORD).await;
    assert!(
        signed_in(status, location.as_deref()),
        "one user holding the value in both annotated fields must sign in; treating two          matches as a conflict without comparing WHO matched locks out the ordinary case:          {status}"
    );
}
