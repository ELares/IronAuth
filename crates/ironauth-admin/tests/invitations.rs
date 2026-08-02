// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admin user invitations over HTTP (issue #60), driven through the management
//! router against a real database.
//!
//! Pins: create provisions a pending-verification user and returns the one-time
//! token exactly ONCE; a read (get/list) and an idempotent replay NEVER return the
//! token (only its digest is ever stored); revoke makes a pending invitation
//! unacceptable and is idempotent; resend rotates the token and returns a fresh one;
//! a cross-scope invitation probe is the uniform not-found (the anti-oracle); a create
//! whose SECOND write fails leaves NOTHING behind, so the same Idempotency-Key retries
//! into a clean 201 instead of the wedged 409 it used to answer; and two CONCURRENT
//! same-key creates land exactly one invitation, with the loser replaying the winner's
//! 201 rather than being told its own identifier is taken (issue #247).

mod common;

use std::sync::{Arc, Mutex};

use common::Harness;
use ironauth_env::{Entropy, Env, FixedEntropy};
use ironauth_store::{EnvironmentId, Scope, TenantId, mint_invitation_token};
use serde_json::Value;

/// The seed the REWOUND stretch of [`RewindableEntropy`] always restarts from. Any
/// fixed value works; what matters is that it is the same on every rewind, so two
/// requests draw the same bytes and mint the same invitation handle.
const REWIND_SEED: u64 = 0x2470;
/// How many draws one `mint_invitation_token` consumes: the `inv_` handle and the
/// token's 256-bit secret. Rewinding exactly this many reproduces the whole mint and
/// leaves everything the request draws AFTER it (the user id, the correlation id, the
/// seal nonces) on the fresh stream, so nothing else collides.
const MINT_DRAWS: u32 = 2;

/// A deterministic entropy source whose next `n` draws can be REWOUND to a fixed
/// sub-stream, then falls back to a stream that keeps advancing.
///
/// This is how the issue #247 test makes an invitation create's SECOND write fail on a
/// real database without any production failure-injection knob: rewind before two
/// different requests and both mint the SAME `inv_` handle and token digest, so the
/// second one's `user_invitations` INSERT hits the unique violation. Test-only, and
/// deliberately local to this file.
struct RewindableEntropy {
    inner: Mutex<RewindState>,
}

struct RewindState {
    /// Draws still to be served from the rewound sub-stream.
    rewound: u32,
    /// The rewound sub-stream, re-seeded on every rewind.
    pinned: FixedEntropy,
    /// The ordinary stream, which never rewinds.
    stream: FixedEntropy,
}

impl RewindableEntropy {
    fn new(seed: u64) -> Self {
        Self {
            inner: Mutex::new(RewindState {
                rewound: 0,
                pinned: FixedEntropy::new(REWIND_SEED),
                stream: FixedEntropy::new(seed),
            }),
        }
    }

    /// Serve the next `draws` fills from the fixed sub-stream, restarted from
    /// [`REWIND_SEED`].
    fn rewind(&self, draws: u32) {
        let mut state = self.inner.lock().expect("rewind lock");
        state.rewound = draws;
        state.pinned = FixedEntropy::new(REWIND_SEED);
    }
}

impl Entropy for RewindableEntropy {
    fn fill_bytes(&self, buf: &mut [u8]) {
        let mut state = self.inner.lock().expect("rewind lock");
        if state.rewound > 0 {
            state.rewound -= 1;
            state.pinned.fill_bytes(buf);
        } else {
            state.stream.fill_bytes(buf);
        }
    }
}

/// A tenant with an environment, and the invitations collection path under it.
async fn tenant_env(h: &Harness) -> (String, String, String) {
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let invitations = format!("/v1/tenants/{tenant}/environments/{environment}/invitations");
    (tenant, environment, invitations)
}

#[tokio::test]
async fn create_returns_the_one_time_token_and_reads_omit_it() {
    let h = Harness::start(50).await;
    let (_t, _e, invitations) = tenant_env(&h).await;

    let body = serde_json::json!({
        "identifier": "ada@example.test",
        "credential_type": "password",
    })
    .to_string();
    let (status, _, response) = h.post(&invitations, "inv-key-1", &body).await;
    assert_eq!(status, reqwest_status_created(), "create: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    let invitation = &value["invitation"];
    assert_eq!(invitation["target_identifier"], "ada@example.test");
    assert_eq!(invitation["state"], "pending");
    assert_eq!(invitation["credential_type"], "password");
    let id = invitation["id"].as_str().expect("invitation id").to_owned();
    // The one-time token is present at creation.
    let token = value["token"].as_str().expect("token present at create");
    assert!(token.starts_with("ira_inv_"), "token wire form: {token}");

    // A GET of the invitation NEVER returns the token (only the digest is stored).
    let (get_status, _, get_body) = h.get(&format!("{invitations}/{id}")).await;
    assert_eq!(get_status, reqwest_status_ok(), "get: {get_body}");
    let got: Value = serde_json::from_str(&get_body).expect("json");
    assert!(
        got.get("token").is_none(),
        "a read must not carry the token"
    );
    assert_eq!(got["id"], id);

    // The LIST also omits the token.
    let (list_status, _, list_body) = h.get(&invitations).await;
    assert_eq!(list_status, reqwest_status_ok(), "list: {list_body}");
    let list: Value = serde_json::from_str(&list_body).expect("json");
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "one invitation listed");
    assert!(
        items[0].get("token").is_none(),
        "list must not carry tokens"
    );
}

#[tokio::test]
async fn an_idempotent_replay_returns_the_invitation_without_the_token() {
    let h = Harness::start(50).await;
    let (_t, _e, invitations) = tenant_env(&h).await;

    let body = serde_json::json!({ "identifier": "grace@example.test" }).to_string();
    let (status, _, first) = h.post(&invitations, "inv-key-2", &body).await;
    assert_eq!(status, reqwest_status_created(), "first create: {first}");
    let first_value: Value = serde_json::from_str(&first).expect("json");
    assert!(
        first_value["token"].as_str().is_some(),
        "the token is revealed on the original creation"
    );

    // Replaying the SAME POST with the SAME key returns the stored response, which is
    // the invitation WITHOUT the one-time token (the token is shown only once).
    let (replay_status, _, replay) = h.post(&invitations, "inv-key-2", &body).await;
    assert_eq!(replay_status, reqwest_status_created(), "replay: {replay}");
    let replay_value: Value = serde_json::from_str(&replay).expect("json");
    assert!(
        replay_value.get("token").is_none() || replay_value["token"].is_null(),
        "an idempotent replay must not re-reveal the one-time token: {replay}"
    );
    assert_eq!(
        replay_value["invitation"]["id"], first_value["invitation"]["id"],
        "the replay returns the same invitation"
    );
}

#[tokio::test]
async fn revoke_makes_a_pending_invitation_unacceptable_and_is_idempotent() {
    let h = Harness::start(50).await;
    let (_t, _e, invitations) = tenant_env(&h).await;

    let body = serde_json::json!({ "identifier": "revoke@example.test" }).to_string();
    let (_s, _, created) = h.post(&invitations, "inv-key-3", &body).await;
    let id = serde_json::from_str::<Value>(&created).expect("json")["invitation"]["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // Revoke the pending invitation.
    let (status, _, response) = h
        .post(&format!("{invitations}/{id}/revoke"), "rev-key-1", "")
        .await;
    assert_eq!(status, reqwest_status_ok(), "revoke: {response}");
    assert_eq!(
        serde_json::from_str::<Value>(&response).expect("json")["state"],
        "revoked"
    );

    // The read reflects the revoked state.
    let (_s, _, got) = h.get(&format!("{invitations}/{id}")).await;
    assert_eq!(
        serde_json::from_str::<Value>(&got).expect("json")["state"],
        "revoked"
    );

    // A replay with the SAME key returns the stored response.
    let (replay_status, _, _) = h
        .post(&format!("{invitations}/{id}/revoke"), "rev-key-1", "")
        .await;
    assert_eq!(replay_status, reqwest_status_ok(), "revoke replay");

    // A fresh revoke of the now-revoked invitation matches no pending row: 404.
    let (again_status, _, again) = h
        .post(&format!("{invitations}/{id}/revoke"), "rev-key-2", "")
        .await;
    assert_eq!(
        again_status,
        reqwest_status_not_found(),
        "re-revoking a revoked invitation is a not-found: {again}"
    );
}

#[tokio::test]
async fn resend_rotates_the_token_and_returns_a_fresh_one() {
    let h = Harness::start(50).await;
    let (_t, _e, invitations) = tenant_env(&h).await;

    let body = serde_json::json!({ "identifier": "resend@example.test" }).to_string();
    let (_s, _, created) = h.post(&invitations, "inv-key-4", &body).await;
    let created_value: Value = serde_json::from_str(&created).expect("json");
    let id = created_value["invitation"]["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let first_token = created_value["token"].as_str().expect("token").to_owned();

    let (status, _, response) = h
        .post(&format!("{invitations}/{id}/resend"), "resend-key-1", "")
        .await;
    assert_eq!(status, reqwest_status_ok(), "resend: {response}");
    let resend_value: Value = serde_json::from_str(&response).expect("json");
    let fresh_token = resend_value["token"].as_str().expect("fresh token");
    assert!(fresh_token.starts_with("ira_inv_"));
    assert_ne!(
        fresh_token, first_token,
        "resend issues a DIFFERENT token, invalidating the prior one"
    );
    assert_eq!(resend_value["invitation"]["state"], "pending");
}

#[tokio::test]
async fn a_cross_scope_invitation_probe_is_the_uniform_not_found() {
    let h = Harness::start(50).await;
    let (tenant_a, env_a) = h.create_tenant("Acme", "k-a").await;
    let (tenant_b, env_b) = h.create_tenant("Beta", "k-b").await;
    let inv_a = format!("/v1/tenants/{tenant_a}/environments/{env_a}/invitations");

    let body = serde_json::json!({ "identifier": "a-person@example.test" }).to_string();
    let (_s, _, created) = h.post(&inv_a, "inv-key-5", &body).await;
    let id_a = serde_json::from_str::<Value>(&created).expect("json")["invitation"]["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // A's invitation id fetched under B's scope is the uniform not-found: a token or
    // id minted in one tenant never resolves in another.
    let (status_cross, _, cross) = h
        .get(&format!(
            "/v1/tenants/{tenant_b}/environments/{env_b}/invitations/{id_a}"
        ))
        .await;
    assert_eq!(
        status_cross,
        reqwest_status_not_found(),
        "cross probe: {cross}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&cross).expect("json")["error"],
        "not_found",
        "the cross-scope probe is the uniform not-found (the anti-oracle)"
    );

    // The invitation is still visible in its OWN scope (the isolation is directional,
    // not a global disappearance).
    let (status_own, _, own) = h.get(&format!("{inv_a}/{id_a}")).await;
    assert_eq!(status_own, reqwest_status_ok(), "own-scope get: {own}");
}

#[tokio::test]
async fn a_create_whose_second_write_fails_leaves_no_ghost_and_the_same_key_then_creates() {
    // THE DECISIVE TEST for issue #247, over HTTP.
    //
    // The create used to provision the pending_verification user in ONE transaction and
    // write the invitation (with the Idempotency-Key record) in a SECOND. A failure of
    // the second after the first committed left an orphaned user with no invitation and
    // no stored key, so the RETRY under the same key missed the replay store, re-ran the
    // user create, hit the identifier unique violation, and answered 409. The identifier
    // stayed wedged behind a ghost account until an operator deleted it.
    //
    // The second write is made to fail for real, with no production knob: the entropy
    // seam is REWOUND so a later request mints an invitation handle that is already
    // taken, which is exactly a collision on the `user_invitations` primary key.
    let entropy = Arc::new(RewindableEntropy::new(0x247));
    let env = Env::from_parts(
        Arc::new(ironauth_env::ManualClock::new(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        )),
        Arc::clone(&entropy) as Arc<dyn Entropy>,
    );
    let h = Harness::start_with_env(50, env.clone()).await;
    let (tenant, environment) = h.create_tenant("acme", "k-atomic").await;
    let invitations = format!("/v1/tenants/{tenant}/environments/{environment}/invitations");
    let users = format!("/v1/tenants/{tenant}/environments/{environment}/users");
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );

    // What a REWOUND mint produces, computed here so the collision below is PROVEN
    // rather than assumed: if the handler's first entropy draw were ever something
    // other than the invitation mint, this id would not match and the test would fail
    // loudly instead of quietly measuring nothing.
    let probe = RewindableEntropy::new(0);
    probe.rewind(MINT_DRAWS);
    let probe_env = Env::from_parts(env.clock_arc(), Arc::new(probe));
    let expected_handle = mint_invitation_token(&probe_env, &scope).id.to_string();

    // The FIRST create, on a rewound mint: it lands and takes the handle.
    entropy.rewind(MINT_DRAWS);
    let ada = serde_json::json!({ "identifier": "ada-247@example.test" }).to_string();
    let (status, _, first) = h.post(&invitations, "atomic-key-ada", &ada).await;
    assert_eq!(status, reqwest_status_created(), "first create: {first}");
    let first_value: Value = serde_json::from_str(&first).expect("json");
    assert_eq!(
        first_value["invitation"]["id"], expected_handle,
        "the rewound mint produced the handle this test predicted"
    );

    // The SECOND create, for a DIFFERENT identifier, on the SAME rewound mint. The user
    // insert succeeds and the invitation insert collides on the handle: the second write
    // fails after the first would have committed, which is the whole defect.
    entropy.rewind(MINT_DRAWS);
    let bob = serde_json::json!({ "identifier": "bob-247@example.test" }).to_string();
    let (failed_status, _, failed) = h.post(&invitations, "atomic-key-bob", &bob).await;
    assert_eq!(
        failed_status,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "a handle collision is an opaque server fault, never a 409 about the identifier: {failed}"
    );

    // NOTHING was left behind. No ghost user holding the identifier, and no second
    // invitation.
    let (_s, _, ghost) = h
        .get(&format!("{users}?identifier=bob-247%40example.test"))
        .await;
    let ghost: Value = serde_json::from_str(&ghost).expect("json");
    assert_eq!(
        ghost["items"].as_array().expect("items").len(),
        0,
        "the failed create leaves no ghost pending_verification user: {ghost}"
    );
    let (_s, _, listed) = h.get(&invitations).await;
    let listed: Value = serde_json::from_str(&listed).expect("json");
    assert_eq!(
        listed["items"].as_array().expect("items").len(),
        1,
        "only the first invitation exists: {listed}"
    );

    // THE RETRY, with the SAME Idempotency-Key. Nothing committed, so nothing replays,
    // and the identifier is free: this is the 201 that used to be a 409.
    let (retry_status, _, retry) = h.post(&invitations, "atomic-key-bob", &bob).await;
    assert_eq!(
        retry_status,
        reqwest_status_created(),
        "the same key retries into a clean create, not a wedged 409: {retry}"
    );
    let retry_value: Value = serde_json::from_str(&retry).expect("json");
    assert_eq!(
        retry_value["invitation"]["target_identifier"],
        "bob-247@example.test"
    );
    assert!(
        retry_value["token"].as_str().is_some(),
        "the retry is an ORIGINAL creation, so it reveals the one-time token: {retry}"
    );

    // And that retry is now the stored original: replaying the key returns it without
    // the token and without creating a third invitation.
    let (replay_status, _, replay) = h.post(&invitations, "atomic-key-bob", &bob).await;
    assert_eq!(replay_status, reqwest_status_created(), "replay: {replay}");
    let replay_value: Value = serde_json::from_str(&replay).expect("json");
    assert_eq!(
        replay_value["invitation"]["id"], retry_value["invitation"]["id"],
        "the replay returns the invitation the retry created"
    );
    assert!(
        replay_value.get("token").is_none() || replay_value["token"].is_null(),
        "a replay never re-reveals the one-time token: {replay}"
    );
    let (_s, _, final_list) = h.get(&invitations).await;
    let final_list: Value = serde_json::from_str(&final_list).expect("json");
    assert_eq!(
        final_list["items"].as_array().expect("items").len(),
        2,
        "exactly two invitations exist: the failed attempt created none: {final_list}"
    );
}

#[tokio::test]
async fn two_concurrent_same_key_creates_land_once_and_the_loser_replays_the_winner() {
    // THE CONCURRENT half of issue #247, over HTTP, and the sentence the CHANGELOG makes.
    //
    // Joining the two writes is NOT what fixes this case: the ORDER inside the joined
    // transaction is. Both requests pass the replay lookup (neither sees a stored
    // response yet) and both reach the store, so one of them is going to block on a
    // unique index and lose. WHICH index decides what the loser is told. With the
    // Idempotency-Key record written LAST it blocks on the login-handle index and the
    // handler answers 409 "a user or invitation with this identifier already exists",
    // which is a lie: the only thing holding that identifier is the caller's own
    // concurrent request. Written FIRST it blocks on `idempotency_keys`, reaches
    // IdempotencyConflict, and the handler replays the winner's committed 201.
    //
    // The two requests run as concurrent futures on one runtime, so they interleave at
    // every await: the loser is past the replay lookup long before the winner commits.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-race").await;
    let invitations = format!("/v1/tenants/{tenant}/environments/{environment}/invitations");
    let users = format!("/v1/tenants/{tenant}/environments/{environment}/users");
    let body = serde_json::json!({ "identifier": "race-247@example.test" }).to_string();

    let ((status_a, _, a), (status_b, _, b)) = tokio::join!(
        h.post(&invitations, "race-key-247", &body),
        h.post(&invitations, "race-key-247", &body)
    );

    // NEITHER is the 409. That answer is the defect: it names the caller's identifier as
    // taken when nothing but their own in-flight twin holds it.
    for (status, response) in [(status_a, &a), (status_b, &b)] {
        assert_eq!(
            status,
            reqwest_status_created(),
            "a same-key racer answered {status} instead of the winner's 201: {response}"
        );
    }

    // ONE of them created; the other REPLAYED that creation. The replay is recognisable
    // without guessing which won: only an original create reveals the one-time token.
    let a: Value = serde_json::from_str(&a).expect("json");
    let b: Value = serde_json::from_str(&b).expect("json");
    let revealed = [&a, &b]
        .iter()
        .filter(|value| value.get("token").is_some_and(|t| !t.is_null()))
        .count();
    assert_eq!(
        revealed, 1,
        "exactly one racer is the original create that reveals the token: {a} / {b}"
    );
    assert_eq!(
        a["invitation"]["id"], b["invitation"]["id"],
        "the loser replayed the WINNER'S invitation, not one of its own: {a} / {b}"
    );

    // And the race created exactly one of everything: one invitation, and one user
    // behind the identifier both requests named.
    let (_s, _, listed) = h.get(&invitations).await;
    let listed: Value = serde_json::from_str(&listed).expect("json");
    assert_eq!(
        listed["items"].as_array().expect("items").len(),
        1,
        "the same-key race creates exactly one invitation: {listed}"
    );
    let (_s, _, found) = h
        .get(&format!("{users}?identifier=race-247%40example.test"))
        .await;
    let found: Value = serde_json::from_str(&found).expect("json");
    assert_eq!(
        found["items"].as_array().expect("items").len(),
        1,
        "the same-key race provisions exactly one pending user: {found}"
    );
}

// Small status-code helpers so the test reads at a glance (the harness returns
// `axum::http::StatusCode`).
fn reqwest_status_created() -> axum::http::StatusCode {
    axum::http::StatusCode::CREATED
}
fn reqwest_status_ok() -> axum::http::StatusCode {
    axum::http::StatusCode::OK
}
fn reqwest_status_not_found() -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_FOUND
}
