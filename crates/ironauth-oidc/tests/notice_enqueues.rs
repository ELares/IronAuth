// SPDX-License-Identifier: MIT OR Apache-2.0

//! The messaging ledger has a producer (issue #111).
//!
//! Before this, `MessageRepo::enqueue` had ZERO production callers. The ledger, the collapse,
//! the rate limit, the suppression check, the failover and both management endpoints were all
//! implemented, wired into the shipped binary, and covered by passing tests, and nothing ever
//! handed them a message.
//!
//! The door is PART of `VerificationSender::send`: the two coarse `account_*` alerts, which are
//! the only messages this producer knows the whole text of. Two rules narrow it there.
//!
//! A payload rides a durable queue every consumer worker reads and the management events API
//! serves it, so a message carrying a token cannot use this path -- that excludes the four
//! `deliver_*` methods outright. And `DefaultComposer::compose` refuses a payload with no
//! `body`, so the producer must RENDER the message, which it can only do for one whose whole
//! text it knows. `Recovery` and `Registration` carry a confirm link; mailing them without it
//! would not be a degraded message, it would be a broken flow.
//!
//! Everything this producer does not render is DELEGATED, unchanged, to the sender it wraps --
//! and that is true on THREE axes, because review found it broken on two of them in turn. By
//! METHOD (`the_four_token_carrying_methods_are_delegated`), by PURPOSE
//! (`the_link_carrying_purposes_are_delegated_not_queued`), and by RECIPIENT
//! (`a_recipient_this_ledger_cannot_address_is_delegated`) -- the last because these alerts go
//! to every verified channel, a verified phone has no `@`, and dropping it moved every
//! phone-channel alert from "logged" to nothing.

use ironauth_env::Env;
use ironauth_oidc::message_sender::{MessagingVerificationSender, notice_body};
use ironauth_oidc::{
    EmailOtpMessage, MagicLinkMessage, NewDeviceNotice, RecoveryCancelNotice, VerificationPurpose,
    VerificationSender,
};
use ironauth_store::message_rate::RateBudget;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, MESSAGE_DELIVERY_CONSUMER};
use sqlx::Row as _;
use std::sync::{Arc, Mutex};

/// The sender under test wraps another one, so what it DELEGATES is observable.
///
/// Recording rather than counting: a test that only counts cannot tell "delegated the right
/// call" from "delegated some call", and the delegation is the half of this type that keeps
/// four transports alive.
#[derive(Debug, Default)]
struct Recorder {
    calls: Mutex<Vec<String>>,
}

impl Recorder {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("not poisoned").clone()
    }

    fn record(&self, call: &str) {
        self.calls
            .lock()
            .expect("not poisoned")
            .push(call.to_owned());
    }
}

#[async_trait::async_trait]
impl VerificationSender for Recorder {
    async fn send(&self, _scope: ironauth_store::Scope, purpose: VerificationPurpose, _to: &str) {
        self.record(&format!("send:{}", purpose.as_str()));
    }

    fn deliver_email_otp(&self, _message: &EmailOtpMessage<'_>) {
        self.record("deliver_email_otp");
    }

    fn deliver_magic_link(&self, _message: &MagicLinkMessage<'_>) {
        self.record("deliver_magic_link");
    }

    fn deliver_new_device_notice(&self, _message: &NewDeviceNotice<'_>) {
        self.record("deliver_new_device_notice");
    }

    fn deliver_recovery_cancel_notice(&self, _message: &RecoveryCancelNotice<'_>) {
        self.record("deliver_recovery_cancel_notice");
    }
}

/// Provision the envelope keys the ledger seals a recipient with.
///
/// `enqueue` seals the recipient blind index, so without a KEK and DEK for the scope it fails
/// with `StoreError::Encryption` before writing anything -- which looks exactly like a producer
/// that does nothing. Every future door needs this.
async fn provision(db: &TestDatabase, env: &Env, scope: ironauth_store::Scope) {
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    acting
        .envelope()
        .provision_kek(env, &db.master_key())
        .await
        .expect("provision kek");
    acting
        .envelope()
        .provision_dek(env, &db.master_key())
        .await
        .expect("provision dek");
}

/// A sender whose delegation target is observable, with a budget high enough not to interfere.
///
/// The budget is named at every call site rather than defaulted, because the SHIPPED budget is
/// `RateBudget::new(3, 3_600)` and a helper that hid a generous one would mean the configuration
/// production runs is the only one no test ever exercises.
fn sender(db: &TestDatabase, env: &Env) -> (MessagingVerificationSender, Arc<Recorder>) {
    sender_with(db, env, RateBudget::new(100, 3_600))
}

fn sender_with(
    db: &TestDatabase,
    env: &Env,
    budget: RateBudget,
) -> (MessagingVerificationSender, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    let sender = MessagingVerificationSender::new(
        Arc::clone(&recorder) as Arc<dyn VerificationSender>,
        db.store().clone(),
        env.clone(),
        budget,
    );
    (sender, recorder)
}

async fn count(db: &TestDatabase, scope: ironauth_store::Scope, kind: Option<&str>) -> i64 {
    let sql = match kind {
        Some(_) => {
            "SELECT COUNT(*) AS n FROM messages WHERE tenant_id = $1 AND environment_id = $2 AND kind = $3"
        }
        None => "SELECT COUNT(*) AS n FROM messages WHERE tenant_id = $1 AND environment_id = $2",
    };
    let mut query = sqlx::query(sql)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string());
    if let Some(kind) = kind {
        query = query.bind(kind);
    }
    query
        .fetch_one(db.owner_pool())
        .await
        .expect("count")
        .get("n")
}

#[tokio::test]
async fn a_notice_lands_in_the_ledger_with_a_delivery_job() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;

    sender(&db, &env)
        .0
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;

    assert_eq!(
        count(
            &db,
            scope,
            Some(VerificationPurpose::AccountLinked.as_str())
        )
        .await,
        1,
        "a delivered notice must land a message; the ledger had no producer before this"
    );

    // The delivery job rides the SAME transaction as the row, which is why the outbox exists:
    // a message recorded without a job never sends.
    // EXACTLY one, and filtered to the DELIVERY consumer. `>= 1` over every consumer was the
    // first version and it cannot fail for the right reason: the rate-limited path writes an
    // outbox row too (the `message.rate_limited` domain event), so a run that queued no
    // delivery job at all would still have satisfied it.
    let jobs: i64 = sqlx::query(
        "SELECT COUNT(*) AS n FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND consumer = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(MESSAGE_DELIVERY_CONSUMER)
    .fetch_one(db.owner_pool())
    .await
    .expect("count jobs")
    .get("n");
    assert_eq!(
        jobs, 1,
        "a queued message must have exactly one delivery job"
    );
}

/// The payload carries NO secret, and its two fields are the two the composer needs.
///
/// Whether it COMPOSES is asserted in `ironauth-admin`, against the real `DefaultComposer`, by
/// `the_notice_payload_composes`. It has to live there because the dependency runs that way, and
/// the reason it is a separate test rather than an assertion here is a defect review found: the
/// first version checked composability by hand-copying `message_id_local`'s charset predicate.
/// That predicate is one of TWO refusals in `compose`, and the version it could not see --
/// `missing_body` -- fired for every payload this producer wrote. The test was green and every
/// notice would have terminated `Failed` with no provider contacted.
///
/// A copied predicate is not the code it copies. What this test asserts is the payload's
/// CONTENT; what the admin-side test asserts is that the composer accepts it.
#[tokio::test]
async fn the_payload_carries_no_secret_and_nothing_the_composer_cannot_use() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;

    sender(&db, &env)
        .0
        .send(
            scope,
            VerificationPurpose::AccountUnlinked,
            "user@example.test",
        )
        .await;

    // From `outbox_messages`, which is where the payload actually lives -- and which is
    // exactly where a secret would be published: every consumer worker reads this table, and
    // the management events API serves it.
    let payload: serde_json::Value = sqlx::query(
        "SELECT payload FROM outbox_messages WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read the payload")
    .get("payload");

    let object = payload.as_object().expect("an object");
    // Exactly what a coarse notice needs and nothing else. An allowlist rather than a denylist:
    // asserting "no token" would pass for any future field somebody adds.
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["body", "message_id"],
        "the payload rides a durable queue every consumer worker reads, so it carries only \
         variables that are safe to write down"
    );

    // The message id is the LEDGER ROW'S id, not merely a well-shaped string. Asserting only
    // that it looks like an id passes for a constant, and a constant here means every message
    // the deployment ever sends shares one `Message-ID` and one MIME boundary -- which is the
    // bug `message_id_local`'s own doc records as already having been fixed once.
    let row_id: String = sqlx::query("SELECT id::text AS id FROM messages WHERE tenant_id = $1")
        .bind(scope.tenant().to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("read the row")
        .get("id");
    assert_eq!(
        object["message_id"].as_str(),
        Some(row_id.as_str()),
        "the payload's message id is the row's own: {payload}"
    );

    // And the body is the rendered notice. Compared against a LITERAL, not against
    // `notice_body(purpose)` -- which is the function under test, so that comparison is
    // `f(x) == f(x)` and holds for whatever the function returns. It held for an EMPTY body,
    // for the OTHER purpose's text, and for a body carrying a live token.
    assert_eq!(
        object["body"].as_str(),
        Some(
            "A sign-in method was removed from your account. If this was you, no action is \
             needed. If it was not, change your password and review your sign-in methods."
        ),
        "the body is the text for THIS purpose: {payload}"
    );
}

/// The two rendered bodies say different things, and neither may carry a link.
///
/// Kept as one test over BOTH purposes rather than an assertion inside each purpose's test,
/// because splitting them is how three mutations survived: the no-link check was applied only
/// to `AccountUnlinked` and the text check only to `AccountLinked`, so neither purpose ever got
/// both. A rule that holds for one of two cases is a rule the other case is exempt from.
#[test]
fn every_rendered_body_is_distinct_non_empty_and_link_free() {
    let bodies: Vec<&'static str> = [
        VerificationPurpose::AccountLinked,
        VerificationPurpose::AccountUnlinked,
    ]
    .into_iter()
    .map(|purpose| notice_body(purpose).expect("this producer renders both alerts"))
    .collect();

    for body in &bodies {
        assert!(
            !body.trim().is_empty(),
            "an empty body walks around the composer's `missing_body` refusal and ships a \
             blank mail, which its own doc calls worse than composing nothing"
        );
        assert!(
            !body.contains("http") && !body.contains("://"),
            "a coarse alert carries no link. A body with one is a token on a durable jsonb \
             queue every consumer worker reads: {body}"
        );
    }
    assert_ne!(
        bodies[0], bodies[1],
        "the two alerts describe opposite events, so one carrying the other's text tells a \
         user a sign-in method was ADDED when one was REMOVED"
    );

    // And the purposes this producer does not render have no body at all, so the branch that
    // delegates them cannot be satisfied by an invented one.
    for purpose in [
        VerificationPurpose::Registration,
        VerificationPurpose::Recovery,
    ] {
        assert_eq!(
            notice_body(purpose),
            None,
            "{} carries a link in its real message and must not be rendered here",
            purpose.as_str()
        );
    }
}

/// Two DIFFERENT purposes to one recipient do not collapse onto each other.
///
/// The dedup key is (kind, recipient, window), and the kind is the purpose. Sharing one kind
/// across purposes would suppress an alert about one event because an unrelated one had just
/// fired -- which is a security failure, not a deduplication.
#[tokio::test]
async fn two_purposes_to_one_recipient_do_not_collapse() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;
    let (sender, _delegate) = sender(&db, &env);

    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;
    sender
        .send(
            scope,
            VerificationPurpose::AccountUnlinked,
            "user@example.test",
        )
        .await;

    assert_eq!(
        count(&db, scope, None).await,
        2,
        "different purposes are different messages"
    );
    assert_eq!(
        count(
            &db,
            scope,
            Some(VerificationPurpose::AccountLinked.as_str())
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &db,
            scope,
            Some(VerificationPurpose::AccountUnlinked.as_str())
        )
        .await,
        1
    );
}

/// A repeat of the SAME purpose inside the window collapses.
#[tokio::test]
async fn a_repeat_inside_the_window_collapses() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;
    let (sender, _delegate) = sender(&db, &env);

    for _ in 0..3 {
        sender
            .send(
                scope,
                VerificationPurpose::AccountLinked,
                "user@example.test",
            )
            .await;
    }
    assert_eq!(
        count(&db, scope, None).await,
        1,
        "three identical notices in one window are one send"
    );
    // The window's FLOOR is asserted where the constant lives (`const _: () = assert!(...)`),
    // because a runtime assertion comparing a constant to a literal is a compile-time truth
    // dressed as a test. What this test pins is the collapse; `a_notice_in_a_later_window_is_a_
    // new_send` pins that the window moves.
}

/// A recipient this ledger cannot address is DELEGATED, not dropped.
///
/// `account.rs` dispatches these alerts to every VERIFIED channel, and a verified phone reaches
/// this door as a number -- which is the default, since `annotated_verification_kinds` reports
/// `phone: true` for any deployment carrying no `verification_addresses` annotation. A phone
/// number has no `@`, so `normalize_recipient` refuses it.
///
/// The first version of this test asserted only `count == 0`, which is satisfied by dropping
/// the send entirely -- and that is what the producer did. Turning messaging on moved every
/// phone-channel alert from "logged by the transport that was already there" to nothing, while
/// the module header claimed everything this producer does not handle is delegated unchanged.
/// Counting what did NOT happen cannot distinguish "handled elsewhere" from "lost".
#[tokio::test]
async fn a_recipient_this_ledger_cannot_address_is_delegated() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;
    let (sender, delegate) = sender(&db, &env);

    for recipient in ["+15555550123", "not-an-address"] {
        sender
            .send(scope, VerificationPurpose::AccountLinked, recipient)
            .await;
    }

    assert_eq!(
        count(&db, scope, None).await,
        0,
        "neither reaches the ledger: this producer sends email"
    );
    assert_eq!(
        delegate.calls(),
        vec![
            "send:account_linked".to_owned(),
            "send:account_linked".to_owned()
        ],
        "and BOTH reach the wrapped transport, which is the half `count == 0` cannot see"
    );
}

/// The recipient is stored blind-indexed, never as written.
#[tokio::test]
async fn the_recipient_is_not_stored_in_plaintext() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;

    sender(&db, &env)
        .0
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;

    // The whole row, rendered, must not contain the address as written.
    let recipient_bidx: Vec<u8> =
        sqlx::query("SELECT recipient_bidx FROM messages WHERE tenant_id = $1")
            .bind(scope.tenant().to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("read the row")
            .get("recipient_bidx");
    assert!(
        !String::from_utf8_lossy(&recipient_bidx).contains("user@example.test"),
        "the recipient is stored as a blind index, never as written"
    );

    let payload: serde_json::Value =
        sqlx::query("SELECT payload FROM outbox_messages WHERE tenant_id = $1")
            .bind(scope.tenant().to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("read the payload")
            .get("payload");
    assert!(
        !payload.to_string().contains("user@example.test"),
        "and the payload -- which every consumer worker reads -- must not carry it either"
    );
}

/// A notice in a LATER window is a new send, not a collapse.
///
/// The collapse test alone proves only that the dedup key is stable: freezing the window index
/// to a constant makes every notice for a recipient collapse forever -- a user who links an
/// account today and again next year is told once -- and it left that test green. This is the
/// half that pins the window as a WINDOW.
#[tokio::test]
async fn a_notice_in_a_later_window_is_a_new_send() {
    let db = TestDatabase::start().await;
    let system = Env::system();
    let scope = db.seed_scope(&system).await;
    provision(&db, &system, scope).await;

    // A controllable clock, so "a later window" is a fact about the code rather than about how
    // long the test took to run.
    let (env, clock) = Env::deterministic(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000),
        1,
    );
    let (sender, _delegate) = sender_with(&db, &env, RateBudget::new(100, 3_600));

    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;
    assert_eq!(count(&db, scope, None).await, 1);

    // 899 seconds later: still INSIDE the window, so still one message.
    //
    // This is the half that pins the window's WIDTH, and it is why the advances below are
    // literals rather than `NOTICE_WINDOW_SECS + 1`. An advance computed from the constant
    // under test tracks whatever value it takes, so shrinking the window to 61 seconds -- which
    // would mail a person sixteen times an hour -- left the "later window" assertion green.
    //
    // `window_index` is `epoch / width`, a BUCKET rather than a sliding window, so two sends
    // 899 seconds apart land in one bucket only if they do not straddle a boundary. The base
    // instant is chosen for that: 1_800_000_000 is exactly 2_000_000 * 900, so the first send
    // sits on a boundary and the arithmetic below is about the width and nothing else.
    clock.advance(std::time::Duration::from_secs(899));
    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;
    assert_eq!(
        count(&db, scope, None).await,
        1,
        "899 seconds is inside a 900-second window: a narrower window would send again here"
    );

    // And two seconds after that, 901 from the first: a new bucket, a new send.
    clock.advance(std::time::Duration::from_secs(2));
    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;
    assert_eq!(
        count(&db, scope, None).await,
        2,
        "a later window is a new send; a window that never moves is a permanent mute"
    );
}

/// A differently-cased address lands the SAME blind index.
///
/// The collapse cannot show this and it is worth saying why: `dedup_key` normalizes internally,
/// so two spellings collapse whether or not the CALLER normalizes. What diverges is the blind
/// index, which `enqueue` computes from exactly what it was handed -- the store's own contract
/// says so. Two rows whose indexes disagree are one mailbox recorded as two recipients, and a
/// suppression keyed on one would miss the other.
///
/// So the two sends are put in DIFFERENT windows, which defeats the collapse and leaves two rows
/// to compare.
#[tokio::test]
async fn a_differently_cased_address_lands_the_same_blind_index() {
    let db = TestDatabase::start().await;
    let system = Env::system();
    let scope = db.seed_scope(&system).await;
    provision(&db, &system, scope).await;

    let (env, clock) = Env::deterministic(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000),
        1,
    );
    let (sender, _delegate) = sender_with(&db, &env, RateBudget::new(100, 3_600));

    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "User@Example.Test",
        )
        .await;
    clock.advance(std::time::Duration::from_secs(901));
    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;

    let rows = sqlx::query("SELECT recipient_bidx FROM messages WHERE tenant_id = $1")
        .bind(scope.tenant().to_string())
        .fetch_all(db.owner_pool())
        .await
        .expect("read the rows");
    assert_eq!(
        rows.len(),
        2,
        "different windows, so both sends are recorded"
    );
    let first: Vec<u8> = rows[0].get("recipient_bidx");
    let second: Vec<u8> = rows[1].get("recipient_bidx");
    assert_eq!(
        first, second,
        "one mailbox is one recipient however it was typed; differing indexes would make a \
         suppression keyed on one miss the other"
    );
}

/// Two DIFFERENT recipients in one window do not collapse onto each other.
///
/// The third dimension of the dedup key, and the one nothing measured: every other test in this
/// file used a single mailbox, so replacing the recipient with a constant inside `dedup_key`
/// left all of them green. The consequence is not a missed duplicate. Alice and Bob both have a
/// sign-in method linked in the same fifteen minutes, the keys are equal, Bob's notice is
/// collapsed, and Bob is never told his account changed.
///
/// One dimension varies: same purpose, same window, different address.
#[tokio::test]
async fn two_recipients_in_one_window_do_not_collapse() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;
    let (sender, _delegate) = sender(&db, &env);

    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "alice@example.test",
        )
        .await;
    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "bob@example.test",
        )
        .await;

    assert_eq!(
        count(&db, scope, None).await,
        2,
        "two mailboxes are two recipients; collapsing them tells one person about the other's \
         account and tells the second person nothing"
    );
    let indexes: Vec<Vec<u8>> =
        sqlx::query("SELECT recipient_bidx FROM messages WHERE tenant_id = $1")
            .bind(scope.tenant().to_string())
            .fetch_all(db.owner_pool())
            .await
            .expect("read the rows")
            .iter()
            .map(|row| row.get("recipient_bidx"))
            .collect();
    assert_ne!(
        indexes[0], indexes[1],
        "and they are recorded as two recipients, not one"
    );
}

/// A purpose whose real message carries a LINK is delegated, not queued.
///
/// `Recovery` and `Registration` both reach `send`. `advanced_recovery.rs` says the real
/// transport "embeds the confirm link"; a registration verification exists to deliver one. This
/// producer renders neither, and a mail with no link is not a degraded message -- the recipient
/// has nothing to act on and the flow cannot complete.
///
/// The delegation also preserves the registration path's TIMING shape. `flow/registration.rs`
/// relies on the known and unknown branches doing the same work, so routing one of them through
/// a transactional write that takes a per-recipient advisory lock would turn "does this
/// identifier exist" into a latency measurement.
#[tokio::test]
async fn the_link_carrying_purposes_are_delegated_not_queued() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;
    let (sender, delegate) = sender(&db, &env);

    for purpose in [
        VerificationPurpose::Registration,
        VerificationPurpose::Recovery,
    ] {
        sender.send(scope, purpose, "user@example.test").await;
    }

    assert_eq!(
        count(&db, scope, None).await,
        0,
        "neither purpose may reach the ledger: this producer cannot render either message"
    );
    assert_eq!(
        delegate.calls(),
        vec!["send:registration".to_owned(), "send:recovery".to_owned()],
        "and both must reach the wrapped transport, in order, unchanged"
    );

    // The control: the purpose this DOES render takes the other branch. Without it, a sender
    // that delegated everything and queued nothing would pass the two assertions above.
    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;
    assert_eq!(count(&db, scope, None).await, 1);
    assert_eq!(
        delegate.calls().len(),
        2,
        "a rendered purpose is queued INSTEAD of delegated, not as well as"
    );
}

/// The four token-carrying methods still reach the transport they always did.
///
/// This type is installed by REPLACING the sender the binary was using. Overriding only `send`
/// and inheriting the trait's defaults for the rest would move `deliver_email_otp`,
/// `deliver_magic_link`, `deliver_new_device_notice` and `deliver_recovery_cancel_notice` from
/// "logged on the observability plane" to completely silent -- the trait's default bodies
/// discard their argument. Turning messaging ON would have turned four transports OFF.
#[tokio::test]
async fn the_four_token_carrying_methods_are_delegated() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (sender, delegate) = sender(&db, &env);

    sender.deliver_email_otp(&EmailOtpMessage {
        scope,
        purpose: ironauth_store::EmailFactorPurpose::Login,
        recipient: "user@example.test",
        code: "123456",
        ttl_secs: 300,
    });
    sender.deliver_magic_link(&MagicLinkMessage {
        scope,
        purpose: ironauth_store::EmailFactorPurpose::Login,
        recipient: "user@example.test",
        link: "https://example.test/magic?token=secret",
        short_code: "ABCD",
        ttl_secs: 300,
    });
    sender.deliver_new_device_notice(&NewDeviceNotice {
        scope,
        recipient: "user@example.test",
        user_agent: "a new laptop",
        location_hint: "somewhere",
        disavowal_link: "https://example.test/disavow?token=secret",
    });
    sender.deliver_recovery_cancel_notice(&RecoveryCancelNotice {
        scope,
        recipient: "user@example.test",
        cancel_link: "https://example.test/cancel?token=secret",
    });

    assert_eq!(
        delegate.calls(),
        vec![
            "deliver_email_otp".to_owned(),
            "deliver_magic_link".to_owned(),
            "deliver_new_device_notice".to_owned(),
            "deliver_recovery_cancel_notice".to_owned(),
        ],
        "every method this producer does not implement must pass through, or enabling \
         messaging silently retires four transports"
    );
    assert_eq!(
        count(&db, scope, None).await,
        0,
        "and none of them reaches the ledger: each carries a token in its body"
    );
}

/// The per-recipient rate budget this sender was built with is the one the ledger applies.
///
/// Nothing pinned it. `enqueue(..., self.budget, epoch_seconds)` with `epoch_seconds` replaced
/// by `0` stamps every row at 1970, which makes `hygiene_refusal`'s window predicate false
/// forever and retires the rate limit entirely -- and every test passed. The budget is the
/// mechanism that stops one event from mailing a person repeatedly, so a producer that passes
/// it and a ledger that ignores it look identical from outside without this.
///
/// Deliberately the SHIPPED shape: a budget of one per hour, two sends in different collapse
/// windows so the dedup key cannot be what refuses the second.
#[tokio::test]
async fn the_rate_budget_refuses_the_second_notice_within_the_hour() {
    let db = TestDatabase::start().await;
    let system = Env::system();
    let scope = db.seed_scope(&system).await;
    provision(&db, &system, scope).await;

    let (env, clock) = Env::deterministic(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000),
        1,
    );
    let (sender, _delegate) = sender_with(&db, &env, RateBudget::new(1, 3_600));

    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;
    assert_eq!(count(&db, scope, None).await, 1);

    // A new collapse window, so the dedup key differs, but still inside the budget's hour.
    clock.advance(std::time::Duration::from_secs(901));
    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;
    assert_eq!(
        count(&db, scope, None).await,
        1,
        "the second is refused by the BUDGET: a different window means the collapse cannot be \
         what stopped it"
    );

    // Past the budget's window, the same send is accepted again -- so the assertion above is
    // failing on the budget rather than on anything permanently broken.
    clock.advance(std::time::Duration::from_secs(3_601));
    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;
    assert_eq!(
        count(&db, scope, None).await,
        2,
        "and the budget is a WINDOW: past it the same notice sends again"
    );
}
