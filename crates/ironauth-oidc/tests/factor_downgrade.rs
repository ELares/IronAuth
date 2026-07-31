// SPDX-License-Identifier: MIT OR Apache-2.0

//! The no-silent-downgrade sweep (issue #267), against a real Postgres.
//!
//! Issue #70 shipped the invariant for SMS as a private helper inside `sms_otp.rs`. The
//! email possession family never got it: the email OTP, the magic link, and the headless
//! recovery journey all fell through to a primary session mint with no probe at all, so
//! an actor who controlled a mailbox took over a passkey-protected account, and an `mfa`
//! or `verify_address` code minted a full login by itself.
//!
//! # Why this file iterates a registry instead of listing tests
//!
//! A gate that fences five surfaces and is proven on one is the failure mode this project
//! keeps shipping. The subject list here is
//! [`GatedSessionPath::ALL`](ironauth_oidc::factor_downgrade::GatedSessionPath::ALL), the
//! SAME registry the production call sites name when they invoke the gate, so:
//!
//! - a new gated surface must add a variant (it cannot call the gate otherwise), and the
//!   exhaustive `match` in [`drive_path`] then fails to COMPILE until it is driven here;
//! - a variant DELETED from `ALL` fails the length assertion in
//!   [`every_gated_path_is_actually_driven`], in THIS binary. That assertion carries the
//!   whole weight in that direction: the two mechanisms are asymmetric, because adding a
//!   variant is compiler-enforced (two `E0004` non-exhaustive matches in production plus
//!   one here) while deleting one from a fixed-size array is not, and every sweep would
//!   go on passing with the fourth path silently undriven;
//! - [`every_gated_path_is_actually_driven`] proves each subject reaches a genuine mint on
//!   an UNPROTECTED account, so a driver that silently stopped exercising its surface
//!   (a typo'd route, a harness that no longer enables the factor) fails rather than
//!   passing vacuously by refusing for the wrong reason.
//!
//! What neither mechanism covers, stated rather than claimed away: a NEW production call
//! site that REUSES an existing variant is gated, but nothing here makes it separately
//! driven. The registry proves the set of gated SURFACES, not the set of call sites.
//!
//! # Two oracles this file deliberately does not derive from the code
//!
//! [`expected_when_unprotected_and_opted_in`] is a literal per-purpose table rather than a
//! call to `EmailFactorPurpose::establishes_session`, and the acr comparison is exercised
//! through a driven surface rather than through the production ordering. Both are cases
//! where reusing the production predicate would make the assertion move with the defect.

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_oidc::factor_downgrade::GatedSessionPath;
use ironauth_oidc::flow::model::{Journey, Transport};
use ironauth_oidc::flow::{Continuation, Submission, TransportAuth, create_flow, drive};
use ironauth_oidc::{
    Argon2Params, EmailOtpMessage, HashingPool, MagicLinkMessage, SESSION_COOKIE, SmsOtpMessage,
    SmsSender, VerificationPurpose, VerificationSender,
};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery staple";
const BINDING_COOKIE: &str = "__Host-ironauth_magic_binding";

// ------------------------------------------------------------------------------------------
// Recording transports.
// ------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct RecordingSender {
    otp: Mutex<Vec<(String, String)>>,
    magic: Mutex<Vec<(String, String, String)>>,
}

impl VerificationSender for RecordingSender {
    fn send(&self, _scope: ironauth_store::Scope, _purpose: VerificationPurpose, _recipient: &str) {
    }

    fn deliver_email_otp(&self, message: &EmailOtpMessage<'_>) {
        self.otp
            .lock()
            .expect("lock")
            .push((message.recipient.to_owned(), message.code.to_owned()));
    }

    fn deliver_magic_link(&self, message: &MagicLinkMessage<'_>) {
        self.magic.lock().expect("lock").push((
            message.recipient.to_owned(),
            message.link.to_owned(),
            message.short_code.to_owned(),
        ));
    }
}

#[derive(Debug, Default)]
struct RecordingSms {
    sent: Mutex<Vec<(String, String)>>,
}

impl SmsSender for RecordingSms {
    fn send(&self, message: &SmsOtpMessage<'_>) {
        self.sent
            .lock()
            .expect("lock")
            .push((message.recipient.to_owned(), message.code.to_owned()));
    }
}

// ------------------------------------------------------------------------------------------
// The harness: every gated factor live at once, so ONE fixture drives all four surfaces.
// ------------------------------------------------------------------------------------------

/// The email identifier the mailbox-family surfaces resolve.
const EMAIL: &str = "ada@example.test";
/// The phone identifier the SMS surface resolves. It is a SEPARATE account because the
/// SMS surface resolves its subject by phone number; the gate is per-subject, so both
/// accounts are protected identically.
const PHONE: &str = "+14155550100";

struct Fixture {
    harness: Harness,
    sender: Arc<RecordingSender>,
    sms: Arc<RecordingSms>,
}

/// What the scope's `email_factor_config` says, INCLUDING saying nothing at all.
///
/// The third state is the point. `fixture` originally always wrote a row, even for the
/// refusing value, so every "the downgrade is refused" assertion in this file measured
/// only "refused because a row said false". The claim made in `EmailFactorConfigRepo`, in
/// `email_otp`, and in migration 0097 is stronger than that: a scope with NO row also
/// refuses. Nothing exercised it, and a reader that resolved a missing row to
/// `allow_factor_downgrade: true` passed the whole suite.
///
/// It is also the state that matters most. Migration 0097 back-fills nothing, so
/// [`Self::NoRow`] is the day-one state of EVERY tenant that exists when it is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmailDowngrade {
    /// No `email_factor_config` row for the scope at all.
    NoRow,
    /// An explicit row that REFUSES the downgrade.
    Denied,
    /// An explicit row that PERMITS it: the deliberate per-tenant opt-in.
    Allowed,
}

/// A harness with the email OTP, the magic link, the SMS OTP, and the flow engine all
/// live. `protected` seeds a passkey on BOTH accounts (the stronger factor the gate is
/// meant to defend); `email` and `sms_opt_in` set the two per-tenant downgrade opt-ins.
async fn fixture(protected: bool, email: EmailDowngrade, sms_opt_in: bool) -> Fixture {
    fixture_with_acr_order(protected, email, sms_opt_in, Vec::new()).await
}

/// [`fixture`], with an explicit deployment `oidc.acr_order` override.
///
/// An empty vector means "no override", which falls back to the canonical ladder at read
/// time and is what every test but the acr-order one wants.
async fn fixture_with_acr_order(
    protected: bool,
    email: EmailDowngrade,
    sms_opt_in: bool,
    acr_order: Vec<String>,
) -> Fixture {
    let mut harness = Harness::start_store_backed_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        sms_otp_enabled: true,
        sms_send_cooldown_secs: 0,
        sms_per_number_window_secs: 1,
        sms_per_number_send_cap: 50,
        sms_per_tenant_window_secs: 1,
        sms_per_tenant_send_cap: 10_000,
        sms_per_route_window_secs: 1,
        sms_per_route_send_cap: 10_000,
        sms_conversion_min_samples: 1_000,
        sms_conversion_alarm_threshold_percent: 0,
        acr_order,
        regulation: RegulationConfig {
            enabled: false,
            ..RegulationConfig::default()
        },
        ..OidcConfig::default()
    })
    .await;
    harness.enable_flows();
    let sender = Arc::new(RecordingSender::default());
    harness.install_verification_sender(sender.clone());
    let sms = Arc::new(RecordingSms::default());
    harness.install_sms_sender(sms.clone());
    // A cheap deterministic Argon2 pool: every surface here hashes a one-time code, and
    // the default parameters make a four-surface sweep needlessly slow.
    harness.install_hashing_pool(Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    )));
    harness.enable_sms(sms_opt_in, &["1"]).await;
    // NOT unconditional: `NoRow` must leave the scope with no row, which is the state
    // migration 0097 leaves every existing tenant in.
    match email {
        EmailDowngrade::NoRow => {}
        EmailDowngrade::Denied => harness.enable_email_factor_downgrade(false).await,
        EmailDowngrade::Allowed => harness.enable_email_factor_downgrade(true).await,
    }

    let email_subject = harness.seed_user(EMAIL, PASSWORD).await;
    let phone_subject = harness.seed_user(PHONE, PASSWORD).await;
    if protected {
        harness.seed_passkey(&email_subject, true).await;
        harness.seed_passkey(&phone_subject, true).await;
    }
    Fixture {
        harness,
        sender,
        sms,
    }
}

fn base(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}", scope.tenant(), scope.environment())
}

// ------------------------------------------------------------------------------------------
// Request helpers.
// ------------------------------------------------------------------------------------------

async fn post_json(harness: &Harness, path: &str, body: &Value) -> (StatusCode, HeaderMap, Value) {
    let (status, headers, raw) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await;
    let parsed = if raw.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&raw).unwrap_or(Value::Null)
    };
    (status, headers, parsed)
}

async fn post_form(
    harness: &Harness,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    harness
        .send(
            builder
                .body(Body::from(body.to_owned()))
                .expect("request builds"),
        )
        .await
}

/// Whether the response SET the primary session cookie. This is the one observation that
/// matters: a downgrade is a SESSION, not a status code.
fn sets_session_cookie(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value.starts_with(SESSION_COOKIE) && !value.contains(&format!("{SESSION_COOKIE}=;"))
        })
}

fn cookie_pair(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(name))
        .and_then(|value| value.split(';').next())
        .map(str::to_owned)
}

fn last_email_code(fixture: &Fixture) -> String {
    fixture
        .sender
        .otp
        .lock()
        .expect("lock")
        .iter()
        .rev()
        .find(|(to, _)| to == EMAIL)
        .map(|(_, code)| code.clone())
        .expect("an email code was delivered")
}

fn last_sms_code(fixture: &Fixture) -> String {
    fixture
        .sms
        .sent
        .lock()
        .expect("lock")
        .iter()
        .rev()
        .find(|(to, _)| to == PHONE)
        .map(|(_, code)| code.clone())
        .expect("an SMS code was delivered")
}

fn token_from_link(link: &str) -> String {
    if let Some((_, token)) = link.rsplit_once("?token=") {
        token.to_owned()
    } else if let Some((_, token)) = link.rsplit_once('#') {
        token.to_owned()
    } else {
        panic!("no token in link: {link}");
    }
}

// ------------------------------------------------------------------------------------------
// THE driver: one arm per gated surface, exhaustive so a new surface cannot be undriven.
// ------------------------------------------------------------------------------------------

/// What a completed proof produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// A PRIMARY session was established (a cookie was set, or the flow engine completed).
    SessionMinted,
    /// No session: the surface refused, or produced a non-session possession proof.
    NoSession,
}

/// Drive `path` end to end with a GENUINE, correct proof for the given purpose, and report
/// whether a primary session came out.
///
/// The `match` is exhaustive on [`GatedSessionPath`], which is what makes the sweep unable
/// to shrink: a surface added to the registry does not compile until it is driven here.
// One exhaustive match, one arm per surface, is the whole point: splitting the arms into
// per-surface helpers would let a surface be dropped from the match without the compiler
// noticing, which is exactly the failure this file exists to prevent. The length lint is
// allowed here rather than the structure being weakened.
#[allow(clippy::too_many_lines)]
async fn drive_path(fixture: &Fixture, path: GatedSessionPath, purpose: &str) -> Outcome {
    let base = base(&fixture.harness);
    match path {
        GatedSessionPath::EmailOtpVerify => {
            post_json(
                &fixture.harness,
                &format!("{base}/otp/send"),
                &json!({ "identifier": EMAIL, "purpose": purpose }),
            )
            .await;
            let code = last_email_code(fixture);
            let (_status, headers, body) = post_json(
                &fixture.harness,
                &format!("{base}/otp/verify"),
                &json!({ "identifier": EMAIL, "purpose": purpose, "code": code }),
            )
            .await;
            if sets_session_cookie(&headers) || body["authenticated"] == json!(true) {
                Outcome::SessionMinted
            } else {
                Outcome::NoSession
            }
        }
        GatedSessionPath::MagicLinkConsume => {
            let (_status, send_headers, _) = post_form(
                &fixture.harness,
                &format!("{base}/magic/send"),
                &format!("identifier={EMAIL}&purpose={purpose}"),
                None,
            )
            .await;
            let binding =
                cookie_pair(&send_headers, BINDING_COOKIE).expect("binding cookie set on send");
            let link = fixture
                .sender
                .magic
                .lock()
                .expect("lock")
                .last()
                .cloned()
                .expect("a link was delivered")
                .1;
            let token = token_from_link(&link);
            let (_status, headers, _body) = post_form(
                &fixture.harness,
                &format!("{base}/magic/consume"),
                &format!("token={token}"),
                Some(&binding),
            )
            .await;
            if sets_session_cookie(&headers) {
                Outcome::SessionMinted
            } else {
                Outcome::NoSession
            }
        }
        GatedSessionPath::SmsOtpVerify => {
            post_json(
                &fixture.harness,
                &format!("{base}/otp/sms/send"),
                &json!({ "identifier": PHONE, "purpose": purpose }),
            )
            .await;
            let code = last_sms_code(fixture);
            let (_status, headers, body) = post_json(
                &fixture.harness,
                &format!("{base}/otp/sms/verify"),
                &json!({ "identifier": PHONE, "purpose": purpose, "code": code }),
            )
            .await;
            if sets_session_cookie(&headers) || body["authenticated"] == json!(true) {
                Outcome::SessionMinted
            } else {
                Outcome::NoSession
            }
        }
        GatedSessionPath::FlowRecoveryVerify => {
            // The headless recovery journey always proves a RECOVERY code; it has no
            // per-purpose wire input, so `purpose` is not applicable and the sweep drives
            // it once (the per-purpose sweep below skips it for that reason).
            assert_eq!(
                purpose, "recovery",
                "the recovery journey has no purpose input; drive it as recovery"
            );
            let (flow_id, token0, _start) = create_flow(
                fixture.harness.state(),
                fixture.harness.scope(),
                Transport::Api,
                Journey::Recovery,
                None,
                None,
                None,
                &HeaderMap::new(),
            )
            .await
            .expect("create recovery flow");
            let ack = drive(
                fixture.harness.state(),
                fixture.harness.scope(),
                &flow_id,
                Transport::Api,
                TransportAuth::Api {
                    presented_submit_token: token0,
                },
                submission(&[("identifier", EMAIL)]),
                &HeaderMap::new(),
            )
            .await
            .expect("submit the identifier");
            let Continuation::Render {
                submit_token: token1,
                ..
            } = ack
            else {
                panic!("the recovery ack must be a render");
            };
            let code = last_email_code(fixture);
            let completion = drive(
                fixture.harness.state(),
                fixture.harness.scope(),
                &flow_id,
                Transport::Api,
                TransportAuth::Api {
                    presented_submit_token: token1,
                },
                submission(&[("code", &code)]),
                &HeaderMap::new(),
            )
            .await;
            match completion {
                Ok(Continuation::Complete { .. }) => Outcome::SessionMinted,
                _ => Outcome::NoSession,
            }
        }
    }
}

fn submission(values: &[(&str, &str)]) -> Submission {
    let mut node_values: BTreeMap<String, Value> = BTreeMap::new();
    for (name, value) in values {
        node_values.insert((*name).to_owned(), json!(value));
    }
    Submission {
        node_values,
        transient_payload: None,
    }
}

/// The session-establishing purpose each surface is driven with in the sweep. The flow
/// recovery journey has no wire purpose (it is always `recovery`).
fn sweep_purpose(path: GatedSessionPath) -> &'static str {
    match path {
        GatedSessionPath::EmailOtpVerify
        | GatedSessionPath::MagicLinkConsume
        | GatedSessionPath::SmsOtpVerify => "login",
        GatedSessionPath::FlowRecoveryVerify => "recovery",
    }
}

/// Every SESSION-ESTABLISHING purpose a surface can be driven with, for the opt-in sweep.
/// The flow recovery journey has no wire purpose input, so it contributes only `recovery`.
fn opt_in_purposes(path: GatedSessionPath) -> &'static [&'static str] {
    match path {
        GatedSessionPath::EmailOtpVerify
        | GatedSessionPath::MagicLinkConsume
        | GatedSessionPath::SmsOtpVerify => &["login", "register", "recovery"],
        GatedSessionPath::FlowRecoveryVerify => &["recovery"],
    }
}

// ------------------------------------------------------------------------------------------
// The sweep.
// ------------------------------------------------------------------------------------------

/// THE anti-vacuity control. Every subject in the registry must reach a GENUINE session
/// mint on an UNPROTECTED account. Without this, a driver that no longer exercises its
/// surface (a wrong route, a factor the harness stopped enabling, a proof that never
/// arrives) would report `NoSession` and pass the refusal sweep for entirely the wrong
/// reason, which is precisely how a five-path gate gets proven on one.
#[tokio::test]
async fn every_gated_path_is_actually_driven() {
    // The registry cannot SHRINK unnoticed. Adding a variant is compiler-enforced (the
    // exhaustive `match` in `drive_path` and the two in production fail with E0004), but
    // DELETING one from `ALL` is not: the sweeps below would simply iterate three paths
    // and still pass, with the fourth silently undriven. The length is asserted here, in
    // the binary that does the driving, rather than only in a unit test in another crate
    // that a reader of this file has no reason to look for.
    //
    // The residual neither mechanism covers: a NEW production call site that reuses an
    // EXISTING variant is gated but never separately driven, because it is invisible to
    // both the compiler and this count. That gap is real and is not claimed away.
    assert_eq!(
        GatedSessionPath::ALL.len(),
        4,
        "a gated surface was added to or removed from the registry; drive it here"
    );
    for path in GatedSessionPath::ALL {
        let fixture = fixture(false, EmailDowngrade::NoRow, false).await;
        let outcome = drive_path(&fixture, path, sweep_purpose(path)).await;
        assert_eq!(
            outcome,
            Outcome::SessionMinted,
            "{} must mint a session for an UNPROTECTED account; if it does not, this \
             driver is not exercising the surface and every refusal it reports is vacuous",
            path.as_str()
        );
    }
}

/// The invariant, on EVERY gated surface: an account protected by a stronger factor gets
/// NO primary session from a weak possession proof unless the scope opted in.
///
/// Before issue #267 this passed for `sms_otp_verify` alone; `email_otp_verify`,
/// `magic_link_consume`, and `flow_recovery_verify` each minted a full session over a
/// passkey.
///
/// The scope has NO `email_factor_config` row, deliberately: that is the day-one state of
/// every tenant migration 0097 is applied to, and the state in which the refusal rests
/// entirely on the reader resolving a missing row to the refusing default. The
/// explicit-row twin is [`an_explicit_refusing_row_blocks_every_gated_path`].
#[tokio::test]
async fn no_gated_path_downgrades_a_protected_account() {
    for path in GatedSessionPath::ALL {
        let fixture = fixture(true, EmailDowngrade::NoRow, false).await;
        let outcome = drive_path(&fixture, path, sweep_purpose(path)).await;
        assert_eq!(
            outcome,
            Outcome::NoSession,
            "{} must NOT mint a primary session for an account holding a passkey when \
             the scope has NO email_factor_config row at all",
            path.as_str()
        );
    }
}

/// The same invariant with the row PRESENT and saying false.
///
/// Split from the no-row sweep rather than folded into it: the two are different claims
/// with different failure modes, and running only the row-present one is what let a
/// missing-row fall-open go undetected. The store-level twin of this pair is
/// [`a_scope_with_no_row_reads_as_refusing`], which pins the reader directly.
#[tokio::test]
async fn an_explicit_refusing_row_blocks_every_gated_path() {
    for path in GatedSessionPath::ALL {
        let fixture = fixture(true, EmailDowngrade::Denied, false).await;
        let outcome = drive_path(&fixture, path, sweep_purpose(path)).await;
        assert_eq!(
            outcome,
            Outcome::NoSession,
            "{} must NOT mint a primary session for a passkey-protected account whose \
             scope has a row saying the downgrade is refused",
            path.as_str()
        );
    }
}

/// The reader, directly: a scope with NO row resolves to the REFUSING default.
///
/// `EmailFactorConfigRepo::config`, `email_otp`, and migration 0097 all state this, and
/// before issue #267's review nothing exercised it. Asserted at the store rather than
/// only through a driven surface, so the claim is pinned where it is made.
#[tokio::test]
async fn a_scope_with_no_row_reads_as_refusing() {
    let no_row = fixture(false, EmailDowngrade::NoRow, false).await;
    let config = no_row
        .harness
        .store()
        .scoped(no_row.harness.scope())
        .email_factor_config()
        .config()
        .await
        .expect("read the email factor config");
    assert!(
        !config.allow_factor_downgrade,
        "a scope with no email_factor_config row must read as REFUSING the downgrade; \
         0097 back-fills nothing, so this is the day-one state of every existing tenant"
    );

    // The control: a row that says true reads as true. Without it, a reader hard-wired to
    // return false would satisfy the assertion above.
    let opted_in = fixture(false, EmailDowngrade::Allowed, false).await;
    let config = opted_in
        .harness
        .store()
        .scoped(opted_in.harness.scope())
        .email_factor_config()
        .config()
        .await
        .expect("read the email factor config");
    assert!(
        config.allow_factor_downgrade,
        "a row that permits the downgrade must read as permitting it"
    );
}

/// The complement, on EVERY gated surface: the EXPLICIT per-tenant opt-in restores the
/// mint. This is what proves the refusal above is the GATE talking and not some unrelated
/// failure on the protected fixture (a passkey seed that broke the account, a lifecycle
/// fence, a route that stopped working).
///
/// The opt-in ON position is swept over EVERY session-establishing purpose, not just
/// `login`. A gate that read the opt-in on one purpose and ignored it on another would
/// pass a login-only version of this test while silently locking a tenant out of the
/// `register` and `recovery` paths it had deliberately enabled.
#[tokio::test]
async fn the_explicit_opt_in_restores_every_gated_path() {
    for path in GatedSessionPath::ALL {
        for purpose in opt_in_purposes(path) {
            let fixture = fixture(true, EmailDowngrade::Allowed, true).await;
            let outcome = drive_path(&fixture, path, purpose).await;
            assert_eq!(
                outcome,
                Outcome::SessionMinted,
                "{} on purpose {purpose} must mint again under the explicit per-tenant \
                 downgrade opt-in; if it does not, the refusal above was not the \
                 downgrade gate",
                path.as_str()
            );
        }
    }
}

/// An ACTIVE TOTP is a stronger factor too, on every surface. The passkey sweep above
/// exercises the `phr` rung; this exercises the `mfa` rung, so a gate that only compared
/// against passkeys would fail here.
#[tokio::test]
async fn an_active_totp_blocks_every_gated_path() {
    for path in GatedSessionPath::ALL {
        let fixture = fixture(false, EmailDowngrade::NoRow, false).await;
        for identifier in [EMAIL, PHONE] {
            let subject = fixture
                .harness
                .store()
                .scoped(fixture.harness.scope())
                .users()
                .by_identifier(identifier)
                .await
                .expect("lookup")
                .expect("user")
                .id
                .to_string();
            fixture.harness.seed_active_totp(&subject).await;
        }
        let outcome = drive_path(&fixture, path, sweep_purpose(path)).await;
        assert_eq!(
            outcome,
            Outcome::NoSession,
            "{} must NOT mint a primary session for a TOTP-protected account",
            path.as_str()
        );
    }
}

/// An UNCONSUMED recovery-code set is an `mfa`-rung factor (issue #81 places
/// `RecoveryFactor::RecoveryCode` there), and the issue #70 SMS probe ignored it: an
/// account whose TOTP had been removed but whose recovery codes survived was treated as
/// unprotected. This is the SMS gate's OWN incompleteness, so it is swept on every
/// surface including `sms_otp_verify`, which fails against the pre-#267 helper.
#[tokio::test]
async fn surviving_recovery_codes_block_every_gated_path() {
    for path in GatedSessionPath::ALL {
        let fixture = fixture(false, EmailDowngrade::NoRow, false).await;
        for identifier in [EMAIL, PHONE] {
            let subject = fixture
                .harness
                .store()
                .scoped(fixture.harness.scope())
                .users()
                .by_identifier(identifier)
                .await
                .expect("lookup")
                .expect("user")
                .id
                .to_string();
            fixture.harness.seed_recovery_code(&subject).await;
        }
        let outcome = drive_path(&fixture, path, sweep_purpose(path)).await;
        assert_eq!(
            outcome,
            Outcome::NoSession,
            "{} must NOT mint a primary session for an account holding unconsumed \
             recovery codes (an mfa-rung factor the issue #70 probe ignored)",
            path.as_str()
        );
    }
}

// ------------------------------------------------------------------------------------------
// The purpose split (issue #267), swept over EVERY purpose rather than a hand-picked few.
// ------------------------------------------------------------------------------------------

/// NO purpose mints a primary session for a protected account, on the surfaces that
/// accept a wire purpose.
///
/// The subject list is [`ironauth_store::EmailFactorPurpose::ALL`], the same registry the
/// production `establishes_session` predicate matches on, so a purpose added later is
/// swept automatically. Before issue #267 the email surface fell through EVERY purpose to
/// a full primary session, so `mfa`, `verify_address`, and `register` each took the
/// account over.
#[tokio::test]
async fn no_purpose_mints_a_session_for_a_protected_account() {
    use ironauth_store::EmailFactorPurpose;
    for path in [
        GatedSessionPath::EmailOtpVerify,
        GatedSessionPath::MagicLinkConsume,
        GatedSessionPath::SmsOtpVerify,
    ] {
        for purpose in EmailFactorPurpose::ALL {
            let fixture = fixture(true, EmailDowngrade::NoRow, false).await;
            let outcome = drive_path(&fixture, path, purpose.as_str()).await;
            assert_eq!(
                outcome,
                Outcome::NoSession,
                "{} must not mint a primary session on purpose {} for a protected \
                 account without the opt-in",
                path.as_str(),
                purpose.as_str()
            );
        }
    }
}

/// Even WITH the opt-in, and even on an UNPROTECTED account, the non-session purposes
/// stay possession proofs: `mfa` and `verify_address` never set the session cookie.
///
/// This is the half of the invariant the downgrade gate does NOT cover. A reader could
/// otherwise conclude the purpose split is redundant with the gate; it is not, because the
/// gate is a no-op for an unprotected account and would let an `mfa` code sign the
/// presenter in, silently claiming a first factor that was never proven.
///
/// The expectation comes from [`expected_when_unprotected_and_opted_in`], a LITERAL table,
/// and deliberately not from `EmailFactorPurpose::establishes_session`. Production branches
/// on that same predicate, so deriving the oracle from it makes both sides move together:
/// moving `Mfa` into the session-establishing arm, which is literally the defect issue #267
/// names, left this suite fully green with the `mfa` OTP setting a real session cookie over
/// HTTP. The table cannot move with the code.
#[tokio::test]
async fn the_non_session_purposes_never_mint_even_unprotected_and_opted_in() {
    use ironauth_store::EmailFactorPurpose;
    for path in [
        GatedSessionPath::EmailOtpVerify,
        GatedSessionPath::MagicLinkConsume,
        GatedSessionPath::SmsOtpVerify,
    ] {
        for purpose in EmailFactorPurpose::ALL {
            let fixture = fixture(false, EmailDowngrade::Allowed, true).await;
            let outcome = drive_path(&fixture, path, purpose.as_str()).await;
            let expected = expected_when_unprotected_and_opted_in(purpose);
            assert_eq!(
                outcome,
                expected,
                "{} on purpose {} must {} for an unprotected, opted-in account",
                path.as_str(),
                purpose.as_str(),
                match expected {
                    Outcome::SessionMinted => "mint",
                    Outcome::NoSession => "stay a possession proof",
                }
            );
        }
    }
}

/// What each purpose must produce on an UNPROTECTED, opted-in account, written out.
///
/// A literal table, not a call to `EmailFactorPurpose::establishes_session`. The predicate
/// is what production branches on, so an oracle that calls it asserts only "the code agrees
/// with itself": flipping `Mfa` or `VerifyAddress` to session-establishing moves the
/// expectation with the behaviour and the whole integration suite stays green while an
/// `mfa` code mints a full login over HTTP. That is the exact defect issue #267 names, so
/// it is the one thing this file must not derive from the code under test.
///
/// The `match` is exhaustive, so a purpose added to the enum has to be classified HERE, by
/// hand, before this compiles.
// One arm per purpose, each with its own reason, is the point: collapsing the two
// non-session arms would make the table shorter and would also make it easier to move a
// purpose across the split without noticing which reason stopped applying.
#[allow(clippy::match_same_arms)]
fn expected_when_unprotected_and_opted_in(purpose: ironauth_store::EmailFactorPurpose) -> Outcome {
    use ironauth_store::EmailFactorPurpose;
    match purpose {
        // The one-time code IS the primary authenticator for these flows.
        EmailFactorPurpose::Login | EmailFactorPurpose::Register | EmailFactorPurpose::Recovery => {
            Outcome::SessionMinted
        }
        // A second factor elevating an EXISTING session is the step-up flow (issue #72);
        // minting a primary session from an `mfa` code alone would silently claim a first
        // factor that was never proven.
        EmailFactorPurpose::Mfa => Outcome::NoSession,
        // Address verification proves control of an identifier without signing anyone in.
        EmailFactorPurpose::VerifyAddress => Outcome::NoSession,
    }
}

/// A blocked downgrade CONSUMES the proven code (issue #70 adversarial review LOW,
/// extended to the email surface by issue #267): the block must not be a short circuit
/// that skips the resolve and the durable write a real attempt performs, and the
/// proven-but-refused code must be BURNED rather than left replayable.
#[tokio::test]
async fn a_blocked_email_downgrade_burns_the_proven_code() {
    use ironauth_store::EmailFactorPurpose;
    let fixture = fixture(true, EmailDowngrade::NoRow, false).await;
    let base = base(&fixture.harness);
    let subject = fixture
        .harness
        .store()
        .scoped(fixture.harness.scope())
        .users()
        .by_identifier(EMAIL)
        .await
        .expect("lookup")
        .expect("user")
        .id;

    post_json(
        &fixture.harness,
        &format!("{base}/otp/send"),
        &json!({ "identifier": EMAIL, "purpose": "login" }),
    )
    .await;
    let code = last_email_code(&fixture);
    let (status, headers, _) = post_json(
        &fixture.harness,
        &format!("{base}/otp/verify"),
        &json!({ "identifier": EMAIL, "purpose": "login", "code": code }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a blocked downgrade renders the SAME uniform invalid-code result a wrong code does"
    );
    assert!(
        !sets_session_cookie(&headers),
        "no session leaks on a blocked downgrade"
    );

    let active = fixture
        .harness
        .store()
        .scoped(fixture.harness.scope())
        .email_otp_codes()
        .resolve_active(&subject, EmailFactorPurpose::Login, 0)
        .await
        .expect("resolve");
    assert!(
        active.is_none(),
        "a blocked downgrade consumes the proven code (it ran the full resolve + \
         Argon2 compare + consume, not a fast short circuit)"
    );
    let (replay, _, _) = post_json(
        &fixture.harness,
        &format!("{base}/otp/verify"),
        &json!({ "identifier": EMAIL, "purpose": "login", "code": code }),
    )
    .await;
    assert_eq!(
        replay,
        StatusCode::UNAUTHORIZED,
        "the consumed code cannot be replayed"
    );
}

// ------------------------------------------------------------------------------------------
// The gate is not steerable by the deployment's step-up policy (issue #267).
// ------------------------------------------------------------------------------------------

/// A boot-VALID `oidc.acr_order` that inverts the ladder must not disable the gate.
///
/// The order below is a permutation of the six known rungs with no duplicate and no
/// unknown value, and it keeps `mfa_remembered` below `mfa`, so every rule that existed
/// before issue #267 accepted it. It ranks `pwd` (where every weak possession factor sits)
/// ABOVE the passkey rungs, so under a gate that compared through `state.acr_order()` a
/// passkey-protected account with no opt-in minted a session from a correct email OTP, on
/// every path, for every tenant in the deployment, from one configuration line.
///
/// The gate now compares through `step_up::default_acr_order`, the canonical ladder, which
/// no configuration can reach. Driven over HTTP rather than asserted on the comparison, so
/// it measures what the surfaces actually do.
#[tokio::test]
async fn a_misordered_acr_order_does_not_disable_the_gate() {
    let inverted: Vec<String> = [
        "phr",
        "phrh",
        "urn:ironauth:acr:attested_passkey",
        "urn:ironauth:acr:pwd",
        "urn:ironauth:acr:mfa_remembered",
        "urn:ironauth:acr:mfa",
    ]
    .iter()
    .map(|acr| (*acr).to_owned())
    .collect();
    for path in GatedSessionPath::ALL {
        let fixture =
            fixture_with_acr_order(true, EmailDowngrade::NoRow, false, inverted.clone()).await;
        let outcome = drive_path(&fixture, path, sweep_purpose(path)).await;
        assert_eq!(
            outcome,
            Outcome::NoSession,
            "{} must still refuse a passkey-protected account under an acr_order that \
             ranks pwd above the passkey rungs; this gate asks about intrinsic credential \
             strength and must not be steerable by the step-up policy knob",
            path.as_str()
        );
    }
}

// ------------------------------------------------------------------------------------------
// Fail CLOSED on a store fault, and the ordering that makes the refusal timing-uniform.
// ------------------------------------------------------------------------------------------

/// A store fault in the gate refuses the mint, and refuses it EARLY.
///
/// Two claims, measured through the one injection (the app role's read of
/// `email_factor_config` is revoked, so the gate's configuration read raises a genuine
/// `StoreError::Database`):
///
/// 1. FAIL CLOSED. No path mints, including on an account holding no stronger factor at
///    all, where the gate would otherwise have permitted the mint. The fault must never
///    fall back to the permissive default. Nothing shipped exercised this arm before; it
///    was verified only by mutation.
/// 2. The gate is decided BEFORE the presented code is judged. A WRONG code now answers
///    the server fault rather than the ordinary invalid-code refusal, which is only
///    possible if the gate's reads happen ahead of the compare. Under the previous
///    ordering (gate after a successful verify) a wrong code answered 401 and a correct
///    one answered 401 too, but the correct one had spent four more transactions getting
///    there, which is the timing distinguisher issue #267's review measured: 125
///    transactions for a wrong code against 129 for a correct-but-blocked one.
#[tokio::test]
async fn a_store_fault_in_the_gate_refuses_before_the_code_is_judged() {
    for protected in [true, false] {
        let fixture = fixture(protected, EmailDowngrade::NoRow, false).await;
        let base = base(&fixture.harness);
        post_json(
            &fixture.harness,
            &format!("{base}/otp/send"),
            &json!({ "identifier": EMAIL, "purpose": "login" }),
        )
        .await;
        let code = last_email_code(&fixture);
        fixture.harness.break_email_factor_config_reads().await;

        let (wrong_status, wrong_headers, _) = post_json(
            &fixture.harness,
            &format!("{base}/otp/verify"),
            &json!({ "identifier": EMAIL, "purpose": "login", "code": "000000" }),
        )
        .await;
        assert_eq!(
            wrong_status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a WRONG code must reach the gate's store fault, which it can only do if the \
             gate is decided before the code is judged (protected={protected})"
        );
        assert!(
            !sets_session_cookie(&wrong_headers),
            "no session on a store fault"
        );

        let (status, headers, _) = post_json(
            &fixture.harness,
            &format!("{base}/otp/verify"),
            &json!({ "identifier": EMAIL, "purpose": "login", "code": code }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a store fault in the gate fails CLOSED, even for an unprotected account the \
             gate would have permitted (protected={protected})"
        );
        assert!(
            !sets_session_cookie(&headers),
            "no session leaks when the gate cannot be evaluated (protected={protected})"
        );
    }
}

/// The same ordering claim on the magic link's CROSS-DEVICE short code, which is the
/// low-entropy half of that factor and therefore the half where a correct guess must not
/// be readable off the response.
///
/// With the gate's configuration read broken, a WRONG short code answers the neutral
/// server-error page (500) rather than the ordinary invalid-link page (400). It can only
/// do that if the gate is decided on the resolved challenge BEFORE the short code is
/// compared. The same-device token path has no analogue and makes no such claim: the token
/// IS the lookup key, so there is no compare to order the gate against.
#[tokio::test]
async fn a_store_fault_in_the_gate_refuses_before_the_short_code_is_judged() {
    let fixture = fixture(true, EmailDowngrade::NoRow, false).await;
    let base = base(&fixture.harness);
    let (_status, send_headers, _) = post_form(
        &fixture.harness,
        &format!("{base}/magic/send"),
        &format!("identifier={EMAIL}&purpose=login"),
        None,
    )
    .await;
    let binding = cookie_pair(&send_headers, BINDING_COOKIE).expect("binding cookie set on send");
    fixture.harness.break_email_factor_config_reads().await;
    let (status, headers, _) = post_form(
        &fixture.harness,
        &format!("{base}/magic/consume"),
        "short_code=000000",
        Some(&binding),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a WRONG cross-device short code must reach the gate's store fault, which it can \
         only do if the gate is decided before the short code is compared"
    );
    assert!(
        !sets_session_cookie(&headers),
        "no session on a store fault"
    );
}

/// The same fault on the headless recovery journey is the neutral store error, never a
/// completion. This is the `FlowError::Store` arm, which no shipped test reached.
#[tokio::test]
async fn a_store_fault_in_the_gate_fails_the_recovery_journey_closed() {
    let fixture = fixture(true, EmailDowngrade::NoRow, false).await;
    let (flow_id, token0, _start) = create_flow(
        fixture.harness.state(),
        fixture.harness.scope(),
        Transport::Api,
        Journey::Recovery,
        None,
        None,
        None,
        &HeaderMap::new(),
    )
    .await
    .expect("create recovery flow");
    let ack = drive(
        fixture.harness.state(),
        fixture.harness.scope(),
        &flow_id,
        Transport::Api,
        TransportAuth::Api {
            presented_submit_token: token0,
        },
        submission(&[("identifier", EMAIL)]),
        &HeaderMap::new(),
    )
    .await
    .expect("submit the identifier");
    let Continuation::Render {
        submit_token: token1,
        ..
    } = ack
    else {
        panic!("the recovery ack must be a render");
    };
    let code = last_email_code(&fixture);
    fixture.harness.break_email_factor_config_reads().await;
    let completion = drive(
        fixture.harness.state(),
        fixture.harness.scope(),
        &flow_id,
        Transport::Api,
        TransportAuth::Api {
            presented_submit_token: token1,
        },
        submission(&[("code", &code)]),
        &HeaderMap::new(),
    )
    .await;
    assert!(
        completion.is_err(),
        "a store fault in the gate must fail the recovery journey closed, never complete it"
    );
}

// ------------------------------------------------------------------------------------------
// The recovery-code rung's boundaries: it must not lock the legitimate path out.
// ------------------------------------------------------------------------------------------

/// A recovery-code set that has been SPENT stops blocking.
///
/// The gate counts UNCONSUMED codes, which is the whole reason it can be an `mfa`-rung
/// factor without becoming a trap: an account whose codes are all spent holds no surviving
/// stronger factor and must be able to use its weak factor again. A gate that counted rows
/// rather than unconsumed rows would lock such an account out permanently, and the
/// surviving-codes sweep alone cannot tell the two apart.
///
/// There is no third state to test. A recovery code is unconsumed or consumed; the
/// `recovery_codes` table carries `consumed_at` and no expiry column, so a code never
/// lapses on its own.
#[tokio::test]
async fn spent_recovery_codes_stop_blocking() {
    for path in GatedSessionPath::ALL {
        let fixture = fixture(false, EmailDowngrade::NoRow, false).await;
        for identifier in [EMAIL, PHONE] {
            let subject = fixture
                .harness
                .store()
                .scoped(fixture.harness.scope())
                .users()
                .by_identifier(identifier)
                .await
                .expect("lookup")
                .expect("user")
                .id
                .to_string();
            fixture.harness.seed_recovery_code(&subject).await;
            fixture.harness.consume_all_recovery_codes(&subject).await;
        }
        let outcome = drive_path(&fixture, path, sweep_purpose(path)).await;
        assert_eq!(
            outcome,
            Outcome::SessionMinted,
            "{} must mint for an account whose recovery codes are ALL spent; a gate that \
             counted rows rather than UNCONSUMED rows would lock the account out",
            path.as_str()
        );
    }
}
