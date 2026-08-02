// SPDX-License-Identifier: MIT OR Apache-2.0

//! The UNAUTHENTICATED scope-routed surface is not an environment existence oracle
//! through an error SHAPE (issue #449), over a real database.
//!
//! # What was measured, before anything was changed
//!
//! `POST /t/{tenant}/e/{environment}/device`, submitting any user code and presenting no
//! credential of any kind, answered `200` for a real environment and `500` for one that
//! never existed. The same sweep found the shape on the whole passwordless family:
//! `otp/send` and `magic/send` answered `200` against a real environment and `429`
//! against a ghost, and the proof-of-work and flow-creation routes answered `200` and
//! `500`.
//!
//! The mechanism was one line at the persistence boundary. Row-level security makes a
//! READ in an absent scope indistinguishable from a read in an empty one, but a WRITE
//! reaches the scope foreign key and fails, and that failure was reported as a database
//! FAULT. Every one of these routes performs a write before it reads anything: a rate
//! counter, an abuse counter, a challenge row, a flow row. The store now answers the
//! uniform not-found for it (`ironauth-store/tests/absent_scope.rs` pins that), and this
//! file pins what the routes then do with it.
//!
//! # What this file can and cannot claim
//!
//! It does NOT claim that environment existence is unobservable. It is not, and it
//! cannot be made so: `/t/{tenant}/e/{environment}/.well-known/openid-configuration`
//! and `.../jwks.json` answer `200` for a live environment and `404` for one that never
//! existed, which is measured in
//! [`environment_existence_is_already_public_through_discovery`] rather than assumed.
//! Those documents are the issuer metadata an RFC 8414 client fetches before it can do
//! anything at all, so they are public by construction.
//!
//! What it claims is the property that WAS violated and is achievable: no
//! unauthenticated scope-routed route answers a scope that never existed with a SERVER
//! FAULT, and the device verification page, which the issue singles out, answers the two
//! cases byte for byte alike.
//!
//! # Why the subject list cannot silently shrink
//!
//! A sweep over a hand-maintained list reports on whatever the list happens to contain
//! and says nothing about what it omits. This one walks the crate's OWN SOURCE TREE,
//! enumerates every scope-routed path literal anywhere in it, and requires each one to
//! be either DRIVEN here or on an explicit exclusion list carrying its reason. A new
//! scope-routed route therefore fails this file the moment it is written.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::{Harness, form};
use ironauth_config::{OidcConfig, PowConfig, RegistrationAbuseConfig};
use ironauth_store::{EnvironmentId, Scope, TenantId};

/// The harness the SWEEP runs on: a shipped-default deployment, which is the posture the
/// unauthenticated surface actually presents to the internet.
async fn harness() -> Harness {
    Harness::start_store_backed_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    })
    .await
}

/// The harness for the proof-of-work route specifically, with the gate switched ON.
///
/// It is separate for a reason worth recording. With the shipped default (gate off)
/// `pow/challenge` returns its uniform `404` from an early return and NEVER reaches the
/// mint, so a case driven against the default harness compares two feature-off answers
/// and says nothing at all about the absent-scope path. That is not a hypothetical: a
/// mutation that removed the absent-scope arm from the mint left this file GREEN, which
/// is how the vacuous fixture was found. And the gate cannot simply be switched on for
/// the whole sweep either, because it then stands in front of `otp/send` and
/// `magic/send` with a `challenge required` refusal, and those two are the cases that
/// measure the abuse-regulation seam.
async fn pow_harness() -> Harness {
    Harness::start_store_backed_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        registration_abuse: RegistrationAbuseConfig {
            pow: PowConfig {
                enabled: true,
                difficulty_bits: 8,
                challenge_at: "low".to_owned(),
                ..PowConfig::default()
            },
            ..RegistrationAbuseConfig::default()
        },
        ..OidcConfig::default()
    })
    .await
}

/// The templated prefix every scope-routed data-plane path hangs off.
const SCOPE_PREFIX: &str = "/t/{tenant_id}/e/{environment_id}";

/// Every scope-routed path literal ANYWHERE in this crate's sources.
///
/// # Why the whole tree and not the router file
///
/// The router registers most paths as literals in `lib.rs`, but not all of them: the
/// five flow paths are constants in `flow/transport.rs` and the first-party challenge
/// path is a constant in `challenge.rs`. An earlier draft of this scan read `lib.rs`
/// plus the flow transport, and it MISSED `authorize-challenge` entirely, which is the
/// failure mode a hand-picked source list has and a tree walk does not. A new module
/// that declares a scope-routed path is picked up with no edit here.
///
/// A literal that is not a route (a `format!` template, say) is a FALSE POSITIVE, and
/// that is the safe direction: it costs one classification entry. A missed route is the
/// dangerous direction, and walking the tree is what removes it.
fn registered_scope_paths() -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    let mut pending = vec![std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("the crate's sources are readable") {
            let path = entry.expect("a readable directory entry").path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("a readable source file");
            for chunk in source.split('"').skip(1).step_by(2) {
                // Longer than the prefix, so the bare scope prefix a `format!` builds is
                // not mistaken for a route at the root of the scope.
                if chunk.starts_with(SCOPE_PREFIX) && chunk.len() > SCOPE_PREFIX.len() {
                    paths.insert(chunk.to_owned());
                }
            }
        }
    }
    paths
}

/// One unauthenticated request this file drives at a live scope and at a ghost one.
struct Case {
    /// The templated path it drives, which is also how it resolves against the router
    /// inventory: a literal that drifts matches nothing and fails the coverage test.
    template: &'static str,
    method: &'static str,
    content_type: &'static str,
    body: &'static str,
    /// The status a LIVE scope answers. Asserted BEFORE the two answers are compared,
    /// because equality alone is satisfied by two requests that both died in the body
    /// parser, and then the equality would be measuring the parser rather than the
    /// route. See the `415` this file's first draft measured on three of these.
    live_status: StatusCode,
}

/// The unauthenticated, scope-routed requests whose ghost-scope answer this file pins.
fn cases() -> Vec<Case> {
    vec![
        Case {
            template: "/t/{tenant_id}/e/{environment_id}/device",
            method: "POST",
            content_type: "application/x-www-form-urlencoded",
            body: "user_code=ABCD-EFGH",
            live_status: StatusCode::OK,
        },
        Case {
            template: "/t/{tenant_id}/e/{environment_id}/device",
            method: "GET",
            content_type: "text/plain",
            body: "",
            live_status: StatusCode::OK,
        },
        Case {
            template: "/t/{tenant_id}/e/{environment_id}/otp/send",
            method: "POST",
            content_type: "application/json",
            body: r#"{"identifier":"sweep@example.test"}"#,
            live_status: StatusCode::OK,
        },
        Case {
            template: "/t/{tenant_id}/e/{environment_id}/magic/send",
            method: "POST",
            content_type: "application/x-www-form-urlencoded",
            body: "identifier=sweep%40example.test",
            live_status: StatusCode::OK,
        },
        Case {
            template: "/t/{tenant_id}/e/{environment_id}/pow/challenge",
            method: "POST",
            content_type: "application/json",
            body: r#"{"endpoint":"register","context":"sweep"}"#,
            // The shipped default leaves the gate OFF, so this case measures the uniform
            // feature-off `404`. The absent-scope path through the MINT is measured
            // separately, on a gate-on harness, by
            // [`the_proof_of_work_gate_is_not_an_environment_existence_oracle`].
            live_status: StatusCode::NOT_FOUND,
        },
        Case {
            template: "/t/{tenant_id}/e/{environment_id}/otp/verify",
            method: "POST",
            content_type: "application/json",
            body: r#"{"identifier":"sweep@example.test","code":"000000"}"#,
            live_status: StatusCode::UNAUTHORIZED,
        },
        Case {
            template: "/t/{tenant_id}/e/{environment_id}/invitations/accept",
            method: "POST",
            content_type: "application/json",
            body: r#"{"token":"not-a-real-invitation-token"}"#,
            live_status: StatusCode::NOT_FOUND,
        },
        // The three issue #295 advanced-recovery endpoints. This harness runs
        // `OidcConfig::default()`, so the `advanced-recovery` experimental feature is OFF, and
        // what these three cases pin is that THE FEATURE GATE ITSELF is not a scope oracle: a
        // disabled feature answers the same `404` for a live scope as for one that never
        // existed. The flag-ON half, where the answer is the uniform `401 recovery_unavailable`
        // for both, is pinned separately by the ghost-scope probe in `advanced_recovery.rs`.
        // Both halves matter: a gate that 404s only for real scopes would be the oracle.
        Case {
            template: "/t/{tenant_id}/e/{environment_id}/recover/admin-approved/initiate",
            method: "POST",
            content_type: "application/json",
            body: r#"{"identifier":"sweep@example.test","code":"000000"}"#,
            live_status: StatusCode::NOT_FOUND,
        },
        Case {
            template: "/t/{tenant_id}/e/{environment_id}/recover/idv/initiate",
            method: "POST",
            content_type: "application/json",
            body: r#"{"identifier":"sweep@example.test","code":"000000","provider":"sweep"}"#,
            live_status: StatusCode::NOT_FOUND,
        },
        Case {
            template: "/t/{tenant_id}/e/{environment_id}/recover/finalize",
            method: "POST",
            content_type: "application/json",
            body: r#"{"identifier":"sweep@example.test","code":"000000"}"#,
            live_status: StatusCode::NOT_FOUND,
        },
    ]
}

/// Every scope-routed path this file deliberately does NOT drive, each with the reason.
///
/// The reasons fall into three families, and none of them is "we did not get to it":
///
/// - SESSION GATED: the handler resolves a `__Host-` session cookie before it touches
///   the store, and `resolve_session` returns `None` without a store call when the
///   cookie is absent, so an unauthenticated caller is refused identically at every
///   scope.
/// - CREDENTIAL GATED: the handler verifies a token, a client credential, a signed
///   assertion, or a correlation state the environment itself minted, before addressing
///   anything. A scope that never existed cannot have minted one.
/// - READ FIRST: the handler's first store operation is a SELECT, which row-level
///   security already makes indistinguishable between an absent scope and an empty one.
// The list is one table, and splitting it into helpers to satisfy a length lint would
// scatter the reasons away from the paths they justify, which is the only thing that
// makes this exclusion set reviewable.
#[allow(clippy::too_many_lines)]
fn excluded() -> BTreeMap<&'static str, &'static str> {
    let mut excluded = BTreeMap::new();
    for path in [
        "/t/{tenant_id}/e/{environment_id}/account/consents",
        "/t/{tenant_id}/e/{environment_id}/account/consents/revoke",
        "/t/{tenant_id}/e/{environment_id}/account/credentials",
        "/t/{tenant_id}/e/{environment_id}/account/credentials/remove",
        "/t/{tenant_id}/e/{environment_id}/account/linked-identities",
        "/t/{tenant_id}/e/{environment_id}/account/linked-identities/remove",
        "/t/{tenant_id}/e/{environment_id}/account/linked-identities/start",
        "/t/{tenant_id}/e/{environment_id}/account/mfa/plan",
        "/t/{tenant_id}/e/{environment_id}/account/mfa/recovery-codes",
        "/t/{tenant_id}/e/{environment_id}/account/mfa/recovery-codes/redeem",
        "/t/{tenant_id}/e/{environment_id}/account/mfa/totp/enroll",
        "/t/{tenant_id}/e/{environment_id}/account/mfa/totp/remove",
        "/t/{tenant_id}/e/{environment_id}/account/mfa/totp/verify",
        "/t/{tenant_id}/e/{environment_id}/account/mfa/totp/verify-enrollment",
        "/t/{tenant_id}/e/{environment_id}/account/password",
        "/t/{tenant_id}/e/{environment_id}/account/password/remove",
        "/t/{tenant_id}/e/{environment_id}/account/sessions",
        "/t/{tenant_id}/e/{environment_id}/account/sessions/revoke",
        "/t/{tenant_id}/e/{environment_id}/account/sessions/revoke-others",
        "/t/{tenant_id}/e/{environment_id}/account/trusted-devices",
        "/t/{tenant_id}/e/{environment_id}/account/trusted-devices/revoke",
        "/t/{tenant_id}/e/{environment_id}/account/trusted-devices/revoke-all",
        "/t/{tenant_id}/e/{environment_id}/webauthn/credentials",
        "/t/{tenant_id}/e/{environment_id}/webauthn/credentials/remove",
        "/t/{tenant_id}/e/{environment_id}/webauthn/credentials/rename",
        "/t/{tenant_id}/e/{environment_id}/webauthn/manage",
        "/t/{tenant_id}/e/{environment_id}/webauthn/register/options",
        "/t/{tenant_id}/e/{environment_id}/webauthn/register/verify",
        "/t/{tenant_id}/e/{environment_id}/webauthn/signal",
    ] {
        excluded.insert(
            path,
            "session gated: `resolve_session` returns None with no store call at all \
             when the cookie is absent, so an unauthenticated caller is refused \
             identically at every scope",
        );
    }
    for path in [
        "/t/{tenant_id}/e/{environment_id}/fedcm/accounts",
        "/t/{tenant_id}/e/{environment_id}/fedcm/assertion",
        "/t/{tenant_id}/e/{environment_id}/fedcm/config.json",
    ] {
        excluded.insert(
            path,
            "designated-scope gated and then session gated: a scope that never existed \
             is never the deployment's designated FedCM scope",
        );
    }
    for path in [
        "/t/{tenant_id}/e/{environment_id}/webauthn/authenticate/options",
        "/t/{tenant_id}/e/{environment_id}/webauthn/authenticate/verify",
        "/t/{tenant_id}/e/{environment_id}/webauthn/signup/options",
        "/t/{tenant_id}/e/{environment_id}/webauthn/signup/verify",
    ] {
        excluded.insert(
            path,
            "same-origin gated before any store call, and the attempt-recording write it \
             then performs is the SAME regulation seam this file drives at otp/send",
        );
    }
    for path in [
        "/t/{tenant_id}/e/{environment_id}/authorize-challenge",
        "/t/{tenant_id}/e/{environment_id}/federation/upstream-token",
        "/t/{tenant_id}/e/{environment_id}/federation/{connector_slug}/callback",
        "/t/{tenant_id}/e/{environment_id}/magic/confirm",
        "/t/{tenant_id}/e/{environment_id}/magic/consume",
        "/t/{tenant_id}/e/{environment_id}/recover/idv/callback",
        "/t/{tenant_id}/e/{environment_id}/recover/trusted-contact/confirm",
        "/t/{tenant_id}/e/{environment_id}/risk/signals",
    ] {
        excluded.insert(
            path,
            "credential gated: a client credential, a signed assertion, or a \
             correlation state the environment itself minted is checked before \
             anything is addressed, and a scope that never existed minted none",
        );
    }
    for path in [
        "/t/{tenant_id}/e/{environment_id}/connect/register",
        "/t/{tenant_id}/e/{environment_id}/connect/register/{client_id}",
    ] {
        excluded.insert(
            path,
            "issuer-entry gated: answers a uniform 404 for any unprovisioned scope \
             BEFORE its rate-limit write, which is the pattern the routes this file \
             does drive lacked",
        );
    }
    for path in [
        "/t/{tenant_id}/e/{environment_id}/brand/{slug}/{kind}",
        "/t/{tenant_id}/e/{environment_id}/federation/{connector_slug}/authorize",
        "/t/{tenant_id}/e/{environment_id}/otp/sms/send",
        "/t/{tenant_id}/e/{environment_id}/pages.css",
    ] {
        excluded.insert(
            path,
            "read first: the first store operation is a SELECT, which row-level \
             security already makes uniform between an absent scope and an empty one",
        );
    }
    for path in [
        "/t/{tenant_id}/e/{environment_id}/flow/{journey}",
        "/t/{tenant_id}/e/{environment_id}/flow/api/{journey}",
        "/t/{tenant_id}/e/{environment_id}/flow/api/{journey}/submit",
        "/t/{tenant_id}/e/{environment_id}/otp/sms/verify",
    ] {
        excluded.insert(
            path,
            "write first. The sms verify is CARRIED: its first write is the regulation \
             seam this file drives at otp/send. The three flow routes are NOT carried \
             end to end and the reason is recorded rather than glossed: their create \
             now maps the store's absent-scope not-found to FlowError::NotFound instead \
             of the neutral 500, but flows are OFF in a shipped default, so a case here \
             would compare two feature-off 404s and measure nothing, exactly the vacuous \
             fixture the proof-of-work case was caught being. The store half of that \
             path IS pinned, in ironauth-store/tests/absent_scope.rs",
        );
    }
    excluded
}

/// The two PUBLIC ISSUER METADATA documents. They are driven, but by
/// [`environment_existence_is_already_public_through_discovery`], which asserts the
/// OPPOSITE of the other cases: that they DO distinguish a live environment from one
/// that never existed, deliberately and unavoidably.
fn public_metadata() -> [&'static str; 2] {
    [
        "/t/{tenant_id}/e/{environment_id}/.well-known/openid-configuration",
        "/t/{tenant_id}/e/{environment_id}/jwks.json",
    ]
}

/// A `(tenant, environment)` pair that is well formed and belongs to no tenant this
/// deployment ever created.
fn ghost_scope(env: &ironauth_env::Env) -> Scope {
    Scope::new(TenantId::generate(env), EnvironmentId::generate(env))
}

/// Render `template` at `scope`.
fn at(template: &str, scope: &Scope) -> String {
    template
        .replace("{tenant_id}", &scope.tenant().to_string())
        .replace("{environment_id}", &scope.environment().to_string())
}

/// The COMPARABLE projection of a response: the status, EVERY header, and the body.
///
/// An existence oracle is a difference anywhere in the answer, not only in the status
/// line, so the headers ride along. The passwordless family's leak was in the headers as
/// much as the status: a ghost scope answered `429` with a whole `ratelimit` header
/// block a live one did not send, so a comparison over the status alone would have
/// called two visibly different answers alike.
fn comparable(status: StatusCode, headers: &HeaderMap, body: &str) -> String {
    let mut rendered: Vec<String> = headers
        .iter()
        .map(|(name, value)| format!("{name}: {}", value.to_str().unwrap_or("<non-ascii>")))
        .collect();
    rendered.sort();
    format!("{status}\n{}\n{body}", rendered.join("\n"))
}

/// [`comparable`], with the caller's OWN scope identifiers replaced by placeholders.
///
/// A scope-routed page echoes the scope it was addressed at into its form action, so two
/// answers at two different scopes can never be equal as literal bytes. That difference
/// is the request's own input reflected back and reveals nothing: the caller chose those
/// identifiers. Substituting them is what makes the REST of the answer comparable byte
/// for byte, and the substitution is per-scope rather than global, so a body that leaked
/// the OTHER scope's identifiers would not be normalized away.
fn scope_blind(status: StatusCode, headers: &HeaderMap, body: &str, scope: &Scope) -> String {
    blind_nonces(
        &comparable(status, headers, body)
            .replace(&scope.tenant().to_string(), "{tenant_id}")
            .replace(&scope.environment().to_string(), "{environment_id}"),
    )
}

/// Replace every run of 32 or more hexadecimal characters with a placeholder.
///
/// This blinds PER-REQUEST NONCES, of which the magic-link binding cookie is the one
/// this file meets: a fresh random value on every single request, including two requests
/// at the SAME scope. Issue #449's own sweep recorded it as a false positive for exactly
/// that reason.
///
/// That it really is per-request and not per-scope is not taken on trust:
/// [`a_blinded_nonce_differs_between_two_requests_at_the_same_scope`] measures it. And
/// the rule is narrow enough that it cannot hide a scope: a tenant or environment id is
/// a prefixed base64url string, not a hex run, and the two substitutions above run FIRST
/// anyway, so an identifier is already a placeholder before this sees it.
fn blind_nonces(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    for character in text.chars() {
        if character.is_ascii_hexdigit() {
            run.push(character);
            continue;
        }
        flush_run(&mut out, &mut run);
        out.push(character);
    }
    flush_run(&mut out, &mut run);
    out
}

fn flush_run(out: &mut String, run: &mut String) {
    if run.len() >= 32 {
        out.push_str("{nonce}");
    } else {
        out.push_str(run);
    }
    run.clear();
}

/// Drive one case at `scope`, presenting NO credential of any kind.
async fn drive(harness: &Harness, case: &Case, scope: &Scope) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder()
        .method(case.method)
        .uri(at(case.template, scope));
    if case.method != "GET" {
        builder = builder.header(header::CONTENT_TYPE, case.content_type);
    }
    let body = if case.method == "GET" {
        Body::empty()
    } else {
        Body::from(case.body)
    };
    harness
        .send(builder.body(body).expect("request builds"))
        .await
}

#[test]
fn every_scope_routed_path_is_either_driven_or_excluded_with_a_reason() {
    // The COVERAGE gate. Without it this file reports on the seven requests it happens
    // to make and says nothing about the fifty-odd routes it does not, which is exactly
    // how the device page sat unmeasured while three neighbouring sweeps ran.
    let registered = registered_scope_paths();
    assert!(
        registered.len() > 40,
        "the router source scan must find the scope-routed paths; found {} which means \
         the scan is broken rather than that the routes are gone",
        registered.len()
    );

    let driven: BTreeSet<&str> = cases().iter().map(|case| case.template).collect();
    let excluded = excluded();
    let classified: BTreeSet<&str> = driven
        .iter()
        .copied()
        .chain(excluded.keys().copied())
        .chain(public_metadata())
        .collect();

    let unclassified: Vec<&String> = registered
        .iter()
        .filter(|path| !classified.contains(path.as_str()))
        .collect();
    assert!(
        unclassified.is_empty(),
        "every scope-routed path must be driven here or excluded with a reason; a new \
         one that is neither is a route whose answer to a scope that never existed \
         nothing compares: {unclassified:#?}"
    );

    // And the other direction: a case or an exclusion naming a path the router does not
    // register is a stale entry, which would let the set above pass while covering less
    // than it claims.
    let stale: Vec<&str> = classified
        .iter()
        .copied()
        .filter(|path| !registered.contains(*path))
        .collect();
    assert!(
        stale.is_empty(),
        "every driven and excluded path must be one the router actually registers: \
         {stale:#?}"
    );
}

#[tokio::test]
async fn no_unauthenticated_scope_routed_route_distinguishes_a_ghost_scope() {
    // THE ASSERTION IS IDENTITY, NOT "not a 500", and that distinction was earned by
    // measurement rather than chosen. The first version of this test asserted only that
    // the ghost answer was not a server error, and a mutation that put the abuse
    // regulation back to failing CLOSED for an absent scope SURVIVED it: the leak came
    // back as a `429` carrying a whole `ratelimit` header block the live answer does not
    // send, which is not a server error and is every bit as good an oracle. A test that
    // pins the fault class pins the symptom the issue happened to name; this one pins
    // the property the issue is about.
    let harness = harness().await;
    let live = harness.scope();
    let ghost = ghost_scope(harness.env());

    for case in cases() {
        let label = format!("{} {}", case.method, case.template);

        // THE SHAPE FIRST. The live answer has to be the one the route really produces,
        // or the comparison below is measuring a body parser. Three of these cases
        // silently measured a `415` before this assertion existed.
        let (live_status, live_headers, live_body) = drive(&harness, &case, &live).await;
        assert_eq!(
            live_status, case.live_status,
            "the {label} probe must be well formed enough to reach the route's own \
             logic at a LIVE scope: {live_body}"
        );

        let (ghost_status, ghost_headers, ghost_body) = drive(&harness, &case, &ghost).await;
        assert_eq!(
            scope_blind(live_status, &live_headers, &live_body, &live),
            scope_blind(ghost_status, &ghost_headers, &ghost_body, &ghost),
            "{label} must answer a scope that never existed exactly as it answers a real \
             one, headers included; any difference is an unauthenticated tenant and \
             environment enumeration oracle"
        );
    }
}

#[tokio::test]
async fn the_device_verification_page_is_not_an_environment_existence_oracle() {
    // ISSUE #449, the byte-for-byte claim. The route answered `200` for a real
    // environment and `500` for one that never existed, with no credential of any kind.
    //
    // The fix is not two branches written to agree. The rate-limit write now reports the
    // uniform not-found for a scope that has no environment row, the handler FALLS
    // THROUGH it (there is no user code to rate limit in a scope that holds no flows),
    // and the lookup below runs the same query it runs for a live environment, matches
    // nothing, and renders the same page. The two answers are identical because ONE code
    // path produces both, which is why this assertion is over the whole answer rather
    // than over the status.
    let harness = harness().await;
    let live = harness.scope();
    let ghost = ghost_scope(harness.env());
    let entry = form(&[("user_code", "ABCD-EFGH")]);

    let case = Case {
        template: "/t/{tenant_id}/e/{environment_id}/device",
        method: "POST",
        content_type: "application/x-www-form-urlencoded",
        body: "",
        live_status: StatusCode::OK,
    };
    let request = |scope: &Scope| {
        Request::builder()
            .method("POST")
            .uri(at(case.template, scope))
            .header(header::CONTENT_TYPE, case.content_type)
            .body(Body::from(entry.clone()))
            .expect("request builds")
    };

    let (live_status, live_headers, live_body) = harness.send(request(&live)).await;
    let (ghost_status, ghost_headers, ghost_body) = harness.send(request(&ghost)).await;

    // THE CONTROL: the live scope really is live and really is answering the page,
    // rather than two uniformly broken answers being compared and called alike.
    assert_eq!(
        live_status,
        StatusCode::OK,
        "the live scope must serve the verification page: {live_body}"
    );
    assert!(
        live_body.contains("That code was not recognized"),
        "and it must be the non-oracular code-not-recognized page: {live_body}"
    );

    // The status and EVERY header are identical as literal bytes, with no substitution
    // at all: nothing in the header block may vary with the scope.
    assert_eq!(
        live_status, ghost_status,
        "the two answers must carry the same status"
    );
    assert_eq!(
        live_headers, ghost_headers,
        "the two answers must carry identical headers, including the whole rate-limit \
         block a throttled answer would add"
    );

    // And the whole answer is identical once each side's OWN scope identifiers are
    // blinded. That is the only difference a caller can observe, it is the caller's own
    // input echoed into the form action, and it reveals nothing.
    assert_eq!(
        scope_blind(live_status, &live_headers, &live_body, &live),
        scope_blind(ghost_status, &ghost_headers, &ghost_body, &ghost),
        "a real environment and one that never existed must answer the device \
         verification page identically, headers included"
    );

    // The substitution is not hiding a leak of the OTHER scope: neither answer names a
    // scope the caller did not address.
    assert!(
        !ghost_body.contains(&live.tenant().to_string())
            && !ghost_body.contains(&live.environment().to_string()),
        "the ghost answer must not name the live scope: {ghost_body}"
    );
    assert!(
        !live_body.contains(&ghost.tenant().to_string())
            && !live_body.contains(&ghost.environment().to_string()),
        "and the live answer must not name the ghost scope: {live_body}"
    );
}

#[tokio::test]
async fn environment_existence_is_already_public_through_discovery() {
    // THE HONEST BOUND on what the assertions above are worth, MEASURED rather than
    // argued. Issue #449 frames the device page as "an unauthenticated enumeration
    // oracle over tenant and environment identifiers". Closing it is right, and a `500`
    // for a well-formed absent scope is a wrong contract whatever else is true, but it
    // does not make environment existence unobservable, and this file must not be read
    // as claiming that it does.
    //
    // The issuer metadata an RFC 8414 client fetches before it can do anything answers
    // `200` for a live environment and `404` for one that never existed. That is
    // deliberate and unavoidable: a discovery document that answered uniformly could not
    // serve its purpose. Issue #449's own sweep recorded discovery and JWKS as "not
    // oracles" on the ground that a SUSPENDED and a never-existed scope answer alike,
    // which is true and is a different question from the one asked here.
    //
    // If this test ever starts failing because discovery went uniform, the assertions
    // above have become stronger than they were written to be, and that is worth
    // noticing deliberately rather than by accident.
    let harness = harness().await;
    let live = harness.scope();
    let ghost = ghost_scope(harness.env());

    for template in [
        "/t/{tenant_id}/e/{environment_id}/.well-known/openid-configuration",
        "/t/{tenant_id}/e/{environment_id}/jwks.json",
    ] {
        let get = |scope: &Scope| {
            Request::builder()
                .method("GET")
                .uri(at(template, scope))
                .body(Body::empty())
                .expect("request builds")
        };
        let (live_status, _, _) = harness.send(get(&live)).await;
        let (ghost_status, _, _) = harness.send(get(&ghost)).await;
        assert_eq!(
            live_status,
            StatusCode::OK,
            "{template} must serve a live environment"
        );
        assert_eq!(
            ghost_status,
            StatusCode::NOT_FOUND,
            "{template} answers a scope that never existed with a 404, which is the \
             pre-existing and deliberate disclosure this file does not claim to close"
        );
    }
}

#[tokio::test]
async fn a_blinded_nonce_differs_between_two_requests_at_the_same_scope() {
    // THE JUSTIFICATION for [`blind_nonces`], measured rather than asserted. The
    // comparison above would be worthless if it blinded something that varies with the
    // SCOPE, so this drives the same request TWICE at the SAME live scope and requires
    // the raw answers to differ and the blinded ones to match. A value that changes when
    // nothing about the scope changed cannot be carrying scope information.
    let harness = harness().await;
    let live = harness.scope();
    let case = Case {
        template: "/t/{tenant_id}/e/{environment_id}/magic/send",
        method: "POST",
        content_type: "application/x-www-form-urlencoded",
        body: "identifier=sweep%40example.test",
        live_status: StatusCode::OK,
    };

    let (first_status, first_headers, first_body) = drive(&harness, &case, &live).await;
    let (second_status, second_headers, second_body) = drive(&harness, &case, &live).await;
    assert_eq!(first_status, StatusCode::OK, "the control must serve");

    assert_ne!(
        comparable(first_status, &first_headers, &first_body),
        comparable(second_status, &second_headers, &second_body),
        "two requests at the SAME scope must differ before blinding, or this file is \
         blinding something that was never varying and the justification is empty"
    );
    assert_eq!(
        scope_blind(first_status, &first_headers, &first_body, &live),
        scope_blind(second_status, &second_headers, &second_body, &live),
        "and must match after it, which is what makes the blinded value a per-request \
         nonce rather than anything that could carry the scope"
    );

    // THE BOUND on the rule, which the equality above does NOT provide: a blinding wide
    // enough to swallow ordinary content would make every comparison in this file pass
    // vacuously, and both assertions above would still hold. This is what fails when the
    // threshold is loosened.
    assert_eq!(
        blind_nonces("404 Not Found deadbeef cafe"),
        "404 Not Found deadbeef cafe",
        "short hex-looking content must survive blinding untouched, or the identity \
         comparisons in this file are hiding real differences"
    );
    assert_eq!(
        blind_nonces("set-cookie: x=0123456789abcdef0123456789abcdef; Path=/"),
        "set-cookie: x={nonce}; Path=/",
        "and a full-length nonce must be blinded, or the rule is inert"
    );
}

#[tokio::test]
async fn the_proof_of_work_gate_is_not_an_environment_existence_oracle() {
    // The one route in this file whose absent-scope path is only reachable with a
    // non-default configuration. It MINTS a challenge row rather than reading anything,
    // so unlike the device page it has no live-and-empty answer to fall through to: a
    // scope with no environment row simply cannot hold the row the request exists to
    // create. It used to answer that with a `500` against a live environment's `200`.
    //
    // The answer it gives instead is the SAME uniform `404` it gives when the gate is
    // switched off, which is what makes it non-oracular in a stronger sense than mere
    // uniformity between two absent cases: a scope that never existed is indistinguishable
    // from a live environment that does not use the gate.
    let gate_on = pow_harness().await;
    let live = gate_on.scope();
    let ghost = ghost_scope(gate_on.env());
    let case = Case {
        template: "/t/{tenant_id}/e/{environment_id}/pow/challenge",
        method: "POST",
        content_type: "application/json",
        body: r#"{"endpoint":"register","context":"sweep"}"#,
        live_status: StatusCode::OK,
    };

    // THE CONTROL: with the gate on, a live scope really mints, so the ghost answer below
    // is being compared against a working route rather than against another refusal.
    let (status, _headers, body) = drive(&gate_on, &case, &live).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a live scope must mint a challenge with the gate on: {body}"
    );
    assert!(
        body.contains("challenge_id"),
        "and the mint must really have stored one: {body}"
    );

    let (status, headers, body) = drive(&gate_on, &case, &ghost).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a scope that never existed must answer the uniform not-found, never a server \
         fault: {}",
        comparable(status, &headers, &body)
    );

    // And byte for byte the answer a live environment with the gate OFF gives, so the two
    // are one wall rather than two similar ones.
    let gate_off = harness().await;
    let (off_status, off_headers, off_body) = drive(&gate_off, &case, &gate_off.scope()).await;
    assert_eq!(
        scope_blind(status, &headers, &body, &ghost),
        scope_blind(off_status, &off_headers, &off_body, &gate_off.scope()),
        "the absent scope and a live gate-off environment must answer identically"
    );
}
