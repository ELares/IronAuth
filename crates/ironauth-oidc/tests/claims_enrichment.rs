// SPDX-License-Identifier: MIT OR Apache-2.0

//! The claims-enrichment hook against a REAL server (issue #100, criterion 4).
//!
//! The filtering logic is unit-tested in the module itself, over a map. What that cannot
//! see is everything between here and there: whether the request is actually made, whether
//! the bearer secret is presented, whether a non-2xx or a hung connection contributes
//! nothing instead of failing issuance, and whether the wrapper shape is the one a service
//! would have to produce. So this drives an in-process HTTP server through the fetcher's
//! injected dialer, exactly as the federation and lazy-migration suites do.
//!
//! The fail-OPEN cases carry most of the weight and are the reason this hook is safe to put
//! on the issuance path at all: an FGA that is down, slow, angry, or speaking nonsense must
//! cost the deployment some claims and never a login.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_oidc::enrichment::ClaimsEnrichmentHook;
use ironauth_store::{EnvironmentId, Scope, TenantId};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// A routable address the SSRF guard accepts; the dialer sends the connection to loopback
/// regardless, which is how these suites reach an in-process server without disabling the
/// guard itself.
const PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

/// What the stub server should do with each request.
#[derive(Clone, Copy)]
enum Behaviour {
    /// Answer 200 with the given body.
    Ok(&'static str),
    /// Answer a non-2xx with an empty body.
    Status(u16),
    /// Answer a non-2xx WITH a well-formed body.
    StatusWithBody(u16, &'static str),
    /// Accept the connection and close it without answering.
    Hangup,
}

struct Stub {
    addr: SocketAddr,
    /// How many requests the server actually received, so a test can tell "the hook made
    /// no call" from "the hook made a call that produced nothing".
    calls: Arc<AtomicUsize>,
    /// The Authorization header of the last request, if any.
    authorization: Arc<std::sync::Mutex<Option<String>>>,
}

async fn stub(behaviour: Behaviour) -> Stub {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the stub");
    let addr = listener.local_addr().expect("stub address");
    let calls = Arc::new(AtomicUsize::new(0));
    let authorization = Arc::new(std::sync::Mutex::new(None));
    let seen = Arc::clone(&calls);
    let auth_slot = Arc::clone(&authorization);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let seen = Arc::clone(&seen);
            let auth_slot = Arc::clone(&auth_slot);
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                let read = socket.read(&mut buf).await.unwrap_or(0);
                seen.fetch_add(1, Ordering::SeqCst);
                let request = String::from_utf8_lossy(&buf[..read]).to_string();
                let auth = request
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
                    .map(|line| line["authorization:".len()..].trim().to_owned());
                *auth_slot.lock().expect("lock") = auth;
                match behaviour {
                    Behaviour::Hangup => {}
                    Behaviour::Ok(body) => {
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                    Behaviour::StatusWithBody(code, body) => {
                        let response = format!(
                            "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                    Behaviour::Status(code) => {
                        let response = format!(
                            "HTTP/1.1 {code} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                }
                let _ = socket.flush().await;
            });
        }
    });
    Stub {
        addr,
        calls,
        authorization,
    }
}

fn hook(stub: &Stub, secret: Option<&str>, allowed: &[&str]) -> ClaimsEnrichmentHook {
    let fetcher = Arc::new(Fetcher::from_parts(
        FetchLimits::default(),
        Arc::new(StaticResolver::new(vec![IpAddr::from(PUBLIC_IP)])),
        Arc::new(RecordingDialer::new(stub.addr)),
    ));
    ClaimsEnrichmentHook::new_allow_http(
        fetcher,
        "http://pdp.example.test/enrich",
        secret.map(std::borrow::ToOwned::to_owned),
        allowed.iter().map(|name| (*name).to_owned()).collect(),
    )
}

fn scope() -> Scope {
    Scope::new(
        TenantId::parse("ten_AAAAAAAAAAAAAAAAAAAAAA").expect("tenant"),
        EnvironmentId::parse("env_AAAAAAAAAAAAAAAAAAAAAA").expect("environment"),
    )
}

/// The happy path: an allowlisted claim comes back and is returned.
#[tokio::test]
async fn an_allowlisted_claim_is_fetched_and_returned() {
    let stub = stub(Behaviour::Ok(
        r#"{"claims":{"fga_roles":["editor"],"tier":"gold"}}"#,
    ))
    .await;
    let claims = hook(&stub, None, &["fga_roles", "tier"])
        .enrich(scope(), "usr_1", "cli_1")
        .await;

    assert_eq!(
        stub.calls.load(Ordering::SeqCst),
        1,
        "one call, not zero or two"
    );
    assert_eq!(
        claims.get("fga_roles"),
        Some(&serde_json::json!(["editor"])),
        "a structured claim must survive verbatim, not be stringified: {claims:?}"
    );
    assert_eq!(claims.get("tier"), Some(&serde_json::json!("gold")));
}

/// A claim the operator did not allowlist is dropped even though the service sent it.
///
/// The call still HAPPENS, which is what separates this from the hook simply being off.
#[tokio::test]
async fn a_claim_outside_the_allowlist_is_dropped() {
    let stub = stub(Behaviour::Ok(
        r#"{"claims":{"fga_roles":["editor"],"is_admin":true}}"#,
    ))
    .await;
    let claims = hook(&stub, None, &["fga_roles"])
        .enrich(scope(), "usr_1", "cli_1")
        .await;

    assert_eq!(stub.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        claims.keys().collect::<Vec<_>>(),
        vec!["fga_roles"],
        "a service can put anything in its response; only what the operator named may \
         enter a token: {claims:?}"
    );
}

/// The bearer secret is presented, so the service can authenticate IronAuth.
#[tokio::test]
async fn the_shared_secret_is_presented_as_a_bearer() {
    let stub = stub(Behaviour::Ok(r#"{"claims":{}}"#)).await;
    hook(&stub, Some("s3cr3t"), &["fga_roles"])
        .enrich(scope(), "usr_1", "cli_1")
        .await;
    assert_eq!(
        stub.authorization.lock().expect("lock").as_deref(),
        Some("Bearer s3cr3t"),
        "without the bearer the service cannot tell IronAuth from anyone who found the URL"
    );
}

/// Every failure shape contributes NOTHING and returns rather than erroring.
///
/// This is the property that makes the hook safe on the issuance path. A 500, a 404, a
/// connection closed without an answer, a body that is not JSON, and a body whose `claims`
/// is the wrong TYPE all have to behave the same: no claims, no panic, no error.
#[tokio::test]
async fn every_failure_shape_contributes_nothing() {
    for (label, behaviour) in [
        ("a server error", Behaviour::Status(500)),
        ("a not-found", Behaviour::Status(404)),
        ("an unauthorized", Behaviour::Status(401)),
        ("a hangup with no response", Behaviour::Hangup),
        ("a body that is not JSON", Behaviour::Ok("not json at all")),
        (
            "a claims key of the wrong type",
            Behaviour::Ok(r#"{"claims":[1,2]}"#),
        ),
        (
            "a bare object with no wrapper",
            Behaviour::Ok(r#"{"fga_roles":["x"]}"#),
        ),
        // The two that make the STATUS check load-bearing rather than incidental. Every
        // case above is refused by the JSON parse whatever the status was, so without a
        // non-2xx carrying a WELL-FORMED body the status check could be deleted and no
        // test would notice. A proxy serving a stale body under a 502, and a service that
        // returns its claims alongside a 500 by mistake, both look exactly like this.
        (
            "a 500 carrying a well-formed claims body",
            Behaviour::StatusWithBody(500, r#"{"claims":{"fga_roles":["editor"]}}"#),
        ),
        (
            "a 502 carrying a well-formed claims body",
            Behaviour::StatusWithBody(502, r#"{"claims":{"fga_roles":["editor"]}}"#),
        ),
    ] {
        let stub = stub(behaviour).await;
        let claims = hook(&stub, None, &["fga_roles"])
            .enrich(scope(), "usr_1", "cli_1")
            .await;
        assert!(
            claims.is_empty(),
            "{label} contributed a claim; the hook must fail open and contribute nothing: \
             {claims:?}"
        );
    }
}

/// A bare object with no `claims` wrapper contributes nothing, and that is deliberate.
///
/// Asserted separately from the failure sweep because it is the case most likely to be
/// "fixed" by someone who reads it as an oversight. A service that returns its own error
/// envelope (`{"error":"forbidden"}`) would otherwise contribute a claim named `error`, and
/// a service that returns a whole user record would contribute all of it.
#[tokio::test]
async fn the_response_must_be_wrapped_and_a_bare_object_is_not_accepted() {
    let stub = stub(Behaviour::Ok(r#"{"fga_roles":["editor"]}"#)).await;
    let claims = hook(&stub, None, &["fga_roles"])
        .enrich(scope(), "usr_1", "cli_1")
        .await;
    assert!(
        claims.is_empty(),
        "an unwrapped object was accepted, so any field a service happens to return can \
         become a token claim: {claims:?}"
    );
}

/// A RESERVED claim is dropped even when the service sends it and the allowlist names it.
///
/// Config load refuses to store such an allowlist, so reaching this needs the constructor
/// that bypasses config, which is exactly the regression being guarded against: an external
/// service must never be able to choose the subject of a token IronAuth signs.
#[tokio::test]
async fn a_reserved_claim_is_dropped_over_the_wire_too() {
    let stub = stub(Behaviour::Ok(
        r#"{"claims":{"sub":"attacker","permissions":["*"],"fga_roles":["reader"]}}"#,
    ))
    .await;
    let claims = hook(&stub, None, &["sub", "permissions", "fga_roles"])
        .enrich(scope(), "usr_1", "cli_1")
        .await;
    assert_eq!(
        claims.keys().collect::<Vec<_>>(),
        vec!["fga_roles"],
        "a reserved claim arrived over the wire and survived: {claims:?}"
    );
}
