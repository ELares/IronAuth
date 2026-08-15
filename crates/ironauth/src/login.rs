// SPDX-License-Identifier: MIT OR Apache-2.0

//! `ironauth login`: the RFC 8628 device flow (issue #120).
//!
//! # Why the device flow first
//!
//! The device flow is the one that works everywhere. It needs no listener, no browser on
//! this machine, and no open port, so it is the only flow available on the headless boxes
//! and over the SSH sessions where a CLI login most often happens. The loopback flow is
//! preferred where it CAN run (`login_flow::choose_flow` decides, and prefers it, because
//! it has no cross-device phishing exposure), but it needs the pieces this module does not:
//! a bound listener, a browser, and a redirect handler.
//!
//! # The transport is shared, deliberately
//!
//! The HTTP goes through `ironauth_apply::client::post_form`, which is the SAME connect,
//! TLS configuration, total deadline, and response size cap the control-plane client uses.
//! A second copy of that in this crate would be two things to keep in step, and the copy
//! that drifts is the one nobody is looking at.
//!
//! # What is testable here, and what is not
//!
//! Everything except the network. [`run_device_flow`] takes the two endpoints as closures,
//! so the tests below drive the whole loop, including the RFC 8628 section 3.5 `slow_down`
//! rule, against scripted responses. What that leaves unproved is the HTTP call itself,
//! which is why it is one shared function call rather than logic of its own.

use std::time::Duration;

use crate::credentials::{CredentialStore, StoredCredential};
use crate::device_login::{DevicePoll, Next, PollOutcome, outcome_for_error};

/// What the device-authorization endpoint returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorization {
    /// The code this client polls with.
    pub device_code: String,
    /// The code the human types on the other device.
    pub user_code: String,
    /// Where the human types it.
    pub verification_uri: String,
    /// The complete URI, when the server offers one.
    pub verification_uri_complete: Option<String>,
    /// The server's requested polling interval, in seconds. Absent means 5 (section 3.5).
    pub interval_secs: Option<u64>,
    /// How long the device code lives.
    pub expires_in_secs: u64,
}

/// One token-endpoint answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenAnswer {
    /// Tokens were issued.
    Issued {
        /// The access token.
        access_token: String,
        /// The refresh token, when one was issued.
        refresh_token: Option<String>,
        /// Access-token lifetime in seconds.
        expires_in_secs: i64,
    },
    /// The endpoint returned an OAuth `error` code.
    Error(String),
}

/// Why a login failed.
#[derive(Debug)]
pub enum LoginError {
    /// The device-authorization request failed.
    Authorization(String),
    /// Polling ended without tokens; the message is the user-facing cause.
    Refused(&'static str),
    /// The credential could not be stored, so the login did not take effect.
    Storage(String),
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authorization(message) => write!(f, "could not start the login: {message}"),
            Self::Refused(message) => write!(f, "{message}"),
            Self::Storage(message) => write!(
                f,
                "signed in, but the credential could not be stored: {message}"
            ),
        }
    }
}

/// Drive the device flow to completion and store the credential.
///
/// `authorize` starts the flow, `poll` performs one token request, and `sleep` waits. All
/// three are injected so the loop is testable without a network or a clock: see the module
/// docs for what that does and does not prove.
///
/// # Errors
///
/// [`LoginError`] naming the stage that failed.
pub async fn run_device_flow<A, P, S, F1, F2, F3>(
    issuer: &str,
    account: &str,
    store: &impl CredentialStore,
    now_unix_secs: i64,
    authorize: A,
    mut poll: P,
    mut sleep: S,
) -> Result<(), LoginError>
where
    A: FnOnce() -> F1,
    F1: Future<Output = Result<DeviceAuthorization, String>>,
    P: FnMut(String) -> F2,
    F2: Future<Output = TokenAnswer>,
    S: FnMut(Duration) -> F3,
    F3: Future<Output = ()>,
{
    let authorization = authorize().await.map_err(LoginError::Authorization)?;

    // Printed BEFORE the first poll, because the user cannot approve what they have not
    // been shown, and the first poll's interval elapses before anything else happens.
    print_instructions(&authorization);

    let mut state = DevicePoll::new(
        authorization.interval_secs,
        Duration::from_secs(authorization.expires_in_secs),
    );

    // The first wait happens BEFORE the first poll. Polling immediately would guarantee an
    // `authorization_pending` that the user could not possibly have avoided, and on a
    // server that counts it toward a rate limit it starts the flow one strike down.
    loop {
        sleep(state.interval()).await;

        let outcome = match poll(authorization.device_code.clone()).await {
            TokenAnswer::Issued {
                access_token,
                refresh_token,
                expires_in_secs,
            } => {
                store
                    .store(
                        account,
                        &StoredCredential {
                            access_token,
                            refresh_token,
                            expires_at_unix_secs: now_unix_secs.saturating_add(expires_in_secs),
                            issuer: issuer.to_owned(),
                        },
                    )
                    .map_err(|error| LoginError::Storage(error.to_string()))?;
                PollOutcome::Issued
            }
            TokenAnswer::Error(code) => outcome_for_error(&code),
        };

        match state.advance(&outcome) {
            Next::Done => return Ok(()),
            Next::Stop(message) => return Err(LoginError::Refused(message)),
            Next::WaitThenPoll(_) => {}
        }
    }
}

/// Build the authorization URL for the loopback flow.
///
/// Every value is percent-encoded, including the redirect URI and the challenge: a
/// `client_id` or a redirect is caller-supplied, and an unencoded one containing `&` would
/// forge parameters into an authorization request.
#[must_use]
pub fn authorize_url(
    issuer: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    state: &str,
    scope: &str,
) -> String {
    format!(
        "{}/authorize?response_type=code&client_id={}&redirect_uri={}\
         &code_challenge={}&code_challenge_method=S256&state={}&scope={}",
        issuer.trim_end_matches('/'),
        encode(client_id),
        encode(redirect_uri),
        encode(code_challenge),
        encode(state),
        encode(scope)
    )
}

/// Exchange an authorization code for tokens (the loopback flow's final leg).
pub async fn exchange_code(
    issuer: &str,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> TokenAnswer {
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        encode(code),
        encode(redirect_uri),
        encode(client_id),
        encode(code_verifier)
    );
    match ironauth_apply::client::post_form(issuer, "/token", body).await {
        Ok(response) => {
            if let Some(access_token) = response.body["access_token"].as_str() {
                return TokenAnswer::Issued {
                    access_token: access_token.to_owned(),
                    refresh_token: response.body["refresh_token"].as_str().map(str::to_owned),
                    expires_in_secs: response.body["expires_in"].as_i64().unwrap_or(0),
                };
            }
            TokenAnswer::Error(
                response.body["error"]
                    .as_str()
                    .unwrap_or("invalid_request")
                    .to_owned(),
            )
        }
        Err(error) => TokenAnswer::Error(error.to_string()),
    }
}

/// Store what an exchange issued.
///
/// # Errors
///
/// [`LoginError::Storage`] when the keychain refuses, or [`LoginError::Refused`] when the
/// answer was an error rather than tokens.
pub fn store_issued(
    answer: TokenAnswer,
    issuer: &str,
    account: &str,
    store: &impl CredentialStore,
    now_unix_secs: i64,
) -> Result<(), LoginError> {
    match answer {
        TokenAnswer::Issued {
            access_token,
            refresh_token,
            expires_in_secs,
        } => store
            .store(
                account,
                &StoredCredential {
                    access_token,
                    refresh_token,
                    expires_at_unix_secs: now_unix_secs.saturating_add(expires_in_secs),
                    issuer: issuer.to_owned(),
                },
            )
            .map_err(|error| LoginError::Storage(error.to_string())),
        TokenAnswer::Error(_) => Err(LoginError::Refused(
            "the authorization server refused the exchange; run the command again",
        )),
    }
}

/// The current time in epoch seconds, read through the [`Clock`] seam.
///
/// Exists so the login command has no reason to reach for the host clock directly: the stored
/// expiry is derived from this instant, which makes it protocol-adjacent state that must
/// stay deterministic under a manual clock in tests.
///
/// A clock before the Unix epoch yields 0 rather than panicking. That is not a real
/// configuration, but a login is the wrong place to abort on one: the consequence is an
/// already-expired credential the next command refreshes, which is recoverable, where a
/// panic in a user-facing CLI is not.
pub fn epoch_secs(clock: &dyn ironauth_env::Clock) -> i64 {
    clock
        .now_utc()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Percent-encode one form value.
///
/// Hand-rolled because the CLI carries no URL crate and this needs exactly the
/// `application/x-www-form-urlencoded` rule: everything outside the unreserved set is
/// escaped. A `client_id` is a caller-supplied opaque string, so interpolating it raw would
/// let a value containing `&` or `=` forge additional parameters.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char);
            }
            other => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

/// POST the RFC 8628 device-authorization request.
///
/// # Errors
///
/// A message naming the transport or protocol failure.
pub async fn request_device_authorization(
    issuer: &str,
    client_id: &str,
) -> Result<DeviceAuthorization, String> {
    let body = format!("client_id={}", encode(client_id));
    let response = ironauth_apply::client::post_form(issuer, "/device_authorization", body)
        .await
        .map_err(|error| error.to_string())?;
    if response.status != 200 {
        // The server's own error code when it gave one: "invalid_client" tells a user to
        // check the id they passed, where a bare status tells them nothing actionable.
        let detail = response.body["error"]
            .as_str()
            .map_or_else(|| format!("HTTP {}", response.status), str::to_owned);
        return Err(detail);
    }
    let field = |name: &str| -> Result<String, String> {
        response.body[name]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("the device authorization response has no '{name}'"))
    };
    Ok(DeviceAuthorization {
        device_code: field("device_code")?,
        user_code: field("user_code")?,
        verification_uri: field("verification_uri")?,
        verification_uri_complete: response.body["verification_uri_complete"]
            .as_str()
            .map(str::to_owned),
        interval_secs: response.body["interval"].as_u64(),
        // Section 3.2 makes expires_in REQUIRED. Defaulting it would invent a lifetime the
        // server did not promise, so a missing one is an error rather than a guess.
        expires_in_secs: response.body["expires_in"]
            .as_u64()
            .ok_or_else(|| "the device authorization response has no 'expires_in'".to_owned())?,
    })
}

/// POST one token request for `device_code`.
///
/// A transport failure is reported as an OAuth-shaped error so the caller's single
/// [`TokenAnswer`] match covers it. It maps to `Next::Stop` rather than a retry, which is
/// the conservative reading: a client that cannot tell a transient fault from a permanent
/// one and keeps polling is the fleet-polling-forever failure section 3.5 warns about.
pub async fn request_token(issuer: &str, client_id: &str, device_code: String) -> TokenAnswer {
    let body = format!(
        "grant_type={}&device_code={}&client_id={}",
        encode("urn:ietf:params:oauth:grant-type:device_code"),
        encode(&device_code),
        encode(client_id)
    );
    match ironauth_apply::client::post_form(issuer, "/token", body).await {
        Ok(response) => {
            if let Some(access_token) = response.body["access_token"].as_str() {
                return TokenAnswer::Issued {
                    access_token: access_token.to_owned(),
                    refresh_token: response.body["refresh_token"].as_str().map(str::to_owned),
                    expires_in_secs: response.body["expires_in"].as_i64().unwrap_or(0),
                };
            }
            TokenAnswer::Error(
                response.body["error"]
                    .as_str()
                    .unwrap_or("invalid_request")
                    .to_owned(),
            )
        }
        Err(error) => TokenAnswer::Error(error.to_string()),
    }
}

/// Tell the user what to do on the other device.
fn print_instructions(authorization: &DeviceAuthorization) {
    println!("To sign in, visit:");
    // The complete URI is preferred when offered: it carries the code, so there is nothing
    // to mistype.
    if let Some(complete) = &authorization.verification_uri_complete {
        println!("  {complete}");
    } else {
        println!("  {}", authorization.verification_uri);
        println!("and enter the code: {}", authorization.user_code);
    }
    println!();
    println!("Waiting for approval...");
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::credentials::testing::MemoryStore;

    fn authorization() -> DeviceAuthorization {
        DeviceAuthorization {
            device_code: "device-code-value".to_owned(),
            user_code: "WDJB-MJHT".to_owned(),
            verification_uri: "https://issuer.example.test/device".to_owned(),
            verification_uri_complete: None,
            interval_secs: Some(5),
            expires_in_secs: 1_800,
        }
    }

    fn issued() -> TokenAnswer {
        TokenAnswer::Issued {
            access_token: "access-value".to_owned(),
            refresh_token: Some("refresh-value".to_owned()),
            expires_in_secs: 3_600,
        }
    }

    /// Drive the loop over a script of token answers, recording every sleep.
    async fn drive(
        answers: Vec<TokenAnswer>,
        store: &MemoryStore,
    ) -> (Result<(), LoginError>, Vec<Duration>) {
        let answers = RefCell::new(answers.into_iter());
        let slept = RefCell::new(Vec::new());
        let result = run_device_flow(
            "https://issuer.example.test",
            "default",
            store,
            1_000,
            || async { Ok(authorization()) },
            |_code| async { answers.borrow_mut().next().expect("a scripted answer") },
            |duration| {
                slept.borrow_mut().push(duration);
                async {}
            },
        )
        .await;
        (result, slept.into_inner())
    }

    /// Every value in the authorization URL is encoded, so a caller-supplied `client_id`
    /// or redirect cannot forge additional parameters into the request.
    #[test]
    fn the_authorize_url_encodes_every_value() {
        let url = super::authorize_url(
            "https://issuer.example.test/",
            "cli&evil=1",
            "http://127.0.0.1:1234/cb",
            "chal",
            "st",
            "openid profile",
        );
        assert!(
            url.starts_with("https://issuer.example.test/authorize?"),
            "{url}"
        );
        assert!(url.contains("client_id=cli%26evil%3D1"), "{url}");
        assert!(
            url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A1234%2Fcb"),
            "{url}"
        );
        assert!(url.contains("scope=openid%20profile"), "{url}");
        assert!(url.contains("code_challenge_method=S256"), "{url}");
        // The trailing slash on the issuer must not produce a double slash.
        assert!(!url.contains("test//authorize"), "{url}");
    }

    /// The clock seam is what the login reads, so a manual clock decides the stored expiry.
    /// Driven through the shared `ManualClock` rather than a hand-rolled double, which is
    /// both less code and one fewer thing claiming an exemption from the rule that exists
    /// to keep this deterministic.
    #[test]
    fn the_time_comes_from_the_clock_seam() {
        let clock =
            ironauth_env::ManualClock::new(std::time::UNIX_EPOCH + Duration::from_secs(1_234_567));
        assert_eq!(super::epoch_secs(&clock), 1_234_567);

        clock.advance(Duration::from_secs(60));
        assert_eq!(
            super::epoch_secs(&clock),
            1_234_627,
            "the seam must report the advanced time, not the host clock"
        );
    }

    /// A form value containing `&` or `=` must NOT be able to forge extra parameters. A
    /// `client_id` is caller-supplied and opaque, so this is the one place a hostile value
    /// could change what the request means.
    #[test]
    fn encoding_prevents_parameter_forging() {
        assert_eq!(
            super::encode("evil&grant_type=password"),
            "evil%26grant_type%3Dpassword"
        );
        assert_eq!(super::encode("a b"), "a%20b");
        // The unreserved set passes through unchanged, so ordinary ids stay readable.
        assert_eq!(super::encode("cli_abc-123._~"), "cli_abc-123._~");
    }

    /// The grant-type URN survives encoding intact, since it is what routes the request.
    #[test]
    fn the_device_grant_urn_encodes_to_the_registered_value() {
        assert_eq!(
            super::encode("urn:ietf:params:oauth:grant-type:device_code"),
            "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
        );
    }

    #[tokio::test]
    async fn a_completed_login_stores_the_credential() {
        let store = MemoryStore::default();
        let (result, _) = drive(vec![issued()], &store).await;
        assert!(result.is_ok(), "{:?}", result.err());
        assert!(store.holds("default"), "the credential must be stored");
    }

    /// Criterion 2, through the COMMAND path: `slow_down` increases the interval, and the
    /// increase persists for every subsequent request (RFC 8628 section 3.5 says "for this
    /// and all subsequent requests", so applying it once is the bug this catches).
    #[tokio::test]
    async fn slow_down_raises_the_interval_and_keeps_it_raised() {
        let store = MemoryStore::default();
        let (result, slept) = drive(
            vec![
                TokenAnswer::Error("authorization_pending".to_owned()),
                TokenAnswer::Error("slow_down".to_owned()),
                TokenAnswer::Error("authorization_pending".to_owned()),
                issued(),
            ],
            &store,
        )
        .await;

        assert!(result.is_ok(), "{:?}", result.err());
        assert_eq!(
            slept,
            vec![
                Duration::from_secs(5),
                Duration::from_secs(5),
                // slow_down was answered here, so this and everything after it is 10.
                Duration::from_secs(10),
                Duration::from_secs(10),
            ],
            "the raised interval must persist, not apply once"
        );
    }

    /// The client waits before its FIRST poll. Polling immediately guarantees an
    /// `authorization_pending` the user could not have avoided.
    #[tokio::test]
    async fn the_first_poll_waits_for_the_interval() {
        let store = MemoryStore::default();
        let (_, slept) = drive(vec![issued()], &store).await;
        assert_eq!(slept.first(), Some(&Duration::from_secs(5)));
    }

    /// An omitted interval means 5 seconds (section 3.5), not zero.
    #[tokio::test]
    async fn an_omitted_interval_defaults_to_five_seconds() {
        let store = MemoryStore::default();
        let answers = RefCell::new(vec![issued()].into_iter());
        let slept = RefCell::new(Vec::new());
        let _ = run_device_flow(
            "https://issuer.example.test",
            "default",
            &store,
            1_000,
            || async {
                Ok(DeviceAuthorization {
                    interval_secs: None,
                    ..authorization()
                })
            },
            |_| async { answers.borrow_mut().next().expect("answer") },
            |duration| {
                slept.borrow_mut().push(duration);
                async {}
            },
        )
        .await;
        assert_eq!(slept.into_inner().first(), Some(&Duration::from_secs(5)));
    }

    /// A refusal stops polling and stores NOTHING. Section 3.5 is explicit that any error
    /// other than the two pending codes ends the loop.
    #[tokio::test]
    async fn a_denial_stops_and_stores_nothing() {
        let store = MemoryStore::default();
        let (result, slept) =
            drive(vec![TokenAnswer::Error("access_denied".to_owned())], &store).await;

        assert!(matches!(result, Err(LoginError::Refused(_))));
        assert!(
            !store.holds("default"),
            "a refused login must store nothing"
        );
        assert_eq!(slept.len(), 1, "polling must stop at the refusal");
    }

    /// An UNRECOGNISED error code also stops. A client cannot know it is transient, and
    /// guessing that it is turns one server change into a fleet polling forever.
    #[tokio::test]
    async fn an_unknown_error_code_stops_polling() {
        let store = MemoryStore::default();
        let (result, slept) =
            drive(vec![TokenAnswer::Error("something_new".to_owned())], &store).await;

        assert!(matches!(result, Err(LoginError::Refused(_))));
        assert_eq!(slept.len(), 1, "an unknown code must not be retried");
    }

    /// A storage failure fails the LOGIN. Reporting success would tell the user they are
    /// signed in on a machine that has nothing stored, and the next command would fail for
    /// a reason that looks unrelated.
    #[tokio::test]
    async fn a_storage_failure_fails_the_login() {
        let store = crate::credentials::testing::RefusingStore;
        let answers = RefCell::new(vec![issued()].into_iter());
        let result = run_device_flow(
            "https://issuer.example.test",
            "default",
            &store,
            1_000,
            || async { Ok(authorization()) },
            |_| async { answers.borrow_mut().next().expect("answer") },
            |_| async {},
        )
        .await;
        assert!(matches!(result, Err(LoginError::Storage(_))), "{result:?}");
    }

    /// The stored expiry is the issuance instant plus the lifetime, so "am I still signed
    /// in" is answerable without a round trip.
    #[tokio::test]
    async fn the_stored_expiry_is_derived_from_the_issuance_instant() {
        let store = MemoryStore::default();
        let (result, _) = drive(vec![issued()], &store).await;
        assert!(result.is_ok());
        assert_eq!(
            store.expiry_of("default"),
            Some(1_000 + 3_600),
            "expiry must be now + expires_in"
        );
    }
}
