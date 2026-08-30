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
//! The HTTP goes through `ironauth_apply::client`: `get_json` for discovery and
//! `post_form_url` for the two protocol POSTs, both the SAME connect, TLS configuration, total
//! deadline, and response size cap the control-plane client uses. A second copy of that in this
//! crate would be two things to keep in step, and the copy that drifts is the one nobody is
//! looking at.
//!
//! NOT `post_form`, which takes a base and appends a path. A discovered endpoint is already
//! complete, and that function composes the PARSED prefix, whose trailing slash is trimmed: a
//! root endpoint would become an empty request target and `/token/` would be sent as `/token`
//! (issue #120).
//!
//! # What is testable here, and what is not
//!
//! Everything except the network. [`run_device_flow`] takes the two endpoints as closures,
//! so the tests below drive the whole loop, including the RFC 8628 section 3.5 `slow_down`
//! rule, against scripted responses. What that leaves unproved is the HTTP calls themselves,
//! which is why each is a shared function call rather than logic of its own. The one piece of
//! URL construction that is NOT deferred to the transport, the authorization URL's query
//! separator, has its own unit tests, because getting it wrong corrupts a published query
//! rather than failing loudly.

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
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    state: &str,
    scope: &str,
) -> String {
    // The separator the endpoint's own shape calls for. RFC 6749 section 3.1 permits the
    // authorization endpoint to carry a query and requires it be RETAINED when parameters are
    // added, so a discovered `https://as.example/authorize?tenant=acme` must continue with `&`.
    // Appending `?` unconditionally made the server read `tenant` as `acme?response_type=code`.
    // Unreachable while the base was always `{issuer}/authorize` built locally; reachable the
    // moment the endpoint comes from discovery.
    //
    // The trailing slash is NOT trimmed, for the reason `absolute_request_target` gives: the
    // endpoint is published as an exact URL, and `/authorize/` is a different resource from
    // `/authorize`.
    let separator = if authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    format!(
        "{}{separator}response_type=code&client_id={}&redirect_uri={}\
         &code_challenge={}&code_challenge_method=S256&state={}&scope={}",
        authorization_endpoint,
        encode(client_id),
        encode(redirect_uri),
        encode(code_challenge),
        encode(state),
        encode(scope)
    )
}

/// Exchange an authorization code for tokens (the loopback flow's final leg).
pub async fn exchange_code(
    token_endpoint: &str,
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
    match ironauth_apply::client::post_form_url(token_endpoint, body).await {
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

/// The protocol endpoints an issuer publishes, resolved by DISCOVERY rather than guessed.
///
/// Every field is an ABSOLUTE URL as the authorization server named it, which is the whole
/// point: an issuer is an identifier, not a base URL to append paths to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    /// RFC 6749 `authorization_endpoint`, for the loopback flow's browser leg.
    pub authorization: String,
    /// RFC 8628 `device_authorization_endpoint`.
    pub device_authorization: String,
    /// RFC 6749 `token_endpoint`, shared by both flows' final leg.
    pub token: String,
}

/// Fetch `{issuer}/.well-known/openid-configuration` and read the endpoints this login needs.
///
/// An earlier CLI built both endpoints by appending `/device_authorization` and `/token` to
/// `--issuer`. That cannot work against this server and is wrong in general. IronAuth issuers
/// are SCOPED (`.../t/{tenant}/e/{environment}`) while both routes are served at the deployment
/// ROOT, so appending produced a 404 for every user who passed the issuer they were given, which
/// is the only issuer they have: it is the `iss` in their tokens. BOTH flows were affected, not
/// just the device one: `/token` is deployment-root only as well, so the loopback flow reached
/// its browser leg (there IS a scoped `/authorize`) and then 404ed on the exchange. More
/// broadly, RFC 8414 lets an authorization server place its endpoints anywhere, so a client that
/// derives them by string concatenation is guessing even where the guess happens to land.
///
/// # Errors
///
/// A message naming the transport failure, a non-200 status, or a document missing an endpoint
/// this login needs. A missing endpoint is an error rather than a fallback to the guessed path,
/// because falling back would restore the bug quietly on exactly the servers that trigger it.
pub async fn discover_endpoints(issuer: &str) -> Result<Endpoints, String> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let response = ironauth_apply::client::get_json(&url)
        .await
        .map_err(|error| format!("could not read {url}: {error}"))?;
    if response.status != 200 {
        return Err(format!("{url} answered HTTP {}", response.status));
    }
    let field = |name: &str| -> Result<String, String> {
        response.body[name]
            .as_str()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| format!("{url} publishes no '{name}'"))
    };
    Ok(Endpoints {
        authorization: field("authorization_endpoint")?,
        device_authorization: field("device_authorization_endpoint")?,
        token: field("token_endpoint")?,
    })
}

/// POST the RFC 8628 device-authorization request.
///
/// # Errors
///
/// A message naming the transport or protocol failure.
pub async fn request_device_authorization(
    endpoint: &str,
    client_id: &str,
) -> Result<DeviceAuthorization, String> {
    let body = format!("client_id={}", encode(client_id));
    // The DISCOVERED endpoint, sent verbatim. `post_form_url` exists for exactly this: it
    // takes the URL's own path as the request target rather than appending to a base, so a
    // root endpoint and a trailing slash both reach the server as published.
    let response = ironauth_apply::client::post_form_url(endpoint, body)
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
pub async fn request_token(
    token_endpoint: &str,
    client_id: &str,
    device_code: String,
) -> TokenAnswer {
    let body = format!(
        "grant_type={}&device_code={}&client_id={}",
        encode("urn:ietf:params:oauth:grant-type:device_code"),
        encode(&device_code),
        encode(client_id)
    );
    match ironauth_apply::client::post_form_url(token_endpoint, body).await {
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
///
/// # The code is ALWAYS printed, including when the complete URI carries it
///
/// The obvious shape is to print the complete URI instead of the code, since it carries the
/// code and there is nothing to mistype. RFC 8628 section 3.3.1 asks for the opposite, and the
/// reason is the cross-device threat rather than typing:
///
/// > the client SHOULD display the `user_code` to the user and ask them to verify that it
/// > matches the `user_code` being displayed on the [approving] device
///
/// A user who is walked to an approval page by an attacker's link has one defence, which is
/// comparing the code on the page against the code their own device showed. A client that never
/// showed one has taken that defence away, and the OAuth 2.0 for Browser-Based Apps and
/// cross-device BCP guidance both rest on that comparison being possible.
///
/// So the complete URI is still preferred for the link -- there is genuinely nothing to
/// mistype -- and the code is printed beside it to be checked rather than typed. The wording
/// differs between the two branches because the user's job differs: enter it, or verify it.
fn print_instructions(authorization: &DeviceAuthorization) {
    print!("{}", instructions(authorization));
}

/// The instruction text, BUILT rather than printed, so a test can read it.
///
/// Split out for exactly that reason: `print_instructions` went to stdout and nothing could
/// assert what it said, so the property this function exists to hold -- that the code appears on
/// both branches -- was unmeasurable. A test that captured stdout would be testing the terminal.
fn instructions(authorization: &DeviceAuthorization) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("To sign in, visit:\n");
    if let Some(complete) = &authorization.verification_uri_complete {
        let _ = writeln!(out, "  {complete}");
        let _ = writeln!(
            out,
            "and check the page shows this code: {}",
            authorization.user_code
        );
    } else {
        let _ = writeln!(out, "  {}", authorization.verification_uri);
        let _ = writeln!(out, "and enter the code: {}", authorization.user_code);
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "Waiting for approval...");
    out
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
        // The DISCOVERED endpoint, not an issuer with `/authorize` appended. The endpoint is
        // deliberately at a path the issuer does not prefix, which is the case appending got
        // wrong: a server may publish its authorization endpoint anywhere.
        let url = super::authorize_url(
            "https://issuer.example.test/oauth2/v1/authorize",
            "cli&evil=1",
            "http://127.0.0.1:1234/cb",
            "chal",
            "st",
            "openid profile",
        );
        assert!(
            url.starts_with("https://issuer.example.test/oauth2/v1/authorize?"),
            "{url}"
        );
        assert!(url.contains("client_id=cli%26evil%3D1"), "{url}");
        assert!(
            url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A1234%2Fcb"),
            "{url}"
        );
        assert!(url.contains("scope=openid%20profile"), "{url}");
        assert!(url.contains("code_challenge_method=S256"), "{url}");
    }

    #[test]
    fn the_authorize_url_keeps_the_endpoint_the_server_published() {
        // A trailing slash is SIGNIFICANT per RFC 3986: `/authorize/` and `/authorize` are
        // different resources, so a discovered endpoint carrying one keeps it. An earlier
        // revision trimmed it, which was right when the base was an issuer with `/authorize`
        // appended and wrong once the endpoint comes from the server.
        let slashed = super::authorize_url(
            "https://as.example/authorize/",
            "cli",
            "http://127.0.0.1:1/cb",
            "chal",
            "st",
            "openid",
        );
        assert!(
            slashed.starts_with("https://as.example/authorize/?response_type=code"),
            "{slashed}"
        );

        // A QUERY the server published must be RETAINED, which RFC 6749 section 3.1 requires
        // explicitly. Appending `?` unconditionally made the server read `tenant` as
        // `acme?response_type=code`.
        let queried = super::authorize_url(
            "https://as.example/authorize?tenant=acme",
            "cli",
            "http://127.0.0.1:1/cb",
            "chal",
            "st",
            "openid",
        );
        assert!(
            queried.starts_with("https://as.example/authorize?tenant=acme&response_type=code"),
            "{queried}"
        );
        assert!(!queried.contains("acme?response_type"), "{queried}");
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

    /// RFC 8628 section 3.3.1: the client SHOULD display the `user_code` and ask the user to
    /// verify it matches the one on the approving device -- INCLUDING when it offers the
    /// complete URI, which already carries the code.
    ///
    /// The obvious implementation prints the complete URI instead of the code, since there is
    /// then nothing to mistype, and that is what this shipped. It removes the user's only
    /// defence against being walked to an approval page by an attacker's link: comparing the
    /// code on the page against the code their own device showed.
    ///
    /// BOTH BRANCHES are asserted. A test over one would pass against exactly the version that
    /// had the bug, because the bare-URI branch always printed the code.
    #[test]
    fn the_user_code_is_displayed_whether_or_not_a_complete_uri_is_offered() {
        let bare = DeviceAuthorization {
            device_code: "dev".to_owned(),
            user_code: "WDJB-MJHT".to_owned(),
            verification_uri: "https://iss.example/device".to_owned(),
            verification_uri_complete: None,
            interval_secs: Some(5),
            expires_in_secs: 900,
        };
        let bare_text = super::instructions(&bare);
        assert!(bare_text.contains("WDJB-MJHT"), "{bare_text}");

        let complete = DeviceAuthorization {
            verification_uri_complete: Some(
                "https://iss.example/device?user_code=WDJB-MJHT".to_owned(),
            ),
            ..bare
        };
        let complete_text = super::instructions(&complete);
        assert!(
            complete_text.contains("shows this code: WDJB-MJHT"),
            "the code must be displayed for comparison even when the link carries it: \
             {complete_text}"
        );
        // And the WORDING differs, because the user's job differs: enter it, or verify it.
        assert!(!complete_text.contains("enter the code"), "{complete_text}");
    }
}
