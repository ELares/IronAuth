// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 8252 loopback half of `ironauth login` (issue #120).
//!
//! # Why loopback is preferred where it can run
//!
//! The device flow works everywhere, and that is its only advantage. Loopback is preferred
//! because it has no cross-device step: nothing is displayed for a human to type somewhere
//! else, so there is no code for an attacker to solicit. `login_flow::choose_flow` makes
//! that choice and returns its reason, and this module is what runs when it says loopback.
//!
//! # Falling back is a RUNTIME decision, not only a host one
//!
//! `choose_flow` reads the host: a display, an SSH session, a platform that opens a browser
//! implicitly. None of that tells you whether a listener can actually bind. A locked-down
//! host, a sandbox with no loopback, or an exhausted ephemeral range all fail at `bind`,
//! after the heuristic has already said loopback.
//!
//! So the fallback lives HERE, at the bind, and it is the criterion's wording: "falls back
//! cleanly to device flow when the listener cannot bind". [`prepare`] returns [`None`] on a
//! bind failure and the caller runs the device flow, which is why the decision is a value
//! rather than a branch buried in the command.
//!
//! # PKCE comes from the server's own transform
//!
//! The `code_challenge` is derived with `ironauth_oidc::pkce::s256_challenge`, the same
//! function the authorization server verifies against. That function's own documentation
//! records why a local copy would be a mistake: two implementations of this transform once
//! existed in this workspace and AGREED, which is the dangerous state, because nothing
//! would have failed if one had been changed.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use ironauth_env::Entropy;

use crate::loopback::{LoopbackError, loopback_redirect};

/// The RFC 7636 unreserved verifier alphabet.
const VERIFIER_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

/// A bound loopback listener and the PKCE material for the exchange that will follow.
pub struct Prepared {
    /// The listener, already bound.
    pub listener: TcpListener,
    /// The redirect URI to send, carrying the port actually bound.
    pub redirect_uri: String,
    /// The PKCE verifier, presented at the token endpoint.
    pub code_verifier: String,
    /// The PKCE challenge, sent to the authorization endpoint.
    pub code_challenge: String,
    /// The CSRF `state`, echoed back and compared.
    pub state: String,
}

/// Generate an RFC 7636 4.1 `code_verifier`: 43 unreserved characters.
///
/// 43 is the RFC's floor and equals 256 bits of base64url, so this sits exactly at the
/// entropy the spec requires rather than above it by accident. Bytes come from the
/// [`Entropy`] seam, never a host RNG directly, so generation stays deterministic in tests.
///
/// The modulo bias here is real and negligible: 256 mod 66 leaves the first 58 characters
/// very slightly favoured. Rejection sampling would remove it, and it is not worth the
/// branch, because the attack it would prevent needs an adversary who can exploit under one
/// bit of bias in a value that is revealed at the token endpoint moments later anyway.
#[must_use]
pub fn generate_verifier(entropy: &dyn Entropy) -> String {
    let mut bytes = [0_u8; 43];
    entropy.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|byte| VERIFIER_ALPHABET[usize::from(*byte) % VERIFIER_ALPHABET.len()] as char)
        .collect()
}

/// Generate the CSRF `state`.
#[must_use]
pub fn generate_state(entropy: &dyn Entropy) -> String {
    let mut bytes = [0_u8; 24];
    entropy.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|byte| VERIFIER_ALPHABET[usize::from(*byte) % VERIFIER_ALPHABET.len()] as char)
        .collect()
}

/// Why the loopback flow could not be prepared.
#[derive(Debug, PartialEq, Eq)]
pub enum PrepareError {
    /// The registered redirect cannot be used for loopback, with the reason.
    Registration(LoopbackError),
    /// A listener could not be bound. The caller falls back to the device flow.
    Bind,
}

/// Bind a loopback listener and build everything the authorization request needs.
///
/// `registered` is the redirect URI the client registered; the port is replaced with the
/// one actually bound, per RFC 8252 7.3.
///
/// # Errors
///
/// [`PrepareError::Registration`] when the registration cannot support a loopback login at
/// all (that is a configuration problem and must be REPORTED, not silently downgraded);
/// [`PrepareError::Bind`] when no listener could be bound, which the caller treats as
/// "use the device flow".
pub fn prepare(registered: &str, entropy: &dyn Entropy) -> Result<Prepared, PrepareError> {
    // Bind FIRST: the port is not known until it is bound, and the redirect URI has to
    // carry it. Port 0 asks the OS for an ephemeral one.
    //
    // The bind host follows the REGISTRATION's family, not this host's preference: the
    // server requires the literal to match, so a `127.0.0.1` registration is not satisfied
    // by `[::1]`. Deciding here and hoping would fail on exactly the dual-stack machines
    // where it is hardest to reproduce.
    let bind_host = if registered.starts_with("http://[::1]") {
        "[::1]:0"
    } else {
        "127.0.0.1:0"
    };
    let listener = TcpListener::bind(bind_host).map_err(|_| PrepareError::Bind)?;
    let port = listener
        .local_addr()
        .map_err(|_| PrepareError::Bind)?
        .port();

    let redirect_uri = loopback_redirect(registered, port).map_err(PrepareError::Registration)?;
    let code_verifier = generate_verifier(entropy);
    let code_challenge = ironauth_oidc::pkce::s256_challenge(&code_verifier);
    Ok(Prepared {
        listener,
        redirect_uri,
        code_verifier,
        code_challenge,
        state: generate_state(entropy),
    })
}

/// What the browser came back with.
#[derive(Debug, PartialEq, Eq)]
pub enum Redirect {
    /// The authorization code, with the `state` it carried.
    Code {
        /// The code to exchange.
        code: String,
        /// The echoed state, for the caller to compare.
        state: String,
    },
    /// The authorization server reported an error.
    Failed(String),
}

/// Parse the request line of the browser's redirect.
///
/// Takes the LINE rather than the stream so the parsing is testable without a socket, and
/// because that is all that is needed: the query carries everything.
///
/// Returns [`None`] for anything that is not a recognisable redirect, including the
/// favicon and preflight requests a browser may send to the same port. Treating those as a
/// failed login would abort a flow that is still perfectly fine.
#[must_use]
pub fn parse_redirect(request_line: &str) -> Option<Redirect> {
    let target = request_line.split_whitespace().nth(1)?;
    let query = target.split_once('?').map(|(_, query)| query)?;

    let mut code = None;
    let mut state = None;
    let mut error = None;
    for pair in query.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        match name {
            "code" => code = Some(percent_decode(value)),
            "state" => state = Some(percent_decode(value)),
            "error" => error = Some(percent_decode(value)),
            _ => {}
        }
    }

    // An error wins over a code. A response carrying both is malformed, and reading the
    // code from it would proceed with a grant the server just said it was refusing.
    if let Some(error) = error {
        return Some(Redirect::Failed(error));
    }
    Some(Redirect::Code {
        code: code?,
        state: state.unwrap_or_default(),
    })
}

/// Decode one percent-encoded query value.
/// Decode one percent-encoded value. Public so the fake upstream provider can reuse it
/// rather than carry a second decoder that could disagree with this one.
pub fn percent_decode_public(value: &str) -> String {
    percent_decode(value)
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    index += 3;
                } else {
                    // A malformed escape is carried through literally rather than dropped:
                    // a value is not made safer by silently losing a character from it.
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Accept ONE redirect on `listener`, answer the browser, and return what it carried.
///
/// # Errors
///
/// A message naming the failure, for the caller to report.
pub fn await_redirect(listener: &TcpListener) -> Result<Redirect, String> {
    // Loops rather than taking the first connection, because a browser may open a
    // speculative or favicon request to the same port; those parse to `None` and must not
    // end a flow that is still fine.
    for stream in listener.incoming() {
        let mut stream = stream.map_err(|error| error.to_string())?;
        let mut line = String::new();
        BufReader::new(&stream)
            .read_line(&mut line)
            .map_err(|error| error.to_string())?;

        if let Some(redirect) = parse_redirect(&line) {
            let page = match &redirect {
                Redirect::Code { .. } => "Signed in. You can close this window.",
                Redirect::Failed(_) => "Sign in failed. Return to the terminal.",
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{page}",
                page.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            return Ok(redirect);
        }
        // Not a redirect: answer briefly and keep waiting.
        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    }
    Err("the browser never completed the redirect".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_env::FixedEntropy;
    use ironauth_oidc::pkce::{code_verifier_is_well_formed, s256_challenge, verify_s256};

    fn entropy() -> FixedEntropy {
        FixedEntropy::new(7)
    }

    /// The generated verifier satisfies the SERVER's own format rule, not one restated here.
    #[test]
    fn the_verifier_satisfies_the_servers_format_rule() {
        let verifier = generate_verifier(&entropy());
        assert!(
            code_verifier_is_well_formed(&verifier),
            "generated a verifier the server would reject: {verifier}"
        );
        assert_eq!(verifier.len(), 43, "43 is the RFC 7636 entropy floor");
    }

    /// The challenge this sends round-trips through the SERVER's verifier. A test comparing
    /// against a string written here would only prove self-consistency; this proves the
    /// exchange would actually succeed.
    #[test]
    fn the_challenge_verifies_against_the_servers_own_check() {
        let verifier = generate_verifier(&entropy());
        let challenge = s256_challenge(&verifier);
        assert!(
            verify_s256(&verifier, &challenge),
            "the server must accept the challenge this flow sends"
        );
    }

    /// A code and state are extracted from the redirect.
    #[test]
    fn a_redirect_yields_its_code_and_state() {
        let parsed = parse_redirect("GET /callback?code=abc123&state=xyz HTTP/1.1");
        assert_eq!(
            parsed,
            Some(Redirect::Code {
                code: "abc123".to_owned(),
                state: "xyz".to_owned()
            })
        );
    }

    /// An error response is reported as a failure rather than parsed for a code.
    #[test]
    fn an_error_redirect_is_a_failure() {
        let parsed = parse_redirect("GET /callback?error=access_denied&state=xyz HTTP/1.1");
        assert_eq!(parsed, Some(Redirect::Failed("access_denied".to_owned())));
    }

    /// A response carrying BOTH is malformed, and the error wins: reading the code would
    /// proceed with a grant the server just said it was refusing.
    #[test]
    fn an_error_beats_a_code_in_the_same_response() {
        let parsed = parse_redirect("GET /cb?code=abc&error=access_denied&state=x HTTP/1.1");
        assert_eq!(parsed, Some(Redirect::Failed("access_denied".to_owned())));
    }

    /// A favicon or speculative request is NOT a redirect, so it must not end the flow.
    #[test]
    fn an_unrelated_request_is_not_a_redirect() {
        assert_eq!(parse_redirect("GET /favicon.ico HTTP/1.1"), None);
        assert_eq!(parse_redirect("GET / HTTP/1.1"), None);
        assert_eq!(parse_redirect("garbage"), None);
    }

    /// Percent-encoded values are decoded, since a code may legitimately contain them.
    #[test]
    fn encoded_values_are_decoded() {
        let parsed = parse_redirect("GET /cb?code=a%2Bb%2Fc&state=s%3D1 HTTP/1.1");
        assert_eq!(
            parsed,
            Some(Redirect::Code {
                code: "a+b/c".to_owned(),
                state: "s=1".to_owned()
            })
        );
    }

    /// Binding produces a redirect URI the SERVER's matcher accepts for the registration it
    /// was built from, with the port actually bound.
    #[test]
    fn preparing_yields_a_redirect_the_server_would_match() {
        let prepared = prepare("http://127.0.0.1/callback", &entropy()).expect("bind");
        let port = prepared.listener.local_addr().expect("addr").port();
        assert_eq!(
            prepared.redirect_uri,
            format!("http://127.0.0.1:{port}/callback")
        );
        assert!(ironauth_store::redirect_uri_matches(
            "http://127.0.0.1/callback",
            &prepared.redirect_uri
        ));
    }

    /// A registration that cannot support loopback is REPORTED, not silently downgraded to
    /// the device flow: it is a configuration problem, and hiding it behind a fallback
    /// makes it undiagnosable.
    #[test]
    fn an_unusable_registration_is_reported_not_downgraded() {
        assert_eq!(
            prepare("http://localhost/cb", &entropy()).err(),
            Some(PrepareError::Registration(LoopbackError::LocalhostNamed))
        );
        assert_eq!(
            prepare("https://127.0.0.1/cb", &entropy()).err(),
            Some(PrepareError::Registration(LoopbackError::NotHttp))
        );
    }
}
