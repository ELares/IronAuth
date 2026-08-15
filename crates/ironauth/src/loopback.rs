// SPDX-License-Identifier: MIT OR Apache-2.0

//! Building the loopback redirect URI for `ironauth login` (issue #120).
//!
//! RFC 8252 section 7.3 has a client listen on an ephemeral loopback port, so the redirect
//! URI the client sends cannot be byte-identical to the one it registered: the port is not
//! known until the listener binds. The server therefore matches loopback redirects
//! port-agnostically, and everything else about the URI exactly.
//!
//! # `localhost` is the trap, and it fails silently
//!
//! RFC 8252 says to use the IP literal rather than the name, and this server enforces it:
//! only `127.0.0.1` and `[::1]` are treated as loopback, so a registration naming
//! `localhost` falls through to EXACT string matching and can never match an ephemeral
//! port. Worse, `localhost` resolves to `::1` on some hosts and `127.0.0.1` on others, so a
//! client that binds the name and reports the literal can disagree with itself between
//! machines.
//!
//! So this refuses `localhost` with a message that says why, rather than building a URI
//! that will be rejected at the authorization endpoint for reasons the user cannot see.
//!
//! # Why the host literal is carried through rather than chosen
//!
//! The server requires the literal to MATCH: a registration of `127.0.0.1` is not satisfied
//! by `[::1]`. So the registered URI decides which family to bind, not the host's
//! preference. Choosing here and hoping would fail on exactly the dual-stack machines where
//! it is hardest to reproduce.

/// Why a registered redirect URI cannot be used for a loopback login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopbackError {
    /// The URI is not `http://`.
    NotHttp,
    /// The host is `localhost` rather than an IP literal.
    LocalhostNamed,
    /// The host is neither `127.0.0.1` nor `[::1]`.
    NotLoopback,
}

impl LoopbackError {
    /// What to tell the user. Each cause says what to change, because "loopback login is
    /// unavailable" sends someone reading their network config for a registration problem.
    #[must_use]
    pub fn message(&self) -> &'static str {
        match self {
            Self::NotHttp => {
                "the registered redirect must be http:// for a loopback login (RFC 8252 7.3)"
            }
            Self::LocalhostNamed => {
                "register http://127.0.0.1/... or http://[::1]/... rather than localhost: \
                 the name is not matched port-agnostically and resolves differently per host"
            }
            Self::NotLoopback => {
                "the registered redirect is not a loopback address; use the device flow"
            }
        }
    }
}

/// Build the redirect URI to send, from the REGISTERED one and the port actually bound.
///
/// Everything except the port is carried through byte for byte, because that is what the
/// server compares. Rewriting a path, normalising a trailing slash, or dropping an empty
/// query would each produce a URI that looks equivalent and is not.
///
/// # Errors
///
/// [`LoopbackError`] naming what about the registration makes a loopback login impossible.
pub fn loopback_redirect(registered: &str, port: u16) -> Result<String, LoopbackError> {
    let rest = registered
        .strip_prefix("http://")
        .ok_or(LoopbackError::NotHttp)?;

    // Split the authority from the path/query, which is carried through untouched.
    let (authority, tail) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, ""),
    };

    // An IPv6 literal is bracketed, and the brackets are part of the authority rather than
    // decoration: `[::1]:80` splits on the LAST colon, not the first.
    let host = if let Some(closing) = authority.strip_prefix('[').and_then(|a| a.find(']')) {
        &authority[..=closing + 1]
    } else {
        authority.split(':').next().unwrap_or(authority)
    };

    if host.eq_ignore_ascii_case("localhost") {
        return Err(LoopbackError::LocalhostNamed);
    }
    if host != "127.0.0.1" && host != "[::1]" {
        return Err(LoopbackError::NotLoopback);
    }

    Ok(format!("http://{host}:{port}{tail}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_store::redirect_uri_matches;

    /// The strongest assertion available: the URI this builds must satisfy the SERVER's own
    /// matcher against the registration it was built from. A test comparing against a
    /// string I wrote would only prove I am self-consistent.
    fn round_trips(registered: &str, port: u16) -> String {
        let built = loopback_redirect(registered, port).expect("buildable");
        assert!(
            redirect_uri_matches(registered, &built),
            "the server must accept {built} for a registration of {registered}"
        );
        built
    }

    #[test]
    fn an_ipv4_loopback_registration_accepts_any_bound_port() {
        assert_eq!(
            round_trips("http://127.0.0.1/callback", 51234),
            "http://127.0.0.1:51234/callback"
        );
    }

    #[test]
    fn an_ipv6_loopback_registration_keeps_its_brackets() {
        // `[::1]:port` splits on the LAST colon. Treating the first colon as the port
        // separator turns `[` into the host and produces something no matcher accepts.
        assert_eq!(
            round_trips("http://[::1]/callback", 51234),
            "http://[::1]:51234/callback"
        );
    }

    #[test]
    fn a_registration_that_already_names_a_port_still_works() {
        // The port in the registration is advisory: the listener binds an ephemeral one and
        // the server ignores the difference. A client that reused the registered port would
        // fail whenever it was already in use, which is the situation ephemeral ports exist
        // for.
        assert_eq!(
            round_trips("http://127.0.0.1:8080/cb", 51234),
            "http://127.0.0.1:51234/cb"
        );
    }

    #[test]
    fn the_path_and_query_are_carried_through_byte_for_byte() {
        // The server compares these exactly. Normalising a trailing slash or dropping an
        // empty query produces a URI that looks equivalent and is not.
        round_trips("http://127.0.0.1/deep/path/", 4000);
        round_trips("http://127.0.0.1/cb?fixed=1", 4000);
    }

    #[test]
    fn localhost_is_refused_with_a_reason_that_names_the_fix() {
        // The trap. `localhost` is not matched port-agnostically by this server, so a
        // loopback login against it can never succeed, and it resolves to ::1 on some
        // hosts and 127.0.0.1 on others.
        let error = loopback_redirect("http://localhost/cb", 4000).expect_err("refused");
        assert_eq!(error, LoopbackError::LocalhostNamed);
        assert!(
            error.message().contains("127.0.0.1"),
            "the message must name what to register instead: {}",
            error.message()
        );
    }

    #[test]
    fn a_non_loopback_or_https_registration_is_refused_distinctly() {
        assert_eq!(
            loopback_redirect("https://127.0.0.1/cb", 4000),
            Err(LoopbackError::NotHttp)
        );
        assert_eq!(
            loopback_redirect("http://example.test/cb", 4000),
            Err(LoopbackError::NotLoopback)
        );
        // Distinct causes, distinct messages: "loopback login is unavailable" for all three
        // sends someone reading their network config for a registration problem.
        let messages = [
            LoopbackError::NotHttp.message(),
            LoopbackError::LocalhostNamed.message(),
            LoopbackError::NotLoopback.message(),
        ];
        assert_eq!(
            messages
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
    }

    #[test]
    fn a_built_uri_is_rejected_for_a_different_loopback_family() {
        // The reason the registered literal is carried through rather than chosen: the
        // server requires the family to match, so binding ::1 against a 127.0.0.1
        // registration fails. Asserted through the real matcher.
        let built = loopback_redirect("http://[::1]/cb", 4000).expect("buildable");
        assert!(
            !redirect_uri_matches("http://127.0.0.1/cb", &built),
            "an ipv6 callback must not satisfy an ipv4 registration: {built}"
        );
    }
}
