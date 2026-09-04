// SPDX-License-Identifier: MIT OR Apache-2.0

//! The single outbound seam an outbound SCIM push leaves the process through (issue #137).
//!
//! # Why a trait and not a direct call
//!
//! It mirrors [`crate::webhook_delivery::WebhookSender`], and for the same measured reason: the
//! production implementor wraps the SSRF-hardened [`ironauth_fetch::Fetcher`], and a test
//! implementor answers from an in-process reference server. Everything ABOVE this trait, which is
//! the part that decides WHICH request a convergence step makes -- look up before creating, fall
//! back from PATCH to PUT, treat a 409 as a race rather than a failure -- is then exercised for
//! real rather than mocked out alongside the transport.
//!
//! That split is not a convenience. The hardened fetcher REFUSES loopback, by design, so a test
//! that pointed it at a server on 127.0.0.1 would exercise the SSRF guard rather than the client.
//! Without a seam, the client's logic would be reachable only against a public host, which is to
//! say untestable.
//!
//! # What rides above this seam and what does not
//!
//! Above: the resource shapes, the lookup-then-create ordering, the write-mode fallback, and the
//! classification of an outcome as retryable or permanent.
//!
//! Below: DNS resolution and pinning, the deny policy, the redirect rule, TLS, and the response
//! cap. None of that is re-implemented here and none of it is bypassable from here: the only
//! production implementor builds an [`ironauth_fetch::FetchRequest`] and hands it to the fetcher.

use std::future::Future;
use std::sync::Arc;

use serde_json::Value;

/// One request to a downstream SCIM server, as the client expresses it.
///
/// The PATH IS RELATIVE to the connection's base URL and the transport joins them, so no caller
/// above this seam can construct an absolute URL and reach a host the connection does not name.
/// A client that built its own URLs would be a second outbound path, which is a second chance to
/// send a directory somewhere nobody configured.
#[derive(Clone)]
pub struct ScimRequest {
    /// The HTTP method.
    pub method: http::Method,
    /// The path beneath the base URL, beginning with a slash (for example `/Users`).
    pub path: String,
    /// The RFC 7644 filter, when this is a query. Percent-encoded by the transport.
    pub filter: Option<String>,
    /// The request body, when the method carries one.
    pub body: Option<Value>,
}

impl ScimRequest {
    /// A `GET` of a collection under a filter (RFC 7644 section 3.4.2).
    #[must_use]
    pub fn query(path: impl Into<String>, filter: impl Into<String>) -> Self {
        Self {
            method: http::Method::GET,
            path: path.into(),
            filter: Some(filter.into()),
            body: None,
        }
    }

    /// A body-carrying request: `POST`, `PUT` or `PATCH`.
    #[must_use]
    pub fn with_body(method: http::Method, path: impl Into<String>, body: Value) -> Self {
        Self {
            method,
            path: path.into(),
            filter: None,
            body: Some(body),
        }
    }

    /// A plain `GET` of one resource by its downstream id.
    ///
    /// Distinct from [`Self::query`] in the way that matters to convergence: a query is answered
    /// by whatever view the downstream serves reads from and can lag, while this addresses one
    /// resource by the id the server itself issued.
    #[must_use]
    pub fn get(path: impl Into<String>) -> Self {
        Self {
            method: http::Method::GET,
            path: path.into(),
            filter: None,
            body: None,
        }
    }

    /// A `DELETE` (RFC 7644 section 3.6).
    #[must_use]
    pub fn delete(path: impl Into<String>) -> Self {
        Self {
            method: http::Method::DELETE,
            path: path.into(),
            filter: None,
            body: None,
        }
    }
}

/// Shape without contents.
///
/// The derived `Debug` printed the whole body, and a SCIM body is a person's directory record:
/// name, e-mail addresses, employee number, manager, group membership. One `tracing` call, or one
/// `.expect()` on a `Result` carrying a request, put that in a log that outlives the request and
/// travels wherever logs are shipped. What an operator debugging a sync needs is which request
/// went where, which is what this prints.
impl std::fmt::Debug for ScimRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScimRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("has_filter", &self.filter.is_some())
            .field("has_body", &self.body.is_some())
            .finish()
    }
}

/// Shape without contents, for the reason [`ScimRequest`]'s own `Debug` gives.
///
/// `scimType` is kept: it is a protocol constant rather than customer data, and it is the one
/// field that tells a duplicate from a bad filter from a refusal.
impl std::fmt::Debug for ScimResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScimResponse")
            .field("status", &self.status)
            .field("scim_type", &self.scim_type())
            .field("has_body", &self.body.is_some())
            .finish()
    }
}

/// What a downstream said.
///
/// The STATUS IS CARRIED, not reduced to a boolean, because the whole convergence protocol is
/// written in status codes: 409 means a race the client recovers from, 501 means fall back to
/// PUT, 404 means the mapping is stale, and 5xx means pause the cursor rather than skip the
/// event. A boolean outcome would make all four the same answer.
#[derive(Clone)]
pub struct ScimResponse {
    /// The HTTP status.
    pub status: http::StatusCode,
    /// The parsed body, absent for a `204` or an unparseable one.
    pub body: Option<Value>,
}

impl ScimResponse {
    /// The `scimType` a SCIM error document carries (RFC 7644 section 3.12), if any.
    ///
    /// Read rather than inferred from the status: 409 is `uniqueness` when a resource already
    /// exists, and a server may use it for other conflicts.
    ///
    /// What the client does with it today is REPORT it, not branch on it. `converge` answers a
    /// 409 by re-querying, and a re-query that finds the resource converges whatever the conflict
    /// was named, while one that finds nothing is a permanent refusal that quotes this value so
    /// an operator can see which conflict the downstream meant. An earlier version of this
    /// sentence said the handler "has to check which one it got", which described a branch that
    /// does not exist.
    #[must_use]
    pub fn scim_type(&self) -> Option<&str> {
        self.body.as_ref()?.get("scimType")?.as_str()
    }
}

/// Why a request did not reach a downstream, or did not come back.
///
/// SEPARATE FROM A STATUS. Every variant here is retryable and none of them says anything about
/// the resource: a paused cursor is the right answer to all three, whereas a 4xx is a statement
/// about the request that retrying will reproduce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimTransportError {
    /// The SSRF policy refused the destination.
    ///
    /// Retryable in the mechanical sense that the cursor should pause rather than skip, but an
    /// operator has to act: it means the connection's base URL resolves somewhere it may not.
    Blocked,
    /// The time budget elapsed.
    Timeout,
    /// Anything else: connect failure, TLS failure, a truncated body.
    Transport,
    /// The CONNECTION's own configuration cannot produce a request.
    ///
    /// A base URL carrying a query or a fragment, or a credential that is not a legal header
    /// value. Distinct from [`Self::Transport`] because no retry can change the outcome: the same
    /// stored configuration produces the same failure forever, and reporting it as a transport
    /// failure makes a connection with a typo in its URL look like a downstream outage. The
    /// operator has to edit the connection, and the health surface has to say so.
    Configuration,
}

/// The one outbound path an outbound SCIM push has.
pub trait ScimTransport: Send + Sync {
    /// Send one request to `base_url`, authenticating with `bearer`.
    ///
    /// The returned future is declared `Send` so a worker built on this seam stays spawnable on
    /// a multi-threaded runtime.
    fn send(
        &self,
        base_url: &str,
        bearer: &str,
        request: ScimRequest,
    ) -> impl Future<Output = Result<ScimResponse, ScimTransportError>> + Send;
}

/// The production transport: every request through the SSRF-hardened outbound fetcher.
#[derive(Debug, Clone)]
pub struct FetchScimTransport {
    fetcher: Arc<ironauth_fetch::Fetcher>,
}

impl FetchScimTransport {
    /// Wrap a shared hardened fetcher.
    #[must_use]
    pub fn new(fetcher: Arc<ironauth_fetch::Fetcher>) -> Self {
        Self { fetcher }
    }
}

/// Join a connection's base URL to a caller-built path, keeping exactly one slash between them.
///
/// A base URL an operator typed may or may not end in a slash, and a path always begins with one.
/// Naive concatenation yields `.../scim/v2//Users`, which some servers 404 and others normalize:
/// a difference that shows up as one downstream working and another not.
/// Joins a connection's base URL to a SCIM path, or says why it cannot.
///
/// # Why this can fail
///
/// The base URL is OPERATOR SUPPLIED and points at somebody else's server, so it is untrusted
/// input in the same sense a redirect URI is. Concatenating blindly has two holes:
///
///   * a base carrying a QUERY (`https://host/scim/v2?tenant=acme`) folds the whole SCIM path
///     into that query, so `/Users` becomes part of a parameter value and every request is sent
///     to the base path instead. A downstream that ignores unknown parameters answers 200 to a
///     request that addressed nothing, and the client reads a create as a success.
///   * a base carrying a FRAGMENT truncates the request at the `#`, with the same result.
///
/// Both are refused here rather than at the surface alone, because this is the last place that
/// sees the two halves together, and a base URL stored before the surface learned to check it
/// would otherwise still be used.
fn join(base_url: &str, path: &str) -> Result<String, ScimTransportError> {
    if base_url.contains('?') || base_url.contains('#') {
        return Err(ScimTransportError::Configuration);
    }
    Ok(format!("{}{}", base_url.trim_end_matches('/'), path))
}

/// Percent-encode a filter for a query string.
///
/// A SCIM filter carries spaces and quotes (`externalId eq "u-1"`), neither of which is legal
/// raw in a query. Encoded HERE, at the one place a filter becomes a URL, rather than at each
/// call site: a caller that forgot would send a request the downstream rejects as malformed and
/// the client would read that as "no match" and create a duplicate.
fn encode_filter(filter: &str) -> String {
    let mut out = String::with_capacity(filter.len() * 3);
    for byte in filter.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

impl ScimTransport for FetchScimTransport {
    fn send(
        &self,
        base_url: &str,
        bearer: &str,
        request: ScimRequest,
    ) -> impl Future<Output = Result<ScimResponse, ScimTransportError>> + Send {
        let fetcher = Arc::clone(&self.fetcher);
        let joined = join(base_url, &request.path).map(|mut url| {
            if let Some(filter) = &request.filter {
                url.push_str("?filter=");
                url.push_str(&encode_filter(filter));
            }
            url
        });
        let authorization = format!("Bearer {bearer}");
        async move {
            let url = joined?;
            let mut fetch = ironauth_fetch::FetchRequest::new(
                ironauth_fetch::FetchPurpose::ScimPush,
                request.method,
                url,
            );
            let Ok(auth) = http::HeaderValue::from_str(&authorization) else {
                // A credential that cannot be a header value never leaves the process, and no
                // retry can change that: the same stored secret produces the same failure every
                // time. `Configuration` rather than `Transport` because the two want different
                // things from an operator -- one means edit the connection, the other means wait
                // for the downstream -- and reporting this as a transport failure made a
                // connection holding a malformed secret look exactly like a downstream outage,
                // which is the one thing an operator would NOT investigate.
                return Err(ScimTransportError::Configuration);
            };
            fetch = fetch.header(http::header::AUTHORIZATION, auth);
            fetch = fetch.header(
                http::header::ACCEPT,
                http::HeaderValue::from_static("application/scim+json"),
            );
            if let Some(body) = request.body {
                fetch = fetch
                    .header(
                        http::header::CONTENT_TYPE,
                        // RFC 7644 section 3.1: the SCIM media type, not `application/json`.
                        // Servers that content-negotiate reject the latter.
                        http::HeaderValue::from_static("application/scim+json"),
                    )
                    .body(body.to_string());
            }
            match fetcher.fetch(fetch).await {
                Ok(response) => {
                    let status = response.status();
                    let body = serde_json::from_slice::<Value>(response.body()).ok();
                    Ok(ScimResponse { status, body })
                }
                Err(ironauth_fetch::FetchError::Blocked) => Err(ScimTransportError::Blocked),
                Err(ironauth_fetch::FetchError::Timeout) => Err(ScimTransportError::Timeout),
                // A PLAINTEXT BASE URL IS A TYPO, not an outage.
                //
                // The fetcher refuses `http` without an explicit opt-in, and it is right to: a
                // bearer with authority over somebody else's directory would otherwise cross the
                // network in clear. But the old catch-all called that `Transport`, so a
                // connection whose URL was pasted with the wrong scheme retried for ever and its
                // health read "the downstream could not be reached" -- pointing an operator at
                // somebody else's server when the fix is one character of their own
                // configuration. Found by this crate's own transport suite, which could not
                // reach the address policy at all until the scheme stopped swallowing it.
                Err(ironauth_fetch::FetchError::SchemeNotAllowed) => {
                    Err(ScimTransportError::Configuration)
                }
                Err(_) => Err(ScimTransportError::Transport),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ScimTransportError, encode_filter, join};

    #[test]
    fn a_base_url_and_a_path_join_with_exactly_one_slash() {
        // BOTH spellings of the base URL, because an operator types either and the difference
        // between them is a double slash some downstreams 404 and others normalize.
        assert_eq!(
            join("https://d.example/scim/v2", "/Users"),
            Ok("https://d.example/scim/v2/Users".to_owned())
        );
        assert_eq!(
            join("https://d.example/scim/v2/", "/Users"),
            Ok("https://d.example/scim/v2/Users".to_owned())
        );
        // And a base that is nothing but a host, which is what a server with SCIM at the root
        // gets configured as.
        assert_eq!(
            join("https://d.example", "/Users"),
            Ok("https://d.example/Users".to_owned())
        );
    }

    #[test]
    fn a_base_url_carrying_a_query_or_a_fragment_is_refused() {
        // Concatenating onto a base with a query folds the SCIM path INTO that query, so
        // `/Users` becomes part of a parameter value and the request addresses the base path.
        // A downstream that ignores unknown parameters answers 200, and the client reads a
        // create that never happened as a success.
        for base in [
            "https://d.example/scim/v2?tenant=acme",
            "https://d.example/scim/v2#frag",
        ] {
            assert_eq!(
                join(base, "/Users"),
                Err(ScimTransportError::Configuration),
                "{base} was accepted"
            );
        }
        // CONTROL: the same shape without the query joins, so the refusal is the query and not
        // the path.
        assert_eq!(
            join("https://d.example/scim/v2", "/Users"),
            Ok("https://d.example/scim/v2/Users".to_owned())
        );
    }

    #[test]
    fn a_filter_is_encoded_so_it_survives_a_query_string() {
        // The exact shape RFC 7644 section 3.4.2 describes for a lookup, which carries both a
        // space and a quote: raw, it is not a legal query, and a downstream that rejects it
        // answers something the client would otherwise read as "no match" and create a duplicate.
        assert_eq!(
            encode_filter("externalId eq \"u-1\""),
            "externalId%20eq%20%22u-1%22"
        );
        // Unreserved characters are NOT encoded, so the common case stays readable in a log.
        assert_eq!(encode_filter("abc-123_x.y~z"), "abc-123_x.y~z");
        // A multi-byte character encodes per BYTE, which is what percent-encoding is defined on.
        assert_eq!(encode_filter("\u{e9}"), "%C3%A9");
    }
}
