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
#[derive(Debug, Clone)]
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

/// What a downstream said.
///
/// The STATUS IS CARRIED, not reduced to a boolean, because the whole convergence protocol is
/// written in status codes: 409 means a race the client recovers from, 501 means fall back to
/// PUT, 404 means the mapping is stale, and 5xx means pause the cursor rather than skip the
/// event. A boolean outcome would make all four the same answer.
#[derive(Debug, Clone)]
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
    /// exists, and a server may use it for other conflicts, so the client that treats a 409 as
    /// "already provisioned" has to check which one it got.
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

/// Join a connection's base URL to a relative path, keeping exactly one slash between them.
///
/// A base URL an operator typed may or may not end in a slash, and a path always begins with one.
/// Naive concatenation yields `.../scim/v2//Users`, which some servers 404 and others normalize:
/// a difference that shows up as one downstream working and another not.
fn join(base_url: &str, path: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), path)
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
            _ => out.push_str(&format!("%{byte:02X}")),
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
        let mut url = join(base_url, &request.path);
        if let Some(filter) = &request.filter {
            url.push_str("?filter=");
            url.push_str(&encode_filter(filter));
        }
        let authorization = format!("Bearer {bearer}");
        async move {
            let mut fetch = ironauth_fetch::FetchRequest::new(
                ironauth_fetch::FetchPurpose::ScimPush,
                request.method,
                url,
            );
            let Ok(auth) = http::HeaderValue::from_str(&authorization) else {
                // A credential that cannot be a header value never leaves the process, and it is
                // NOT a transport failure to retry: the secret is malformed and every retry
                // reproduces it. Reported as `Transport` because this seam does not classify
                // configuration problems; the caller pauses and an operator sees the connection
                // stop, which is the correct outcome for a credential that cannot be presented.
                return Err(ScimTransportError::Transport);
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
                Err(_) => Err(ScimTransportError::Transport),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{encode_filter, join};

    #[test]
    fn a_base_url_and_a_path_join_with_exactly_one_slash() {
        // BOTH spellings of the base URL, because an operator types either and the difference
        // between them is a double slash some downstreams 404 and others normalize.
        assert_eq!(
            join("https://d.example/scim/v2", "/Users"),
            "https://d.example/scim/v2/Users"
        );
        assert_eq!(
            join("https://d.example/scim/v2/", "/Users"),
            "https://d.example/scim/v2/Users"
        );
        // And a base that is nothing but a host, which is what a server with SCIM at the root
        // gets configured as.
        assert_eq!(
            join("https://d.example", "/Users"),
            "https://d.example/Users"
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
