// SPDX-License-Identifier: MIT OR Apache-2.0

//! The management-API client: a minimal HTTP/1.1 client for the operator's own
//! control plane.
//!
//! # Why this is not `ironauth-fetch`
//!
//! `ironauth-fetch` is the server's SSRF-hardened OUTBOUND path: it refuses every
//! loopback and private destination by a policy that is deliberately not
//! configurable, because the server must never be tricked into dialing an internal
//! address from an attacker-controlled URL. This client has the OPPOSITE threat
//! model. It is an operator deliberately pointing their own CLI at their own
//! control plane, which by design lives on a loopback or private address (a
//! management API is not exposed to the internet). So it dials exactly the
//! addresses the fetcher must refuse. It reuses the same vetted hyper +
//! tokio-rustls stack (no new dependency enters the lock), adds no SSRF policy,
//! and follows no redirects.
//!
//! The client carries the operator's bearer credential (see [`Credential`], which
//! redacts on `Debug`) and never writes it to any output; a bad credential
//! surfaces as an unauthenticated STATUS from the server, never as the token text.

use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1; // http-audit-allow: control-plane client, not the server's outbound path
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector; // http-audit-allow: control-plane client TLS
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore}; // http-audit-allow: control-plane client TLS

use crate::error::ClientError;

/// The default response size cap: 8 mebibytes. A promotion plan for a large
/// environment is far smaller, and the cap keeps a hostile or broken endpoint
/// from exhausting memory.
const MAX_RESPONSE_BYTES: usize = 8 << 20;

/// The management API's content type.
const JSON_CONTENT_TYPE: &str = "application/json";

/// The OAuth content type (RFC 6749 section 4.1.3 and every token-endpoint request).
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

/// The default total deadline for one request (connect, TLS, exchange, body).
const TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The URL scheme of the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    /// Plaintext `http` (typical for a loopback control plane or one behind a
    /// TLS-terminating sidecar).
    Http,
    /// TLS `https`.
    Https,
}

/// The operator's bearer credential for the management API. Redacts on `Debug`
/// and is never rendered to any output, so a secret-scan over the CLI's logs and
/// stdout finds no token.
#[derive(Clone)]
pub struct Credential(String);

impl Credential {
    /// Wrap a raw bearer token.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    /// The `Bearer <token>` header value.
    fn header_value(&self) -> String {
        format!("Bearer {}", self.0)
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the token, so it cannot leak through a Debug print.
        f.write_str("Credential(redacted)")
    }
}

/// A parsed API base URL: scheme, host, port, and any path prefix.
#[derive(Debug, Clone)]
struct BaseUrl {
    /// The URL scheme.
    scheme: Scheme,
    /// The host, without brackets for an IPv6 literal.
    host: String,
    /// The resolved port (defaulted from the scheme when absent).
    port: u16,
    /// The path prefix from the base URL, without a trailing slash (empty for the
    /// common `http://host:port` form).
    prefix: String,
}

/// Parse an API base URL into its parts. Accepts `http`/`https`, an optional port,
/// a bracketed IPv6 literal, and an optional path prefix.
fn parse_base_url(raw: &str) -> Result<BaseUrl, ClientError> {
    let invalid = || ClientError::InvalidUrl(raw.to_owned());
    let (scheme, rest) = if let Some(rest) = raw.strip_prefix("https://") {
        (Scheme::Https, rest)
    } else if let Some(rest) = raw.strip_prefix("http://") {
        (Scheme::Http, rest)
    } else {
        return Err(invalid());
    };

    // Split the authority from the path at the first '/'.
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err(invalid());
    }

    let (host, port_str) = split_host_port(authority).ok_or_else(invalid)?;
    if host.is_empty() {
        return Err(invalid());
    }
    let port = match port_str {
        Some(text) => text.parse::<u16>().map_err(|_| invalid())?,
        None => match scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        },
    };
    let prefix = path.trim_end_matches('/').to_owned();
    Ok(BaseUrl {
        scheme,
        host: host.to_owned(),
        port,
        prefix,
    })
}

/// Split an authority into its host and optional port, handling a bracketed IPv6
/// literal (`[::1]:8080`). Returns `None` on a malformed bracket.
fn split_host_port(authority: &str) -> Option<(&str, Option<&str>)> {
    if let Some(after_bracket) = authority.strip_prefix('[') {
        let close = after_bracket.find(']')?;
        let host = &after_bracket[..close];
        let remainder = &after_bracket[close + 1..];
        if remainder.is_empty() {
            return Some((host, None));
        }
        let port = remainder.strip_prefix(':')?;
        return Some((host, Some(port)));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host, Some(port))),
        None => Some((authority, None)),
    }
}

/// A raw response from the management API: the HTTP status and the parsed JSON
/// body (or [`serde_json::Value::Null`] when the body is empty or not JSON, which
/// the caller treats as an unstructured error at that status).
#[derive(Debug, Clone)]
pub struct ServerResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The parsed JSON body.
    pub body: serde_json::Value,
}

/// A client for one control plane, holding the parsed base URL, the operator
/// credential, and (for https) the shared TLS configuration.
#[derive(Debug)]
pub struct ManagementClient {
    /// The parsed base URL.
    base: BaseUrl,
    /// The operator bearer credential.
    credential: Credential,
    /// The shared TLS client configuration, built only for an https base URL.
    tls: Option<Arc<ClientConfig>>,
}

impl ManagementClient {
    /// Build a client for `base_url` authenticating with `credential`.
    ///
    /// # Errors
    ///
    /// [`ClientError::InvalidUrl`] if the base URL cannot be parsed;
    /// [`ClientError::NoTrustRoots`] or [`ClientError::TlsProvider`] if an https
    /// base URL's TLS configuration cannot be built.
    pub fn new(base_url: &str, credential: Credential) -> Result<Self, ClientError> {
        let base = parse_base_url(base_url)?;
        let tls = match base.scheme {
            Scheme::Https => Some(build_tls_config()?),
            Scheme::Http => None,
        };
        Ok(Self {
            base,
            credential,
            tls,
        })
    }

    /// POST `body` to `path` (an absolute path beginning with `/`) and return the
    /// status and parsed JSON body. The whole exchange runs under a total deadline.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a URL, resolution, connection, TLS, timeout, size-cap, or
    /// protocol failure.
    pub async fn post_json(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<ServerResponse, ClientError> {
        match tokio::time::timeout(TOTAL_TIMEOUT, self.exchange(path, body)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(ClientError::Timeout),
        }
    }

    /// The connect-then-exchange line for one POST.
    async fn exchange(&self, path: &str, body: Vec<u8>) -> Result<ServerResponse, ClientError> {
        let full_path = format!("{}{path}", self.base.prefix);
        let host = self.base.host.as_str();
        let port = self.base.port;

        // Resolve and connect. Unlike the server's SSRF path, loopback and private
        // addresses are the EXPECTED destinations for a control-plane client, so no
        // address policy is applied.
        let mut addrs = tokio::net::lookup_host((host, port))
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let addr = addrs
            .next()
            .ok_or_else(|| ClientError::Unresolved(host.to_owned()))?;
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;

        let host_header = self.host_header();
        let auth = self.credential.header_value();
        match self.base.scheme {
            Scheme::Https => {
                let config = self.tls.clone().ok_or(ClientError::TlsProvider)?;
                let tls_stream = tls_connect(&config, host, stream).await?;
                send(
                    TokioIo::new(tls_stream),
                    Method::POST,
                    &full_path,
                    &host_header,
                    Some(&auth),
                    Some(JSON_CONTENT_TYPE),
                    body,
                )
                .await
            }
            Scheme::Http => {
                send(
                    TokioIo::new(stream),
                    Method::POST,
                    &full_path,
                    &host_header,
                    Some(&auth),
                    Some(JSON_CONTENT_TYPE),
                    body,
                )
                .await
            }
        }
    }

    /// The `Host` header value: the host, plus the port when it is not the scheme
    /// default. An IPv6 literal is bracketed.
    fn host_header(&self) -> String {
        let host = if self.base.host.contains(':') {
            format!("[{}]", self.base.host)
        } else {
            self.base.host.clone()
        };
        let default_port = match self.base.scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        };
        if self.base.port == default_port {
            host
        } else {
            format!("{host}:{}", self.base.port)
        }
    }
}

/// Complete a rustls client handshake over the connected socket, verifying the
/// certificate against the configured host name.
async fn tls_connect(
    config: &Arc<ClientConfig>,
    host: &str,
    stream: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ClientError> {
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| ClientError::InvalidUrl(host.to_owned()))?;
    TlsConnector::from(Arc::clone(config)) // http-audit-allow: control-plane client TLS
        .connect(server_name, stream)
        .await
        .map_err(|error| ClientError::Transport(error.to_string()))
}

/// Handshake HTTP/1.1 over `io`, send one request, and read the response under the size cap.
/// No redirect is followed.
///
/// The METHOD, the `Content-Type` and the credential are all the caller's. The method became
/// one when discovery needed a GET (issue #120); the other two were already caller-supplied,
/// and `post_form` has always passed no credential. The callers now differ in all three: the
/// management client sends an authenticated JSON POST, `post_form` and `post_form_url` an
/// unauthenticated form POST, and `get_json` a GET with no body and therefore no
/// `Content-Type` to describe one.
async fn send<I>(
    io: I,
    method: Method,
    path: &str,
    host_header: &str,
    authorization: Option<&str>,
    content_type: Option<&str>,
    body: Vec<u8>,
) -> Result<ServerResponse, ClientError>
where
    I: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
{
    let (mut sender, conn) = http1::handshake(io) // http-audit-allow: control-plane client
        .await
        .map_err(|error| ClientError::Transport(error.to_string()))?;
    // Drive the connection until the sender and body are dropped.
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(http::header::HOST, host_header)
        .header(http::header::ACCEPT, "application/json");
    // OPTIONAL, because a GET has no body to describe. Sending `Content-Type` on a bodyless
    // request is not fatal but it is a lie about a body that is not there, and some
    // intermediaries treat it as one.
    if let Some(content_type) = content_type {
        builder = builder.header(http::header::CONTENT_TYPE, content_type);
    }
    // OPTIONAL, because an OAuth token request authenticates in the body (or not at all,
    // for a public client) rather than with a bearer credential. Sending an empty
    // Authorization header instead would be a malformed request rather than an absent one.
    if let Some(authorization) = authorization {
        builder = builder.header(http::header::AUTHORIZATION, authorization);
    }
    let request = builder
        .body(Full::new(Bytes::from(body)))
        .map_err(|error| ClientError::Transport(error.to_string()))?;

    let response = sender
        .send_request(request)
        .await
        .map_err(|error| ClientError::Transport(error.to_string()))?;
    let status = response.status().as_u16();
    let bytes = read_capped(response.into_body(), MAX_RESPONSE_BYTES).await?;
    let body = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    Ok(ServerResponse { status, body })
}

/// POST a form-encoded body to `base_url` + `path`, with NO bearer credential.
///
/// This is the OAuth shape: `ironauth login` drives the RFC 8628 device-authorization and
/// token endpoints, which take `application/x-www-form-urlencoded` and authenticate in the
/// body (or not at all, for a public client).
///
/// It lives HERE rather than in the CLI crate on purpose. The parts that matter for safety
/// are the ones it shares with [`ManagementClient`]: the TLS configuration built from the
/// platform trust roots, the total deadline, and the response size cap. A second copy of
/// those in another crate would be two things to keep in step, and the copy that drifts is
/// the one nobody is looking at. Only the content type and the absent Authorization header
/// differ, so only those are parameters.
///
/// # Errors
///
/// [`ClientError`] on a URL, resolution, connection, TLS, timeout, size-cap, or protocol
/// failure.
pub async fn post_form(
    base_url: &str,
    path: &str,
    form_body: String,
) -> Result<ServerResponse, ClientError> {
    let base = parse_base_url(base_url)?;
    let tls = match base.scheme {
        Scheme::Https => Some(build_tls_config()?),
        Scheme::Http => None,
    };
    let exchange = async {
        let full_path = format!("{}{path}", base.prefix);
        let host = base.host.as_str();
        let mut addrs = tokio::net::lookup_host((host, base.port))
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let addr = addrs
            .next()
            .ok_or_else(|| ClientError::Unresolved(host.to_owned()))?;
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let host_header = if base.host.contains(':') {
            format!("[{}]:{}", base.host, base.port)
        } else {
            format!("{}:{}", base.host, base.port)
        };
        let body = form_body.into_bytes();
        match base.scheme {
            Scheme::Https => {
                let config = tls.clone().ok_or(ClientError::TlsProvider)?;
                let tls_stream = tls_connect(&config, host, stream).await?;
                send(
                    TokioIo::new(tls_stream),
                    Method::POST,
                    &full_path,
                    &host_header,
                    None,
                    Some(FORM_CONTENT_TYPE),
                    body,
                )
                .await
            }
            Scheme::Http => {
                send(
                    TokioIo::new(stream),
                    Method::POST,
                    &full_path,
                    &host_header,
                    None,
                    Some(FORM_CONTENT_TYPE),
                    body,
                )
                .await
            }
        }
    };
    match tokio::time::timeout(TOTAL_TIMEOUT, exchange).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ClientError::Timeout),
    }
}

/// The request target for an ABSOLUTE endpoint URL: its path, verbatim.
///
/// `parse_base_url` trims a trailing slash, which is right for a BASE that paths get appended
/// to and wrong for an endpoint published as an exact URL. Two cases it gets wrong on its own:
/// a root endpoint (`https://as.example`) leaves an EMPTY prefix, and `Request::builder().uri("")`
/// is a hard error rather than a request for `/`; and `https://as.example/token/` and
/// `https://as.example/token` are different targets per RFC 3986, so silently dropping the
/// slash sends a request the server did not publish.
fn absolute_request_target(url: &str) -> String {
    // The raw path, taken from the URL rather than the trimmed prefix.
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    // No path at all means `/`. That is what a client asks for, and it is what the trimmed
    // prefix cannot express: an empty request target is a hard error in the URI builder.
    after_scheme
        .find('/')
        .map_or_else(|| "/".to_owned(), |index| after_scheme[index..].to_owned())
}

/// POST a form to an ABSOLUTE endpoint URL, as published by discovery.
///
/// Distinct from [`post_form`], which takes a base and appends a path. A discovered endpoint is
/// already complete, and appending to it or trimming it would send a request the authorization
/// server did not advertise.
///
/// # Errors
///
/// As [`post_form`].
pub async fn post_form_url(url: &str, form_body: String) -> Result<ServerResponse, ClientError> {
    let base = parse_base_url(url)?;
    let target = absolute_request_target(url);
    let tls = match base.scheme {
        Scheme::Https => Some(build_tls_config()?),
        Scheme::Http => None,
    };
    let exchange = async {
        let host = base.host.as_str();
        let mut addrs = tokio::net::lookup_host((host, base.port))
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let addr = addrs
            .next()
            .ok_or_else(|| ClientError::Unresolved(host.to_owned()))?;
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let host_header = if base.host.contains(':') {
            format!("[{}]:{}", base.host, base.port)
        } else {
            format!("{}:{}", base.host, base.port)
        };
        let body = form_body.into_bytes();
        match base.scheme {
            Scheme::Https => {
                let config = tls.clone().ok_or(ClientError::TlsProvider)?;
                let tls_stream = tls_connect(&config, host, stream).await?;
                send(
                    TokioIo::new(tls_stream),
                    Method::POST,
                    &target,
                    &host_header,
                    None,
                    Some(FORM_CONTENT_TYPE),
                    body,
                )
                .await
            }
            Scheme::Http => {
                send(
                    TokioIo::new(stream),
                    Method::POST,
                    &target,
                    &host_header,
                    None,
                    Some(FORM_CONTENT_TYPE),
                    body,
                )
                .await
            }
        }
    };
    match tokio::time::timeout(TOTAL_TIMEOUT, exchange).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ClientError::Timeout),
    }
}

/// GET a JSON document, through the same transport, timeout and size caps as [`post_form`].
///
/// Added for OAuth DISCOVERY (issue #120). A client must not build protocol endpoints by
/// appending paths to an issuer: an issuer is an identifier, not a base URL, and IronAuth's own
/// are scoped (`.../t/{tenant}/e/{environment}`) while the protocol routes are served at the
/// deployment root. Appending therefore 404s against this server, which is exactly the defect
/// this exists to fix, and it is wrong in general because RFC 8414 lets an AS place its
/// endpoints anywhere it likes.
///
/// # Errors
///
/// As [`post_form`]: an unparseable URL, a name that does not resolve, a transport or TLS
/// failure, a body over the cap, or the total timeout.
pub async fn get_json(url: &str) -> Result<ServerResponse, ClientError> {
    let base = parse_base_url(url)?;
    let tls = match base.scheme {
        Scheme::Https => Some(build_tls_config()?),
        Scheme::Http => None,
    };
    let exchange = async {
        let full_path = absolute_request_target(url);
        let host = base.host.as_str();
        let mut addrs = tokio::net::lookup_host((host, base.port))
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let addr = addrs
            .next()
            .ok_or_else(|| ClientError::Unresolved(host.to_owned()))?;
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let host_header = if base.host.contains(':') {
            format!("[{}]:{}", base.host, base.port)
        } else {
            format!("{}:{}", base.host, base.port)
        };
        match base.scheme {
            Scheme::Https => {
                let config = tls.clone().ok_or(ClientError::TlsProvider)?;
                let tls_stream = tls_connect(&config, host, stream).await?;
                send(
                    TokioIo::new(tls_stream),
                    Method::GET,
                    &full_path,
                    &host_header,
                    None,
                    None,
                    Vec::new(),
                )
                .await
            }
            Scheme::Http => {
                send(
                    TokioIo::new(stream),
                    Method::GET,
                    &full_path,
                    &host_header,
                    None,
                    None,
                    Vec::new(),
                )
                .await
            }
        }
    };
    match tokio::time::timeout(TOTAL_TIMEOUT, exchange).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ClientError::Timeout),
    }
}

/// Read a streaming body frame by frame, aborting the moment the accumulated size
/// would cross `max_bytes`.
async fn read_capped(body: Incoming, max_bytes: usize) -> Result<Vec<u8>, ClientError> {
    let mut body = body;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| ClientError::Transport(error.to_string()))?;
        if let Ok(data) = frame.into_data() {
            if buf.len().saturating_add(data.len()) > max_bytes {
                return Err(ClientError::ResponseTooLarge);
            }
            buf.extend_from_slice(&data);
        }
    }
    Ok(buf)
}

/// Build the shared TLS client configuration: the OS trust store via
/// `rustls-native-certs` and the ring provider, no client authentication, and no
/// custom verifier that would weaken certificate validation. This mirrors the
/// vetted configuration in `ironauth-fetch` and `ironauth-store`.
///
/// # Errors
///
/// [`ClientError::NoTrustRoots`] if the OS trust store yields no usable roots;
/// [`ClientError::TlsProvider`] if the ring provider rejects the default versions.
fn build_tls_config() -> Result<Arc<ClientConfig>, ClientError> {
    let mut roots = RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    for cert in loaded.certs {
        // A single malformed system certificate must not abort the CLI; skip it.
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        return Err(ClientError::NoTrustRoots);
    }
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| ClientError::TlsProvider)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::{Scheme, absolute_request_target, parse_base_url};

    /// The request target for a discovered endpoint is its path VERBATIM.
    ///
    /// Both cases here were wrong when the CLI passed a whole endpoint URL to `post_form` with
    /// an empty path (issue #120): that composes `prefix + ""`, and `prefix` is the parsed path
    /// with its trailing slash trimmed.
    #[test]
    fn an_absolute_endpoint_keeps_its_path_exactly() {
        assert_eq!(
            absolute_request_target("https://as.example/oauth2/v1/token"),
            "/oauth2/v1/token"
        );
        // A ROOT endpoint. The trimmed prefix is empty, and an empty request target is a hard
        // error in the URI builder rather than a request for `/`.
        assert_eq!(absolute_request_target("https://as.example"), "/");
        assert_eq!(absolute_request_target("https://as.example/"), "/");
        // A TRAILING SLASH is significant per RFC 3986, so dropping it sends a request the
        // server did not publish.
        assert_eq!(
            absolute_request_target("https://as.example/token/"),
            "/token/"
        );
        // A query the server chose to publish travels too.
        assert_eq!(
            absolute_request_target("https://as.example/token?v=2"),
            "/token?v=2"
        );
        // A port must not be mistaken for the start of a path.
        assert_eq!(
            absolute_request_target("http://127.0.0.1:8080/token"),
            "/token"
        );
        assert_eq!(absolute_request_target("http://127.0.0.1:8080"), "/");
    }

    #[test]
    fn parses_http_with_port_and_no_prefix() {
        let base = parse_base_url("http://127.0.0.1:8080").expect("parses");
        assert_eq!(base.scheme, Scheme::Http);
        assert_eq!(base.host, "127.0.0.1");
        assert_eq!(base.port, 8080);
        assert_eq!(base.prefix, "");
    }

    #[test]
    fn defaults_ports_from_scheme() {
        assert_eq!(
            parse_base_url("http://example.test").expect("parses").port,
            80
        );
        assert_eq!(
            parse_base_url("https://example.test").expect("parses").port,
            443
        );
    }

    #[test]
    fn strips_trailing_slash_and_keeps_prefix() {
        let base = parse_base_url("https://mgmt.example.test/control/").expect("parses");
        assert_eq!(base.scheme, Scheme::Https);
        assert_eq!(base.prefix, "/control");
    }

    #[test]
    fn parses_bracketed_ipv6_literal() {
        let base = parse_base_url("http://[::1]:9000").expect("parses");
        assert_eq!(base.host, "::1");
        assert_eq!(base.port, 9000);
    }

    #[test]
    fn rejects_missing_scheme_and_empty_authority() {
        assert!(parse_base_url("127.0.0.1:8080").is_err());
        assert!(parse_base_url("http://").is_err());
        assert!(parse_base_url("ftp://host").is_err());
    }

    #[test]
    fn rejects_non_numeric_port() {
        assert!(parse_base_url("http://host:notaport").is_err());
    }

    #[test]
    fn credential_debug_redacts_the_token() {
        let credential = super::Credential::new("super-secret-token");
        let rendered = format!("{credential:?}");
        assert!(!rendered.contains("super-secret-token"));
        assert!(rendered.contains("redacted"));
    }
}
