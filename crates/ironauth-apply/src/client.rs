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
                    &full_path,
                    &host_header,
                    &auth,
                    body,
                )
                .await
            }
            Scheme::Http => send(TokioIo::new(stream), &full_path, &host_header, &auth, body).await,
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

/// Handshake HTTP/1.1 over `io`, send one POST with a JSON body and the bearer
/// credential, and read the response under the size cap. No redirect is followed.
async fn send<I>(
    io: I,
    path: &str,
    host_header: &str,
    authorization: &str,
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

    let request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(http::header::HOST, host_header)
        .header(http::header::AUTHORIZATION, authorization)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::ACCEPT, "application/json")
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
    use super::{Scheme, parse_base_url};

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
