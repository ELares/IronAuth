// SPDX-License-Identifier: MIT OR Apache-2.0

//! The connector: the single, module-private outbound path.
//!
//! Everything that touches a socket lives here and is unreachable outside the
//! crate. The exchange is one straight line whose order IS the security
//! property:
//!
//! 1. Resolve the host to addresses exactly once (or take the IP literal
//!    directly), through the injected [`Resolve`] seam.
//! 2. Validate EVERY resolved address against the deny policy; a single denied
//!    address blocks the whole fetch.
//! 3. Pin: hand ONE validated [`SocketAddr`] to the injected [`Dial`] seam. The
//!    dialer never sees the hostname, so nothing re-resolves between the check
//!    and the connect; the DNS-rebinding window is closed structurally.
//! 4. For `https`, complete the rustls handshake using the ORIGINAL hostname as
//!    the SNI and certificate name, while the bytes still flow over the pinned
//!    socket.
//! 5. Speak HTTP/1.1 over hyper's low-level connection API. A 3xx with a
//!    `Location` is surfaced as an error, never followed. The response body is
//!    read frame by frame and aborted the instant it crosses the size cap, and
//!    the whole exchange runs under a single total-deadline timeout.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::observe::BlockReason;
use crate::policy;
use crate::resolve::{Dial, Resolve};
use crate::target::{Scheme, Target};
use crate::{FetchLimits, FetchResponse};

/// A dispatch that did not produce a response. Carries enough internal detail
/// for the caller to meter the outcome; it never leaves the crate unmapped.
#[derive(Debug, Clone, Copy)]
pub(crate) enum DispatchFailure {
    /// The destination was refused (with the internal reason for metering).
    Blocked(BlockReason),
    /// A redirect status was returned and not followed.
    Redirect(u16),
    /// The body exceeded the size cap.
    TooLarge,
    /// The total deadline elapsed.
    Timeout,
    /// The connection, TLS handshake, or HTTP exchange failed.
    Upstream,
}

/// Everything the connector needs for one exchange. Assembled by the public
/// [`crate::Fetcher`] after the URL is parsed and the scheme is permitted.
pub(crate) struct Dispatch<'a> {
    /// The parsed, scheme-approved destination.
    pub(crate) target: &'a Target,
    /// The request method.
    pub(crate) method: Method,
    /// The full header set to send, including the `Host` header. This is exactly
    /// what the caller set plus `Host`; there is no cookie jar, no default
    /// `Authorization`, and no proxy header.
    pub(crate) headers: HeaderMap,
    /// The request body (empty for a bodyless method).
    pub(crate) body: Bytes,
    /// The response caps.
    pub(crate) limits: FetchLimits,
    /// The shared TLS client configuration (native roots, ring provider).
    pub(crate) tls: &'a Arc<ClientConfig>,
    /// The DNS seam.
    pub(crate) resolver: &'a dyn Resolve,
    /// The socket seam.
    pub(crate) dialer: &'a dyn Dial,
}

impl Dispatch<'_> {
    /// Run the exchange under the total-deadline timeout.
    pub(crate) async fn run(self) -> Result<FetchResponse, DispatchFailure> {
        let deadline = self.limits.total_timeout;
        match tokio::time::timeout(deadline, self.exchange()).await {
            Ok(result) => result,
            Err(_elapsed) => Err(DispatchFailure::Timeout),
        }
    }

    /// The resolve-validate-pin-connect-exchange line. Kept private; the only
    /// way to reach it is [`Dispatch::run`].
    async fn exchange(self) -> Result<FetchResponse, DispatchFailure> {
        let Dispatch {
            target,
            method,
            headers,
            body,
            limits,
            tls,
            resolver,
            dialer,
        } = self;

        // 1. Addresses: an IP literal is taken directly (still validated); a
        //    name is resolved exactly once.
        let addrs = match target.literal_ip {
            Some(ip) => vec![ip],
            None => resolver
                .resolve(&target.host, target.port)
                .await
                .map_err(|_| DispatchFailure::Blocked(BlockReason::ResolutionFailed))?,
        };
        if addrs.is_empty() {
            return Err(DispatchFailure::Blocked(BlockReason::NoAddresses));
        }

        // 2. Validate EVERY resolved address. One denied address in a multi
        //    record answer blocks the whole fetch, so an attacker cannot slip a
        //    private address into the set.
        for ip in &addrs {
            if let Some(class) = policy::classify(*ip) {
                return Err(DispatchFailure::Blocked(BlockReason::Address(class)));
            }
        }

        // 3. Pin: connect to a validated address by value. The dialer never
        //    receives the hostname, so it cannot re-resolve.
        let pinned = SocketAddr::new(addrs[0], target.port);
        let stream = dialer
            .dial(pinned)
            .await
            .map_err(|_| DispatchFailure::Upstream)?;

        // 4 + 5. Complete TLS if needed, then exchange over hyper.
        let path = target.path_and_query.as_str();
        let response = match target.scheme {
            Scheme::Https => {
                let tls_stream = tls_connect(tls, &target.host, stream).await?;
                send(TokioIo::new(tls_stream), &method, path, &headers, body).await?
            }
            Scheme::Http => send(TokioIo::new(stream), &method, path, &headers, body).await?,
        };

        finish(response, limits.max_response_bytes).await
    }
}

/// Complete a rustls client handshake over the pinned socket, verifying the
/// certificate against the ORIGINAL hostname (SNI and name verification both use
/// the name the caller asked for, not the pinned IP).
async fn tls_connect(
    config: &Arc<ClientConfig>,
    host: &str,
    stream: tokio::net::TcpStream,
) -> Result<TlsStream<tokio::net::TcpStream>, DispatchFailure> {
    let server_name =
        ServerName::try_from(host.to_owned()).map_err(|_| DispatchFailure::Upstream)?;
    TlsConnector::from(Arc::clone(config))
        .connect(server_name, stream)
        .await
        .map_err(|_| DispatchFailure::Upstream)
}

/// Handshake HTTP/1.1 over `io`, send a single request, and return the response
/// head plus its streaming body. No redirect is ever followed here; that
/// decision is made by [`finish`].
async fn send<I>(
    io: I,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response<Incoming>, DispatchFailure>
where
    I: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|_| DispatchFailure::Upstream)?;
    // The connection task drives the socket; it ends when the sender and the
    // response body are dropped (including on a size-cap abort or a timeout).
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut request = Request::builder()
        .method(method.clone())
        .uri(path)
        .body(Full::new(body))
        .map_err(|_| DispatchFailure::Upstream)?;
    // The dispatcher owns request framing: install the assembled headers but drop
    // any framing or hop-by-hop header a caller may have set, so hyper derives
    // Content-Length from the actual Full body and a caller-supplied
    // Content-Length/Transfer-Encoding can never desync the wire. Host is set by
    // the dispatcher (not carried here) and legitimate headers pass through.
    let dest = request.headers_mut();
    for (name, value) in headers {
        if is_connector_owned(name) {
            continue;
        }
        dest.append(name.clone(), value.clone());
    }

    sender
        .send_request(request)
        .await
        .map_err(|_| DispatchFailure::Upstream)
}

/// Whether a header is one the connector owns and must not accept from a caller:
/// the framing headers (`Content-Length`, `Transfer-Encoding`), which hyper
/// derives from the actual body, and the hop-by-hop headers (`Connection` and
/// any `Proxy-*`, including `Proxy-Connection`), which have no place on an
/// outbound request. `Host` is set by the dispatcher and never carried in the
/// caller set, so it is not listed here.
fn is_connector_owned(name: &http::HeaderName) -> bool {
    *name == header::CONTENT_LENGTH
        || *name == header::TRANSFER_ENCODING
        || *name == header::CONNECTION
        || name.as_str().starts_with("proxy-")
}

/// Apply the redirect rule and read the body under the size cap.
async fn finish(
    response: Response<Incoming>,
    max_bytes: u64,
) -> Result<FetchResponse, DispatchFailure> {
    let status = response.status();
    // A 3xx carrying a Location is the SSRF pivot; surface it, never follow it.
    if status.is_redirection() && response.headers().contains_key(header::LOCATION) {
        return Err(DispatchFailure::Redirect(status.as_u16()));
    }

    let headers = response.headers().clone();
    let body = read_capped(response.into_body(), max_bytes).await?;
    Ok(FetchResponse {
        status,
        headers,
        body,
    })
}

/// Read a streaming body frame by frame, aborting the moment the accumulated
/// size would cross `max_bytes`. Dropping the body on abort closes the
/// connection, so an oversized or endless body is never fully buffered.
async fn read_capped(body: Incoming, max_bytes: u64) -> Result<Vec<u8>, DispatchFailure> {
    // Saturating on a 32-bit host: a cap above the address space cannot be
    // exceeded there anyway, so clamping to usize::MAX is safe.
    let cap = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    let mut body = body;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| DispatchFailure::Upstream)?;
        if let Ok(data) = frame.into_data() {
            if buf.len().saturating_add(data.len()) > cap {
                return Err(DispatchFailure::TooLarge);
            }
            buf.extend_from_slice(&data);
        }
    }
    Ok(buf)
}

/// Build the shared TLS client configuration: the OS trust store loaded through
/// `rustls-native-certs` and the ring crypto provider. No client authentication,
/// no custom verifier that would weaken certificate validation.
///
/// # Errors
///
/// Returns [`TlsSetupError::NoTrustRoots`] if the OS trust store yields no usable
/// roots (a fetcher with no roots would fail every https handshake), or
/// [`TlsSetupError::Provider`] if the ring provider rejects the default protocol
/// versions (should never happen).
pub(crate) fn build_tls_config() -> Result<Arc<ClientConfig>, TlsSetupError> {
    let mut roots = RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    for cert in loaded.certs {
        // A single malformed system certificate must not abort startup; skip it.
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        return Err(TlsSetupError::NoTrustRoots);
    }
    let config = client_config_with_roots(roots)?;
    Ok(Arc::new(config))
}

/// Assemble a [`ClientConfig`] over `roots` with the ring provider.
fn client_config_with_roots(roots: RootCertStore) -> Result<ClientConfig, TlsSetupError> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsSetupError::Provider)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

/// A TLS client configuration with an EMPTY trust store, for tests that exercise
/// the connector over plaintext `http` and therefore never complete a
/// handshake. It never fails and never loads the OS store, keeping tests
/// hermetic.
#[cfg(feature = "test-harness")]
pub(crate) fn test_tls_config() -> Arc<ClientConfig> {
    let config = client_config_with_roots(RootCertStore::empty())
        .expect("ring provider supports the default protocol versions");
    Arc::new(config)
}

/// Why the TLS client configuration could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlsSetupError {
    /// The OS trust store produced no usable root certificates.
    NoTrustRoots,
    /// The crypto provider rejected the default protocol versions.
    Provider,
}

impl std::fmt::Display for TlsSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsSetupError::NoTrustRoots => {
                f.write_str("no usable root certificates in the OS trust store")
            }
            TlsSetupError::Provider => {
                f.write_str("the TLS crypto provider rejected the default protocol versions")
            }
        }
    }
}

impl std::error::Error for TlsSetupError {}
