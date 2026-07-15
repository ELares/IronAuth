// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IronAuth SSRF-hardened outbound fetcher.
//!
//! An OpenID Provider fetches attacker-influenced URLs by design: a client's
//! `jwks_uri` and `sector_identifier_uri`, a consent page's `logo_uri`, client
//! metadata documents, and webhook targets are all URLs a tenant or a
//! registering client controls. Every one of them is a server-side request
//! forgery (SSRF) primitive against cloud metadata services and internal
//! networks unless outbound fetching is centralized and hardened. This crate is
//! that center: it is the ONE way IronAuth code performs a server-side HTTP
//! request, so the SSRF class is closed structurally rather than re-litigated in
//! every feature that learns to fetch.
//!
//! # The guarantees
//!
//! - **Single dispatcher.** [`Fetcher::fetch`] is the only outbound path. The
//!   connector and all socket construction live in a private module; no other
//!   workspace crate may depend on an HTTP-client crate (enforced by
//!   `scripts/http-audit.sh`).
//! - **Resolve, validate, then pin (no DNS rebinding).** The host is resolved to
//!   addresses exactly once; every resolved address is checked against the deny
//!   policy; and the connection is then pinned to one validated address by
//!   value. The socket layer never re-resolves the hostname, so a DNS record
//!   that flips between the check and the connect cannot move the connection to
//!   an internal address. See [`policy`] for the denied ranges.
//! - **Deny, do not allowlist.** Loopback, private, link-local (including the
//!   `169.254.169.254` cloud-metadata address), unique-local, multicast,
//!   unspecified, documentation, and other special-use ranges are refused for
//!   IPv4, IPv6, and the IPv4-in-IPv6 forms. A host that resolves to ANY denied
//!   address blocks the whole fetch.
//! - **https by default.** Plaintext `http` is permitted only when the request
//!   explicitly opts in ([`FetchRequest::allow_plaintext_http`]).
//! - **No redirects.** A 3xx with a `Location` is returned as an error, never
//!   followed.
//! - **Response caps.** A maximum body size and a total deadline are enforced
//!   while streaming (aborting mid-body at the size cap and mid-flight at the
//!   time cap), with safe defaults, configurable per [`FetchLimits`].
//! - **No ambient authority.** No cookie jar, no default credentials, and no
//!   `HTTP_PROXY`/`NO_PROXY` trust. A request carries only what the caller set,
//!   plus the `Host` header for the true destination.
//! - **Uniform block errors, per-purpose diagnostics.** A blocked destination
//!   yields the single opaque [`FetchError::Blocked`] (no oracle for internal
//!   topology), while the structured reason and the caller-declared
//!   [`FetchPurpose`] are recorded in metrics and logs (see [`observe`]).
//!
//! # TLS
//!
//! Client TLS is rustls with the ring provider and the OS trust store
//! (`rustls-native-certs`), matching `ironauth-store`: no aws-lc, no
//! native-tls/openssl, no webpki-roots, so the tree stays permissive and the
//! musl static lane holds. See `docs/adr/0003-outbound-fetch.md`.
//!
//! # Time
//!
//! The fetcher reads no wall-clock or monotonic time of its own; its only
//! temporal concern is the request deadline, enforced with tokio's timer per
//! `docs/adr/0001-http-runtime.md`. There is therefore nothing to route through
//! the `ironauth-env` clock seam, and the invariant lint holds without it.

mod connect;
mod error;
pub mod observe;
pub mod policy;
pub(crate) mod resolve;
pub mod target;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};

pub use connect::TlsSetupError;
pub use error::FetchError;
pub use policy::{BlockClass, classify};
pub use target::{Scheme, Target, TargetError, parse_target};

use connect::{Dispatch, DispatchFailure};
use observe::Outcome;
use resolve::{SystemDialer, SystemResolver};

/// The injectable resolver and dialer seams, and their in-crate test doubles,
/// exposed only under the `test-harness` feature. A production build has neither
/// these nor [`Fetcher::from_parts`]: its sole outbound path is [`Fetcher::new`]
/// plus [`Fetcher::fetch`].
#[cfg(feature = "test-harness")]
pub use resolve::{Dial, RecordingDialer, Resolve, SequenceResolver, StaticResolver};

/// The default maximum response body size: one mebibyte. Generous for a JWKS,
/// sector-identifier, or client-metadata document, and small enough that a
/// hostile origin cannot exhaust memory.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 1 << 20;

/// The default total request deadline.
pub const DEFAULT_TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a caller is fetching, declared at the call site so blocked and completed
/// attempts are observable per purpose (a bounded-cardinality metric label).
///
/// The set is closed on purpose: every outbound fetch in IronAuth is one of
/// these, and a fixed label set keeps an attacker-influenced URL from becoming a
/// metric series.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FetchPurpose {
    /// Fetching a client's `jwks_uri` (DCR and signature verification).
    JwksUri,
    /// Fetching a client's `sector_identifier_uri` for pairwise subject
    /// validation.
    SectorIdentifier,
    /// Fetching a client-metadata document (CIMD).
    ClientMetadata,
    /// Delivering a webhook to a tenant-configured target.
    WebhookDelivery,
    /// Fetching a client `logo_uri` for a consent page.
    Logo,
    /// Calling out to an external customer-managed KMS/HSM to wrap or unwrap a
    /// tenant key-encryption key (BYOK, issue #49). The endpoint is operator
    /// configured and outbound, so it rides the same SSRF-hardened path as every
    /// other external fetch: a KMS URL that resolves to an internal or loopback
    /// address is refused exactly like any other blocked destination.
    KmsRequest,
}

impl FetchPurpose {
    /// A stable, bounded label for metrics and structured logs.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            FetchPurpose::JwksUri => "jwks_uri",
            FetchPurpose::SectorIdentifier => "sector_identifier",
            FetchPurpose::ClientMetadata => "client_metadata",
            FetchPurpose::WebhookDelivery => "webhook_delivery",
            FetchPurpose::Logo => "logo",
            FetchPurpose::KmsRequest => "kms_request",
        }
    }
}

/// The tunable response caps. Both have safe defaults and are meant to be
/// sourced from configuration per the tunability principle; neither the deny
/// policy nor the redirect rule is tunable, because loosening those would
/// reopen the SSRF class.
#[derive(Debug, Clone, Copy)]
pub struct FetchLimits {
    /// Maximum response body size in bytes; the stream aborts the moment it
    /// would be exceeded.
    pub max_response_bytes: u64,
    /// Total time budget for the whole exchange (connect, TLS, request, and
    /// body); the fetch aborts when it elapses.
    pub total_timeout: Duration,
}

impl Default for FetchLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            total_timeout: DEFAULT_TOTAL_TIMEOUT,
        }
    }
}

/// One outbound request: its purpose, target, method, caller-set headers, body,
/// and scheme opt-in. Built fluently; nothing here carries ambient authority.
#[derive(Debug, Clone)]
pub struct FetchRequest {
    purpose: FetchPurpose,
    url: String,
    method: Method,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Bytes,
    allow_http: bool,
}

impl FetchRequest {
    /// A `GET` request for `url`, https-only, with no headers or body. The
    /// common shape for a `jwks_uri`, sector-identifier, metadata, or logo
    /// fetch.
    #[must_use]
    pub fn get(purpose: FetchPurpose, url: impl Into<String>) -> Self {
        Self::new(purpose, Method::GET, url)
    }

    /// A request with an explicit method (for example a webhook `POST`),
    /// https-only, with no headers or body.
    #[must_use]
    pub fn new(purpose: FetchPurpose, method: Method, url: impl Into<String>) -> Self {
        Self {
            purpose,
            url: url.into(),
            method,
            headers: Vec::new(),
            body: Bytes::new(),
            allow_http: false,
        }
    }

    /// Add a request header. Callers set only what they need; the fetcher adds
    /// no cookies, credentials, or proxy headers of its own. A `Host` header set
    /// here is overridden with the true destination authority.
    #[must_use]
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    /// Set the request body (for a `POST`/`PUT`, such as webhook delivery).
    #[must_use]
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Permit a plaintext `http` target for this request. Off by default; the
    /// seam exists so later non-production guardrails can gate it.
    #[must_use]
    pub fn allow_plaintext_http(mut self) -> Self {
        self.allow_http = true;
        self
    }

    /// The declared purpose.
    #[must_use]
    pub fn purpose(&self) -> FetchPurpose {
        self.purpose
    }
}

/// A completed response: the status, the response headers, and the fully read
/// (size-capped) body.
#[derive(Debug, Clone)]
pub struct FetchResponse {
    /// The HTTP status.
    pub status: StatusCode,
    /// The response headers.
    pub headers: HeaderMap,
    /// The response body, at most [`FetchLimits::max_response_bytes`] long.
    pub body: Vec<u8>,
}

impl FetchResponse {
    /// The HTTP status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The response body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The response headers.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

/// The single hardened outbound dispatcher.
///
/// Construct one with [`Fetcher::new`] (production: OS resolver, direct dialer,
/// OS trust store) and share it; it is cheap to clone the handles it holds.
/// [`Fetcher::fetch`] is the only method that performs a request.
pub struct Fetcher {
    limits: FetchLimits,
    tls: Arc<tokio_rustls::rustls::ClientConfig>,
    resolver: Arc<dyn resolve::Resolve>,
    dialer: Arc<dyn resolve::Dial>,
}

impl std::fmt::Debug for Fetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fetcher")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Fetcher {
    /// Build a production fetcher with the given caps.
    ///
    /// Uses the operating system's name resolver, a direct TCP dialer, and the
    /// OS trust store for TLS. Pass caps derived from configuration; the
    /// [`FetchLimits::default`] values are safe if you have none.
    ///
    /// # Errors
    ///
    /// [`TlsSetupError`] if the OS trust store yields no usable roots or the
    /// crypto provider cannot be initialized.
    pub fn new(limits: FetchLimits) -> Result<Self, TlsSetupError> {
        Ok(Self {
            limits,
            tls: connect::build_tls_config()?,
            resolver: Arc::new(SystemResolver),
            dialer: Arc::new(SystemDialer),
        })
    }

    /// Perform one outbound fetch.
    ///
    /// Parses and scheme-checks the URL, resolves and validates the
    /// destination, pins the connection, and runs the exchange under the caps.
    ///
    /// # Errors
    ///
    /// [`FetchError::Blocked`] (uniform) for any refused destination;
    /// [`FetchError::SchemeNotAllowed`] for a disallowed plaintext target;
    /// [`FetchError::RedirectNotFollowed`] for a 3xx with a `Location`;
    /// [`FetchError::ResponseTooLarge`] or [`FetchError::Timeout`] at the caps;
    /// [`FetchError::Upstream`] for a transport or protocol failure; and
    /// [`FetchError::InvalidRequest`] for a malformed URL or header.
    pub async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        let purpose = request.purpose;

        let target = match parse_target(&request.url) {
            Ok(target) => target,
            Err(err) => {
                observe::record_outcome(purpose, Outcome::InvalidRequest);
                return Err(FetchError::InvalidRequest(err.to_string()));
            }
        };

        if target.scheme == Scheme::Http && !request.allow_http {
            observe::record_outcome(purpose, Outcome::SchemeNotAllowed);
            return Err(FetchError::SchemeNotAllowed);
        }

        let headers = match Self::assemble_headers(&target, &request.headers) {
            Ok(headers) => headers,
            Err(err) => {
                observe::record_outcome(purpose, Outcome::InvalidRequest);
                return Err(err);
            }
        };

        let dispatch = Dispatch {
            target: &target,
            method: request.method,
            headers,
            body: request.body,
            limits: self.limits,
            tls: &self.tls,
            resolver: self.resolver.as_ref(),
            dialer: self.dialer.as_ref(),
        };

        match dispatch.run().await {
            Ok(response) => {
                observe::record_outcome(purpose, Outcome::Ok);
                Ok(response)
            }
            Err(failure) => Err(self.map_failure(purpose, failure)),
        }
    }

    /// Build the outgoing header set: the caller's headers plus a `Host` header
    /// for the true destination authority (which overrides any `Host` the caller
    /// set). No cookie, credential, or proxy header is added.
    fn assemble_headers(
        target: &Target,
        caller: &[(HeaderName, HeaderValue)],
    ) -> Result<HeaderMap, FetchError> {
        let mut headers = HeaderMap::with_capacity(caller.len() + 1);
        for (name, value) in caller {
            headers.append(name.clone(), value.clone());
        }
        let host = HeaderValue::from_str(&target.host_header()).map_err(|_| {
            FetchError::InvalidRequest("host is not a valid header value".to_owned())
        })?;
        headers.insert(header::HOST, host);
        Ok(headers)
    }

    /// Meter a failed dispatch and translate it to the caller-facing error.
    fn map_failure(&self, purpose: FetchPurpose, failure: DispatchFailure) -> FetchError {
        match failure {
            DispatchFailure::Blocked(reason) => {
                observe::record_block(purpose, reason);
                FetchError::Blocked
            }
            DispatchFailure::Redirect(status) => {
                observe::record_outcome(purpose, Outcome::Redirect);
                FetchError::RedirectNotFollowed { status }
            }
            DispatchFailure::TooLarge => {
                observe::record_outcome(purpose, Outcome::TooLarge);
                FetchError::ResponseTooLarge {
                    limit: self.limits.max_response_bytes,
                }
            }
            DispatchFailure::Timeout => {
                observe::record_outcome(purpose, Outcome::Timeout);
                FetchError::Timeout
            }
            DispatchFailure::Upstream => {
                observe::record_outcome(purpose, Outcome::UpstreamError);
                FetchError::Upstream
            }
        }
    }
}

/// Test-only construction from injected seams. Behind the `test-harness`
/// feature so it never exists in a production build: the only outbound path a
/// released binary has is [`Fetcher::new`] plus [`Fetcher::fetch`].
#[cfg(feature = "test-harness")]
impl Fetcher {
    /// Build a fetcher from an injected resolver and dialer, with an empty TLS
    /// trust store (tests drive the connector over plaintext `http`, so no
    /// handshake occurs). This is how the adversarial tests control resolution
    /// and observe the pinned dial address.
    ///
    /// Generic over the concrete seam types so a caller can hand in a
    /// `Arc<StaticResolver>` and still keep a typed handle for inspection; the
    /// concrete Arcs coerce to the internal trait objects here.
    #[must_use]
    pub fn from_parts<R, D>(limits: FetchLimits, resolver: Arc<R>, dialer: Arc<D>) -> Self
    where
        R: resolve::Resolve + 'static,
        D: resolve::Dial + 'static,
    {
        Self {
            limits,
            tls: connect::test_tls_config(),
            resolver,
            dialer,
        }
    }
}
