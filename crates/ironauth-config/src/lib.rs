// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict configuration layer for IronAuth.
//!
//! Silent misconfiguration is a real identity-provider failure class, so this
//! crate is deliberately unforgiving: config is TOML, every table rejects
//! unknown keys, and any parse problem aborts startup naming the file, line,
//! column, and the accepted keys. There is no warn-and-continue path.
//!
//! The published contract is a JSON Schema derived from [`Config`]
//! ([`Config::json_schema`]); scripts/config-schema.sh regenerates the
//! `docs/config-schema.json` artifact (editors validate TOML against it via
//! taplo) and the generated `docs/CONFIG.md` reference, and CI fails on
//! drift.
//!
//! Secrets enter only through [`Secret`] indirection (file or env var;
//! literals are flagged outside dev mode) and can never leak through
//! `Debug`, `Display`, or serialization. Connection strings are validated
//! [`Dsn`] values with redacted passwords. Feature flags ride the maturity
//! ladder in [`features`]: experimental features boot only behind an
//! exact-version acknowledgment.

mod dsn;
mod features;
mod secret;

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use dsn::{Dsn, DsnError, KNOWN_SCHEMES};
pub use features::{
    Feature, FeatureRegistry, FeatureValidationError, FeatureViolation,
    GLOBAL_TOKEN_REVOCATION_DRAFT, GLOBAL_TOKEN_REVOCATION_FEATURE, Maturity,
};
pub use secret::{REDACTED, Secret, SecretError, SecretString};

/// The root of the IronAuth process configuration.
///
/// Every section rejects unknown keys and every field has a serde default,
/// so an empty file is a valid (dev-oriented) configuration and a typo is a
/// startup failure, never a silently ignored setting.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Development mode. Relaxes operational nagging (currently: the
    /// literal-secret warning) but never relaxes parse strictness or the
    /// feature acknowledgment gate. Never set this in production.
    pub dev_mode: bool,

    /// HTTP server settings.
    pub server: ServerConfig,

    /// Trusted-proxy policy. Controls whether forwarding headers are honored;
    /// the safe default trusts nothing.
    pub proxy: ProxyConfig,

    /// Observability settings: log format and trace export.
    pub telemetry: TelemetryConfig,

    /// Primary database settings.
    pub database: DatabaseConfig,

    /// Management API settings (issue #11).
    pub admin: AdminConfig,

    /// OIDC provider settings (issue #12).
    pub oidc: OidcConfig,

    /// Feature toggles keyed by registered feature name. Enabling an
    /// experimental feature additionally requires `ack` equal to the
    /// feature's exact current version; see the feature reference in the
    /// generated docs/CONFIG.md.
    pub features: BTreeMap<String, FeatureToggle>,
}

/// HTTP server settings.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// Socket address the public data plane listens on. This plane serves the
    /// protocol and hosted-page surfaces; health, readiness, and metrics are
    /// never exposed here.
    pub bind: String,

    /// Socket address the management plane listens on. Liveness, readiness,
    /// and the Prometheus metrics endpoint live here so the data plane is
    /// never probed publicly; bind it to a private interface.
    pub management_bind: String,

    /// Externally visible base URL (scheme and host) used to mint issuer and
    /// endpoint URLs. Unset means single-host development behind the bind
    /// address. The scheme, host, and issuer always derive from this value,
    /// never from request headers (see the `[proxy]` policy).
    pub public_url: Option<String>,

    /// Maximum seconds to drain in-flight requests after a shutdown signal
    /// before the process exits regardless. Zero exits without draining.
    pub shutdown_grace_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8443".to_owned(),
            management_bind: "127.0.0.1:9443".to_owned(),
            public_url: None,
            shutdown_grace_secs: 25,
        }
    }
}

/// Trusted-proxy policy.
///
/// Forwarding headers (RFC 7239 `Forwarded`, `X-Forwarded-For`,
/// `X-Forwarded-Proto`, `X-Forwarded-Host`) and the `Host` header are an
/// account-takeover class when trusted blindly. The default trusts NOTHING:
/// `trusted_hops = 0` and `trust_forwarded = false` mean the effective client
/// IP is the transport peer and the scheme, host, and issuer derive entirely
/// from `server.public_url`. Only when the server genuinely runs behind a
/// fixed number of trusted reverse proxies should these be raised, and even
/// then scheme and issuer stay config-derived.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ProxyConfig {
    /// Exact number of trusted reverse-proxy hops in front of the server.
    /// Zero (the default) means the server is exposed directly and no
    /// forwarding header is ever honored. Forwarding is honored only when the
    /// request presents exactly this many forwarding entries; any other count
    /// fails closed to the transport peer.
    pub trusted_hops: u32,

    /// Whether to honor forwarding headers at all. False (the default) ignores
    /// every forwarding header regardless of `trusted_hops`. Both this and a
    /// non-zero `trusted_hops` are required before any header is consulted.
    pub trust_forwarded: bool,
}

/// Observability settings.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct TelemetryConfig {
    /// Structured-log output format for the process log stream.
    pub log_format: LogFormat,

    /// OpenTelemetry OTLP collector endpoint for trace export (for example
    /// `http://otel-collector:4317`). Trace export is compiled in only when
    /// the binary is built with the non-default `otlp` feature; setting this
    /// on a build without that feature logs a warning and is otherwise inert.
    pub otlp_endpoint: Option<String>,
}

/// The access-token format an environment mints by default (issue #29).
///
/// A registered resource server can override this per audience; when no resource
/// server is targeted, the environment default applies. The default is the
/// self-contained RFC 9068 `at+jwt`, which preserves the existing `UserInfo` and
/// offline-verification behavior; `opaque` mints a random, digest-only reference
/// token that can only be validated by a store lookup (introspection).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenFormat {
    /// An RFC 9068 `at+jwt` signed access token (the default). Self-contained and
    /// offline-verifiable; the audience is the client id when no resource server
    /// is targeted, so `UserInfo` keeps working.
    #[default]
    AtJwt,
    /// An opaque, digest-only reference access token (`ira_at_` prefix). Not
    /// offline-verifiable; state lives only in the store and is validated by a
    /// scoped store lookup. `UserInfo` resolves it directly; the RFC 7662
    /// introspection endpoint (#22) exposes the same lookup over HTTP.
    Opaque,
}

/// The audience an inbound JWT client assertion (`private_key_jwt` /
/// `client_secret_jwt`, issue #25) must be addressed to (RFC 7523 section 3, OIDC
/// Core section 9). This is the SHARED audience knob the JWT bearer grant (#26)
/// reuses: both surfaces validate an assertion's `aud` through it.
///
/// The default accepts the token-endpoint URL OR the per-environment issuer, which
/// is the interoperable choice: real client libraries disagree on which they place
/// in `aud`. The strict mode accepts ONLY the issuer, per rfc7523bis and FAPI 2.0,
/// which reject a token-endpoint-audienced assertion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClientAssertionAudience {
    /// Accept an assertion whose `aud` is the token-endpoint URL OR the
    /// per-environment issuer. The interoperable default.
    #[default]
    TokenEndpointOrIssuer,
    /// Accept ONLY an assertion whose `aud` is the per-environment issuer (a
    /// token-endpoint-audienced assertion is rejected), per rfc7523bis / FAPI 2.0.
    IssuerOnly,
}

/// The Dynamic Client Registration exposure switch (issue #31): who may register
/// a client through the public `/connect/register` endpoint. Layered under
/// `oidc.registration_enabled` (which mounts the endpoint at all): when the
/// endpoint is mounted, this decides whether a request is allowed and how.
///
/// The SAFE default is `token_gated`: a valid initial access token is required,
/// so open self-service registration is opt-in, never on by accident. `closed`
/// refuses every public registration (clients are then created only through the
/// management API). `open` allows anonymous registration but the resulting client
/// starts QUARANTINED (consent always shown, redirect set restricted) until an
/// admin verifies it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationMode {
    /// The public endpoint refuses every registration; clients are created only
    /// through the management API. The most restrictive posture.
    Closed,
    /// A valid initial access token (RFC 7591 section 1.2) is required; a request
    /// without one is refused. The safe default.
    #[default]
    TokenGated,
    /// Anonymous registration is allowed, but the resulting client starts
    /// quarantined until an admin verifies it. Requires explicit opt-in.
    Open,
}

/// The default audience a client-credentials access token carries when the request
/// targets NO resource server (issue #23).
///
/// The client-credentials grant (RFC 6749 4.4) mints machine-to-machine tokens. RFC
/// 8707 lets a request target a specific resource server via the `resource`
/// parameter (issue #28), whose registered audience then wins; when none is
/// targeted, this configurable default applies. The default (`client_id`) preserves
/// the environment's existing no-resource behavior (the token's `aud` is the OAuth
/// client id). `issuer` sets the per-environment issuer as the audience instead, for
/// deployments that treat the provider itself as the default M2M audience. This is a
/// promotable per-environment setting in spirit; the process value is the deployment
/// default until per-environment overrides ride the M5 promotion pipeline.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClientCredentialsAudience {
    /// The token's `aud` is the OAuth client id (the default; preserves the existing
    /// no-resource behavior).
    #[default]
    ClientId,
    /// The token's `aud` is the per-environment issuer.
    Issuer,
}

/// Structured-log output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// One JSON object per line with ECS-friendly field names. The production
    /// default: machine-parseable and safe to ship to a log pipeline.
    #[default]
    Json,
    /// Human-readable multi-line output for local development. Never emit this
    /// where logs are ingested by tooling.
    Pretty,
}

/// Primary database settings.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct DatabaseConfig {
    /// Postgres connection string. Embedding the password here is
    /// discouraged; prefer the `password` secret, which is merged at
    /// connection time.
    pub url: Dsn,

    /// Database password supplied out of band, overriding any password
    /// embedded in `url`.
    pub password: Option<Secret>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: Dsn::parse("postgres://ironauth@localhost:5432/ironauth")
                .expect("default DSN is valid by construction (covered by test)"),
            password: None,
        }
    }
}

/// The ceiling any management list response is bounded by, no matter the
/// configured `admin.max_page_size` or a caller-supplied `limit`. It is the
/// last-resort bound so a single response can never trigger an unbounded scan.
/// The store applies the same value to every list query; keep this equal to
/// `ironauth_store`'s hard cap (a cross-crate test in `ironauth-admin` pins the
/// two together). Config load rejects an `admin.max_page_size` above it.
pub const MANAGEMENT_LIST_HARD_CAP: u32 = 1000;

/// Management API settings (issue #11).
///
/// The management API is the OpenAPI-first control plane on the management port.
/// It authorizes the operator plane (tenant CRUD) in M1 with a single config
/// bootstrap operator token; the full operator-plane credential class lands in
/// M5. Page-size limits are configurable (the tunability principle) with safe
/// defaults, never a baked-in one-way choice.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct AdminConfig {
    /// The bootstrap operator bearer token that authorizes the operator plane
    /// (tenant CRUD) in M1, presented as `Authorization: Bearer <token>`. Unset
    /// leaves the operator plane unauthorized (the management API still mounts,
    /// but every operator-plane request is rejected). Use the `file`/`env` secret
    /// indirection, never a literal, outside dev mode. The full operator-plane
    /// credential class lands in M5.
    pub bootstrap_operator_token: Option<Secret>,

    /// The database connection string the management (control) plane connects
    /// with. It MUST authenticate as the least-privilege `ironauth_control` role,
    /// a distinct credential class from the data-plane role, so the
    /// `management_credentials` FORCE row-level-security backstop applies beneath
    /// the repository layer. Use the `file`/`env` secret indirection, never a
    /// literal, outside dev mode. When unset and the management API is enabled:
    /// in production (`dev_mode = false`) the API refuses to mount (fail closed);
    /// in `dev_mode = true` it falls back to `database.url` with a warning that
    /// the role separation and the FORCE-RLS backstop are NOT enforced.
    pub control_database_url: Option<Secret>,

    /// The largest page a list endpoint will return, regardless of a larger
    /// caller-supplied `limit`. A ceiling that bounds any one response so a
    /// caller cannot request an unbounded scan. Config load rejects a value above
    /// the management list hard cap (1000).
    pub max_page_size: u32,

    /// The page size a list endpoint uses when the caller supplies no `limit`.
    /// Clamped to `max_page_size`.
    pub default_page_size: u32,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            bootstrap_operator_token: None,
            control_database_url: None,
            max_page_size: 200,
            default_page_size: 50,
        }
    }
}

/// The largest an authorization-code or access-token lifetime may be configured
/// to, in seconds. A code is a short-lived, single-use bearer credential and an
/// access token a bearer credential; a lifetime beyond one day is almost always
/// a misconfiguration, so config load rejects it (fail fast rather than mint a
/// long-lived code). The safe defaults are far below this ceiling.
pub const OIDC_MAX_LIFETIME_SECS: u64 = 86_400;

/// The largest a session lifetime may be configured to, in seconds. A session is
/// longer lived than a code or an access token (a user stays logged in across
/// requests), but a session beyond thirty days is almost always a misconfiguration,
/// so config load rejects it. Bounds both the absolute cap (`oidc.session_ttl_secs`)
/// and the idle timeout (`oidc.session_idle_ttl_secs`).
pub const OIDC_MAX_SESSION_TTL_SECS: u64 = 2_592_000;

/// The internal request header carrying the POLICY-RESOLVED client IP: the input of
/// the OFF-BY-DEFAULT peer-IP session binding (issue #32).
///
/// It lives here, in the crate both the server and the OIDC provider already depend
/// on, so the two agree on the name WITHOUT the server crate taking a dependency on
/// the OIDC crate (the server stays decoupled from the routers it mounts).
///
/// It is a trusted INTERNAL seam, never client input. The server's observability
/// middleware resolves the effective client IP under the trusted-proxy policy (which
/// ignores every forwarding header unless an operator declared a proxy topology) and
/// `insert`s it here on every request, REPLACING any value a client tried to supply,
/// so a spoofed header cannot survive. A request that never passed that middleware
/// carries no value at all, and the peer-IP binding then fails CLOSED (a request with
/// no resolvable peer IP does not resolve a bound session), so the binding cannot be
/// bypassed by omitting the header either.
pub const PEER_IP_HEADER: &str = "x-ironauth-peer-ip";

/// The minimum permitted JWKS `Cache-Control: max-age` (issue #19), in seconds.
/// A shorter window would make relying parties refetch the key set too often and
/// undercut the pre-publish lead the rotation choreography depends on.
pub const OIDC_JWKS_CACHE_MIN_SECS: u64 = 300;

/// The maximum permitted JWKS `Cache-Control: max-age` (issue #19), in seconds. A
/// longer window would keep a rotated-out key trusted in caches for too long.
pub const OIDC_JWKS_CACHE_MAX_SECS: u64 = 900;

/// The largest clock skew a JWT client assertion's `exp`/`nbf`/`iat` may be
/// tolerated by, in seconds (issue #25). A small skew absorbs realistic clock
/// drift between a client and the provider; a large one would keep an expired
/// assertion replayable for too long, so config load rejects a value above this
/// ceiling. The default is one minute.
pub const OIDC_MAX_CLIENT_ASSERTION_SKEW_SECS: u64 = 300;

/// The largest a refresh-token IDLE timeout may be configured to, in seconds
/// (issue #21). A refresh token that goes unused for longer than its idle timeout
/// expires; the cap (ninety days) bounds how long an unused, session-bound or
/// offline refresh token stays live. A value beyond this is almost always a
/// misconfiguration, so config load rejects it.
pub const OIDC_MAX_REFRESH_IDLE_TTL_SECS: u64 = 7_776_000;

/// The largest a rotated refresh-token FAMILY lifetime may be configured to, in
/// seconds (issue #21). This is the hard cap on the total lifetime of a family
/// rooted at one authorization grant, however many times its tokens rotate; the
/// ceiling (one year) bounds an offline grant's maximum lifetime. A value beyond
/// this is almost always a misconfiguration, so config load rejects it.
pub const OIDC_MAX_REFRESH_MAX_LIFETIME_SECS: u64 = 31_536_000;

/// The largest a remembered-consent TTL may be configured to, in seconds (issue
/// #21). A client whose consent mode is `remembered` keeps a recorded consent
/// valid for this long before re-prompting; the ceiling (one year) bounds how
/// long a remembered decision is honored. A value beyond this is almost always a
/// misconfiguration, so config load rejects it.
pub const OIDC_MAX_REMEMBERED_CONSENT_TTL_SECS: u64 = 31_536_000;

/// The largest a pushed-authorization-request `request_uri` lifetime may be
/// configured to, in seconds (RFC 9126, issue #27). A pushed request is a
/// short-lived, single-use reference the client redeems immediately at the
/// authorization endpoint; RFC 9126 section 2.2 recommends a short expiry, so config
/// load rejects a value above this ceiling (ten minutes). The default is one minute.
pub const OIDC_MAX_PAR_TTL_SECS: u64 = 600;

/// The largest a device-authorization flow lifetime may be configured to, in
/// seconds (RFC 8628, issue #24). A device code and user code are short-lived by
/// design (a short TTL is a core brute-force mitigation, RFC 8628 section 5.1), so
/// config load rejects a value above this ceiling (thirty minutes). The default is
/// ten minutes.
pub const OIDC_MAX_DEVICE_CODE_TTL_SECS: u64 = 1_800;

/// The largest a device-authorization polling interval (base or `slow_down` increment)
/// may be configured to, in seconds (RFC 8628 section 3.5, issue #24). The polling
/// interval governs how often a constrained device may poll the token endpoint; it is
/// bounded so a misconfiguration cannot make a device wait unreasonably long. Five
/// minutes is a generous ceiling; the default interval is five seconds.
pub const OIDC_MAX_DEVICE_POLL_INTERVAL_SECS: u64 = 300;

/// OIDC provider settings (issue #12).
///
/// The public authorization and token endpoints. Lifetimes are configurable (the
/// tunability principle) with safe defaults, never a baked-in one-way choice: the
/// authorization code is short-lived and single-use, the access token a little
/// longer. Mounting is opt-in so the default (and database-free) boot is
/// unchanged.
// Each bool is an INDEPENDENT, individually documented TOML toggle keyed by its
// field name in the published schema; the excessive-bools refactor (a state
// machine or two-variant enums) would corrupt the config contract and the
// generated docs/config-schema.json, so it is deliberately not applied here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct OidcConfig {
    /// Whether to mount the public OIDC endpoints (`/authorize`, `/token`). Off
    /// by default so the default boot serves only the skeleton and needs no
    /// database. When on, the provider connects the data-plane store using
    /// `database.url`.
    pub enabled: bool,

    /// Authorization-code lifetime in seconds. A code is single-use and
    /// short-lived; the default (60) follows the OAuth 2.1 guidance that codes
    /// live about a minute. Must be at least 1 and at most
    /// `OIDC_MAX_LIFETIME_SECS`.
    pub authorization_code_ttl_secs: u64,

    /// Access-token lifetime in seconds. The default (300) is a conservative five
    /// minutes; refresh handling (rotation, families) lands in M3. Must be at
    /// least 1 and at most `OIDC_MAX_LIFETIME_SECS`. A registered resource server
    /// (issue #29) may override this per audience.
    pub access_token_ttl_secs: u64,

    /// The access-token format this environment mints when no resource server is
    /// targeted (issue #29). The spec-conform default (`at_jwt`) mints a
    /// self-contained RFC 9068 signed JWT whose audience is the client id, so
    /// `UserInfo` and offline verification keep working. Setting it to `opaque`
    /// mints a random, digest-only reference token instead, validated by a scoped
    /// store lookup (`UserInfo` resolves it directly; the RFC 7662 introspection
    /// endpoint, #22, exposes the same lookup). A registered resource server overrides this per
    /// audience. This is a promotable per-environment setting: it appears in config
    /// snapshots and rides the M5 promotion pipeline; the process value is the
    /// deployment default until per-environment overrides land.
    pub default_access_token_format: TokenFormat,

    /// Reuse grace window in seconds for an already-consumed authorization code.
    /// A second presentation of a consumed code within this window (a concurrent
    /// double-submit or an immediate client retry) is treated as a BENIGN retry:
    /// it fails with `invalid_grant` but does NOT revoke the grant chain and does
    /// NOT audit a reuse. A second presentation AFTER the window is a genuine
    /// reuse: it revokes the grant chain and audits it (RFC 9700). The default
    /// (10) tolerates realistic retry and clock jitter without a false revoke; set
    /// it to 0 to treat every reuse as genuine. At most `OIDC_MAX_LIFETIME_SECS`.
    pub reuse_grace_secs: u64,

    /// Session ABSOLUTE hard-cap lifetime in seconds (issue #20, extended by issue
    /// #32). The opaque `__Host-` session cookie established at login is valid for at
    /// most this long however active; a request presenting an expired session
    /// re-authenticates. The default (3600) is a conservative one hour. Must be at
    /// least 1 and at most `OIDC_MAX_SESSION_TTL_SECS`. Pairs with
    /// `session_idle_ttl_secs` (the idle timeout).
    pub session_ttl_secs: u64,

    /// Session IDLE timeout in seconds (issue #32): a session unused for longer than
    /// this stops resolving, independently of the absolute cap `session_ttl_secs`.
    /// The default (3600) equals the absolute cap, so the default behavior matches
    /// the single-lifetime bootstrap; lower it to expire idle sessions sooner. Must
    /// be at least 1, at most `OIDC_MAX_SESSION_TTL_SECS`, and at most
    /// `session_ttl_secs` (an idle timeout beyond the absolute cap is meaningless).
    pub session_idle_ttl_secs: u64,

    /// Add the CHIPS `Partitioned` attribute to session cookies (issue #32). The safe
    /// default (`false`) leaves it OFF: the cookie is the standard
    /// `__Host-`/`Secure`/`HttpOnly`/`SameSite=Lax` cookie. Set it to `true` for
    /// embedded-widget (cross-site) scenarios so the browser gives each top-level
    /// site its own partitioned session cookie; enabling it NEVER drops `SameSite`
    /// and NEVER breaks the `__Host-` prefix, it only ADDS `Partitioned`.
    pub session_partitioned_cookie: bool,

    /// Bind the session to the peer IP it was established from (issue #32). The safe
    /// default (`false`) leaves it OFF (the tunability principle: env-dependent
    /// behavior is config, never a baked-in one-way choice), so a NAT or a mobile IP
    /// change never logs a user out. Enable it only where clients have stable IPs; it
    /// then fails closed (a session presented from a different peer IP does not
    /// resolve).
    pub session_peer_ip_binding: bool,

    /// Bind the session to the device / user agent it was established from (issue
    /// #32). The safe default (`false`) leaves it OFF (the tunability principle).
    /// Enable it to fail closed when the device/user-agent fingerprint changes.
    pub session_device_binding: bool,

    /// The `Cache-Control: max-age` (in seconds) advertised on every JWKS
    /// response (issue #19). A relying party may cache the published keys for this
    /// long, so it bounds how quickly a rotated-in key propagates and feeds the
    /// pre-publish lead. Operational discipline requires it to stay between
    /// `OIDC_JWKS_CACHE_MIN_SECS` (300) and `OIDC_JWKS_CACHE_MAX_SECS` (900); the
    /// default (600) is the midpoint. This is a promotable per-environment setting
    /// in spirit; the process value is the deployment default until per-environment
    /// overrides ride the M5 promotion pipeline.
    pub jwks_cache_max_age_secs: u64,

    /// Whether a CONFIDENTIAL client (one that authenticates at the token endpoint
    /// with a secret) must use PKCE (issue #13, RFC 9700 2.1). Default `true`: PKCE
    /// is required for every client. A PUBLIC client (`token_endpoint_auth_method`
    /// = `none`) ALWAYS requires PKCE regardless of this setting, because RFC 9700
    /// 2.1.1 makes it structural for public clients; this knob only governs the
    /// per-environment policy for confidential clients, whose default is `required`.
    /// Set it to `false` only for an environment whose confidential clients cannot
    /// yet send a `code_challenge` (a migration aid); a code issued without a
    /// challenge is still never redeemable with a verifier (downgrade prevention
    /// holds in both directions). This is a promotable per-environment setting in
    /// spirit, like `jwks_cache_max_age_secs`; the process value is the deployment
    /// default until per-environment overrides ride the M5 promotion pipeline.
    pub require_pkce_for_confidential_clients: bool,

    /// Copy the scope-derived standard claims into the ID token (issue #15). The
    /// spec-conform default (`false`) places scope-derived claims (`profile`,
    /// `email`, `address`, `phone`) at the `UserInfo` endpoint and keeps the ID
    /// token lean, per OIDC Core 5.4. Setting this `true` additionally copies those
    /// claims into the ID token for legacy relying parties that never call
    /// `UserInfo`; that placement is explicitly NON-conform (it is the
    /// node-oidc-provider `conformIdTokenClaims = false` behavior) and is documented
    /// as such. This is a promotable per-environment setting: it appears in config
    /// snapshots and rides the M5 promotion pipeline; the process value is the
    /// deployment default until per-environment overrides land.
    pub conform_id_token_claims: bool,

    /// The audience an inbound JWT client assertion (`private_key_jwt`, issue #25)
    /// must be addressed to (RFC 7523, OIDC Core section 9). The interoperable
    /// default (`token_endpoint_or_issuer`) accepts an assertion whose `aud` is the
    /// token-endpoint URL OR the per-environment issuer; `issuer_only` accepts ONLY
    /// the issuer (rejecting a token-endpoint-audienced assertion) per rfc7523bis
    /// and FAPI 2.0. This is the SHARED knob the JWT bearer grant (#26) reuses. A
    /// promotable per-environment setting in spirit; the process value is the
    /// deployment default until per-environment overrides ride the M5 pipeline.
    pub client_assertion_audience: ClientAssertionAudience,

    /// The clock-skew tolerance (in seconds) applied to a JWT client assertion's
    /// `exp`/`nbf`/`iat` (issue #25). A small window absorbs realistic client/server
    /// clock drift; the default (60) is one minute and config load rejects a value
    /// above `OIDC_MAX_CLIENT_ASSERTION_SKEW_SECS` (300), because a wide skew keeps
    /// an expired assertion replayable for too long. The replay cache retains a
    /// jti until its assertion's `exp` PLUS this skew, so pruning never opens a
    /// replay window.
    pub client_assertion_max_skew_secs: u64,

    /// The web origins (scheme + host + optional port, no path) of registered
    /// single-page-app clients allowed to call the `UserInfo` endpoint cross-origin
    /// (issue #15). Empty by default, so no CORS is offered. Each entry is matched
    /// EXACTLY against a request's `Origin`; a match echoes that origin back in the
    /// `UserInfo` CORS headers (never a wildcard), and an unmatched origin gets no
    /// CORS headers at all. CORS is offered on `UserInfo` ONLY and never on the
    /// authorization endpoint. This is a promotable per-environment setting: it
    /// appears in config snapshots and rides the M5 promotion pipeline; the process
    /// value is the deployment default until per-environment overrides land.
    pub userinfo_cors_origins: Vec<String>,

    /// Enable the legacy implicit `response_type=id_token` flow for this
    /// environment (issue #17). The spec-conform, safe default (`false`) leaves it
    /// DISABLED: the authorization endpoint accepts only `code` unless a legacy
    /// type is explicitly turned on. When `true`, the endpoint also serves the
    /// implicit ID-token-only flow (an ID token, carrying `nonce`, returned in the
    /// front channel; never an access token, which is a permanent non-goal), and
    /// discovery advertises `id_token` and the `fragment` response mode. Intended
    /// for certification runs. This is a promotable per-environment setting: it
    /// appears in config snapshots and rides the M5 promotion pipeline; the process
    /// value is the deployment default until per-environment overrides land.
    pub enable_response_type_id_token: bool,

    /// Enable the legacy hybrid `response_type=code id_token` flow for this
    /// environment (issue #17). The safe default (`false`) leaves it DISABLED. When
    /// `true`, the authorization endpoint also serves the hybrid flow (a `code` AND
    /// a front-channel ID token carrying `nonce` and `c_hash`, but never an access
    /// token and never `at_hash`), and discovery advertises `code id_token` and the
    /// `fragment` response mode. Intended for certification runs. This is a
    /// promotable per-environment setting: it appears in config snapshots and rides
    /// the M5 promotion pipeline; the process value is the deployment default until
    /// per-environment overrides land.
    pub enable_response_type_code_id_token: bool,

    /// Enable the legacy `response_type=none` flow for this environment (issue
    /// #17). The safe default (`false`) leaves it DISABLED. When `true`, the
    /// authorization endpoint also serves `none` (a redirect echoing `state` and
    /// the RFC 9207 `iss`, issuing no code and no token), and discovery advertises
    /// `none`. Intended for certification runs. This is a promotable per-environment
    /// setting: it appears in config snapshots and rides the M5 promotion pipeline;
    /// the process value is the deployment default until per-environment overrides
    /// land.
    pub enable_response_type_none: bool,

    /// Enable the `response_mode=form_post` encoding for this environment (issue
    /// #17, OAuth 2.0 Form Post Response Mode 1.0). The safe default (`false`)
    /// leaves it DISABLED: the authorization endpoint returns results only by
    /// `query` (and, when a front-channel response type is enabled, `fragment`).
    /// When `true`, a client may request `response_mode=form_post` and the endpoint
    /// returns an auto-submitting HTML form that POSTs the authorization-response
    /// parameters to the `redirect_uri`, and discovery advertises `form_post`.
    /// Intended for certification runs. This is a promotable per-environment
    /// setting: it appears in config snapshots and rides the M5 promotion pipeline;
    /// the process value is the deployment default until per-environment overrides
    /// land.
    pub enable_response_mode_form_post: bool,

    /// Whether the authorization-code grant issues a refresh token (issue #21).
    /// Default `true`: a successful code exchange returns a rotating refresh token
    /// alongside the access token. A refresh token issued WITHOUT the
    /// `offline_access` scope is session-bound (it is revoked when the end user's
    /// RP session is logged out); one issued WITH `offline_access` survives RP
    /// logout and gets the separate offline lifecycle. Set it to `false` for an
    /// environment that mints access tokens only.
    pub issue_refresh_tokens: bool,

    /// The IDLE timeout in seconds of a SESSION-bound refresh token (issue #21):
    /// one issued without `offline_access`. A refresh token unused for longer than
    /// this expires. The default (1209600) is fourteen days. Must be at least 1 and
    /// at most `OIDC_MAX_REFRESH_IDLE_TTL_SECS`.
    pub refresh_idle_ttl_secs: u64,

    /// The hard cap in seconds on the total lifetime of a SESSION-bound refresh
    /// token FAMILY (issue #21), measured from the original grant however many
    /// times the family rotates. Once the family passes this age no rotation
    /// renews it and a refresh attempt fails with `invalid_grant`. The default
    /// (2592000) is thirty days. Must be at least 1, at most
    /// `OIDC_MAX_REFRESH_MAX_LIFETIME_SECS`, and at least `refresh_idle_ttl_secs`.
    pub refresh_max_lifetime_secs: u64,

    /// The IDLE timeout in seconds of an OFFLINE refresh token (issue #21): one
    /// issued WITH the `offline_access` scope, which survives RP logout (OIDC
    /// Back-Channel Logout 2.7). The default (2592000) is thirty days. There is NO
    /// never-expires option: an offline token still expires when unused this long.
    /// Must be at least 1 and at most `OIDC_MAX_REFRESH_IDLE_TTL_SECS`.
    pub offline_idle_ttl_secs: u64,

    /// The hard cap in seconds on the total lifetime of an OFFLINE refresh token
    /// FAMILY (issue #21), measured from the original grant. Once the family passes
    /// this age no rotation renews it. There is NO never-expires option. The
    /// default (7776000) is ninety days. Must be at least 1, at most
    /// `OIDC_MAX_REFRESH_MAX_LIFETIME_SECS`, and at least `offline_idle_ttl_secs`.
    pub offline_max_lifetime_secs: u64,

    /// The grace window in seconds during which a superseded (rotated) refresh
    /// token may still be presented as a benign concurrent refresh (issue #21).
    /// Within this window of the rotation, a duplicate presentation (multi-tab, a
    /// retry, a flaky network) succeeds with a fresh successor and does NOT revoke
    /// the family. A presentation AFTER the window is a genuine reuse: it revokes
    /// the whole family and emits one typed reuse event (RFC 9700 2.2.2). The
    /// default (10) tolerates realistic retry and clock jitter; set it to 0 to
    /// treat every superseded-token presentation as reuse. At most
    /// `OIDC_MAX_LIFETIME_SECS`.
    pub refresh_rotation_grace_secs: u64,

    /// The fraction (as a whole percent, 0 to 100) of a refresh token's idle TTL a
    /// confidential or otherwise sender-bound client's token must reach before it
    /// rotates (issue #21). A PUBLIC, sender-unbound client always rotates on every
    /// refresh; a confidential or bound client rotates only once the presented
    /// token has passed this fraction of its lifetime, so a well-behaved
    /// confidential client rotates less often. The default (70) rotates past 70% of
    /// TTL. A per-client override may force always-rotate or threshold-rotate.
    pub refresh_rotation_threshold_percent: u64,

    /// Whether the `offline_access` scope requires explicit consent for a web
    /// client (issue #21, OIDC Core 11). Default `true`: a confidential/web client
    /// requesting `offline_access` must obtain explicit consent that covers it,
    /// UNLESS the trusted first-party carve-out applies (the client's consent mode
    /// is `implicit` or its `skip_consent` flag is set). Set it to `false` to grant
    /// `offline_access` without a dedicated consent prompt for every client.
    pub offline_access_requires_consent: bool,

    /// The lifetime in seconds of a REMEMBERED consent (issue #21): the TTL applied
    /// to a recorded consent for a client whose consent mode is `remembered`. After
    /// this long the recorded consent expires and the next authorization re-prompts.
    /// The default (2592000) is thirty days. Must be at least 1 and at most
    /// `OIDC_MAX_REMEMBERED_CONSENT_TTL_SECS`. It has no effect on `explicit` mode
    /// (whose consent never expires) or `implicit` mode (which never prompts).
    pub remembered_consent_ttl_secs: u64,

    /// Require a pushed authorization request (PAR, RFC 9126 section 5) for EVERY
    /// client in this environment. The safe default (`false`) leaves PAR optional:
    /// a client may still push a request, but a plain authorization request is also
    /// accepted. When `true`, the authorization endpoint rejects any plain (non-PAR)
    /// request with `invalid_request`, and discovery advertises
    /// `require_pushed_authorization_requests = true`. A per-client
    /// `require_pushed_authorization_requests` registration flag layers ON TOP of
    /// this: either the environment switch OR the client flag being set requires PAR
    /// for that client. This is a promotable per-environment setting: it appears in
    /// config snapshots and rides the M5 promotion pipeline; the process value is the
    /// deployment default until per-environment overrides land.
    pub require_pushed_authorization_requests: bool,

    /// The pushed-authorization-request `request_uri` lifetime in seconds (RFC 9126
    /// section 2.2, issue #27). A pushed request is short-lived and single-use; the
    /// default (60) is one minute, following the RFC's guidance that a `request_uri`
    /// expires soon after it is pushed. Must be at least 1 and at most
    /// `OIDC_MAX_PAR_TTL_SECS` (600). This is a promotable per-environment setting in
    /// spirit, like the token lifetimes; the process value is the deployment default
    /// until per-environment overrides ride the M5 promotion pipeline.
    pub par_ttl_secs: u64,

    /// Whether to mount the Dynamic Client Registration endpoint
    /// (`/connect/register`, RFC 7591 + OIDC DCR 1.0, issue #30). The SAFE default
    /// (`false`) leaves it UNMOUNTED, because open self-service client registration
    /// is an abuse surface whose real gating (initial access token policy chains,
    /// per-tenant quotas, and quarantine) is owned by the abuse-controls work
    /// (issue #31). This flag ships ONLY the endpoint and this plain on/off switch;
    /// #31 layers its policy chains on top. When `true`, the RFC 7591 registration
    /// endpoint and the RFC 7592 configuration-management endpoint are served under
    /// each environment's issuer path, and discovery advertises
    /// `registration_endpoint`. This is a promotable per-environment setting in
    /// spirit; the process value is the deployment default until per-environment
    /// overrides ride the M5 promotion pipeline.
    pub registration_enabled: bool,

    /// The Dynamic Client Registration exposure switch (issue #31): `closed`
    /// (management API only), `token_gated` (a valid initial access token is
    /// required), or `open` (anonymous registration allowed, but the resulting
    /// client starts quarantined). The SAFE default (`token_gated`) makes open
    /// self-service registration opt-in. This only takes effect when
    /// `registration_enabled` mounts the endpoint. This is a promotable
    /// per-environment setting in spirit; the process value is the deployment
    /// default until per-environment overrides ride the M5 promotion pipeline.
    pub registration_mode: RegistrationMode,

    /// The maximum number of dynamically registered clients allowed per environment
    /// (issue #31). A registration that would exceed this cap is refused with a
    /// typed error and a `dcr.quota_hit` audit event. The default (100) bounds the
    /// self-service abuse surface; only DCR-origin clients count toward it (clients
    /// created through the management API do not). Raise it for an environment that
    /// legitimately hosts many self-service clients.
    pub registration_max_clients: u32,

    /// The maximum number of registration requests one source (or one initial
    /// access token) may make within `registration_rate_window_secs` (issue #31). A
    /// request beyond the limit is refused with a typed error and a
    /// `dcr.rate_limited` audit event. The default (20) is a conservative
    /// endpoint-local guard; set it to 0 to disable rate limiting (relying on the
    /// quota alone). This ships endpoint-local controls that later delegate to the
    /// M15 layered rate limiter.
    pub registration_rate_limit: u32,

    /// The fixed rate-limit window in seconds for `registration_rate_limit` (issue
    /// #31). The default (60) is one minute. Must be at least 1 and at most
    /// `OIDC_MAX_LIFETIME_SECS`.
    pub registration_rate_window_secs: u64,

    /// The default audience a client-credentials access token (RFC 6749 4.4, issue
    /// #23) carries when the request targets NO resource server. The default
    /// (`client_id`) makes the token's `aud` the OAuth client id, preserving the
    /// environment's existing no-resource behavior; `issuer` makes it the
    /// per-environment issuer. When a request DOES target a registered resource
    /// server (the RFC 8707 `resource` parameter, issue #28), that resource server's
    /// audience wins and this default does not apply. This is a promotable
    /// per-environment setting in spirit; the process value is the deployment default
    /// until per-environment overrides ride the M5 promotion pipeline.
    pub client_credentials_default_audience: ClientCredentialsAudience,

    /// Whether the Global Token Revocation receiver (issue #36) HARD-KILLS the
    /// subject's `offline_access` refresh families too, not only the session-bound
    /// ones. This has effect ONLY when the experimental `global-token-revocation`
    /// feature is enabled (the endpoint is otherwise unmounted). The SAFE default
    /// (`false`) matches the platform-wide revoke-everything semantic: offline
    /// (consented long-lived) grants survive a revoke unless a hard kill is asked for
    /// (issue #21/#32), so a routine global revoke does not silently strip a user's
    /// standing offline authorizations. Set it to `true` for an account-takeover
    /// posture, where a global revoke must terminate absolutely everything the subject
    /// holds, offline grants included, so every already-issued token dies at once.
    pub global_token_revocation_hard_kill: bool,

    /// The device-authorization flow lifetime in seconds (RFC 8628 section 3.2, issue
    /// #24). Both the device code and the user code expire after this; a poll after it
    /// yields `expired_token` and the verification page shows a safe error. A short TTL
    /// is a core user-code brute-force mitigation (RFC 8628 section 5.1), so the
    /// default (600) is a conservative ten minutes. Must be at least 1 and at most
    /// `OIDC_MAX_DEVICE_CODE_TTL_SECS` (1800).
    pub device_code_ttl_secs: u64,

    /// The base minimum polling interval a device-authorization response advertises,
    /// in seconds (RFC 8628 section 3.2 `interval`, issue #24). A constrained device
    /// waits this long between polls; a poll sooner than the current interval is
    /// answered with `slow_down` and the interval is increased server-side. The default
    /// (5) follows RFC 8628's recommended default. Must be at least 1 and at most
    /// `OIDC_MAX_DEVICE_POLL_INTERVAL_SECS`.
    pub device_poll_interval_secs: u64,

    /// The number of seconds the enforced polling interval grows by each time a device
    /// polls too fast (RFC 8628 section 3.5 `slow_down`, issue #24). Tracked per device
    /// code, so a device that keeps polling early is throttled progressively. The
    /// default (5) matches RFC 8628's guidance; 0 answers `slow_down` without growing
    /// the interval. At most `OIDC_MAX_DEVICE_POLL_INTERVAL_SECS`.
    pub device_slow_down_increment_secs: u64,

    /// The number of failed user-code match attempts a single device-authorization
    /// flow tolerates before it is invalidated (RFC 8628 section 5.1, issue #24). Once
    /// a flow reaches this bound it is denied, so a user code cannot be brute forced by
    /// repeated guessing against a known flow. The default (5) is conservative. Must be
    /// at least 1.
    pub device_user_code_max_attempts: u32,

    /// The maximum number of user-code submissions one source may make against the
    /// verification page within `device_verification_rate_window_secs` (RFC 8628
    /// section 5.1, issue #24). A submission beyond the limit is refused with a safe
    /// rate-limited page, the primary defense against brute forcing the user-code space
    /// across many flows. The default (10) is a conservative endpoint-local guard; 0
    /// disables per-source rate limiting (relying on entropy, the short TTL, and the
    /// per-flow attempt bound alone).
    pub device_verification_rate_limit: u32,

    /// The fixed rate-limit window in seconds for `device_verification_rate_limit`
    /// (issue #24). The default (60) is one minute. Must be at least 1 and at most
    /// `OIDC_MAX_LIFETIME_SECS`.
    pub device_verification_rate_window_secs: u64,

    /// Enable OIDC Session Management 1.0 for this environment (issue #39). The
    /// SAFE default (`false`) leaves it OFF: no `check_session_iframe` is mounted,
    /// discovery omits `check_session_iframe`, and no `session_state` is emitted on
    /// authorization responses. When `true`, the OP serves the
    /// `check_session_iframe` (framable cross-origin by design, the one page exempt
    /// from the platform anti-clickjacking posture) and every authorization
    /// response for a participating client carries `session_state`. This mechanism
    /// is functionally degraded under 2026 third-party-cookie partitioning (OIDC
    /// Session Management 1.0 section 5.1 warns a blocked poll can loop
    /// re-authentication); it ships ONLY for certification completeness, never as a
    /// recommended mechanism, and integrators are steered to back-channel logout.
    /// Enabling it requires BOTH this environment flag AND per-client opt-in, so it
    /// can never turn on globally by accident. This is a promotable per-environment
    /// setting in spirit; the process value is the deployment default until
    /// per-environment overrides ride the M5 promotion pipeline.
    pub session_management_enabled: bool,

    /// Enable OIDC Front-Channel Logout 1.0 for this environment (issue #39). The
    /// SAFE default (`false`) leaves it OFF: discovery omits
    /// `frontchannel_logout_supported` and `frontchannel_logout_session_supported`,
    /// and RP-initiated logout renders no front-channel iframes. When `true`, the
    /// `end_session` flow renders a page embedding a hidden iframe per participating
    /// RP that registered a `frontchannel_logout_uri`, passing `iss` and the RP's
    /// OWN per-(client, session) `sid` when it registered
    /// `frontchannel_logout_session_required`. Front-channel delivery is best-effort
    /// by construction: it never blocks, replaces, or reorders the authoritative
    /// back-channel logout path. Like Session Management, this iframe mechanism is
    /// degraded under third-party-cookie partitioning and ships ONLY for
    /// certification completeness. Enabling it requires BOTH this environment flag
    /// AND per-client opt-in (a registered `frontchannel_logout_uri`), so it can
    /// never turn on globally by accident. This is a promotable per-environment
    /// setting in spirit; the process value is the deployment default until
    /// per-environment overrides ride the M5 promotion pipeline.
    pub frontchannel_logout_enabled: bool,
    /// Whether the OIDC Back-Channel Logout delivery worker runs (issue #34). OFF by
    /// default (the covenant posture: no mandatory background infrastructure), so the
    /// default build enqueues nothing and sends nothing. When enabled, the worker drains
    /// the durable session-ended outbox, builds one signed Logout Token per participating
    /// relying party (each carrying that RP's own `sid`), and POSTs it to the RP's
    /// registered `backchannel_logout_uri` through the SSRF-hardened outbound fetcher,
    /// with bounded-backoff retries and a dead-letter state. Discovery advertises
    /// `backchannel_logout_supported` regardless (the OP supports the mechanism); this
    /// switch governs only whether the delivery worker is scheduled.
    pub backchannel_logout_enabled: bool,

    /// The maximum number of delivery attempts the back-channel logout worker makes for
    /// one relying party before it DEAD-LETTERS the delivery (issue #34). A slow or down
    /// RP is retried with exponential backoff up to this cap, then given up on (recorded
    /// with its last error) so it never retries unboundedly. The default (5) is
    /// conservative. Must be at least 1.
    pub backchannel_logout_max_attempts: u32,

    /// The base delay in seconds for the back-channel logout worker's exponential backoff
    /// between delivery retries (issue #34). The nth retry waits about
    /// `base * 2^(n-1)` seconds plus jitter (both drawn from the deterministic clock and
    /// entropy seams). The default (10) is conservative. Must be at least 1 and at most
    /// `OIDC_MAX_LIFETIME_SECS`.
    pub backchannel_logout_retry_base_secs: u64,

    /// How often, in seconds, the back-channel logout worker polls the queue for due work
    /// (issue #34). The default (5) is a responsive-yet-cheap cadence. Must be at least 1
    /// and at most `OIDC_MAX_LIFETIME_SECS`.
    pub backchannel_logout_poll_interval_secs: u64,

    /// The per-delivery total time budget in seconds for one back-channel logout POST
    /// (issue #34): the SSRF-hardened fetcher aborts a delivery that exceeds it, so a slow
    /// RP cannot wedge the worker or block other RPs. The default (10) is conservative.
    /// Must be at least 1 and at most `OIDC_MAX_LIFETIME_SECS`.
    pub backchannel_logout_request_timeout_secs: u64,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            authorization_code_ttl_secs: 60,
            access_token_ttl_secs: 300,
            default_access_token_format: TokenFormat::AtJwt,
            reuse_grace_secs: 10,
            session_ttl_secs: 3600,
            session_idle_ttl_secs: 3600,
            session_partitioned_cookie: false,
            session_peer_ip_binding: false,
            session_device_binding: false,
            jwks_cache_max_age_secs: 600,
            require_pkce_for_confidential_clients: true,
            conform_id_token_claims: false,
            client_assertion_audience: ClientAssertionAudience::TokenEndpointOrIssuer,
            client_assertion_max_skew_secs: 60,
            userinfo_cors_origins: Vec::new(),
            enable_response_type_id_token: false,
            enable_response_type_code_id_token: false,
            enable_response_type_none: false,
            enable_response_mode_form_post: false,
            issue_refresh_tokens: true,
            refresh_idle_ttl_secs: 1_209_600,
            refresh_max_lifetime_secs: 2_592_000,
            offline_idle_ttl_secs: 2_592_000,
            offline_max_lifetime_secs: 7_776_000,
            refresh_rotation_grace_secs: 10,
            refresh_rotation_threshold_percent: 70,
            offline_access_requires_consent: true,
            remembered_consent_ttl_secs: 2_592_000,
            require_pushed_authorization_requests: false,
            par_ttl_secs: 60,
            registration_enabled: false,
            registration_mode: RegistrationMode::TokenGated,
            registration_max_clients: 100,
            registration_rate_limit: 20,
            registration_rate_window_secs: 60,
            client_credentials_default_audience: ClientCredentialsAudience::ClientId,
            global_token_revocation_hard_kill: false,
            device_code_ttl_secs: 600,
            device_poll_interval_secs: 5,
            device_slow_down_increment_secs: 5,
            device_user_code_max_attempts: 5,
            device_verification_rate_limit: 10,
            device_verification_rate_window_secs: 60,
            session_management_enabled: false,
            frontchannel_logout_enabled: false,
            backchannel_logout_enabled: false,
            backchannel_logout_max_attempts: 5,
            backchannel_logout_retry_base_secs: 10,
            backchannel_logout_poll_interval_secs: 5,
            backchannel_logout_request_timeout_secs: 10,
        }
    }
}

/// One entry in the `[features]` table.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct FeatureToggle {
    /// Whether the feature is enabled. When omitted, the feature's own default
    /// applies (on only for a Supported feature declared on by default), so
    /// naming a feature just to attach an `ack` does not silently turn a
    /// default-on feature off. Set `enabled = false` to force it off.
    pub enabled: Option<bool>,

    /// Exact-version acknowledgment, required to enable an experimental
    /// feature. Ignored for preview and supported features.
    pub ack: Option<String>,
}

/// A successfully parsed configuration plus the warnings the caller must
/// surface. Warnings never gate startup; everything gating startup is an
/// error.
#[derive(Debug)]
pub struct Loaded {
    /// The parsed, validated configuration.
    pub config: Config,
    /// Warnings to surface to the operator. Empty when `dev_mode` is set.
    pub warnings: Vec<Warning>,
}

/// An operator-facing warning collected during load.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Warning {
    /// A secret-typed field uses the literal form outside dev mode.
    LiteralSecret {
        /// Dotted key path of the offending field (for example
        /// `database.password`).
        key: String,
    },
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Warning::LiteralSecret { key } => write!(
                f,
                "secret '{key}' is a literal value in the config file; \
                 use {{ file = \"/path\" }} or {{ env = \"VAR\" }} instead \
                 (or set dev_mode = true in development)"
            ),
        }
    }
}

impl Config {
    /// Load and strictly parse a TOML config file.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Io`] if the file cannot be read; [`ConfigError::Parse`]
    /// (naming the file, line, column, and offending key with the accepted
    /// alternatives) on any syntax or schema violation. Unknown keys are
    /// errors; there is no warn-and-continue mode.
    pub fn load(path: impl AsRef<Path>) -> Result<Loaded, ConfigError> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml_str(&contents, &path.display().to_string())
    }

    /// Strictly parse TOML config text. `source_name` names the origin in
    /// errors (a file path, or a marker like `"<inline>"` in tests).
    ///
    /// # Errors
    ///
    /// [`ConfigError::Parse`] with the same contract as [`Config::load`].
    pub fn from_toml_str(input: &str, source_name: &str) -> Result<Loaded, ConfigError> {
        let config: Config = toml::from_str(input).map_err(|error| {
            let position = error.span().map(|span| line_and_column(input, span.start));
            ConfigError::Parse {
                source_name: source_name.to_owned(),
                position,
                message: error.message().to_owned(),
            }
        })?;
        config.validate()?;
        let warnings = config.collect_warnings();
        Ok(Loaded { config, warnings })
    }

    /// The JSON Schema (draft 2020-12) this crate's parser enforces, with
    /// field doc comments as descriptions. Published as a release artifact
    /// by scripts/config-schema.sh.
    #[must_use]
    pub fn json_schema() -> schemars::Schema {
        schemars::schema_for!(Config)
    }

    /// Post-parse lint pass. Warnings are suppressed wholesale in dev mode;
    /// parse strictness is not affected.
    fn collect_warnings(&self) -> Vec<Warning> {
        if self.dev_mode {
            return Vec::new();
        }
        let mut warnings = Vec::new();
        self.for_each_secret(|key, secret| {
            if secret.is_literal() {
                warnings.push(Warning::LiteralSecret {
                    key: key.to_owned(),
                });
            }
        });
        warnings
    }

    /// Visit every secret-typed field with its dotted key path. Sections
    /// added by later issues must register their secret fields here so the
    /// literal-form lint keeps covering the whole tree.
    fn for_each_secret(&self, mut visit: impl FnMut(&str, &Secret)) {
        if let Some(password) = &self.database.password {
            visit("database.password", password);
        }
        if let Some(token) = &self.admin.bootstrap_operator_token {
            visit("admin.bootstrap_operator_token", token);
        }
        if let Some(dsn) = &self.admin.control_database_url {
            visit("admin.control_database_url", dsn);
        }
    }

    /// Post-parse bound and cross-field checks the schema alone cannot express.
    /// Fatal (unlike a [`Warning`]): a violation aborts startup.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] if `admin.max_page_size` exceeds the management
    /// list hard cap (a larger cap would let the store's has-next sentinel be
    /// clamped away, hiding the last page).
    fn validate(&self) -> Result<(), ConfigError> {
        if self.admin.max_page_size > MANAGEMENT_LIST_HARD_CAP {
            return Err(ConfigError::Invalid {
                message: format!(
                    "admin.max_page_size ({}) must not exceed the management list hard cap ({MANAGEMENT_LIST_HARD_CAP})",
                    self.admin.max_page_size
                ),
            });
        }
        check_oidc_lifetime(
            "oidc.authorization_code_ttl_secs",
            self.oidc.authorization_code_ttl_secs,
        )?;
        check_oidc_lifetime(
            "oidc.access_token_ttl_secs",
            self.oidc.access_token_ttl_secs,
        )?;
        // The reuse grace window differs from the lifetimes: 0 is valid (it means
        // treat every reuse as genuine), so only the upper bound is enforced.
        if self.oidc.reuse_grace_secs > OIDC_MAX_LIFETIME_SECS {
            return Err(ConfigError::Invalid {
                message: format!(
                    "oidc.reuse_grace_secs ({}) must not exceed {OIDC_MAX_LIFETIME_SECS} seconds",
                    self.oidc.reuse_grace_secs
                ),
            });
        }
        validate_session_lifetimes(&self.oidc)?;
        // The JWKS cache window must stay in the operational-discipline range.
        let cache = self.oidc.jwks_cache_max_age_secs;
        if !(OIDC_JWKS_CACHE_MIN_SECS..=OIDC_JWKS_CACHE_MAX_SECS).contains(&cache) {
            return Err(ConfigError::Invalid {
                message: format!(
                    "oidc.jwks_cache_max_age_secs ({cache}) must be between \
                     {OIDC_JWKS_CACHE_MIN_SECS} and {OIDC_JWKS_CACHE_MAX_SECS} seconds"
                ),
            });
        }
        // The client-assertion skew has only an upper bound: 0 is valid (no
        // tolerance), but a wide skew keeps an expired assertion replayable.
        if self.oidc.client_assertion_max_skew_secs > OIDC_MAX_CLIENT_ASSERTION_SKEW_SECS {
            return Err(ConfigError::Invalid {
                message: format!(
                    "oidc.client_assertion_max_skew_secs ({}) must not exceed \
                     {OIDC_MAX_CLIENT_ASSERTION_SKEW_SECS} seconds",
                    self.oidc.client_assertion_max_skew_secs
                ),
            });
        }
        validate_refresh_and_consent(&self.oidc)?;
        // The PAR request_uri lifetime is bounded like the other credential
        // lifetimes: a zero-second request_uri is born expired, and a lifetime beyond
        // the ceiling would keep a pushed request usable for too long (RFC 9126
        // recommends a short expiry).
        if self.oidc.par_ttl_secs < 1 {
            return Err(ConfigError::Invalid {
                message: "oidc.par_ttl_secs must be at least 1 second".to_owned(),
            });
        }
        if self.oidc.par_ttl_secs > OIDC_MAX_PAR_TTL_SECS {
            return Err(ConfigError::Invalid {
                message: format!(
                    "oidc.par_ttl_secs ({}) must not exceed {OIDC_MAX_PAR_TTL_SECS} seconds",
                    self.oidc.par_ttl_secs
                ),
            });
        }
        // The DCR registration rate-limit window (issue #31) is bounded like the
        // other windows: a zero-second window is meaningless, and a window beyond
        // the ceiling would let a source accumulate an unbounded burst.
        if self.oidc.registration_rate_window_secs < 1 {
            return Err(ConfigError::Invalid {
                message: "oidc.registration_rate_window_secs must be at least 1 second".to_owned(),
            });
        }
        if self.oidc.registration_rate_window_secs > OIDC_MAX_LIFETIME_SECS {
            return Err(ConfigError::Invalid {
                message: format!(
                    "oidc.registration_rate_window_secs ({}) must not exceed \
                     {OIDC_MAX_LIFETIME_SECS} seconds",
                    self.oidc.registration_rate_window_secs
                ),
            });
        }
        validate_device_authorization(&self.oidc)?;
        validate_backchannel_logout(&self.oidc)?;
        Ok(())
    }
}

/// Validate the back-channel logout worker settings (issue #34), kept out of
/// [`Config::validate`] so each stays within the readable-length lint. The attempts cap
/// must admit at least one attempt, and the backoff base, poll cadence, and per-delivery
/// timeout are bounded like the other second-valued knobs: a zero is meaningless, and a
/// value beyond the ceiling is a misconfiguration.
fn validate_backchannel_logout(oidc: &OidcConfig) -> Result<(), ConfigError> {
    if oidc.backchannel_logout_max_attempts < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.backchannel_logout_max_attempts must be at least 1".to_owned(),
        });
    }
    for (name, value) in [
        (
            "oidc.backchannel_logout_retry_base_secs",
            oidc.backchannel_logout_retry_base_secs,
        ),
        (
            "oidc.backchannel_logout_poll_interval_secs",
            oidc.backchannel_logout_poll_interval_secs,
        ),
        (
            "oidc.backchannel_logout_request_timeout_secs",
            oidc.backchannel_logout_request_timeout_secs,
        ),
    ] {
        if value < 1 {
            return Err(ConfigError::Invalid {
                message: format!("{name} must be at least 1 second"),
            });
        }
        if value > OIDC_MAX_LIFETIME_SECS {
            return Err(ConfigError::Invalid {
                message: format!(
                    "{name} ({value}) must not exceed {OIDC_MAX_LIFETIME_SECS} seconds"
                ),
            });
        }
    }
    Ok(())
}

/// Validate the device-authorization grant settings (issue #24, RFC 8628), kept out
/// of [`Config::validate`] so each stays within the readable-length lint.
///
/// The flow TTL and the polling intervals are bounded like the other credential
/// lifetimes: a zero-second value is meaningless (a code born expired, or a
/// zero-second poll interval), and a value beyond the ceiling would blunt a core
/// brute-force mitigation (a long-lived user code) or make a device wait
/// unreasonably. The failed-attempt bound must admit at least one attempt.
fn validate_device_authorization(oidc: &OidcConfig) -> Result<(), ConfigError> {
    if oidc.device_code_ttl_secs < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.device_code_ttl_secs must be at least 1 second".to_owned(),
        });
    }
    if oidc.device_code_ttl_secs > OIDC_MAX_DEVICE_CODE_TTL_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.device_code_ttl_secs ({}) must not exceed \
                 {OIDC_MAX_DEVICE_CODE_TTL_SECS} seconds",
                oidc.device_code_ttl_secs
            ),
        });
    }
    if oidc.device_poll_interval_secs < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.device_poll_interval_secs must be at least 1 second".to_owned(),
        });
    }
    if oidc.device_poll_interval_secs > OIDC_MAX_DEVICE_POLL_INTERVAL_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.device_poll_interval_secs ({}) must not exceed \
                 {OIDC_MAX_DEVICE_POLL_INTERVAL_SECS} seconds",
                oidc.device_poll_interval_secs
            ),
        });
    }
    // The slow_down increment may be 0 (answer slow_down without growing the interval),
    // but is bounded by the same ceiling as the interval.
    if oidc.device_slow_down_increment_secs > OIDC_MAX_DEVICE_POLL_INTERVAL_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.device_slow_down_increment_secs ({}) must not exceed \
                 {OIDC_MAX_DEVICE_POLL_INTERVAL_SECS} seconds",
                oidc.device_slow_down_increment_secs
            ),
        });
    }
    if oidc.device_user_code_max_attempts < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.device_user_code_max_attempts must be at least 1".to_owned(),
        });
    }
    // The verification rate-limit window is bounded like the other windows: a
    // zero-second window is meaningless, and a window beyond the ceiling would let a
    // source accumulate an unbounded burst.
    if oidc.device_verification_rate_window_secs < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.device_verification_rate_window_secs must be at least 1 second"
                .to_owned(),
        });
    }
    if oidc.device_verification_rate_window_secs > OIDC_MAX_LIFETIME_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.device_verification_rate_window_secs ({}) must not exceed \
                 {OIDC_MAX_LIFETIME_SECS} seconds",
                oidc.device_verification_rate_window_secs
            ),
        });
    }
    Ok(())
}

/// Validate the session lifetimes (issue #20, extended by issue #32), kept out of
/// [`Config::validate`] so each stays within the readable-length lint.
///
/// A session has its own, larger ceiling than a code or an access token (a session
/// is longer lived). Both lifetimes have a one-second lower bound: a zero-second
/// session is born expired. The IDLE timeout must not exceed the ABSOLUTE hard cap,
/// because an idle timeout beyond the cap can never fire (the session is already
/// dead), so accepting it would silently mislead an operator into believing idle
/// expiry is configured when it is inert.
fn validate_session_lifetimes(oidc: &OidcConfig) -> Result<(), ConfigError> {
    if oidc.session_ttl_secs < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.session_ttl_secs must be at least 1 second".to_owned(),
        });
    }
    if oidc.session_ttl_secs > OIDC_MAX_SESSION_TTL_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.session_ttl_secs ({}) must not exceed {OIDC_MAX_SESSION_TTL_SECS} seconds",
                oidc.session_ttl_secs
            ),
        });
    }
    if oidc.session_idle_ttl_secs < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.session_idle_ttl_secs must be at least 1 second".to_owned(),
        });
    }
    if oidc.session_idle_ttl_secs > OIDC_MAX_SESSION_TTL_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.session_idle_ttl_secs ({}) must not exceed \
                 {OIDC_MAX_SESSION_TTL_SECS} seconds",
                oidc.session_idle_ttl_secs
            ),
        });
    }
    if oidc.session_idle_ttl_secs > oidc.session_ttl_secs {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.session_idle_ttl_secs ({}) must not exceed oidc.session_ttl_secs ({}): an \
                 idle timeout beyond the absolute cap can never fire",
                oidc.session_idle_ttl_secs, oidc.session_ttl_secs
            ),
        });
    }
    Ok(())
}

/// Validate the refresh-token lifecycle and consent settings (issue #21), kept out
/// of [`Config::validate`] so each stays within the readable-length lint.
///
/// Idle timeouts and family hard caps each have a one-second lower bound (a
/// zero-second window is born expired) and their own, larger ceilings, and a hard
/// cap must be at least its idle timeout (a family cannot expire before an unused
/// token). The rotation grace window, like `reuse_grace`, permits 0 (treat every
/// superseded-token presentation as reuse) and only bounds the upper end. The
/// rotation threshold is a percent, bounded 0..=100. The remembered-consent TTL is a
/// lifetime: at least one second, at most its own ceiling.
fn validate_refresh_and_consent(oidc: &OidcConfig) -> Result<(), ConfigError> {
    check_refresh_idle("oidc.refresh_idle_ttl_secs", oidc.refresh_idle_ttl_secs)?;
    check_refresh_max(
        "oidc.refresh_max_lifetime_secs",
        oidc.refresh_max_lifetime_secs,
        "oidc.refresh_idle_ttl_secs",
        oidc.refresh_idle_ttl_secs,
    )?;
    check_refresh_idle("oidc.offline_idle_ttl_secs", oidc.offline_idle_ttl_secs)?;
    check_refresh_max(
        "oidc.offline_max_lifetime_secs",
        oidc.offline_max_lifetime_secs,
        "oidc.offline_idle_ttl_secs",
        oidc.offline_idle_ttl_secs,
    )?;
    if oidc.refresh_rotation_grace_secs > OIDC_MAX_LIFETIME_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.refresh_rotation_grace_secs ({}) must not exceed {OIDC_MAX_LIFETIME_SECS} seconds",
                oidc.refresh_rotation_grace_secs
            ),
        });
    }
    if oidc.refresh_rotation_threshold_percent > 100 {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.refresh_rotation_threshold_percent ({}) must be between 0 and 100",
                oidc.refresh_rotation_threshold_percent
            ),
        });
    }
    if oidc.remembered_consent_ttl_secs < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.remembered_consent_ttl_secs must be at least 1 second".to_owned(),
        });
    }
    if oidc.remembered_consent_ttl_secs > OIDC_MAX_REMEMBERED_CONSENT_TTL_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.remembered_consent_ttl_secs ({}) must not exceed \
                 {OIDC_MAX_REMEMBERED_CONSENT_TTL_SECS} seconds",
                oidc.remembered_consent_ttl_secs
            ),
        });
    }
    Ok(())
}

/// Validate a refresh-token idle timeout: at least one second (a zero-second idle
/// window is born expired) and no more than [`OIDC_MAX_REFRESH_IDLE_TTL_SECS`].
fn check_refresh_idle(key: &str, value: u64) -> Result<(), ConfigError> {
    if value < 1 {
        return Err(ConfigError::Invalid {
            message: format!("{key} must be at least 1 second"),
        });
    }
    if value > OIDC_MAX_REFRESH_IDLE_TTL_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "{key} ({value}) must not exceed {OIDC_MAX_REFRESH_IDLE_TTL_SECS} seconds"
            ),
        });
    }
    Ok(())
}

/// Validate a refresh-token family hard cap: at least one second, no more than
/// [`OIDC_MAX_REFRESH_MAX_LIFETIME_SECS`], and at least the paired idle timeout (a
/// family must not expire before an unused token would).
fn check_refresh_max(
    key: &str,
    value: u64,
    idle_key: &str,
    idle_value: u64,
) -> Result<(), ConfigError> {
    if value < 1 {
        return Err(ConfigError::Invalid {
            message: format!("{key} must be at least 1 second"),
        });
    }
    if value > OIDC_MAX_REFRESH_MAX_LIFETIME_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "{key} ({value}) must not exceed {OIDC_MAX_REFRESH_MAX_LIFETIME_SECS} seconds"
            ),
        });
    }
    if value < idle_value {
        return Err(ConfigError::Invalid {
            message: format!("{key} ({value}) must be at least {idle_key} ({idle_value}) seconds"),
        });
    }
    Ok(())
}

/// Validate one OIDC lifetime: at least one second (a zero-second credential is
/// born expired) and no more than [`OIDC_MAX_LIFETIME_SECS`].
fn check_oidc_lifetime(key: &str, value: u64) -> Result<(), ConfigError> {
    if value < 1 {
        return Err(ConfigError::Invalid {
            message: format!("{key} must be at least 1 second"),
        });
    }
    if value > OIDC_MAX_LIFETIME_SECS {
        return Err(ConfigError::Invalid {
            message: format!("{key} ({value}) must not exceed {OIDC_MAX_LIFETIME_SECS} seconds"),
        });
    }
    Ok(())
}

/// Translate a byte offset into 1-based line and column (in characters).
fn line_and_column(input: &str, offset: usize) -> (usize, usize) {
    let prefix = &input[..offset.min(input.len())];
    let line = prefix.matches('\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, tail)| tail)
        .chars()
        .count()
        + 1;
    (line, column)
}

/// Why a configuration failed to load. Always fatal: the caller aborts
/// startup and shows the message.
#[derive(Debug)]
pub enum ConfigError {
    /// The config file could not be read.
    Io {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The config text violates the schema (syntax error, wrong type, or
    /// unknown key).
    Parse {
        /// The file path (or inline marker) the text came from.
        source_name: String,
        /// 1-based line and column of the offending item, when the parser
        /// attributed one.
        position: Option<(usize, usize)>,
        /// The parser's message; for unknown keys this names the offending
        /// key and lists the accepted fields.
        message: String,
    },
    /// A parsed value violates a bound or cross-field constraint the schema
    /// alone cannot express (for example `admin.max_page_size` above the
    /// management list hard cap).
    Invalid {
        /// The human-readable constraint violation. Never carries a secret.
        message: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io { path, source } => {
                write!(f, "cannot read config file '{}': {source}", path.display())
            }
            ConfigError::Parse {
                source_name,
                position,
                message,
            } => match position {
                Some((line, column)) => {
                    write!(f, "invalid config {source_name}:{line}:{column}: {message}")
                }
                None => write!(f, "invalid config {source_name}: {message}"),
            },
            ConfigError::Invalid { message } => write!(f, "invalid config: {message}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io { source, .. } => Some(source),
            ConfigError::Parse { .. } | ConfigError::Invalid { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_the_documented_defaults() {
        let loaded = Config::from_toml_str("", "<inline>").expect("empty config is valid");
        assert!(loaded.warnings.is_empty());
        let config = loaded.config;
        assert!(!config.dev_mode);
        assert_eq!(config.server.bind, "127.0.0.1:8443");
        assert_eq!(config.server.management_bind, "127.0.0.1:9443");
        assert_eq!(config.server.public_url, None);
        assert_eq!(config.server.shutdown_grace_secs, 25);
        // Trusted-proxy policy defaults to trusting nothing.
        assert_eq!(config.proxy.trusted_hops, 0);
        assert!(!config.proxy.trust_forwarded);
        // Telemetry defaults to machine-parseable JSON with no exporter.
        assert_eq!(config.telemetry.log_format, LogFormat::Json);
        assert_eq!(config.telemetry.otlp_endpoint, None);
        assert_eq!(config.database.url.host(), "localhost");
        assert!(config.database.password.is_none());
        assert!(config.features.is_empty());
    }

    #[test]
    fn admin_section_defaults_parse_and_flag_a_literal_token() {
        // Defaults: operator plane unauthorized, control DSN unset, safe caps.
        let config = Config::from_toml_str("", "<inline>").expect("valid").config;
        assert!(config.admin.bootstrap_operator_token.is_none());
        assert!(config.admin.control_database_url.is_none());
        assert_eq!(config.admin.max_page_size, 200);
        assert_eq!(config.admin.default_page_size, 50);

        // The bootstrap token is a secret: a literal value is flagged outside
        // dev mode and never echoed.
        let input = "[admin]\nbootstrap_operator_token = \"op-secret-123\"\nmax_page_size = 10\n";
        let loaded = Config::from_toml_str(input, "<inline>").expect("valid");
        assert_eq!(
            loaded.warnings,
            vec![Warning::LiteralSecret {
                key: "admin.bootstrap_operator_token".to_owned()
            }]
        );
        assert_eq!(loaded.config.admin.max_page_size, 10);
        assert!(!loaded.warnings[0].to_string().contains("op-secret-123"));

        // Unknown admin keys abort with the accepted fields.
        let err = Config::from_toml_str("[admin]\nmax_pages = 5\n", "ironauth.toml")
            .expect_err("unknown admin key");
        let msg = err.to_string();
        assert!(msg.contains("max_pages"), "{msg}");
        assert!(msg.contains("max_page_size"), "{msg}");
    }

    #[test]
    fn admin_control_database_url_parses_and_flags_a_literal() {
        // The indirection form resolves and never warns.
        let indirect = "[admin]\ncontrol_database_url = { env = \"IRONAUTH_CONTROL_DSN\" }\n";
        let loaded = Config::from_toml_str(indirect, "<inline>").expect("valid");
        assert!(loaded.config.admin.control_database_url.is_some());
        assert!(loaded.warnings.is_empty());

        // A literal control DSN is a secret: flagged outside dev mode, never echoed.
        let literal =
            "[admin]\ncontrol_database_url = \"postgres://ironauth_control:pw@db/ironauth\"\n";
        let loaded = Config::from_toml_str(literal, "<inline>").expect("valid");
        assert_eq!(
            loaded.warnings,
            vec![Warning::LiteralSecret {
                key: "admin.control_database_url".to_owned()
            }]
        );
        assert!(!loaded.warnings[0].to_string().contains("pw@db"), "leak");
    }

    #[test]
    fn max_page_size_above_the_hard_cap_is_rejected() {
        let ok = format!("[admin]\nmax_page_size = {MANAGEMENT_LIST_HARD_CAP}\n");
        assert_eq!(
            Config::from_toml_str(&ok, "<inline>")
                .expect("at the cap is valid")
                .config
                .admin
                .max_page_size,
            MANAGEMENT_LIST_HARD_CAP
        );

        let over = format!(
            "[admin]\nmax_page_size = {}\n",
            MANAGEMENT_LIST_HARD_CAP + 1
        );
        let err = Config::from_toml_str(&over, "ironauth.toml").expect_err("over the cap");
        let msg = err.to_string();
        assert!(msg.contains("max_page_size"), "{msg}");
        assert!(msg.contains(&MANAGEMENT_LIST_HARD_CAP.to_string()), "{msg}");
    }

    #[test]
    fn oidc_section_defaults_and_rejects_bad_lifetimes_and_unknown_keys() {
        // Defaults: not mounted, 60s code, 300s access token, 10s reuse grace,
        // 3600s bootstrap session, 600s JWKS cache window.
        let config = Config::from_toml_str("", "<inline>").expect("valid").config;
        assert!(!config.oidc.enabled);
        assert_eq!(config.oidc.authorization_code_ttl_secs, 60);
        assert_eq!(config.oidc.access_token_ttl_secs, 300);
        // The environment default access-token format is the spec-conform at+jwt
        // (issue #29), so UserInfo and offline verification keep working.
        assert_eq!(config.oidc.default_access_token_format, TokenFormat::AtJwt);
        assert_eq!(config.oidc.reuse_grace_secs, 10);
        assert_eq!(config.oidc.session_ttl_secs, 3600);
        assert_eq!(config.oidc.jwks_cache_max_age_secs, 600);
        // PKCE is required for confidential clients by default (issue #13); public
        // clients always require it regardless.
        assert!(config.oidc.require_pkce_for_confidential_clients);
        // The UserInfo placement default is spec-conform (claims at UserInfo, lean
        // ID token) and no SPA origins are registered for CORS by default.
        assert!(!config.oidc.conform_id_token_claims);
        assert!(config.oidc.userinfo_cors_origins.is_empty());
        // Every legacy response type and form_post is DISABLED by default (issue
        // #17): only the code flow with the query response mode is served.
        assert!(!config.oidc.enable_response_type_id_token);
        assert!(!config.oidc.enable_response_type_code_id_token);
        assert!(!config.oidc.enable_response_type_none);
        assert!(!config.oidc.enable_response_mode_form_post);
        // Refresh-token rotation and offline_access defaults (issue #21).
        assert!(config.oidc.issue_refresh_tokens);
        assert_eq!(config.oidc.refresh_idle_ttl_secs, 1_209_600);
        assert_eq!(config.oidc.refresh_max_lifetime_secs, 2_592_000);
        assert_eq!(config.oidc.offline_idle_ttl_secs, 2_592_000);
        assert_eq!(config.oidc.offline_max_lifetime_secs, 7_776_000);
        assert_eq!(config.oidc.refresh_rotation_grace_secs, 10);
        assert_eq!(config.oidc.refresh_rotation_threshold_percent, 70);
        assert!(config.oidc.offline_access_requires_consent);
        assert_eq!(config.oidc.remembered_consent_ttl_secs, 2_592_000);

        // A zero session lifetime (born expired) is rejected; a lifetime above the
        // session ceiling is rejected too.
        let err = Config::from_toml_str("[oidc]\nsession_ttl_secs = 0\n", "ironauth.toml")
            .expect_err("zero session ttl");
        assert!(err.to_string().contains("session_ttl_secs"), "{err}");
        let over = format!(
            "[oidc]\nsession_ttl_secs = {}\n",
            OIDC_MAX_SESSION_TTL_SECS + 1
        );
        let err = Config::from_toml_str(&over, "ironauth.toml").expect_err("session over cap");
        assert!(err.to_string().contains("session_ttl_secs"), "{err}");

        // The JWKS cache window is bounded to 300..=900; outside is rejected.
        for bad in [OIDC_JWKS_CACHE_MIN_SECS - 1, OIDC_JWKS_CACHE_MAX_SECS + 1] {
            let input = format!("[oidc]\njwks_cache_max_age_secs = {bad}\n");
            let err = Config::from_toml_str(&input, "ironauth.toml").expect_err("out of range");
            assert!(err.to_string().contains("jwks_cache_max_age_secs"), "{err}");
        }
        // The boundary values are accepted.
        for ok in [OIDC_JWKS_CACHE_MIN_SECS, OIDC_JWKS_CACHE_MAX_SECS] {
            let input = format!("[oidc]\njwks_cache_max_age_secs = {ok}\n");
            assert_eq!(
                Config::from_toml_str(&input, "<inline>")
                    .expect("boundary valid")
                    .config
                    .oidc
                    .jwks_cache_max_age_secs,
                ok
            );
        }

        // A configured, in-bounds override parses.
        let input = "[oidc]\nenabled = true\nauthorization_code_ttl_secs = 30\n";
        let config = Config::from_toml_str(input, "<inline>")
            .expect("valid")
            .config;
        assert!(config.oidc.enabled);
        assert_eq!(config.oidc.authorization_code_ttl_secs, 30);

        // A zero reuse grace is VALID (treat every reuse as genuine); a zero
        // lifetime is not.
        let config = Config::from_toml_str("[oidc]\nreuse_grace_secs = 0\n", "<inline>")
            .expect("zero grace is valid")
            .config;
        assert_eq!(config.oidc.reuse_grace_secs, 0);

        // A zero lifetime (born expired) is rejected.
        let err =
            Config::from_toml_str("[oidc]\nauthorization_code_ttl_secs = 0\n", "ironauth.toml")
                .expect_err("zero ttl");
        assert!(
            err.to_string().contains("authorization_code_ttl_secs"),
            "{err}"
        );

        // A lifetime above the ceiling is rejected.
        let over = format!(
            "[oidc]\naccess_token_ttl_secs = {}\n",
            OIDC_MAX_LIFETIME_SECS + 1
        );
        let err = Config::from_toml_str(&over, "ironauth.toml").expect_err("over cap");
        assert!(err.to_string().contains("access_token_ttl_secs"), "{err}");

        // A reuse grace above the ceiling is rejected too.
        let over = format!(
            "[oidc]\nreuse_grace_secs = {}\n",
            OIDC_MAX_LIFETIME_SECS + 1
        );
        let err = Config::from_toml_str(&over, "ironauth.toml").expect_err("grace over cap");
        assert!(err.to_string().contains("reuse_grace_secs"), "{err}");

        // Unknown oidc keys abort with the accepted fields.
        let err = Config::from_toml_str("[oidc]\nttl = 5\n", "ironauth.toml")
            .expect_err("unknown oidc key");
        let msg = err.to_string();
        assert!(msg.contains("ttl"), "{msg}");
        assert!(msg.contains("authorization_code_ttl_secs"), "{msg}");
    }

    #[test]
    fn oidc_refresh_and_consent_settings_parse_and_validate() {
        // Issue #21: the refresh-token lifecycles, rotation policy, and consent
        // knobs parse in bounds and reject bad values.
        let input = "[oidc]\n\
             issue_refresh_tokens = false\n\
             refresh_idle_ttl_secs = 3600\n\
             refresh_max_lifetime_secs = 7200\n\
             offline_idle_ttl_secs = 86400\n\
             offline_max_lifetime_secs = 172800\n\
             refresh_rotation_grace_secs = 0\n\
             refresh_rotation_threshold_percent = 100\n\
             offline_access_requires_consent = false\n\
             remembered_consent_ttl_secs = 604800\n";
        let oidc = Config::from_toml_str(input, "<inline>")
            .expect("valid refresh config")
            .config
            .oidc;
        assert!(!oidc.issue_refresh_tokens);
        assert_eq!(oidc.refresh_idle_ttl_secs, 3600);
        assert_eq!(oidc.refresh_max_lifetime_secs, 7200);
        assert_eq!(oidc.refresh_rotation_grace_secs, 0);
        assert_eq!(oidc.refresh_rotation_threshold_percent, 100);
        assert!(!oidc.offline_access_requires_consent);

        // A zero idle TTL is born expired and rejected.
        let err = Config::from_toml_str("[oidc]\nrefresh_idle_ttl_secs = 0\n", "ironauth.toml")
            .expect_err("zero idle");
        assert!(err.to_string().contains("refresh_idle_ttl_secs"), "{err}");

        // An idle TTL above the idle ceiling is rejected.
        let over = format!(
            "[oidc]\noffline_idle_ttl_secs = {}\n",
            OIDC_MAX_REFRESH_IDLE_TTL_SECS + 1
        );
        let err = Config::from_toml_str(&over, "ironauth.toml").expect_err("idle over cap");
        assert!(err.to_string().contains("offline_idle_ttl_secs"), "{err}");

        // A family hard cap below its idle timeout is rejected (a family must not
        // expire before an unused token would).
        let err = Config::from_toml_str(
            "[oidc]\nrefresh_idle_ttl_secs = 7200\nrefresh_max_lifetime_secs = 3600\n",
            "ironauth.toml",
        )
        .expect_err("cap below idle");
        assert!(
            err.to_string().contains("refresh_max_lifetime_secs"),
            "{err}"
        );

        // A rotation threshold above 100 percent is rejected.
        let err = Config::from_toml_str(
            "[oidc]\nrefresh_rotation_threshold_percent = 101\n",
            "ironauth.toml",
        )
        .expect_err("threshold over 100");
        assert!(
            err.to_string()
                .contains("refresh_rotation_threshold_percent"),
            "{err}"
        );

        // A rotation grace above the lifetime ceiling is rejected.
        let over = format!(
            "[oidc]\nrefresh_rotation_grace_secs = {}\n",
            OIDC_MAX_LIFETIME_SECS + 1
        );
        let err = Config::from_toml_str(&over, "ironauth.toml").expect_err("grace over cap");
        assert!(
            err.to_string().contains("refresh_rotation_grace_secs"),
            "{err}"
        );

        // A remembered-consent TTL above its ceiling is rejected.
        let over = format!(
            "[oidc]\nremembered_consent_ttl_secs = {}\n",
            OIDC_MAX_REMEMBERED_CONSENT_TTL_SECS + 1
        );
        let err = Config::from_toml_str(&over, "ironauth.toml").expect_err("remembered over cap");
        assert!(
            err.to_string().contains("remembered_consent_ttl_secs"),
            "{err}"
        );
    }

    #[test]
    fn oidc_legacy_response_types_and_form_post_parse_and_default_off() {
        // Issue #17: the legacy response types and form_post are opt-in per
        // environment. Enabling each is an explicit boolean, mirroring the other
        // promotable OIDC toggles.
        let input = "[oidc]\nenable_response_type_id_token = true\n\
                     enable_response_type_code_id_token = true\n\
                     enable_response_type_none = true\n\
                     enable_response_mode_form_post = true\n";
        let config = Config::from_toml_str(input, "<inline>")
            .expect("valid")
            .config;
        assert!(config.oidc.enable_response_type_id_token);
        assert!(config.oidc.enable_response_type_code_id_token);
        assert!(config.oidc.enable_response_type_none);
        assert!(config.oidc.enable_response_mode_form_post);

        // A misspelled toggle aborts with the accepted fields (strict parsing).
        let err = Config::from_toml_str(
            "[oidc]\nenable_response_type_idtoken = true\n",
            "ironauth.toml",
        )
        .expect_err("unknown oidc key");
        let msg = err.to_string();
        assert!(msg.contains("enable_response_type_idtoken"), "{msg}");
        assert!(msg.contains("enable_response_type_id_token"), "{msg}");
    }

    #[test]
    fn oidc_default_access_token_format_parses_both_values_and_rejects_unknown() {
        // Issue #29: the environment default access-token format is a snake_case
        // enum with two members. Both parse; an unknown value is a strict error.
        let opaque = Config::from_toml_str(
            "[oidc]\ndefault_access_token_format = \"opaque\"\n",
            "<inline>",
        )
        .expect("valid")
        .config;
        assert_eq!(opaque.oidc.default_access_token_format, TokenFormat::Opaque);

        let at_jwt = Config::from_toml_str(
            "[oidc]\ndefault_access_token_format = \"at_jwt\"\n",
            "<inline>",
        )
        .expect("valid")
        .config;
        assert_eq!(at_jwt.oidc.default_access_token_format, TokenFormat::AtJwt);

        // A misspelled or unsupported value aborts with the accepted alternatives.
        let err = Config::from_toml_str(
            "[oidc]\ndefault_access_token_format = \"jwt\"\n",
            "ironauth.toml",
        )
        .expect_err("unknown token format");
        let msg = err.to_string();
        assert!(msg.contains("at_jwt") && msg.contains("opaque"), "{msg}");
    }

    #[test]
    fn oidc_client_credentials_default_audience_parses_both_values_and_rejects_unknown() {
        // Issue #23: the client-credentials default audience is a snake_case enum
        // with two members; the default is client_id. Both parse; unknown is strict.
        assert_eq!(
            OidcConfig::default().client_credentials_default_audience,
            ClientCredentialsAudience::ClientId,
        );
        let issuer = Config::from_toml_str(
            "[oidc]\nclient_credentials_default_audience = \"issuer\"\n",
            "<inline>",
        )
        .expect("valid")
        .config;
        assert_eq!(
            issuer.oidc.client_credentials_default_audience,
            ClientCredentialsAudience::Issuer,
        );
        let client_id = Config::from_toml_str(
            "[oidc]\nclient_credentials_default_audience = \"client_id\"\n",
            "<inline>",
        )
        .expect("valid")
        .config;
        assert_eq!(
            client_id.oidc.client_credentials_default_audience,
            ClientCredentialsAudience::ClientId,
        );
        // A misspelled value aborts with a strict error.
        let err = Config::from_toml_str(
            "[oidc]\nclient_credentials_default_audience = \"aud\"\n",
            "ironauth.toml",
        )
        .expect_err("unknown audience mode");
        assert!(err.to_string().contains("client_id"), "{err}");
    }

    #[test]
    fn oidc_userinfo_placement_and_cors_origins_parse() {
        // The conform override and the registered SPA origins parse from TOML.
        let input = "[oidc]\nconform_id_token_claims = true\n\
                     userinfo_cors_origins = [\"https://spa.example\", \"https://app.test:8443\"]\n";
        let config = Config::from_toml_str(input, "<inline>")
            .expect("valid")
            .config;
        assert!(config.oidc.conform_id_token_claims);
        assert_eq!(
            config.oidc.userinfo_cors_origins,
            vec![
                "https://spa.example".to_owned(),
                "https://app.test:8443".to_owned()
            ]
        );
    }

    #[test]
    fn oidc_par_settings_default_parse_and_validate() {
        // Issue #27 (RFC 9126): PAR is optional by default, with a short default
        // request_uri lifetime.
        let default = OidcConfig::default();
        assert!(
            !default.require_pushed_authorization_requests,
            "PAR is optional by default"
        );
        assert_eq!(
            default.par_ttl_secs, 60,
            "the default request_uri TTL is 60s"
        );

        // The environment-wide require switch and a bounded, in-range TTL parse.
        let config = Config::from_toml_str(
            "[oidc]\nrequire_pushed_authorization_requests = true\npar_ttl_secs = 120\n",
            "<inline>",
        )
        .expect("valid")
        .config;
        assert!(config.oidc.require_pushed_authorization_requests);
        assert_eq!(config.oidc.par_ttl_secs, 120);

        // A zero TTL (born expired) is rejected; a TTL above the ceiling is rejected.
        let err = Config::from_toml_str("[oidc]\npar_ttl_secs = 0\n", "ironauth.toml")
            .expect_err("zero par ttl");
        assert!(err.to_string().contains("par_ttl_secs"), "{err}");
        let over = format!("[oidc]\npar_ttl_secs = {}\n", OIDC_MAX_PAR_TTL_SECS + 1);
        let err = Config::from_toml_str(&over, "ironauth.toml").expect_err("par ttl over cap");
        assert!(err.to_string().contains("par_ttl_secs"), "{err}");

        // The boundary values are accepted.
        for ok in [1, OIDC_MAX_PAR_TTL_SECS] {
            let input = format!("[oidc]\npar_ttl_secs = {ok}\n");
            assert_eq!(
                Config::from_toml_str(&input, "<inline>")
                    .expect("boundary valid")
                    .config
                    .oidc
                    .par_ttl_secs,
                ok
            );
        }
    }

    #[test]
    fn oidc_client_assertion_audience_and_skew_parse_and_validate() {
        // Issue #25: the shared audience knob is a snake_case enum with two members;
        // the skew is bounded above (0 is valid, over the ceiling aborts).
        let default = OidcConfig::default();
        assert_eq!(
            default.client_assertion_audience,
            ClientAssertionAudience::TokenEndpointOrIssuer,
            "the interoperable audience is the default"
        );
        assert_eq!(default.client_assertion_max_skew_secs, 60);

        let strict = Config::from_toml_str(
            "[oidc]\nclient_assertion_audience = \"issuer_only\"\n\
             client_assertion_max_skew_secs = 0\n",
            "<inline>",
        )
        .expect("valid")
        .config;
        assert_eq!(
            strict.oidc.client_assertion_audience,
            ClientAssertionAudience::IssuerOnly
        );
        assert_eq!(strict.oidc.client_assertion_max_skew_secs, 0);

        // An unknown audience aborts with the accepted alternatives.
        let err = Config::from_toml_str(
            "[oidc]\nclient_assertion_audience = \"whatever\"\n",
            "ironauth.toml",
        )
        .expect_err("unknown audience");
        assert!(
            err.to_string().contains("token_endpoint_or_issuer"),
            "{err}"
        );

        // A skew above the ceiling aborts.
        let err = Config::from_toml_str(
            &format!(
                "[oidc]\nclient_assertion_max_skew_secs = {}\n",
                OIDC_MAX_CLIENT_ASSERTION_SKEW_SECS + 1
            ),
            "ironauth.toml",
        )
        .expect_err("skew over ceiling");
        assert!(
            err.to_string().contains("client_assertion_max_skew_secs"),
            "{err}"
        );
    }

    #[test]
    fn proxy_and_telemetry_sections_parse_and_reject_unknown_keys() {
        let input = "[proxy]\ntrusted_hops = 2\ntrust_forwarded = true\n\
                     [telemetry]\nlog_format = \"pretty\"\notlp_endpoint = \"http://c:4317\"\n";
        let config = Config::from_toml_str(input, "<inline>")
            .expect("valid")
            .config;
        assert_eq!(config.proxy.trusted_hops, 2);
        assert!(config.proxy.trust_forwarded);
        assert_eq!(config.telemetry.log_format, LogFormat::Pretty);
        assert_eq!(
            config.telemetry.otlp_endpoint.as_deref(),
            Some("http://c:4317")
        );

        let err = Config::from_toml_str("[proxy]\nhops = 1\n", "ironauth.toml")
            .expect_err("unknown proxy key");
        let msg = err.to_string();
        assert!(msg.contains("hops"), "{msg}");
        assert!(msg.contains("trusted_hops"), "{msg}");

        let err = Config::from_toml_str("[telemetry]\nlog_format = \"yaml\"\n", "ironauth.toml")
            .expect_err("unknown log format");
        let msg = err.to_string();
        assert!(msg.contains("yaml"), "{msg}");
        assert!(msg.contains("json") && msg.contains("pretty"), "{msg}");
    }

    #[test]
    fn unknown_root_key_aborts_with_position_and_expected_fields() {
        let input = "dev_mode = true\nservre = { bind = \"0.0.0.0:1\" }\n";
        let err = Config::from_toml_str(input, "ironauth.toml").expect_err("unknown key");
        let msg = err.to_string();
        assert!(msg.contains("ironauth.toml:2:1"), "{msg}");
        assert!(msg.contains("servre"), "{msg}");
        // serde's expected-fields list is the did-you-mean.
        assert!(msg.contains("server"), "{msg}");
        assert!(msg.contains("database"), "{msg}");
    }

    #[test]
    fn unknown_nested_key_aborts_with_position() {
        let input = "[server]\nbindd = \"0.0.0.0:1\"\n";
        let err = Config::from_toml_str(input, "ironauth.toml").expect_err("unknown key");
        let msg = err.to_string();
        assert!(msg.contains("ironauth.toml:2:1"), "{msg}");
        assert!(msg.contains("bindd"), "{msg}");
        assert!(msg.contains("bind"), "{msg}");
    }

    #[test]
    fn literal_secret_warns_outside_dev_mode_only() {
        let input = "[database]\npassword = \"hunter2\"\n";
        let loaded = Config::from_toml_str(input, "<inline>").expect("valid");
        assert_eq!(
            loaded.warnings,
            vec![Warning::LiteralSecret {
                key: "database.password".to_owned()
            }]
        );
        let text = loaded.warnings[0].to_string();
        assert!(text.contains("database.password"), "{text}");
        assert!(!text.contains("hunter2"), "leak: {text}");

        let dev_input = format!("dev_mode = true\n{input}");
        let loaded = Config::from_toml_str(&dev_input, "<inline>").expect("valid");
        assert!(loaded.warnings.is_empty());

        let indirect = "[database]\npassword = { env = \"PGPASSWORD\" }\n";
        let loaded = Config::from_toml_str(indirect, "<inline>").expect("valid");
        assert!(loaded.warnings.is_empty());
    }

    #[test]
    fn invalid_dsn_aborts_with_position_and_no_password_echo() {
        let input = "[database]\nurl = \"mysql://app:supersecret@db/x\"\n";
        let err = Config::from_toml_str(input, "ironauth.toml").expect_err("bad scheme");
        let msg = err.to_string();
        assert!(msg.contains("unknown scheme 'mysql'"), "{msg}");
        assert!(msg.contains("ironauth.toml:2"), "{msg}");
        assert!(!msg.contains("supersecret"), "leak: {msg}");
    }

    #[test]
    fn config_debug_and_dumps_redact_secrets() {
        let input = "[database]\nurl = \"postgres://app:dbpw@db:5432/x\"\npassword = \"hunter2\"\n";
        let config = Config::from_toml_str(input, "<inline>")
            .expect("valid")
            .config;
        let debug = format!("{config:?}");
        let dump = toml::to_string(&config).expect("dumps");
        for rendered in [debug, dump] {
            assert!(!rendered.contains("hunter2"), "leak: {rendered}");
            assert!(!rendered.contains("dbpw"), "leak: {rendered}");
            assert!(rendered.contains(REDACTED), "{rendered}");
        }
    }

    #[test]
    fn default_dsn_parses_by_construction() {
        // Guards the expect() in DatabaseConfig::default.
        let config = DatabaseConfig::default();
        assert_eq!(config.url.scheme(), "postgres");
    }

    #[test]
    fn line_and_column_are_one_based_and_char_counted() {
        assert_eq!(line_and_column("abc", 0), (1, 1));
        assert_eq!(line_and_column("abc\ndef", 4), (2, 1));
        assert_eq!(line_and_column("abc\ndef", 6), (2, 3));
    }

    #[test]
    fn json_schema_is_strict_and_described() {
        let schema = Config::json_schema();
        let value = serde_json::to_value(&schema).expect("schema serializes");
        // Strictness must reach the schema: unknown keys invalid at the root
        // and in every section definition.
        assert_eq!(value["additionalProperties"], serde_json::json!(false));
        for section in [
            "ServerConfig",
            "ProxyConfig",
            "TelemetryConfig",
            "DatabaseConfig",
            "AdminConfig",
            "OidcConfig",
            "FeatureToggle",
        ] {
            assert_eq!(
                value["$defs"][section]["additionalProperties"],
                serde_json::json!(false),
                "{section} must reject unknown keys"
            );
        }
        // Doc comments must flow into the schema as descriptions, and serde
        // defaults must surface as schema defaults.
        let bind = &value["$defs"]["ServerConfig"]["properties"]["bind"];
        assert!(
            bind["description"].as_str().is_some_and(|d| !d.is_empty()),
            "doc comments must flow into the schema: {bind}"
        );
        assert_eq!(bind["default"], serde_json::json!("127.0.0.1:8443"));
    }
}
