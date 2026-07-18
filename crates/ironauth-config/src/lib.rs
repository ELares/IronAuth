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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use dsn::{Dsn, DsnError, KNOWN_SCHEMES};
pub use features::{
    CUSTOM_DOMAINS_ACME_FEATURE, CUSTOM_DOMAINS_ACME_VERSION, FEDCM_FEATURE, FEDCM_VERSION,
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

    /// Flexible-identifier settings (issue #54): the per-environment uniqueness
    /// policy for typed login identifiers. Safe default: environment-wide uniqueness.
    pub identifiers: IdentifiersConfig,

    /// Per-tenant and per-environment quota fairness settings (issue #50). The
    /// operator-plane noisy-neighbor guard: nested token buckets that keep one
    /// tenant or environment from starving another. Safe defaults, fully tunable
    /// (the tunability principle); a burst of 0 for a dimension means unlimited
    /// (the single-tenant self-hoster posture).
    pub quota: QuotaConfig,

    /// Password-hashing settings (issue #62): the Argon2id parameters for newly
    /// set passwords and the dedicated, admission-controlled hashing worker pool.
    /// Argon2id at the OWASP defaults, off the async request threads, with
    /// per-tenant fair-share admission reusing the `[quota]` layer so one tenant's
    /// credential-stuffing storm degrades only that tenant.
    pub password_hashing: PasswordHashingConfig,

    /// Breached-password screening and NIST SP 800-63B-4 password policy (issue #63).
    /// The shipped defaults are the modern 63B-4 posture (length primacy, no composition,
    /// no forced rotation, Unicode accepted, screening MANDATORY over the free HIBP
    /// k-anonymity provider). Legacy compliance regimes are per-tenant SETTINGS here, each
    /// annotated to the admin surface as a deviation from 63B-4.
    pub password_policy: PasswordPolicyConfig,

    /// Bring-your-own-key (BYOK) customer-managed encryption settings (issue #49).
    /// EXPERIMENTAL and DEFAULT-OFF: an opt-in rung on the isolation ladder that
    /// lets a customer-managed root key (in an external KMS/HSM, or a
    /// customer-supplied key) wrap a tenant's key-encryption key, so the customer
    /// controls the root of the tenant's encryption and revoking it crypto-shreds
    /// the tenant. Off by default; the external-KMS path is owner/infra-gated.
    pub byok: ByokConfig,

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

/// Which BYOK key-management driver backs a customer root key (issue #49). A
/// closed set matching the `ironauth-kms` driver interface. `local` is a
/// customer-SUPPLIED key held in process (the simplest BYOK form, no external
/// service); the other four reach an external KMS/HSM and are owner/infra-gated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ByokProvider {
    /// An in-process customer-supplied root key (the default when BYOK is enabled;
    /// no external service).
    #[default]
    Local,
    /// AWS Key Management Service (external, owner/infra-gated).
    Aws,
    /// Google Cloud KMS (external, owner/infra-gated).
    Gcp,
    /// Azure Key Vault (external, owner/infra-gated).
    Azure,
    /// `HashiCorp` Vault transit (external, owner/infra-gated).
    Vault,
}

/// Bring-your-own-key (BYOK) customer-managed encryption settings (issue #49).
///
/// EXPERIMENTAL and DEFAULT-OFF. When `enabled` is false (the default) no BYOK
/// path is reachable and the platform envelope keys behave exactly as before. When
/// enabled, a customer-managed root (selected by `provider`) wraps a tenant's
/// key-encryption key. The external-KMS `endpoint` is outbound and rides the
/// SSRF-hardened fetcher; its live use is owner/infra-gated.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ByokConfig {
    /// Whether BYOK is enabled at all. False (the default) leaves every BYOK path
    /// unreachable; enabling it is an explicit, exploratory opt-in.
    pub enabled: bool,

    /// Which key-management driver backs the customer root when BYOK is enabled.
    /// Defaults to `local` (a customer-supplied in-process root); the external
    /// drivers are owner/infra-gated.
    pub provider: ByokProvider,

    /// The external KMS/HSM endpoint URL for an external `provider` (an https URL).
    /// Outbound and routed through the SSRF-hardened fetcher, so a loopback or
    /// otherwise internal endpoint is refused. Unset for the `local` provider or
    /// when BYOK is disabled.
    pub endpoint: Option<String>,
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

/// The per-environment login-identifier UNIQUENESS mode (issue #54).
///
/// Uniqueness is a POLICY, not a fixed schema rule: a greenfield identity model
/// bakes scoped uniqueness in on day one rather than retrofitting it later (Zitadel
/// #9535, Auth0's multi-year path to non-unique emails). The safe default
/// (`environment_wide`) gives one canonical identifier at most one user per
/// (tenant, environment). `org_scoped` makes an identifier unique only within an
/// organization (meaningful once M10 org membership ships; a membership-free user
/// falls back to the environment scope). `non_unique` allows several accounts to
/// share one identifier (identifier-first login still resolves deterministically:
/// the M7 factor step disambiguates). Changing the mode on a POPULATED environment
/// requires a validation pass that reports post-canonicalization collisions before
/// the change applies. This is a promotable per-environment setting in spirit; the
/// process value is the deployment default until per-environment overrides ride the
/// M5 promotion pipeline.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierUniqueness {
    /// A canonical identifier maps to at most one user per (tenant, environment).
    /// The safe default.
    #[default]
    EnvironmentWide,
    /// A canonical identifier is unique within an organization; users in different
    /// orgs may share one. Falls back to the environment scope for a user with no
    /// org membership.
    OrgScoped,
    /// Multiple users may share one canonical identifier.
    NonUnique,
}

/// Flexible-identifier settings (issue #54): the per-environment uniqueness policy
/// for typed login identifiers (email, username, phone).
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct IdentifiersConfig {
    /// The uniqueness mode for login identifiers. Safe default: environment-wide.
    pub uniqueness: IdentifierUniqueness,
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

    /// The platform envelope master key (issue #48): a high-entropy secret from
    /// which the per-tenant key hierarchy that seals classified PII columns
    /// (login handles, standard claims) at rest is derived. Supply it out of
    /// band (`{ env = "IRONAUTH_MASTER_KEY" }` or `{ file = "..." }`); a stable
    /// value is required across restarts, because every wrapped tenant key
    /// depends on it. Unset leaves the encrypted-PII paths (registration, login,
    /// `UserInfo`) failing closed rather than storing plaintext; a production
    /// deployment must set it.
    pub master_key: Option<Secret>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: Dsn::parse("postgres://ironauth@localhost:5432/ironauth")
                .expect("default DSN is valid by construction (covered by test)"),
            password: None,
            master_key: None,
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

    /// The operator's configured data-residency region set (issue #46): the
    /// allowed values for a tenant's `home_region` and (later) a per-environment
    /// region pin. A tenant-create request that names a `home_region` outside this
    /// set is rejected. Empty (the default) means the operator has configured no
    /// region set, so residency pinning is unavailable and any `home_region` on a
    /// create is refused; a deployment that wants residency pins lists its regions
    /// here (for example `["eu-west", "us-east"]`). Nothing routes or replicates by
    /// region yet; this only governs which values are recordable.
    #[serde(default)]
    pub allowed_regions: Vec<String>,

    /// The tenant-offboarding retention window in seconds (issue #46): the grace
    /// period during which a soft-deleted (offboarded) tenant can be RESTORED with no
    /// data loss, after which the terminal hard deletion (crypto-shred) is due.
    /// Tunable, with a safe default of 30 days (`2_592_000` seconds): long enough that
    /// an accidental offboarding is recoverable, so the erasure is never a one-way
    /// surprise. A restore is refused once the window elapses; a hard delete is
    /// refused until it does.
    #[serde(default = "default_offboarding_retention_secs")]
    pub offboarding_retention_secs: u64,

    /// Enable the OUTBOUND lazy-migration credential-verification endpoint (issue
    /// #58): the mirror of IronAuth's inbound migration hook, so a SUCCESSOR system
    /// can migrate away from IronAuth exactly as easily as IronAuth migrates off an
    /// incumbent. When enabled, `POST .../migration/verify-credential` lets a
    /// successor present a user's identifier plus password during its OWN lazy
    /// migration and receive a verdict (and, on success, an optional profile), so it
    /// upgrades users to its native store on their next login without a password
    /// reset. The SAFE default (`false`) leaves the endpoint returning a uniform
    /// not-found: the exit-friendliness covenant makes the export SELF-SERVE, but
    /// exposing a live credential-oracle to a third party is an explicit,
    /// per-deployment opt-in. This is a promotable per-environment setting in spirit
    /// (like the OIDC toggles); the process value is the deployment default until
    /// per-environment overrides ride the M5 promotion pipeline.
    pub outbound_verification_enabled: bool,

    /// The shared bearer token a successor system presents to the OUTBOUND
    /// lazy-migration verification endpoint (issue #58), as
    /// `Authorization: Bearer <token>`. It is a DISTINCT credential from the
    /// management operator token and any management key: it authorizes ONLY the
    /// credential-verification endpoint, never any other management surface. Unset
    /// (the default) leaves the endpoint unauthorized even when
    /// `outbound_verification_enabled` is true (fail closed: no token, no access).
    /// Use the `file`/`env` secret indirection, never a literal, outside dev mode.
    pub outbound_verification_token: Option<Secret>,

    /// The tenant id the OUTBOUND lazy-migration verification endpoint is authorized
    /// for (issue #58). The endpoint is bound to exactly ONE `(tenant, environment)`:
    /// a request whose path scope does not match this tenant AND
    /// `outbound_verification_environment` is a uniform not-found, so the shared token
    /// can only ever verify credentials in its one configured environment and never
    /// leaks across tenants. Unset (the default) leaves the endpoint bound to no
    /// scope, so it matches nothing and is a uniform not-found even when enabled and
    /// credentialed (fail closed: no scope, no access). A larger per-environment
    /// secret home rides the M5 promotion pipeline; this pins the authorized scope
    /// today so the most sensitive new surface is never deployment-global.
    #[serde(default)]
    pub outbound_verification_tenant: Option<String>,

    /// The environment id the OUTBOUND lazy-migration verification endpoint is
    /// authorized for (issue #58), paired with `outbound_verification_tenant`. Both
    /// must be set and must match the request's path scope, or the endpoint is a
    /// uniform not-found. Unset (the default) is fail closed.
    #[serde(default)]
    pub outbound_verification_environment: Option<String>,

    /// Whether admin sudo mode (session privilege separation) is active on the
    /// management surface (issue #73). OFF by default: it is an exploratory bet, gated
    /// behind a per-environment flag and a graduation decision. When ON, admin READS are
    /// unaffected but a MUTATION requires a RECENT re-authentication: the acting
    /// credential must have a recorded elevation whose freshness window has not lapsed,
    /// evaluated the same way step-up (issue #72) evaluates a max-auth-age window. A
    /// mutation without a fresh elevation returns a structured RFC 9470 challenge
    /// (`insufficient_user_authentication`) and executes nothing. The enforced guarantee
    /// is that the elevation is SERVER-RECORDED and never CLIENT-ASSERTED: it derives only
    /// from a server-written re-auth event, never from a client-supplied header or flag, so
    /// a forged header cannot elevate. CAVEAT: because the admin plane authenticates via a
    /// single non-interactive bearer credential with NO second factor, sudo mode does NOT
    /// yet defeat a fully-stolen admin bearer, which can call the elevate endpoint itself
    /// and then mutate. It bounds a header-forgery or replay path, not a stolen bearer.
    /// Binding elevation to a distinct interactive re-auth factor (an operator passkey) is
    /// a documented graduation step; the freshness seam is factored so end-user
    /// application sessions, which have that factor split, get the full guarantee. When
    /// OFF, the admin surface behaves exactly as before (no freshness gate). Independent of
    /// every other flag.
    #[serde(default)]
    pub sudo_mode_enabled: bool,

    /// The admin sudo re-authentication freshness window, in seconds (issue #73): how
    /// long a recorded elevation authorizes admin mutations before a fresh
    /// re-authentication is required. Only consulted when `sudo_mode_enabled` is true.
    /// The default (600) is ten minutes, the GitHub-sudo-mode convention. A tunable with
    /// a safe default; a shorter window trades operator friction for a tighter blast
    /// radius on a stolen credential.
    #[serde(default = "default_sudo_mode_window_secs")]
    pub sudo_mode_window_secs: u64,
}

/// The default admin sudo re-authentication freshness window: ten minutes (issue #73).
fn default_sudo_mode_window_secs() -> u64 {
    600
}

/// The default tenant-offboarding retention window: 30 days in seconds (issue #46).
fn default_offboarding_retention_secs() -> u64 {
    2_592_000
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            bootstrap_operator_token: None,
            control_database_url: None,
            max_page_size: 200,
            default_page_size: 50,
            allowed_regions: Vec::new(),
            offboarding_retention_secs: default_offboarding_retention_secs(),
            outbound_verification_enabled: false,
            outbound_verification_token: None,
            outbound_verification_tenant: None,
            outbound_verification_environment: None,
            sudo_mode_enabled: false,
            sudo_mode_window_secs: default_sudo_mode_window_secs(),
        }
    }
}

/// The largest an authorization-code or access-token lifetime may be configured
/// to, in seconds. A code is a short-lived, single-use bearer credential and an
/// access token a bearer credential; a lifetime beyond one day is almost always
/// a misconfiguration, so config load rejects it (fail fast rather than mint a
/// long-lived code). The safe defaults are far below this ceiling.
pub const OIDC_MAX_LIFETIME_SECS: u64 = 86_400;

/// The largest the account-recovery DELAY window may be configured to, in seconds
/// (issue #81): 30 days. The delay is a security feature (a security-reducing recovery
/// is held, notified, and cancellable throughout), but an unbounded hold would strand a
/// legitimate user forever, so config load caps it.
pub const RECOVERY_MAX_DELAY_SECS: u64 = 2_592_000;

/// The FLOOR of the email-OTP / magic-link TTL band, in seconds (issue #68): five
/// minutes. NIST SP 800-63B recommends a short out-of-band code lifetime; a shorter
/// window than this frustrates a legitimate user retrieving the code from their inbox.
pub const OIDC_EMAIL_OTP_MIN_TTL_SECS: u64 = 300;
/// The CEILING of the email-OTP TTL band, in seconds (issue #68): ten minutes. A typed
/// low-entropy code must not linger; a per-tenant value sits inside 300..=600.
pub const OIDC_EMAIL_OTP_MAX_TTL_SECS: u64 = 600;
/// The CEILING of the magic-link TTL band, in seconds (issue #68): one hour. A
/// high-entropy single-use link may live a little longer than a typed code, but is still
/// short-lived; a per-tenant value sits inside 300..=3600.
pub const OIDC_MAGIC_LINK_MAX_TTL_SECS: u64 = 3_600;

/// The FLOOR of the remembered-device max-age band, in seconds (issue #71): one hour. A
/// device remembered for less than this is not worth the state; the real value sits far
/// higher, up to the NIST SP 800-63B reauthentication ceiling.
pub const OIDC_TRUSTED_DEVICE_MIN_MAX_AGE_SECS: u64 = 3_600;
/// The CEILING of the remembered-device max-age band, in seconds (issue #71): thirty
/// days, the NIST SP 800-63B reauthentication ceiling. Trust must be re-established at
/// least this often, so a misconfiguration cannot extend a remembered device indefinitely.
pub const OIDC_TRUSTED_DEVICE_MAX_MAX_AGE_SECS: u64 = 2_592_000;
/// The FLOOR of the remembered-device idle window, in seconds (issue #71): one hour. The
/// idle window must be at least this and never wider than the absolute max age.
pub const OIDC_TRUSTED_DEVICE_MIN_IDLE_SECS: u64 = 3_600;

// The canonical `acr` rungs (weakest to strongest, issues #66/#71/#72). These MIRROR the
// OIDC step-up ladder (`ironauth_oidc::step_up::default_acr_order`, derived from the fixed
// `AuthMethod::ALL`); a pinning test in the oidc crate asserts the two stay identical, so a
// new rung added to the ladder cannot silently drift out of the shipped config default.
const OIDC_ACR_PWD: &str = "urn:ironauth:acr:pwd";
// `mfa_remembered` (issue #71) sits STRICTLY between `pwd` and `mfa`: a remembered device
// outranks a bare password but must never satisfy a genuine `mfa` floor.
const OIDC_ACR_MFA_REMEMBERED: &str = "urn:ironauth:acr:mfa_remembered";
const OIDC_ACR_MFA: &str = "urn:ironauth:acr:mfa";
const OIDC_ACR_PHR: &str = "phr";
const OIDC_ACR_PHRH: &str = "phrh";
const OIDC_ACR_ATTESTED: &str = "urn:ironauth:acr:attested_passkey";

/// The canonical `acr` order (weakest to strongest, issue #72): the single source of truth
/// the shipped [`OidcConfig::acr_order`] default and the boot validation both derive from,
/// kept identical to `ironauth_oidc::step_up::default_acr_order` by a pinning test. Includes
/// `mfa_remembered` (issue #71) between `pwd` and `mfa`, and `attested_passkey` (issue #66)
/// at the top, so neither is left unranked under the default configuration.
pub const OIDC_DEFAULT_ACR_ORDER: &[&str] = &[
    OIDC_ACR_PWD,
    OIDC_ACR_MFA_REMEMBERED,
    OIDC_ACR_MFA,
    OIDC_ACR_PHR,
    OIDC_ACR_PHRH,
    OIDC_ACR_ATTESTED,
];

/// The FLOOR of the SMS-OTP TTL band, in seconds (issue #70): two minutes. An SMS
/// arrives quickly, so a short window is both usable and tighter than the email band;
/// a shorter lifetime than this risks expiring before a slow carrier delivers the text.
pub const OIDC_SMS_OTP_MIN_TTL_SECS: u64 = 120;
/// The CEILING of the SMS-OTP TTL band, in seconds (issue #70): ten minutes. SMS is a
/// restricted authenticator (NIST SP 800-63B-4), so its low-entropy code must not
/// linger; a per-tenant value sits inside 120..=600.
pub const OIDC_SMS_OTP_MAX_TTL_SECS: u64 = 600;

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

    /// The INBOUND lazy-migration hook (issue #56): verify a first login against a
    /// legacy credential store over the SSRF-hardened outbound fetcher and, on success,
    /// create the user locally with a native Argon2id hash so subsequent logins never
    /// call the hook. Disabled by default; the endpoint and its authentication secret
    /// are environment-scoped config (see [`LazyMigrationConfig`]). This is a promotable
    /// per-environment setting in spirit; the process value is the deployment default
    /// until per-environment overrides ride the M5 promotion pipeline.
    pub lazy_migration: LazyMigrationConfig,

    /// Generic OIDC UPSTREAM federation (issue #75, PR B): turn a declarative connector
    /// into an inbound federated login with zero per-provider code. OFF by default (the
    /// `/federation` routes stay a uniform not-found), so an existing deployment is
    /// unaffected. When enabled, the boot path builds the federation runtime (its own
    /// SSRF-hardened fetcher plus the discovery / JWKS cache TTLs). The connectors
    /// themselves are per-connector STORED data, not config. PRIVACY NOTE (issue #76): a
    /// connector may forward the downstream `login_hint` to its upstream provider, which
    /// DISCLOSES an end-user identifier (typically an email) to that upstream; a connector
    /// that must not leak identifiers sets its `passthrough.login_hint = false` (per-connector
    /// stored data) to suppress it. See [`FederationConfig`].
    pub federation: FederationConfig,

    /// The IdP-side FedCM surface settings (issue #83, EXPLORATORY): the single
    /// designated `(tenant, environment)` this origin exposes over FedCM plus the
    /// branding metadata the browser account chooser renders. This section only
    /// SHAPES the FedCM documents; it can never ARM the endpoints. The arming switch
    /// is the `fedcm` experimental feature flag, resolved to a state-builder bool at
    /// boot (never an `[oidc]` toggle), so a designated env configured here still
    /// answers a uniform 404 on every FedCM route until the feature is enabled AND
    /// acknowledged. See [`FedcmConfig`].
    pub fedcm: FedcmConfig,

    /// Credential-abuse regulation and anti-enumeration posture (issue #64): the
    /// risk-based escalating throttle, the durable ban policy, and the closed-
    /// registration switch. The default posture is account-DoS-safe (no hard lockout).
    /// See [`RegulationConfig`].
    pub regulation: RegulationConfig,

    /// The minimal risk engine (issue #79): the explainable signals, the LOW/MED/HIGH
    /// scoring, the block/challenge/notify action vocabulary, the risk-driven step-up
    /// threshold, and the new-device notification. OFF by default (fully inert). See
    /// [`RiskConfig`].
    pub risk: RiskConfig,

    /// The registration abuse defenses (issue #80): the invisible self-contained
    /// proof-of-work challenge (the default, with ZERO third-party calls; Turnstile and
    /// reCAPTCHA are optional adapters), the disposable / low-reputation email defense,
    /// and the waitlist gate. All OFF by default (fully inert). See
    /// [`RegistrationAbuseConfig`].
    pub registration_abuse: RegistrationAbuseConfig,

    /// Whether the WebAuthn passkey ceremony endpoints are mounted and the hosted
    /// login page offers conditional-UI passkey sign-in (issue #65). On by default:
    /// passkeys are the headline primary credential for the platform. When on,
    /// discovery advertises the ceremony endpoints and the passkey `phr`/`phrh`
    /// ACRs are achievable.
    pub webauthn_enabled: bool,

    /// The per-environment WebAuthn Relying Party ID (issue #65). WebAuthn scopes a
    /// credential to this registrable-domain identifier. When unset, it is DERIVED
    /// from the serving origin's host (`server.public_url`), which is the correct
    /// default for a single-origin deployment. When set, it is validated at STARTUP
    /// to be the serving origin's host or a parent (registrable-suffix) domain of
    /// it; a mismatch is a boot-time [`ConfigError::Invalid`], never a per-ceremony
    /// runtime surprise. Different deployments (dev/staging/prod) serve different
    /// origins and so resolve different RP IDs.
    pub webauthn_rp_id: Option<String>,

    /// The additional origins permitted to run a WebAuthn ceremony for this
    /// environment's RP ID (issue #67, WebAuthn Level 3 Related Origin Requests).
    /// The serving origin is ALWAYS permitted implicitly; this list adds the OTHER
    /// origins, including ones on a different registrable domain (a multi-brand or
    /// ccTLD estate: `example.com`, `example.de`, `brand2.com`), which the standard
    /// registrable-suffix rule would reject. The platform publishes these at
    /// `GET /.well-known/webauthn` as `{"origins": [...]}` so a browser that
    /// supports related origin requests (Chrome 128+, Safari 18+) accepts an
    /// assertion from a listed origin against the RP ID. Each entry must be a
    /// well-formed https origin (`scheme://host[:port]`, no path), validated at
    /// STARTUP; a malformed entry is a boot-time [`ConfigError::Invalid`]. Browsers
    /// cap the document at about five distinct registrable labels; the label budget
    /// is ADVISORY (the browser is the real enforcer of its own cap), so a list whose
    /// distinct-label count reaches OR exceeds that budget emits a [`Warning`] rather
    /// than failing startup (an over-budget boot error would wrongly reject a valid
    /// one-brand-many-ccTLD estate, which counts as a single label to a browser).
    /// Unlike the RP ID, a related origin need NOT be a
    /// registrable-suffix of the RP ID (that cross-domain reach is the whole point);
    /// the authorization is this explicit, operator-controlled list served from the
    /// RP ID's own domain. Empty by default (single-origin deployments serve no
    /// related-origins document and 404 the well-known path).
    pub webauthn_related_origins: Vec<String>,

    /// The lifetime, in seconds, of a WebAuthn ceremony challenge (issue #65). A
    /// ceremony not completed within this window has its single-use challenge
    /// expire. The default (300) is a conservative five minutes. Must be at least 1
    /// and at most `OIDC_MAX_LIFETIME_SECS`.
    pub webauthn_challenge_ttl_secs: u64,

    /// Whether a WebAuthn ceremony requires user verification (issue #65). On by
    /// default. Phishing resistance comes from WebAuthn's origin binding, which every
    /// ceremony has, so the `phr`/`phrh` ACRs do NOT require user verification; what
    /// user verification governs is the `amr` (a UV assertion additionally carries
    /// `mfa`, since the possession of the key plus the verification are two factors,
    /// while a user-presence-only assertion does not). Turning it off allows
    /// user-presence-only assertions (not recommended).
    pub webauthn_require_user_verification: bool,

    /// The clone-detection policy when a WebAuthn assertion presents a regressing
    /// signature counter (issue #65): `true` BLOCKS the sign-in, `false` only WARNS
    /// (records the security event and flags the credential but allows the login).
    /// The default (`false`, warn) avoids locking a user out on a benign counter
    /// desync while still surfacing the event; a true per-tenant override rides the
    /// tenant-policy pipeline.
    pub webauthn_clone_detection_block: bool,

    /// The base URL of the FIDO Metadata Service (MDS3) BLOB endpoint the passkey
    /// attestation path fetches the signed authenticator-metadata BLOB from (issue #66,
    /// PR B). When unset (`None`), the built-in default the webauthn/mds3 module carries
    /// (`https://mds3.fidoalliance.org/`) is used; a deployment behind an outbound proxy
    /// or an air-gapped mirror overrides it here. The fetch rides the SSRF-hardened
    /// outbound path, so the value MUST be an `https` URL: a plaintext `http` override is
    /// refused at config load, mirroring the HIBP base-URL rule.
    pub mds3_base_url: Option<String>,

    /// Whether the exploratory WebAuthn Level 3 Signal API surface is active (issue
    /// #73). OFF by default: it is a forward bet on a browser API that only Chrome 132
    /// and later ships, gated behind a per-environment flag and a graduation decision.
    /// When ON, the hosted passkey-management page emits the feature-detected signal
    /// JavaScript (signalUnknownCredential, signalAllAcceptedCredentials,
    /// signalCurrentUserDetails) under a nonce-guarded CSP, and the signal-data endpoint
    /// returns the current accepted-credential id list and user details for the
    /// authenticated subject. When OFF, no signal JavaScript is emitted (no page change)
    /// and the signal-data endpoint is a uniform 404, so an unsupported or
    /// signal-disabled deployment sees no behavior change and no errors. Independent of
    /// every other flag; a browser that does not support the API feature-detects it away
    /// regardless.
    pub webauthn_signal_api_enabled: bool,

    /// Whether conditional-create passkey enrollment is offered after a successful
    /// password login (issue #73), the silent-upgrade half of the Signal API bet. OFF by
    /// default and additionally gated by [`OidcConfig::webauthn_signal_api_enabled`] and
    /// [`OidcConfig::webauthn_enabled`]: even when the signal surface is active, a tenant
    /// opts INTO the silent upgrade separately (the per-tenant policy on/off). When ON,
    /// the hosted page attempts a `mediation: 'conditional'` credential creation for a
    /// user who has no passkey yet, recorded through the STANDARD passkey ceremony
    /// pipeline (issue #65), and NEVER interrupts or fails the login on a
    /// conditional-create failure. Honors the frequency cap below.
    pub webauthn_conditional_create_enabled: bool,

    /// The minimum interval, in seconds, between conditional-create passkey-enrollment
    /// offers to the same browser (issue #73): the per-tenant frequency cap that keeps
    /// the silent upgrade from nagging a user who dismissed it. A prior offer within this
    /// window suppresses the next one. The default (604800) is one week. It is a nag
    /// cap, not a security control, so it degrades safely to a no-op on a browser that
    /// does not retain the last-offer marker.
    pub webauthn_conditional_create_min_interval_secs: u64,

    /// Whether the TOTP second-factor endpoints are mounted (issue #69). On by
    /// default: TOTP is the universal second factor. When off, the enroll/verify/
    /// recovery endpoints fail closed with a uniform 404, so a deployment that does
    /// not want TOTP exposes no surface. Enrollment is always opt-in per user.
    pub totp_enabled: bool,

    /// The issuer label shown in an authenticator app (the `issuer=` parameter of
    /// the `otpauth://` provisioning URI, issue #69). When unset, it is DERIVED at
    /// enrollment from the serving scope, which is the correct default for a
    /// single-brand deployment. A true per-tenant override rides the tenant-policy
    /// pipeline.
    pub totp_issuer: Option<String>,

    /// The TOTP time-step period in seconds (issue #69). The RFC 6238 default (30)
    /// is what every authenticator app assumes; changing it requires an app that
    /// honors the `period=` parameter. Must be in 15..=60.
    pub totp_period_secs: u64,

    /// The number of decimal digits in a TOTP code (issue #69). The
    /// authenticator-app default (6) is the widest compatibility; 7 or 8 are
    /// accepted for apps that honor the `digits=` parameter. Must be in 6..=8.
    pub totp_digits: u32,

    /// The one-sided drift tolerance, in time-steps, a TOTP verification accepts
    /// (issue #69): a code from up to this many steps before or after the current
    /// step verifies, absorbing clock skew between the server and the authenticator.
    /// The default (1) is plus or minus one 30-second period. Bounded to 0..=2 so a
    /// misconfiguration cannot widen the accepted window into a brute-force aid; a
    /// per-tenant override within that bound rides the tenant-policy pipeline.
    pub totp_drift_steps: u32,

    /// The number of one-time recovery codes minted at MFA enrollment (issue #69).
    /// The default (10) sits in the accepted 8..=16 range. A per-tenant override
    /// within that bound rides the tenant-policy pipeline.
    pub totp_recovery_code_count: u32,

    /// Whether MFA is REQUIRED for a user who has no second factor (issue #69). SCOPE
    /// TODAY: this drives the ENROLLMENT PROMPT only. When true, the
    /// factor-orchestration plan (`/account/mfa/plan`) marks a second-factor
    /// enrollment as `enrollment_required` for a user who has none, so the hosted flow
    /// prompts for it after primary authentication. It does NOT today HARD-GATE the
    /// login flow: a full session is still established after the password alone. Hard
    /// login-flow enforcement (challenging the second factor with a partial session
    /// BEFORE a full session is issued) is the core deliverable of the step-up issue
    /// (#72) and lands with it, so do not rely on this to BLOCK a login until #72
    /// ships. Off by default (MFA is offered, not forced); a per-tenant override rides
    /// the tenant-policy pipeline.
    pub mfa_required: bool,

    /// The per-tenant factor order (issue #69): which second-factor kinds are
    /// offered or required first, at both enrollment prompts and login. Entries are
    /// drawn from the closed set `passkey`, `totp`, `password`; the order is
    /// honored by the factor-orchestration plan. The default prefers a
    /// phishing-resistant passkey, then TOTP. Duplicates and unknown kinds are a
    /// boot-time [`ConfigError::Invalid`].
    pub mfa_factor_order: Vec<String>,

    /// The DEPLOYMENT-level `acr` order for step-up comparison (RFC 9470, issue #72),
    /// weakest first. A step-up requirement's `acr` floor is satisfied when the
    /// achieved `acr` is the same value or ranks at least as strong under this
    /// order. The default is the canonical credential-ladder order the provider
    /// advertises ([`OIDC_DEFAULT_ACR_ORDER`]: `pwd`, `mfa_remembered`, `mfa`, `phr`,
    /// `phrh`, `attested_passkey`); a deployment that trusts its factors differently
    /// (for example ranking a verified TOTP above a synced passkey) reorders them here.
    /// An empty list falls back to the default ladder. A non-empty override must be a
    /// PERMUTATION of the known rungs (no unknown value, no duplicate, nothing left
    /// unranked) and must keep `mfa_remembered` STRICTLY below `mfa` (a remembered
    /// device must never satisfy a genuine `mfa` floor); any violation is a boot-time
    /// [`ConfigError::Invalid`].
    /// This is resolved ONCE from configuration and applied across the deployment;
    /// per-(tenant, environment) resolution is a future enhancement, consistent with
    /// how the other per-environment config is handled.
    pub acr_order: Vec<String>,

    /// Whether the remember-device (trusted-device) feature is enabled (issue #71). OFF
    /// by default: a tenant opts INTO letting a completed multi-factor login remember the
    /// device so a subsequent login from it skips the second factor (primary
    /// authentication is still required). When off, no remember-device cookie is ever
    /// issued, a presented one is ignored, and the account device list shows no trusted
    /// devices, so the feature is fully inert. The skip NEVER satisfies a step-up acr
    /// floor (RFC 9470 / issue #72 always overrides a remembered device) or a
    /// passkey/attested credential-class floor; it only satisfies a tenant's baseline
    /// MFA requirement.
    pub trusted_devices_enabled: bool,

    /// Whether the user gets an OPT-IN "remember this device" checkbox (issue #71) or the
    /// TENANT decides. When true (the safer default), the device is remembered only if the
    /// user checks the box after a completed multi-factor login; when false, a completed
    /// multi-factor login always remembers the device (the tenant's choice). Only
    /// consulted when [`OidcConfig::trusted_devices_enabled`] is on.
    pub trusted_device_user_opt_in: bool,

    /// The absolute maximum age of a remembered device, in seconds (issue #71): past it
    /// the device never skips again and must re-prove a second factor. Bounded to
    /// `OIDC_TRUSTED_DEVICE_MIN_MAX_AGE_SECS..=OIDC_TRUSTED_DEVICE_MAX_MAX_AGE_SECS`
    /// (3600..=2592000), so a misconfiguration cannot extend trust indefinitely; the
    /// default (2592000) is the NIST SP 800-63B reauthentication ceiling of 30 days.
    pub trusted_device_max_age_secs: u64,

    /// The idle window of a remembered device, in seconds (issue #71): an unused device
    /// expires after this, while an actively used one lives to the absolute max age. Must
    /// be at least `OIDC_TRUSTED_DEVICE_MIN_IDLE_SECS` (3600) and no greater than
    /// [`OidcConfig::trusted_device_max_age_secs`] (a boot-time [`ConfigError::Invalid`]
    /// otherwise, since an idle window wider than the absolute cap is meaningless); the
    /// default (604800) is seven days.
    pub trusted_device_idle_secs: u64,

    /// Whether a password change or reset INVALIDATES the subject's remembered devices
    /// (issue #71). On by default: a credential change is a strong signal that trust
    /// should be re-established, so every remembered device is revoked server-side. A
    /// tenant that separates device trust from password lifecycle can turn it off. Only
    /// consulted when [`OidcConfig::trusted_devices_enabled`] is on.
    pub trusted_device_revoke_on_password_change: bool,

    /// Whether the email-OTP factor endpoints are mounted (issue #68). On by default:
    /// email OTP is the recovery-of-last-resort factor every product ships. When off,
    /// the send/verify endpoints fail closed with a uniform 404, so a deployment that
    /// does not want email OTP exposes no surface. The actual email transport is a
    /// documented seam (M11 messaging); the default sender performs no delivery.
    pub email_otp_enabled: bool,

    /// The number of decimal digits in an email-OTP code (issue #68). NIST SP 800-63B
    /// out-of-band authenticators require at least a 6-digit code; 7 or 8 add entropy.
    /// Must be in 6..=8.
    pub email_otp_code_digits: u32,

    /// The email-OTP code time-to-live, in seconds (issue #68). NIST recommends a short
    /// window; a per-tenant value inside the 5-10 minute band. The default (600) is ten
    /// minutes. Must be in `OIDC_EMAIL_OTP_MIN_TTL_SECS..=OIDC_EMAIL_OTP_MAX_TTL_SECS`
    /// (300..=600), so a misconfiguration cannot widen the window into a brute-force aid.
    pub email_otp_code_ttl_secs: u64,

    /// The per-code wrong-guess budget (issue #68): a code dies after this many wrong
    /// attempts, so an online brute force against a single low-entropy code is bounded.
    /// The default (5) matches the device user-code budget. Must be at least 1.
    pub email_otp_max_attempts: u32,

    /// Whether the scanner-safe magic-link factor endpoints are mounted (issue #68). On
    /// by default. When off, the confirm/consume endpoints fail closed with a uniform
    /// 404. The link is consumed only by a POST from the confirmation page, so an email
    /// security scanner that prefetches the link never consumes it.
    pub magic_link_enabled: bool,

    /// The magic-link time-to-live, in seconds (issue #68). The default (600) is ten
    /// minutes. Must be in `OIDC_EMAIL_OTP_MIN_TTL_SECS..=OIDC_MAGIC_LINK_MAX_TTL_SECS`
    /// (300..=3600): a link may live a little longer than a typed code because it is
    /// high-entropy and single-use, but is still short-lived.
    pub magic_link_ttl_secs: u64,

    /// Whether the magic-link token rides the URL FRAGMENT rather than the query string
    /// (issue #68), per deployment. When true the confirmation page reads the token from
    /// `location.hash` and submits it, so the token never appears in a server access log
    /// or a scanner's request path. Off by default (the token rides the query string,
    /// still scanner-safe because only a POST consumes it).
    pub magic_link_fragment_mode: bool,

    /// The number of decimal digits in the cross-device magic-link short code (issue
    /// #68): the code printed in the email alongside the link, entered on the originating
    /// device when the link is opened on another device (or the email client breaks the
    /// link). Must be in 6..=8. The default (8) gives a little more entropy than the code
    /// OTP because it is not rate-limited by a per-code attempt counter on entry.
    pub magic_link_short_code_digits: u32,

    /// Whether the guarded SMS-OTP factor endpoints are mounted at all (issue #70). OFF
    /// by default: SMS is the WEAKEST factor IronAuth ships. NIST SP 800-63B-4 classifies
    /// PSTN out-of-band as a RESTRICTED authenticator (SIM swap, SS7 interception, and
    /// industrial SMS-pumping fraud), so it must be a deliberate choice to expose it at
    /// all. This flag is a deployment-level kill switch; even when it is on, SMS OTP stays
    /// unusable in every tenant until that tenant EXPLICITLY enables it AND configures a
    /// country allowlist (there is no allow-all shortcut). See docs/CONFIG.md for the
    /// restricted-authenticator disclosure obligations.
    pub sms_otp_enabled: bool,

    /// The number of decimal digits in an SMS-OTP code (issue #70). Must be in 6..=8,
    /// exactly like the email OTP. The default is 6.
    pub sms_otp_code_digits: u32,

    /// The SMS-OTP code time-to-live, in seconds (issue #70). Must be in
    /// `OIDC_SMS_OTP_MIN_TTL_SECS..=OIDC_SMS_OTP_MAX_TTL_SECS` (120..=600). The default
    /// (300) is five minutes: SMS arrives fast, so the window is tighter than email.
    pub sms_otp_code_ttl_secs: u64,

    /// The per-code wrong-guess budget for an SMS-OTP code (issue #70): the code dies
    /// after this many wrong attempts. Must be at least 1. The default is 5.
    pub sms_otp_max_attempts: u32,

    /// The per-DESTINATION-NUMBER send cap inside `sms_per_number_window_secs` (issue
    /// #70): a hard velocity cap so a single number can never be pumped. Must be at least
    /// 1. The default (3) allows a code plus a couple of resends.
    pub sms_per_number_send_cap: u32,

    /// The fixed window for the per-number send cap, in seconds (issue #70). Must be at
    /// least 1. The default (3600) is one hour.
    pub sms_per_number_window_secs: u64,

    /// The cooldown between two sends to the SAME number, in seconds (issue #70): a
    /// second send inside the cooldown is refused even if the window cap is not yet spent,
    /// which blunts rapid resend abuse. Must be at least 1. The default is 60.
    pub sms_send_cooldown_secs: u64,

    /// The per-(tenant, environment) send cap inside `sms_per_tenant_window_secs` (issue
    /// #70): a tenant-wide velocity ceiling so a compromised account cannot spend the
    /// tenant's whole SMS budget. Must be at least 1. The default is 1000.
    pub sms_per_tenant_send_cap: u32,

    /// The fixed window for the per-tenant send cap, in seconds (issue #70). Must be at
    /// least 1. The default (3600) is one hour.
    pub sms_per_tenant_window_secs: u64,

    /// The per-ROUTE (country/carrier bucket) send cap inside `sms_per_route_window_secs`
    /// (issue #70): a per-route velocity ceiling, the coarse companion to the conversion
    /// auto-throttle. Must be at least 1. The default is 500.
    pub sms_per_route_send_cap: u32,

    /// The fixed window for the per-route send cap, in seconds (issue #70). Must be at
    /// least 1. The default (3600) is one hour.
    pub sms_per_route_window_secs: u64,

    /// Whether pre-send phone scoring is applied (issue #70): the number-type checks
    /// (blocking known virtual / premium ranges from the number itself) and structural
    /// sanity that refuse an obviously abusive destination BEFORE any send. On by default.
    pub sms_phone_scoring_enabled: bool,

    /// The rolling window over which send-to-verify conversion is measured per route,
    /// in seconds (issue #70). Must be at least 1. The default (3600) is one hour.
    pub sms_conversion_window_secs: u64,

    /// The minimum number of sends on a route before its conversion rate is trusted
    /// enough to auto-throttle (issue #70): below this sample size a low rate is noise,
    /// not a signal. Must be at least 1. The default is 20.
    pub sms_conversion_min_samples: u32,

    /// The send-to-verify conversion percentage BELOW which a route's pumping alarm fires
    /// and the route auto-throttles (issue #70): the Twilio Fraud Guard insight is that
    /// healthy routes convert at 60-85 percent and under ~30 percent signals pumping. Must
    /// be in 1..=100. The default is 30.
    pub sms_conversion_alarm_threshold_percent: u32,

    /// How long an auto-throttled route stays throttled, in seconds (issue #70): a route
    /// that trips the conversion alarm is refused for this long WITHOUT operator
    /// intervention, while healthy routes keep sending. Must be at least 1. The default
    /// (3600) is one hour.
    pub sms_route_throttle_secs: u64,

    /// The cooldown between two account-recovery initiations for the SAME account, in
    /// seconds (issue #81): a repeated recovery request inside this window is refused, so
    /// recovery-request spam against one account is rate-limited on the recovery path
    /// independently of the login path. Must be at least 1. The default (300) is five
    /// minutes.
    pub recovery_cooldown_secs: u64,

    /// The delay window a security-REDUCING account recovery is HELD for before it can
    /// complete, in seconds (issue #81): a recovery that would remove or bypass a factor
    /// STRONGER than the one used to recover is held for this long, notified on every
    /// registered channel and cancellable throughout, so an attacker-initiated recovery
    /// can never silently downgrade an account inside the window. Must be between 1 and
    /// 2592000 (30 days). The default (259200) is 72 hours, matching the platform-level
    /// recovery-delay patterns Apple and Google ship.
    pub recovery_delay_secs: u64,
}

impl Default for OidcConfig {
    // A flat field-by-field default for a large config struct; it is one assignment per
    // field with no logic, so the length lint is not meaningful here.
    #[allow(clippy::too_many_lines)]
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
            regulation: RegulationConfig::default(),
            risk: RiskConfig::default(),
            registration_abuse: RegistrationAbuseConfig::default(),
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
            lazy_migration: LazyMigrationConfig::default(),
            federation: FederationConfig::default(),
            fedcm: FedcmConfig::default(),
            webauthn_enabled: true,
            webauthn_rp_id: None,
            webauthn_related_origins: Vec::new(),
            webauthn_challenge_ttl_secs: 300,
            webauthn_require_user_verification: true,
            webauthn_clone_detection_block: false,
            mds3_base_url: None,
            webauthn_signal_api_enabled: false,
            webauthn_conditional_create_enabled: false,
            webauthn_conditional_create_min_interval_secs: 604_800,
            totp_enabled: true,
            totp_issuer: None,
            totp_period_secs: 30,
            totp_digits: 6,
            totp_drift_steps: 1,
            totp_recovery_code_count: 10,
            mfa_required: false,
            mfa_factor_order: vec!["passkey".to_owned(), "totp".to_owned()],
            acr_order: OIDC_DEFAULT_ACR_ORDER
                .iter()
                .map(|acr| (*acr).to_owned())
                .collect(),
            trusted_devices_enabled: false,
            trusted_device_user_opt_in: true,
            trusted_device_max_age_secs: 2_592_000,
            trusted_device_idle_secs: 604_800,
            trusted_device_revoke_on_password_change: true,
            email_otp_enabled: true,
            email_otp_code_digits: 6,
            email_otp_code_ttl_secs: 600,
            email_otp_max_attempts: 5,
            magic_link_enabled: true,
            magic_link_ttl_secs: 600,
            magic_link_fragment_mode: false,
            magic_link_short_code_digits: 8,
            // SMS OTP is OFF by default in every deployment and tenant (issue #70).
            sms_otp_enabled: false,
            sms_otp_code_digits: 6,
            sms_otp_code_ttl_secs: 300,
            sms_otp_max_attempts: 5,
            sms_per_number_send_cap: 3,
            sms_per_number_window_secs: 3600,
            sms_send_cooldown_secs: 60,
            sms_per_tenant_send_cap: 1000,
            sms_per_tenant_window_secs: 3600,
            sms_per_route_send_cap: 500,
            sms_per_route_window_secs: 3600,
            sms_phone_scoring_enabled: true,
            sms_conversion_window_secs: 3600,
            sms_conversion_min_samples: 20,
            sms_conversion_alarm_threshold_percent: 30,
            sms_route_throttle_secs: 3600,
            recovery_cooldown_secs: 300,
            recovery_delay_secs: 259_200,
        }
    }
}

/// The largest per-call timeout the inbound lazy-migration hook may be configured to,
/// in seconds (issue #56). The hook rides the login path, so a slow or dead legacy
/// backend must never stall a login for long: the fetcher aborts a call that exceeds
/// this, the circuit breaker opens on a sustained error/timeout rate, and unmigrated
/// logins then fail fast with the uniform error. A value beyond thirty seconds is
/// almost always a misconfiguration, so config load rejects it.
pub const OIDC_MAX_LAZY_MIGRATION_TIMEOUT_SECS: u64 = 30;

/// The INBOUND lazy-migration hook settings (issue #56).
///
/// When enabled, a login whose canonicalized identifier is UNKNOWN locally verifies the
/// submitted credential against a legacy store through the `endpoint` webhook (delivered
/// over the M1 SSRF-hardened outbound fetcher, HTTPS ONLY, authenticated with `secret`).
/// On a positive verdict the user is created locally with a native Argon2id hash and is
/// MIGRATED by construction, so their next login verifies natively and never calls the
/// hook. Every failure verdict (wrong password, unknown to the legacy store, timeout,
/// breaker open) yields the SAME uniform login failure as a local wrong password, so the
/// hook's existence is not observable to an attacker.
///
/// DISABLED BY DEFAULT (`enabled = false`): pointing the login path at an external
/// credential oracle is an explicit, per-deployment opt-in. Once the tail of stragglers
/// is closed by a standard #55 bulk import, the hook is disabled again by flipping
/// `enabled` back to false (a pure config change).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct LazyMigrationConfig {
    /// Whether the inbound lazy-migration hook is armed. False (the default) leaves the
    /// login path unchanged: an unknown identifier is the uniform failure, no outbound
    /// call is made. When true, `endpoint` MUST be set (config load rejects an enabled
    /// hook with no endpoint) and an unknown-identifier login triggers one hook call.
    pub enabled: bool,

    /// The legacy-store verification webhook URL (an https URL). Outbound and routed
    /// through the SSRF-hardened fetcher, so a loopback or otherwise internal endpoint is
    /// refused exactly like any other blocked destination, and a plaintext `http` target
    /// is refused. Unset when the hook is disabled; REQUIRED (and https) when enabled.
    pub endpoint: Option<String>,

    /// The shared bearer secret presented to the verification webhook as
    /// `Authorization: Bearer <secret>`, so the legacy store can authenticate IronAuth.
    /// Use the `file`/`env` secret indirection, never a literal, outside dev mode. Unset
    /// sends no Authorization header (for a legacy store that authenticates another way,
    /// for example a URL-embedded token); most deployments set it.
    pub secret: Option<Secret>,

    /// The per-call timeout in seconds for one hook verification (issue #56). The
    /// SSRF-hardened fetcher aborts a call that exceeds it, so a slow legacy backend
    /// cannot stall the login path. The default (5) is conservative. Must be at least 1
    /// and at most `OIDC_MAX_LAZY_MIGRATION_TIMEOUT_SECS`.
    pub timeout_secs: u64,

    /// The circuit-breaker failure threshold (issue #56): the number of hook errors and
    /// timeouts within `breaker_window_secs` that trips the breaker OPEN. While open,
    /// unmigrated logins fail fast with the uniform error (no hook call), local users are
    /// unaffected, and after `breaker_cooldown_secs` the breaker half-opens to trial one
    /// call. A verdict (verified or rejected) is a HEALTHY response and never counts
    /// toward the threshold; only transport errors and timeouts do. The default (5) is
    /// conservative. Must be at least 1.
    pub breaker_failure_threshold: u32,

    /// The rolling window in seconds over which `breaker_failure_threshold` errors and
    /// timeouts are counted (issue #56). The default (30) is conservative. Must be at
    /// least 1.
    pub breaker_window_secs: u64,

    /// How long the breaker stays OPEN before it half-opens to trial one call (issue
    /// #56), in seconds. A half-open success closes it; a half-open failure re-opens it
    /// for another cooldown. The default (30) is conservative. Must be at least 1.
    pub breaker_cooldown_secs: u64,
}

impl Default for LazyMigrationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            secret: None,
            timeout_secs: 5,
            breaker_failure_threshold: 5,
            breaker_window_secs: 30,
            breaker_cooldown_secs: 30,
        }
    }
}

/// The largest cache TTL (in seconds) the federation discovery / JWKS caches may be
/// configured to (issue #75). A stale upstream discovery document or key set beyond a day
/// is almost always a misconfiguration (a key rotation should propagate well within it, and
/// a kid-miss triggers an immediate refetch regardless), so config load rejects a larger
/// value.
pub const OIDC_MAX_FEDERATION_TTL_SECS: u64 = 86_400;

/// The posture governing whether a federated login may AUTO-LINK into a pre-existing
/// local account (issue #78). The default is the most conservative one: a federated
/// login NEVER silently merges into a pre-existing local account. An operator opts into
/// verified-to-verified auto-linking per environment.
///
/// This is one structural floor of the guarded linking subsystem: even under
/// `VerifiedToVerified` an auto-link fires only when the FULL trust decision table
/// agrees (a verified local email, an upstream `email_verified`, and a trusted
/// connector), so the "unverified local" and "untrusted upstream" cells are unreachable
/// TWICE OVER (once by this posture, once by the trust table). Under `Off` (the default)
/// no arm of the trust table can return `AutoLink` at all.
///
/// FORK B (issue #78): the intended tenancy grain is PER ENVIRONMENT. In PR 1 this ships
/// as the deployment default; the per-environment override the pure trust decision
/// consumes is threaded by the PR 2 wiring (the decision function takes the posture as an
/// input, so its source is the caller's concern).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AutoLinkPosture {
    /// A federated login NEVER auto-links into a pre-existing local account (the
    /// conservative default). A first-ever federated login still provisions its own
    /// separate account; a collision with an existing local account is surfaced for a
    /// deliberate, fresh-re-auth-gated manual link, never merged automatically.
    #[default]
    Off,
    /// A federated login MAY auto-link into a pre-existing local account, but ONLY when
    /// the full trust decision table agrees (verified local email, upstream
    /// `email_verified` true, and a trusted connector). Any weaker cell falls back to the
    /// manual-link interstitial or a separate account.
    VerifiedToVerified,
}

impl AutoLinkPosture {
    /// The stable wire string (`off`, `verified_to_verified`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AutoLinkPosture::Off => "off",
            AutoLinkPosture::VerifiedToVerified => "verified_to_verified",
        }
    }

    /// Parse the stable wire string (`off`, `verified_to_verified`) back into a posture,
    /// or [`None`] for any other token. Used by the per-environment override read (issue
    /// #78, FORK B): the stored column token round-trips through this, and an
    /// unrecognized token falls back to the deployment default rather than coercing.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "off" => Some(AutoLinkPosture::Off),
            "verified_to_verified" => Some(AutoLinkPosture::VerifiedToVerified),
            _ => None,
        }
    }
}

/// The largest fresh-re-auth window (in seconds) manual account linking may be
/// configured to (issue #78). A link freshness window beyond a day defeats the purpose
/// of demanding a FRESH re-authentication of the target account, so config load rejects a
/// larger value.
pub const OIDC_MAX_LINK_REAUTH_MAX_AGE_SECS: u64 = 86_400;

/// The generic OIDC upstream federation settings (issue #75, PR B).
///
/// When enabled, the boot path builds the federation runtime that turns a declarative,
/// DATA-ONLY connector (issue #75, PR A) into a full inbound federated login WITHOUT any
/// per-provider code: it resolves the connector's endpoints (discovery), exchanges the
/// authorization code, and validates the upstream ID token through the one JOSE core, then
/// provisions a local identity keyed on the upstream ISSUER + `sub`. Every federation
/// outbound rides the one SSRF-hardened fetcher.
///
/// DISABLED BY DEFAULT (`enabled = false`): the `/federation` routes are a uniform
/// not-found, so an existing deployment is unaffected. The TTLs govern how long a resolved
/// discovery document and a fetched upstream key set are cached (both refetched on expiry,
/// and a JWKS is refetched immediately when an ID token names an unknown `kid`).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct FederationConfig {
    /// Whether inbound federation is wired. False (the default) leaves the `/federation`
    /// routes a uniform not-found and builds no federation runtime. When true, the boot
    /// path constructs the runtime (a dedicated SSRF-hardened fetcher plus the caches
    /// below) and installs it, so a stored connector's federated login legs go live.
    pub enabled: bool,

    /// How long a resolved upstream discovery document is cached, in seconds (issue #75).
    /// The default (3600, one hour) balances freshness against refetch load; a change to an
    /// upstream's advertised endpoints propagates within it. Must be at least 1 and at most
    /// `OIDC_MAX_FEDERATION_TTL_SECS`.
    pub discovery_ttl_secs: u64,

    /// How long a fetched upstream JWKS is cached, in seconds (issue #75). The default
    /// (3600, one hour) bounds how long a rotated-OUT key stays trusted; a rotated-IN key
    /// naming a new `kid` is picked up immediately by the kid-miss refetch, so this TTL need
    /// not be short. Must be at least 1 and at most `OIDC_MAX_FEDERATION_TTL_SECS`.
    pub jwks_ttl_secs: u64,

    /// The per-connector health probe window, in seconds (issue #76): the BASE health-driven
    /// backoff interval. When a connector's upstream is unavailable the runtime waits at least
    /// this long (growing exponentially per consecutive failure, capped) before probing it
    /// again, so a dead upstream is not hammered while a transiently-down one is retried and
    /// recovers. It is also the window over which the exported per-connector error rate is
    /// measured. The default (30) is a responsive-but-gentle probe cadence. Must be at least 1
    /// and at most `OIDC_MAX_FEDERATION_TTL_SECS`.
    pub health_probe_window_secs: u64,

    /// The posture governing whether a federated login may AUTO-LINK into a pre-existing
    /// local account (issue #78). `Off` (the default) is the most conservative posture: a
    /// federated login never silently merges into a pre-existing local account. An
    /// operator opts into `verified_to_verified` to permit auto-linking, and even then an
    /// auto-link fires only when the full trust decision table agrees (verified local
    /// email, upstream `email_verified`, trusted connector). See [`AutoLinkPosture`].
    pub auto_link_posture: AutoLinkPosture,

    /// The maximum age, in seconds, of the caller's re-authentication that a manual
    /// account link accepts (issue #78, FORK C). Manual linking requires a FRESH
    /// re-authentication of the TARGET account (never merely an active session): the
    /// `start` leg refuses unless `now - auth_time <= link_reauth_max_age_secs`. The
    /// default (300, five minutes) matches the passkey-conversion freshness window
    /// without reusing that hardcoded const, so linking freshness is tunable
    /// independently. Must be at least 1 and at most `OIDC_MAX_LINK_REAUTH_MAX_AGE_SECS`.
    pub link_reauth_max_age_secs: u64,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            discovery_ttl_secs: 3600,
            jwks_ttl_secs: 3600,
            health_probe_window_secs: 30,
            auto_link_posture: AutoLinkPosture::Off,
            link_reauth_max_age_secs: 300,
        }
    }
}

/// The IdP-side FedCM surface settings (issue #83, EXPLORATORY).
///
/// FedCM's `/.well-known/web-identity` is an ORIGIN-level document, but IronAuth
/// serves everything else per `(tenant, environment)` and has no origin-level
/// default env. This section names the SINGLE designated `(tenant, environment)`
/// this origin exposes over FedCM (mirroring the WebAuthn related-origins
/// process-level model), so the origin-level well-known points at that env's
/// path-scoped config, and it carries the branding metadata the browser account
/// chooser renders. Multi-tenant-per-origin FedCM is a graduation trigger, not a
/// goal of the experiment.
///
/// This section can only SHAPE the FedCM documents; it can never ARM the endpoints.
/// The arming switch is the `fedcm` experimental feature flag, resolved to a
/// state-builder bool at boot (never an `[oidc]` toggle, so the experimental ack
/// gate can never be bypassed). With a designated env configured here but the
/// feature disabled, every FedCM route still answers a uniform 404.
///
/// Empty by default: no designated env means the FedCM well-known and config 404
/// even when the feature is enabled, disclosing nothing on an origin that has not
/// opted a specific env into the experiment.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct FedcmConfig {
    /// The tenant id of the single `(tenant, environment)` this origin exposes over
    /// FedCM (issue #83). Unset by default; when unset (or `designated_environment`
    /// is unset) the FedCM well-known and config answer a uniform 404. The value is a
    /// `ten_` id string; it is resolved to a live scope at boot, and a malformed or
    /// unknown value simply yields the same non-disclosing 404.
    pub designated_tenant: Option<String>,

    /// The environment id of the single `(tenant, environment)` this origin exposes
    /// over FedCM (issue #83). Unset by default; see [`Self::designated_tenant`]. Both
    /// must be set together for the FedCM well-known and config to serve a document.
    pub designated_environment: Option<String>,

    /// The provider display name the browser account chooser shows (issue #83). Falls
    /// back to a neutral default when unset, so the config document is always
    /// well-formed. Non-secret branding metadata.
    pub provider_name: Option<String>,

    /// The provider icon URL the browser account chooser renders (issue #83). Non-secret
    /// branding metadata; omitted from the config document when unset.
    pub icon_url: Option<String>,

    /// The account chooser background color, a CSS color string (issue #83). Non-secret
    /// branding metadata; omitted from the config document when unset.
    pub background_color: Option<String>,

    /// The account chooser text color, a CSS color string (issue #83). Non-secret
    /// branding metadata; omitted from the config document when unset.
    pub text_color: Option<String>,
}

/// The credential-abuse regulation settings (issue #64).
///
/// This governs the RISK-BASED, ESCALATING response to failed authentication and the
/// anti-enumeration posture, both keyed on the CANONICAL identifier (the #54 seam) so a
/// case/unicode variant of one identity shares regulation state. The DEFAULT posture is
/// deliberately account-DoS-SAFE (Keycloak CVE-2024-1722): escalation is an increasing
/// `Retry-After` delay that targets the ATTACKER's dimensions (IP, identifier), NEVER a
/// hard account lockout, and every path is governed independently, so failed-password
/// spray against a victim can never lock the legitimate owner out of the passkey or
/// recovery path.
///
/// [`hard_lockout`](Self::hard_lockout) is the explicit per-tenant OPT-IN to a hard
/// lockout, with the documented weaponization tradeoff: enabling it lets an attacker who
/// sprays failed passwords at a victim's account temporarily deny that victim the
/// PASSWORD path. Even then the lockout is confined to the password path (the passkey
/// and recovery paths stay open), so the victim is never locked out of every path.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct RegulationConfig {
    /// Whether credential-abuse regulation is active. On by default (it is table-stakes
    /// online-guessing resistance, NIST SP 800-63B-4 3.2.2). When false, the failure
    /// counters and ban checks are skipped; the anti-enumeration UNIFORMITY of the
    /// login/register/recovery surfaces does not depend on this switch.
    pub enabled: bool,

    /// The fixed window, in seconds, over which failed-attempt counts accumulate for
    /// escalation (issue #64). The default (300) is a conservative five minutes. Must be
    /// at least 1 and at most `OIDC_MAX_LIFETIME_SECS`.
    pub window_secs: u64,

    /// The number of failed attempts on a dimension within `window_secs` before
    /// escalation begins (issue #64). Attempts at or below it are unthrottled; beyond it
    /// each further failure raises the `Retry-After` delay. The default (5) follows the
    /// NIST online-guessing guidance. Must be at least 1.
    pub soft_threshold: u32,

    /// The base escalation delay, in seconds, applied the first time a dimension exceeds
    /// `soft_threshold` (issue #64). The delay doubles per further failure up to
    /// `max_delay_secs`. The default (1) is gentle. Must be at least 1.
    pub base_delay_secs: u64,

    /// The ceiling, in seconds, on the escalating `Retry-After` delay (issue #64). The
    /// default (60) bounds the throttle so a legitimate user is never delayed
    /// indefinitely. Must be at least `base_delay_secs`.
    pub max_delay_secs: u64,

    /// The explicit per-tenant OPT-IN to a HARD account lockout (issue #64). FALSE by
    /// default: the account-DoS-safe posture. When true, a per-account password-path ban
    /// is auto-placed once the account dimension exceeds `hard_lockout_threshold`,
    /// blocking the PASSWORD path for `hard_lockout_duration_secs`. The passkey and
    /// recovery paths are NEVER locked (they are governed independently), so even under
    /// hard lockout the owner is not locked out of every path.
    ///
    /// Enabling this accepts TWO distinct documented tradeoffs. First, the denial-of-service
    /// WEAPONIZATION tradeoff (Keycloak CVE-2024-1722): an attacker who sprays failed
    /// passwords at a victim's account can hard-lock the victim's password path. Second,
    /// and SEPARATELY, a login ENUMERATION oracle: because a real account auto-bans once
    /// its per-account counter crosses the threshold while an unknown identifier never
    /// does, the 429 onset comes earlier for a present account, so an attacker can
    /// distinguish existing from unknown accounts by the ONSET (timing) of the throttle.
    /// That onset difference is INHERENT to hard lockout and cannot be removed; only the
    /// avoidable RESPONSE-SHAPE leak is closed (a banned present account and a throttled
    /// identifier return the same status, body, and `Retry-After` header shape). On the
    /// DEFAULT posture (`hard_lockout` false) neither tradeoff applies and the login,
    /// registration, and recovery surfaces stay fully anti-enumeration uniform.
    pub hard_lockout: bool,

    /// The account-dimension failure count within `window_secs` that auto-places a
    /// password-path hard-lockout ban, when `hard_lockout` is true (issue #64). The
    /// default (20) is well above `soft_threshold` so the escalating delay bites first.
    /// Must be at least 1.
    pub hard_lockout_threshold: u32,

    /// How long, in seconds, an auto-placed hard-lockout ban lasts before it expires
    /// (issue #64). The default (900) is fifteen minutes. Must be at least 1 and at most
    /// `OIDC_MAX_LIFETIME_SECS`.
    pub hard_lockout_duration_secs: u64,

    /// Whether self-service registration is CLOSED (issue #64, the Logto v1.41 pattern).
    /// FALSE by default (open self-service registration, unchanged). When true,
    /// `POST /register` no longer creates an account inline; it returns a UNIFORM
    /// acknowledgment for both known and unknown identifiers, and any verification send
    /// to an unknown recipient is SUPPRESSED, so a probe cannot distinguish an existing
    /// account from an unknown one at the registration surface.
    pub registration_closed: bool,
}

impl Default for RegulationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_secs: 300,
            soft_threshold: 5,
            base_delay_secs: 1,
            max_delay_secs: 60,
            hard_lockout: false,
            hard_lockout_threshold: 20,
            hard_lockout_duration_secs: 900,
            registration_closed: false,
        }
    }
}

/// The lower bound on the impossible-travel superhuman-velocity floor, in km/h (issue
/// #79). A floor below this would flag ordinary intercontinental travel as impossible.
pub const OIDC_RISK_MIN_IMPOSSIBLE_TRAVEL_KMH: u64 = 100;
/// The lower bound on the "this wasn't me" disavowal-token TTL, in seconds (issue #79).
pub const OIDC_RISK_MIN_DISAVOWAL_TTL_SECS: u64 = 300;
/// The upper bound on the "this wasn't me" disavowal-token TTL, in seconds (issue #79):
/// thirty days, matching the trusted-device max-age ceiling.
pub const OIDC_RISK_MAX_DISAVOWAL_TTL_SECS: u64 = 2_592_000;
/// The closed set of risk-score thresholds an authentication policy can require step-up
/// AT (issue #79): `off` (never), or the LOW/MED/HIGH rung at or above which a MED-or-
/// stronger score forces MFA. `oidc.risk.require_mfa_at` must be one of these.
pub const OIDC_RISK_THRESHOLDS: [&str; 4] = ["off", "low", "med", "high"];

/// The minimal risk-engine settings (issue #79).
///
/// The design bet is LEGIBILITY over ML: a small set of EXPLAINABLE signals feed a
/// three-level score (LOW/MED/HIGH) and a three-verb action vocabulary
/// (block/challenge/notify), and every decision is traceable and auditable. Each signal
/// is INDEPENDENTLY toggleable per environment, so a deployment enables only the signals
/// it wants. OFF by default ([`enabled`](Self::enabled) false): the whole engine is inert
/// until a tenant opts in, so no decision is recorded, no notification is sent, and
/// step-up is never forced by risk. The `GeoIP` and IP-reputation providers are PLUGGABLE
/// SEAMS with null defaults (no bundled third-party dependency), so the engine runs
/// complete with ZERO third-party services; the allow/deny lists below are the only
/// built-in IP-reputation input.
// The per-signal toggles are inherently a set of independent booleans (each signal is
// independently toggleable per environment, issue #79), so more than three bools is the
// legible shape here, exactly as the signal vocabulary demands.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct RiskConfig {
    /// Whether the minimal risk engine is active (issue #79). OFF by default: the engine
    /// is fully inert (no signals evaluated, no decision recorded, no notification sent,
    /// step-up never forced by risk). When on, the per-signal toggles below select which
    /// signals contribute.
    pub enabled: bool,

    /// Whether the NEW-DEVICE signal is evaluated (issue #79): a login from a device with
    /// no valid trusted-device row (the #71 signed cookie / `trusted_devices` state) is a
    /// new device. On by default (consulted only when `enabled`). Drives the new-device
    /// notification and contributes MED to the score.
    pub new_device_enabled: bool,

    /// Whether the IMPOSSIBLE-TRAVEL signal is evaluated (issue #79): a superhuman
    /// geo-velocity between consecutive logins, computed from the previous login's coarse
    /// location and instant against this login via a pluggable `GeoIP` provider. On by
    /// default, but INERT unless a `GeoIP` provider is wired (the null default resolves no
    /// coordinates). Contributes HIGH to the score.
    pub impossible_travel_enabled: bool,

    /// Whether the IP-REPUTATION signal is evaluated (issue #79): the per-environment
    /// allow/deny lists below plus a pluggable provider seam. On by default. A deny-list
    /// hit contributes HIGH; a provider "suspect" verdict contributes MED; an allow-list
    /// hit neutralizes the signal.
    pub ip_reputation_enabled: bool,

    /// Whether the VELOCITY signal is evaluated (issue #79): per-account, per-IP, and
    /// per-ASN attempt rates over `velocity_window_secs`, building on the #64 counter
    /// layer. On by default. Contributes MED at `velocity_med_threshold` and HIGH at
    /// `velocity_high_threshold`.
    pub velocity_enabled: bool,

    /// The risk-score threshold at or above which the authentication policy forces step-up
    /// (issue #79): one of `off` (never), `low`, `med`, or `high`. The canonical
    /// "require MFA at MED or above" is `med`: a MED-or-stronger score raises the effective
    /// requirement so the step-up gate (issue #72) challenges a second factor, while a LOW
    /// score does not. Default `off`.
    ///
    /// NOTE (enforcement): with `require_mfa_at="off"` and no IP deny-list configured,
    /// enabling the engine does NOTHING enforcement-wise for a non-deny HIGH score (a new
    /// device, impossible travel, a velocity flood, or a provider "suspect" verdict): such a
    /// score only Allows or Notifies. To actually ENFORCE on risk, set `require_mfa_at` to
    /// `low`/`med`/`high` (so a qualifying score forces step-up) and/or populate the IP
    /// deny-list (a deny-list hit hard-blocks when `block_on_high`).
    pub require_mfa_at: String,

    /// Whether a hard-deny HIGH score BLOCKS the login with a uniform, anti-enumeration
    /// failure (issue #79). ONLY an explicit IP deny-list hit is a hard deny (a block);
    /// every other signal, including a VELOCITY flood, raises the score (and can force
    /// step-up via `require_mfa_at`) but NEVER blocks, so a shared NAT or ASN cannot become
    /// a victim lockout. On by default. When off, a would-be block degrades to a challenge.
    /// A block is indistinguishable from an ordinary login failure (reusing the #64
    /// uniformity discipline).
    pub block_on_high: bool,

    /// Whether a new-device (or new-location) login sends the user a notification (issue
    /// #79) with the device, User-Agent, and geo context plus the single-use "this wasn't
    /// me" link. On by default (consulted only when `new_device_enabled`). The delivery
    /// uses the #68 `VerificationSender` seam (the default sender performs no delivery).
    pub notify_on_new_device: bool,

    /// The cooldown window, in seconds, over which repeated new-device notifications to the
    /// SAME (subject, device/User-Agent fingerprint) are SUPPRESSED (issue #79). At most one
    /// new-device notice (and one minted "this wasn't me" token) is sent per new device per
    /// window, so an attacker WITH valid credentials who logs in repeatedly WITHOUT the
    /// remember-device cookie (each read as a new device) cannot flood the victim's inbox or
    /// accumulate unbounded disavowal-token rows. Reuses the #64 counter layer. Default 3600
    /// (one hour). 0 disables the throttle (every new device notifies).
    pub notify_cooldown_secs: u64,

    /// The fixed window, in seconds, over which the velocity signal counts attempts per
    /// dimension (issue #79). Default 300 (five minutes). Must be at least 1 and at most
    /// `OIDC_MAX_LIFETIME_SECS`.
    pub velocity_window_secs: u64,

    /// The per-dimension attempt count within `velocity_window_secs` at which the velocity
    /// signal contributes MED (issue #79). Default 10. Must be at least 1.
    pub velocity_med_threshold: u32,

    /// The per-dimension attempt count within `velocity_window_secs` at which the velocity
    /// signal contributes HIGH (issue #79). Default 30. Must be at least
    /// `velocity_med_threshold`.
    pub velocity_high_threshold: u32,

    /// The superhuman geo-velocity floor, in km/h, above which the impossible-travel
    /// signal fires (issue #79). Default 1000 (faster than a commercial flight). Must be at
    /// least `OIDC_RISK_MIN_IMPOSSIBLE_TRAVEL_KMH`.
    pub impossible_travel_kmh: u64,

    /// The per-environment IP ALLOW list (issue #79): plain IPs or CIDR ranges a login is
    /// trusted from, which neutralize the IP-reputation signal. Empty by default.
    pub ip_allowlist: Vec<String>,

    /// The per-environment IP DENY list (issue #79): plain IPs or CIDR ranges a login is
    /// refused from, which contribute HIGH (and block when `block_on_high`). Empty by
    /// default.
    pub ip_denylist: Vec<String>,

    /// The "this wasn't me" disavowal-token time-to-live, in seconds (issue #79). Default
    /// 604800 (seven days). Must be in
    /// `OIDC_RISK_MIN_DISAVOWAL_TTL_SECS..=OIDC_RISK_MAX_DISAVOWAL_TTL_SECS`.
    pub disavowal_ttl_secs: u64,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            new_device_enabled: true,
            impossible_travel_enabled: true,
            ip_reputation_enabled: true,
            velocity_enabled: true,
            require_mfa_at: "off".to_owned(),
            block_on_high: true,
            notify_on_new_device: true,
            notify_cooldown_secs: 3600,
            velocity_window_secs: 300,
            velocity_med_threshold: 10,
            velocity_high_threshold: 30,
            impossible_travel_kmh: 1000,
            ip_allowlist: Vec::new(),
            ip_denylist: Vec::new(),
            disavowal_ttl_secs: 604_800,
        }
    }
}

/// The lower bound on the proof-of-work difficulty, in leading zero bits (issue #80). A
/// difficulty of 0 would demand no work at all; the floor of 1 keeps an enabled `PoW`
/// meaningful.
pub const OIDC_POW_MIN_DIFFICULTY_BITS: u8 = 1;
/// The upper bound on the proof-of-work difficulty, in leading zero bits (issue #80).
/// Beyond this an honest browser could take unbounded time to solve the invisible
/// challenge; 24 bits keeps the worst case tractable while still costing a bot farm.
pub const OIDC_POW_MAX_DIFFICULTY_BITS: u8 = 24;
/// The closed set of disposable-email modes (issue #80): `off` (no check), `flag` (feed
/// the risk engine a signal but admit), or `block` (refuse with an anti-enumeration
/// uniform failure).
pub const OIDC_DISPOSABLE_EMAIL_MODES: [&str; 3] = ["off", "flag", "block"];

/// Which challenge provider verifies a registration/reset/OTP-send proof-of-work (issue
/// #80). A closed set. The built-in invisible `PoW` is the DEFAULT and never depends on an
/// external service (the no-mandatory-third-party-infrastructure covenant); Turnstile and
/// reCAPTCHA are OPTIONAL adapters that make an outbound verify call through the audited
/// `ironauth-fetch` seam.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PowProvider {
    /// The built-in, self-contained hashcash proof-of-work (the default). ZERO external
    /// calls, so it can never fail-open/closed on an outage.
    #[default]
    Builtin,
    /// Cloudflare Turnstile (external adapter; brings Apple Private Access Tokens).
    Turnstile,
    /// Google reCAPTCHA (external adapter).
    Recaptcha,
}

/// How an EXTERNAL challenge adapter (Turnstile/reCAPTCHA) degrades when the provider is
/// unreachable (issue #80). The built-in `PoW` never depends on an external service, so this
/// policy applies ONLY to the adapters. Default fail-CLOSED (an outage refuses the
/// attempt); a deployment that prizes availability over abuse resistance may opt into
/// fail-OPEN.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdapterFailPolicy {
    /// An adapter outage REFUSES the attempt (abuse-resistant; the default).
    #[default]
    FailClosed,
    /// An adapter outage ADMITS the attempt (availability-biased).
    FailOpen,
}

/// The proof-of-work challenge settings (issue #80). OFF by default: the challenge is
/// never issued or required until a tenant opts in. `challenge_at` reuses the #79 risk
/// threshold vocabulary (`off`/`low`/`med`/`high`): the challenge is required when the
/// anonymous registration/verification risk level meets the threshold, so `low` challenges
/// every attempt while `med` challenges only an elevated one (a suspect IP or a flagged
/// disposable domain).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct PowConfig {
    /// Whether proof-of-work challenges are issued and required. OFF by default (inert).
    pub enabled: bool,

    /// The challenge difficulty, in leading zero bits a solving nonce must produce
    /// (issue #80). Configurable per environment. Bounded to
    /// [`OIDC_POW_MIN_DIFFICULTY_BITS`]`..=`[`OIDC_POW_MAX_DIFFICULTY_BITS`] so a
    /// misconfiguration cannot demand impossible or trivial work. Default 12.
    pub difficulty_bits: u8,

    /// The risk threshold at or above which a challenge is required (issue #80): one of
    /// `off` (never), `low` (always, once `enabled`), `med`, or `high`. Reuses the #79
    /// score vocabulary; the anonymous level is computed from the IP-reputation signal
    /// and, at registration, a flagged disposable-domain signal. Default `low`.
    pub challenge_at: String,

    /// How long, in seconds, an issued challenge remains solvable before it expires
    /// (issue #80). Default 300 (five minutes). Must be at least 1 and at most
    /// `OIDC_MAX_LIFETIME_SECS`.
    pub challenge_ttl_secs: u64,

    /// Which provider verifies the challenge (issue #80). Default the built-in
    /// self-contained `PoW` ([`PowProvider::Builtin`]); Turnstile and reCAPTCHA are
    /// optional adapters.
    pub provider: PowProvider,

    /// How an external adapter degrades on an outage (issue #80). Ignored by the built-in
    /// `PoW` (which never calls out). Default fail-CLOSED.
    pub fail_policy: AdapterFailPolicy,

    /// The external adapter's site SECRET (issue #80), for Turnstile/reCAPTCHA server-side
    /// verification. A [`Secret`] indirection (env/file), so the VALUE never lands in a
    /// config dump or a config snapshot; only a named reference travels. `None` for the
    /// built-in `PoW` (which has no secret).
    pub adapter_secret: Option<Secret>,
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            difficulty_bits: 12,
            challenge_at: "low".to_owned(),
            challenge_ttl_secs: 300,
            provider: PowProvider::Builtin,
            fail_policy: AdapterFailPolicy::FailClosed,
            adapter_secret: None,
        }
    }
}

/// The disposable / low-reputation email defense (issue #80). Evaluated at signup on the
/// NFKC-normalized email domain. OFF by default. The lists are updateable per-environment
/// data (like the #79 IP allow/deny lists) that promote with the config snapshot: `denylist`
/// names domains treated as disposable, and `allowlist` is the override that always admits a
/// domain even if it matches a heuristic or the deny list.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct DisposableEmailConfig {
    /// The mode (issue #80): `off` (no check), `flag` (admit but feed the risk engine a
    /// MED signal, so a challenge may be required), or `block` (refuse with an
    /// anti-enumeration uniform failure indistinguishable from an ordinary validation
    /// error). Default `off`.
    pub mode: String,

    /// The per-environment DENY list of email domains treated as disposable /
    /// low-reputation (issue #80). Lower-cased and compared against the normalized email
    /// domain. Empty by default.
    pub denylist: Vec<String>,

    /// The per-environment ALLOW override (issue #80): domains always admitted even if
    /// they match `denylist`. Empty by default.
    pub allowlist: Vec<String>,
}

impl Default for DisposableEmailConfig {
    fn default() -> Self {
        Self {
            mode: "off".to_owned(),
            denylist: Vec::new(),
            allowlist: Vec::new(),
        }
    }
}

/// The waitlist gate (issue #80). OFF by default. When on, a self-service registration
/// lands in a PENDING (`waitlisted`) lifecycle state that CANNOT authenticate until an
/// admin approves it (transition to active) or rejects it (transition to disabled) through
/// the user-lifecycle management API.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct WaitlistConfig {
    /// Whether self-service signup is waitlist-gated (issue #80). OFF by default.
    pub enabled: bool,
}

/// The registration abuse defenses (issue #80): proof-of-work challenges, the disposable
/// email defense, and the waitlist gate. Every sub-feature is independently toggleable per
/// environment and OFF by default, and the whole struct promotes with the config snapshot
/// (only a named reference to an adapter secret ever travels, never the value).
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct RegistrationAbuseConfig {
    /// The invisible, self-contained proof-of-work challenge (issue #80). See
    /// [`PowConfig`].
    pub pow: PowConfig,

    /// The disposable / low-reputation email defense (issue #80). See
    /// [`DisposableEmailConfig`].
    pub disposable_email: DisposableEmailConfig,

    /// The waitlist gate (issue #80). See [`WaitlistConfig`].
    pub waitlist: WaitlistConfig,
}

/// The OWASP-recommended Argon2id memory cost, in KiB (issue #62). The shipped
/// default for `password_hashing.memory_kib`.
pub const PASSWORD_HASHING_OWASP_MEMORY_KIB: u32 = 19_456;
/// The OWASP-recommended Argon2id iteration (time) cost (issue #62).
pub const PASSWORD_HASHING_OWASP_ITERATIONS: u32 = 2;
/// The OWASP-recommended Argon2id parallelism (lanes) (issue #62).
pub const PASSWORD_HASHING_OWASP_PARALLELISM: u32 = 1;
/// The security FLOOR for `password_hashing.memory_kib` (issue #62): config load
/// refuses a memory cost below this, so a tuning mistake cannot ship a hashing
/// parameter weaker than a defensible minimum (8 MiB). The shipped default is far
/// above it.
pub const PASSWORD_HASHING_MIN_MEMORY_KIB: u32 = 8_192;
/// The CEILING for `password_hashing.memory_kib` (issue #62): 4 GiB. A larger
/// value is almost always a misconfiguration that would let a single hash exhaust
/// host memory, so config load refuses it.
pub const PASSWORD_HASHING_MAX_MEMORY_KIB: u32 = 4_194_304;
/// The CEILING for `password_hashing.iterations` (issue #62). A value beyond this
/// makes each hash absurdly slow; config load refuses it.
pub const PASSWORD_HASHING_MAX_ITERATIONS: u32 = 16;
/// The CEILING for `password_hashing.parallelism` (issue #62). Argon2 lanes above
/// this are pointless on any realistic host; config load refuses it.
pub const PASSWORD_HASHING_MAX_PARALLELISM: u32 = 64;
/// The CEILING for `password_hashing.pool_threads` (issue #62). A worker count
/// beyond this is a misconfiguration; config load refuses it. `0` (the default)
/// derives the count from the host core count at boot.
pub const PASSWORD_HASHING_MAX_POOL_THREADS: usize = 1_024;
/// The CEILING for `password_hashing.probe_target_latency_ms` (issue #62): five
/// seconds. A target beyond this would recommend an unusably slow login.
pub const PASSWORD_HASHING_MAX_PROBE_TARGET_LATENCY_MS: u64 = 5_000;
/// The FLOOR for `password_hashing.probe_target_latency_ms` (issue #62): ten
/// milliseconds. A target below it cannot be met by any memory-hard hash.
pub const PASSWORD_HASHING_MIN_PROBE_TARGET_LATENCY_MS: u64 = 10;

/// The NIST SP 800-63B-4 minimum length (code points) when the password is the SOLE
/// authentication factor (section 3.1.1.2 SHALL). The shipped default for
/// `password_policy.min_length_sole_factor`; a lower value is a documented deviation.
pub const PASSWORD_POLICY_NIST_MIN_LENGTH_SOLE_FACTOR: usize = 15;
/// The NIST SP 800-63B-4 minimum length permitted when the password is ONE factor of a
/// multi-factor authentication. The shipped default for
/// `password_policy.min_length_mfa_factor`.
pub const PASSWORD_POLICY_NIST_MIN_LENGTH_MFA_FACTOR: usize = 8;
/// The NIST SP 800-63B-4 recommended minimum for the maximum acceptable length (SHOULD
/// be at least this). The shipped default for `password_policy.max_length`.
pub const PASSWORD_POLICY_NIST_MIN_MAX_LENGTH: usize = 64;
/// The CEILING for `password_policy.max_length` (issue #63): a very long accepted
/// password is an Argon2id input-size denial-of-service vector, so config load bounds
/// it. Far above the 64-code-point recommendation.
pub const PASSWORD_POLICY_MAX_LENGTH_CEILING: usize = 1_024;
/// The CEILING for `password_policy.rotation_max_age_days` (issue #63): ten years. `0`
/// (the default) disables forced rotation, per 63B-4; any positive value is a
/// documented deviation.
pub const PASSWORD_POLICY_MAX_ROTATION_DAYS: u64 = 3_650;

/// Which breached-password screening provider an environment uses (issue #63). A closed
/// set matching the first-party `ironauth-screening` providers. Neither is paywalled and
/// neither depends on a first-party IronAuth service (the covenant).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScreeningProvider {
    /// The online Have I Been Pwned range API over the SSRF-hardened fetcher, using the
    /// k-anonymity protocol (only a 5-character SHA-1 prefix ever leaves the process).
    /// The zero-configuration default; free and public.
    #[default]
    Hibp,
    /// An operator-supplied offline corpus, screened entirely locally with no outbound
    /// access (for air-gapped or callout-restricted deployments). Requires
    /// `password_policy.offline_corpus_path`.
    Offline,
}

/// What to do when the screening provider cannot answer (issue #63), consistent with
/// the platform's documented fail-open/closed conventions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScreeningFailurePolicy {
    /// Allow the password (do not block the set) and emit an audit event. The default, and
    /// AVAILABILITY-BIASED: a screening-provider outage must not lock every user out of
    /// setting a password, so under an outage a KNOWN-breached password can be accepted
    /// (audited and detectable via the `fail_open` metric/log). For hard enforcement that
    /// never accepts an unscreened password use `fail_closed`, or the `offline` provider
    /// (an operator-supplied corpus is immune to an outbound-provider outage).
    #[default]
    FailOpen,
    /// Refuse the set until screening succeeds. The strict-compliance posture: a password
    /// is never accepted unscreened.
    FailClosed,
}

/// The breached-password screening and NIST SP 800-63B-4 password policy (issue #63).
///
/// The shipped defaults are the modern 800-63B-4 memorized-secret posture: a 15
/// code-point minimum when the password is the SOLE factor (an 8 code-point floor only
/// when it is one factor of MFA), a 64 code-point maximum, NO composition rules, NO
/// forced rotation, Unicode accepted (NFKC-normalized once, length counted in code
/// points), and compromised-list screening MANDATORY (on by default, over the online
/// HIBP k-anonymity provider). Legacy compliance regimes are expressed as SETTINGS here
/// (enable composition, set a rotation interval, change the lengths); each deviating
/// setting is reported to the admin surface as a documented deviation from 63B-4, so a
/// deviation is a configuration, never a fork.
///
/// This is a promotable per-environment setting in spirit; the process value is the
/// deployment default until per-environment overrides ride the M5 promotion pipeline,
/// mirroring the other promotable settings.
// Each composition flag plus the screening/on-login flags is an INDEPENDENT, individually
// documented TOML toggle keyed by its field name in the published schema; folding them
// into enums would corrupt the config contract and the generated docs, so the
// excessive-bools lint is deliberately allowed here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct PasswordPolicyConfig {
    /// The minimum length in CODE POINTS when the password is the SOLE authentication
    /// factor. The 800-63B-4 default (`15`) is a SHALL; a lower value is accepted but is
    /// annotated to the admin surface as a deviation. Must be at least 1 and at most
    /// `max_length`.
    pub min_length_sole_factor: usize,

    /// The minimum length in CODE POINTS permitted when the password is ONE factor of a
    /// multi-factor authentication. The 800-63B-4 default (`8`). Must be at least 1 and
    /// at most `max_length`.
    pub min_length_mfa_factor: usize,

    /// The maximum acceptable length in CODE POINTS. The default (`64`) meets the
    /// 800-63B-4 SHOULD (accept at least 64); a value below 64 is annotated as a
    /// deviation. Must be at least `min_length_sole_factor` and `min_length_mfa_factor`,
    /// and at most `PASSWORD_POLICY_MAX_LENGTH_CEILING` (a very long accepted password is
    /// an Argon2id input-size denial-of-service vector).
    pub max_length: usize,

    /// Require at least one lowercase letter (a legacy composition rule). The
    /// 800-63B-4-conform default (`false`) imposes NO composition; enabling this is a
    /// documented deviation.
    pub require_lowercase: bool,

    /// Require at least one uppercase letter (a legacy composition rule). Default
    /// `false`; enabling it is a documented deviation.
    pub require_uppercase: bool,

    /// Require at least one digit (a legacy composition rule). Default `false`; enabling
    /// it is a documented deviation.
    pub require_digit: bool,

    /// Require at least one symbol (a legacy composition rule). Default `false`; enabling
    /// it is a documented deviation.
    pub require_symbol: bool,

    /// The forced-rotation interval in days (a legacy policy). The 800-63B-4-conform
    /// default (`0`) DISABLES periodic rotation (63B-4 forbids rotation without evidence
    /// of compromise); a positive value is a documented deviation. At most
    /// `PASSWORD_POLICY_MAX_ROTATION_DAYS`.
    pub rotation_max_age_days: u64,

    /// Whether compromised-list screening runs on set / change / reset. The 800-63B-4
    /// default (`true`) makes screening MANDATORY; setting it to `false` is a documented
    /// deviation (screening is a covenant no-paywall security feature, on by default).
    pub screening_enabled: bool,

    /// The minimum in-tree password-strength score (0-4) required on the password set /
    /// change path (issue #66), scored AFTER the length/composition policy and BEFORE the
    /// breach screen; `0` (the default) turns scoring OFF. COARSENESS (read before raising
    /// this): this is a COARSE length/charset/pattern floor that is BLIND to dictionary
    /// words and l33t substitution (e.g. `summer2024` scores the MAXIMUM 4 and clears every
    /// threshold, including `4`), NOT a zxcvbn-equivalent guard, so the mandatory
    /// HIBP/offline breach screen is the PRIMARY defense that backstops it. Must be at most
    /// `4`.
    ///
    /// The default (`0`) means an existing deployment sees no regression; a higher value
    /// only ever TIGHTENS admission. The real `zxcvbn` crate can be swapped in behind the
    /// same seam once its dependency tree passes cargo-deny (today a
    /// `time`/RUSTSEC-vs-MSRV-1.85 conflict blocks it).
    #[schemars(range(max = 4))]
    pub min_password_strength_score: u8,

    /// Which screening provider to use (issue #63): `hibp` (the online k-anonymity range
    /// API, the default) or `offline` (an operator-supplied corpus, fully offline).
    pub screening_provider: ScreeningProvider,

    /// What to do when the screening provider cannot answer: `fail_open` (allow the
    /// password and emit an audit event) or `fail_closed` (refuse the set until screening
    /// succeeds). The default (`fail_open`) is AVAILABILITY-BIASED: a HIBP outage lets a
    /// known-breached password through (audited and detectable via the `fail_open`
    /// metric/log), so a provider outage never locks every user out of setting a password.
    /// For HARD enforcement that never accepts an unscreened password, set `fail_closed`, or
    /// use the `offline` provider (an operator-supplied corpus is immune to an
    /// outbound-provider outage).
    pub screening_failure_policy: ScreeningFailurePolicy,

    /// Screen the presented password at LOGIN too (issue #63), so a password that has
    /// since become breached (the corpus grew after it was set) is detected on the user's
    /// next sign-in and surfaced (an audit event; a forced change once the hosted
    /// change-password surface lands). The safe default (`false`) avoids an outbound
    /// screening call on every login; enable it for continuous detection.
    pub screen_on_login: bool,

    /// An alternate base URL for the online HIBP provider (an https URL, base only, no
    /// `/range` and no trailing slash), for a deployment that fronts HIBP with its own
    /// compatible mirror. Unset (the default) uses the canonical public range API.
    pub hibp_base_url: Option<String>,

    /// The path to the offline corpus dataset file (a UTF-8 list of SHA-1 hashes, the
    /// HIBP downloadable format or a plain list), required when `screening_provider` is
    /// `offline` and `screening_enabled` is true. Unset for the `hibp` provider.
    pub offline_corpus_path: Option<String>,
}

impl Default for PasswordPolicyConfig {
    fn default() -> Self {
        Self {
            min_length_sole_factor: PASSWORD_POLICY_NIST_MIN_LENGTH_SOLE_FACTOR,
            min_length_mfa_factor: PASSWORD_POLICY_NIST_MIN_LENGTH_MFA_FACTOR,
            max_length: PASSWORD_POLICY_NIST_MIN_MAX_LENGTH,
            require_lowercase: false,
            require_uppercase: false,
            require_digit: false,
            require_symbol: false,
            rotation_max_age_days: 0,
            screening_enabled: true,
            min_password_strength_score: 0,
            screening_provider: ScreeningProvider::Hibp,
            screening_failure_policy: ScreeningFailurePolicy::FailOpen,
            screen_on_login: false,
            hibp_base_url: None,
            offline_corpus_path: None,
        }
    }
}

/// Password-hashing settings (issue #62): the Argon2id parameters for NEWLY set
/// passwords and the dedicated, admission-controlled hashing worker pool.
///
/// Password hashing is the hottest and most denial-of-service-prone operation an
/// identity provider performs, so it runs in a bounded worker pool kept OFF the
/// async request threads, fronted by the per-tenant fair-share admission of the
/// [`QuotaConfig`] layer (issue #50): one tenant's credential-stuffing storm
/// degrades only that tenant, never the instance.
///
/// The Argon2id parameters are per-environment in spirit (dev/staging/prod may
/// differ) and safe by default (the OWASP recommendation: `m = 19456` KiB,
/// `t = 2`, `p = 1`); a parameter change applies to NEW hashes, and an existing
/// hash upgrades transparently through the rehash-on-successful-login path,
/// because the parameters are stored per hash in the PHC string. The process
/// value is the deployment default until per-environment overrides ride the M5
/// promotion pipeline, mirroring the other promotable settings.
///
/// The pool sizing and queue depth are host infrastructure, not a per-environment
/// concern: they bound the whole process. The `ironauth hash-probe` CLI (and the
/// in-admin tuning helper) run a measured probe on the actual host and recommend
/// parameters that meet `probe_target_latency_ms`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct PasswordHashingConfig {
    /// Argon2id memory cost in KiB for newly set passwords. The default
    /// (`19456`, the OWASP recommendation) is 19 MiB. Must be between
    /// `PASSWORD_HASHING_MIN_MEMORY_KIB` (8 MiB) and
    /// `PASSWORD_HASHING_MAX_MEMORY_KIB` (4 GiB). A change applies to new hashes;
    /// an existing hash upgrades on the user's next successful login.
    pub memory_kib: u32,

    /// Argon2id iteration (time) cost for newly set passwords. The default (`2`,
    /// the OWASP recommendation) pairs with the 19 MiB memory cost. Must be at
    /// least 1 and at most `PASSWORD_HASHING_MAX_ITERATIONS`.
    pub iterations: u32,

    /// Argon2id parallelism (lanes) for newly set passwords. The default (`1`,
    /// the OWASP recommendation). Must be at least 1 and at most
    /// `PASSWORD_HASHING_MAX_PARALLELISM`.
    pub parallelism: u32,

    /// The number of dedicated OS threads in the hashing worker pool. Argon2 runs
    /// ONLY on these threads, never on a tokio protocol-I/O worker, so a hash can
    /// never block request I/O. The default (`0`) derives a safe count from the
    /// host core count at boot. Must be at most
    /// `PASSWORD_HASHING_MAX_POOL_THREADS`.
    pub pool_threads: usize,

    /// The maximum number of hash jobs ONE `(tenant, environment)` may have waiting
    /// in the pool's queue before that tenant is load-shed (issue #62). This is the
    /// per-tenant FAIR-SHARE bound: the pool keeps a separate sub-queue per tenant
    /// and dequeues round-robin across them, so one tenant's backlog can never
    /// head-of-line-block or shed another tenant's already-admitted work. A
    /// submission that would exceed this per-tenant depth is refused with a
    /// retryable `503` and a machine-readable reason (the pool is a bounded
    /// resource, never an unbounded inline hash). A generous global memory backstop
    /// (a multiple of this bound) caps total waiting work and is charged only to the
    /// submitting tenant. Per-tenant fairness is also enforced BEFORE the queue by
    /// the quota admission layer. The default (`512`) is a conservative bound. Must
    /// be at least 1.
    pub max_queue_depth: usize,

    /// The target per-hash latency in milliseconds the tuning probe aims for when
    /// recommending parameters (`ironauth hash-probe`). The default (`250`) is a
    /// common interactive-login budget. Must be between
    /// `PASSWORD_HASHING_MIN_PROBE_TARGET_LATENCY_MS` and
    /// `PASSWORD_HASHING_MAX_PROBE_TARGET_LATENCY_MS`.
    pub probe_target_latency_ms: u64,
}

impl Default for PasswordHashingConfig {
    fn default() -> Self {
        Self {
            memory_kib: PASSWORD_HASHING_OWASP_MEMORY_KIB,
            iterations: PASSWORD_HASHING_OWASP_ITERATIONS,
            parallelism: PASSWORD_HASHING_OWASP_PARALLELISM,
            pool_threads: 0,
            max_queue_depth: 512,
            probe_target_latency_ms: 250,
        }
    }
}

/// The largest number of usage-threshold percentages the quota engine will emit
/// webhooks for (issue #50). A short list (the default is two: an early-warning
/// and the hard limit); the cap keeps the config bounded and the per-bucket
/// threshold bookkeeping small.
pub const QUOTA_MAX_USAGE_THRESHOLDS: usize = 16;

/// Per-tenant and per-environment quota settings (issue #50).
///
/// The tenant-plane fairness layer. Two nested token-bucket tiers, one keyed by
/// tenant and one by (tenant, environment), over three independently enforced
/// dimensions (request rate, token issuance, hook execution seconds). An
/// environment spend also draws from its tenant bucket, so an environment can
/// never exceed its tenant and no tenant can starve another (the buckets are
/// per-scope and isolated). Every limit is a setting with a safe default (the
/// tunability principle); the full five-layer limiter with the edge and the
/// IronCache-backed shared L2 lands in M15 on top of this process-local core.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct QuotaConfig {
    /// The per-tenant tier. Bounds the aggregate of all of a tenant's
    /// environments; a single tenant cannot exceed it however many environments
    /// it runs.
    pub tenant: ScopeQuotaConfig,

    /// The per-environment tier. Bounds one environment, nested under its
    /// tenant: an environment spend draws from BOTH the environment bucket and
    /// the tenant bucket, so it can never consume beyond its tenant's remaining
    /// share.
    pub environment: ScopeQuotaConfig,

    /// The usage percentages (1 to 100) at which a saturation webhook fires per
    /// dimension, so operators see pressure before the hard limit. The default
    /// (`[80, 100]`) warns at 80 percent and again at the limit. An empty list
    /// disables saturation webhooks. At most `QUOTA_MAX_USAGE_THRESHOLDS`
    /// entries; each must be between 1 and 100.
    pub usage_thresholds_percent: Vec<u8>,

    /// How long (in seconds) an idle per-tenant or per-environment token bucket is
    /// retained before the reaper evicts it, bounding the in-memory footprint under
    /// legitimate scope churn (an environment deleted, a tenant offboarded). A
    /// bucket untouched for this long is dropped; it is re-created full on the next
    /// spend, exactly as a never-seen scope would be, so eviction is behaviorally
    /// transparent (a scope idle this long has already refilled to full under any
    /// normal rate). The default (3600) is one hour. Set it to 0 to disable the
    /// reaper (buckets then live for the process lifetime); the key space is still
    /// bounded by real tenancy, because only a verified, existing scope ever
    /// allocates a bucket.
    pub idle_bucket_ttl_secs: u64,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            // Safe operational defaults. The per-tenant aggregate is the larger
            // envelope; each environment gets a smaller share nested under it.
            // These are conservative starting points, not marketed tiers (the
            // published tiers ride M15); tune per deployment.
            tenant: ScopeQuotaConfig {
                requests_per_second: 500,
                requests_burst: 1_000,
                token_issuance_per_second: 100,
                token_issuance_burst: 200,
                hook_seconds_per_second: 60,
                hook_seconds_burst: 120,
                password_hashing_per_second: 50,
                password_hashing_burst: 100,
            },
            environment: ScopeQuotaConfig {
                requests_per_second: 100,
                requests_burst: 200,
                token_issuance_per_second: 50,
                token_issuance_burst: 100,
                hook_seconds_per_second: 30,
                hook_seconds_burst: 60,
                password_hashing_per_second: 20,
                password_hashing_burst: 40,
            },
            usage_thresholds_percent: vec![80, 100],
            idle_bucket_ttl_secs: 3600,
        }
    }
}

/// The limits for one quota tier (issue #50), over the three enforced
/// dimensions. Each dimension is a token bucket with a sustained refill rate
/// (`*_per_second`) and a burst capacity (`*_burst`); the dimensions enforce
/// independently, so exhausting one does not affect another. A `*_burst` of 0
/// disables that dimension (unlimited), which is how a single-tenant self-hoster
/// expresses no quota.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ScopeQuotaConfig {
    /// Sustained requests per second (the token bucket refill rate for the
    /// request-rate dimension).
    pub requests_per_second: u64,

    /// Burst capacity for the request-rate dimension: the most requests that can
    /// be admitted in an instantaneous spike before the sustained rate governs.
    /// 0 means unlimited (the dimension is not enforced).
    pub requests_burst: u64,

    /// Sustained token issuance per second (the refill rate for the
    /// token-issuance dimension: access, ID, and refresh tokens minted).
    pub token_issuance_per_second: u64,

    /// Burst capacity for the token-issuance dimension. 0 means unlimited.
    pub token_issuance_burst: u64,

    /// Sustained hook/webhook execution seconds admitted per wall second (the
    /// refill rate for the hook-seconds dimension). Bounds how much outbound
    /// hook execution time a scope may consume.
    pub hook_seconds_per_second: u64,

    /// Burst capacity for the hook-seconds dimension. 0 means unlimited.
    pub hook_seconds_burst: u64,

    /// Sustained password-hash admissions per second (the refill rate for the
    /// password-hashing dimension, issue #62). This is the per-tenant fair-share
    /// admission in front of the dedicated hashing pool: it bounds how much Argon2
    /// work one scope may drive, so a credential-stuffing storm against one tenant
    /// degrades only that tenant, never the instance.
    pub password_hashing_per_second: u64,

    /// Burst capacity for the password-hashing dimension (issue #62). 0 means
    /// unlimited (the single-tenant self-hoster posture: no admission control on
    /// hashing, though the pool queue depth still bounds it).
    pub password_hashing_burst: u64,
}

impl Default for ScopeQuotaConfig {
    fn default() -> Self {
        // The per-environment defaults; `QuotaConfig::default` overrides the
        // tenant tier with its larger envelope. A standalone default here keeps
        // a partially specified `[quota.tenant]` or `[quota.environment]` table
        // filling missing fields sensibly.
        Self {
            requests_per_second: 100,
            requests_burst: 200,
            token_issuance_per_second: 50,
            token_issuance_burst: 100,
            hook_seconds_per_second: 30,
            hook_seconds_burst: 60,
            password_hashing_per_second: 20,
            password_hashing_burst: 40,
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
    /// The WebAuthn related-origins estate has reached OR exceeded the browser
    /// label budget (issue #67). At the budget there is simply no headroom for
    /// another registrable label; over the budget a browser silently ignores the
    /// origins past its cap, so some listed origins may never work. This is
    /// advisory (the browser enforces its own cap); it never gates startup.
    WebauthnRelatedOriginLabelBudget {
        /// The distinct registrable-label count of the estate (serving origin plus
        /// related origins), approximated by SLD label.
        count: usize,
        /// The browser label budget the count has reached or exceeded.
        budget: usize,
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
            Warning::WebauthnRelatedOriginLabelBudget { count, budget } if count == budget => {
                write!(
                    f,
                    "oidc.webauthn_related_origins (with the serving origin) spans {count} distinct \
                     registrable labels, the browser related-origin budget of {budget}; there is no \
                     headroom for another registrable label before browsers begin ignoring origins \
                     in the /.well-known/webauthn document"
                )
            }
            Warning::WebauthnRelatedOriginLabelBudget { count, budget } => write!(
                f,
                "oidc.webauthn_related_origins (with the serving origin) spans {count} distinct \
                 registrable labels, exceeding the browser related-origin budget of {budget}; a \
                 browser silently ignores origins past its cap, so some listed origins may never \
                 work (this is an advisory approximation by SLD label; the browser enforces the \
                 real limit)"
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
        // The related-origins estate reaching OR exceeding the browser label budget
        // is an advisory warn (issue #67), never a boot error: the browser is the real
        // enforcer of its own cap, and an over-budget error would wrongly reject a valid
        // one-brand-many-ccTLD estate (which is a single label to a browser). At the
        // budget = no headroom; over it = the browser will ignore origins past its cap.
        if self.oidc.webauthn_enabled && !self.oidc.webauthn_related_origins.is_empty() {
            let count = webauthn_related_origin_labels(&self.oidc, &self.server).len();
            if count >= WEBAUTHN_RELATED_ORIGIN_LABEL_BUDGET {
                warnings.push(Warning::WebauthnRelatedOriginLabelBudget {
                    count,
                    budget: WEBAUTHN_RELATED_ORIGIN_LABEL_BUDGET,
                });
            }
        }
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
        if let Some(secret) = &self.oidc.lazy_migration.secret {
            visit("oidc.lazy_migration.secret", secret);
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
        validate_lazy_migration(&self.oidc)?;
        validate_federation(&self.oidc)?;
        validate_regulation(&self.oidc)?;
        validate_risk(&self.oidc)?;
        validate_registration_abuse(&self.oidc)?;
        validate_webauthn(&self.oidc, &self.server)?;
        validate_totp(&self.oidc)?;
        validate_trusted_device(&self.oidc)?;
        validate_email_otp(&self.oidc)?;
        validate_sms_otp(&self.oidc)?;
        validate_recovery(&self.oidc)?;
        validate_fedcm(&self.oidc)?;
        validate_quota(&self.quota)?;
        validate_password_hashing(&self.password_hashing)?;
        validate_password_policy(&self.password_policy)?;
        Ok(())
    }
}

/// Validate the account-recovery cooldown and delay windows (issue #81), kept out of
/// [`Config::validate`] so each stays within the readable-length lint. Validated at
/// load even when recovery is otherwise idle, so a misconfigured window fails fast.
fn validate_recovery(oidc: &OidcConfig) -> Result<(), ConfigError> {
    if oidc.recovery_cooldown_secs < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.recovery_cooldown_secs must be at least 1 second".to_owned(),
        });
    }
    if oidc.recovery_delay_secs < 1 || oidc.recovery_delay_secs > RECOVERY_MAX_DELAY_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.recovery_delay_secs ({}) must be between 1 and \
                 {RECOVERY_MAX_DELAY_SECS} seconds",
                oidc.recovery_delay_secs
            ),
        });
    }
    Ok(())
}

/// Validate the IdP-side FedCM surface settings (issue #83). The designated
/// `(tenant, environment)` must be given as BOTH ids or NEITHER: a lone tenant or a
/// lone environment is an operator mistake that would otherwise silently leave the
/// well-known 404 with no diagnostic. The exact id shape is validated at boot when
/// the pair is resolved to a live scope (this crate does not depend on the id
/// parser), so a malformed pair fails safe to the same non-disclosing 404.
fn validate_fedcm(oidc: &OidcConfig) -> Result<(), ConfigError> {
    let tenant = oidc.fedcm.designated_tenant.as_deref();
    let environment = oidc.fedcm.designated_environment.as_deref();
    if tenant.is_some() != environment.is_some() {
        return Err(ConfigError::Invalid {
            message: "oidc.fedcm.designated_tenant and oidc.fedcm.designated_environment must be \
                      set together (both name the single (tenant, environment) this origin \
                      exposes over FedCM) or both left unset"
                .to_owned(),
        });
    }
    if tenant.is_some_and(str::is_empty) || environment.is_some_and(str::is_empty) {
        return Err(ConfigError::Invalid {
            message: "oidc.fedcm.designated_tenant and oidc.fedcm.designated_environment must not \
                      be empty strings when set"
                .to_owned(),
        });
    }
    Ok(())
}

/// Validate the credential-abuse regulation settings (issue #64), kept out of
/// [`Config::validate`] so each stays within the readable-length lint.
fn validate_regulation(oidc: &OidcConfig) -> Result<(), ConfigError> {
    let regulation = &oidc.regulation;
    if regulation.window_secs < 1 || regulation.window_secs > OIDC_MAX_LIFETIME_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.regulation.window_secs ({}) must be between 1 and \
                 {OIDC_MAX_LIFETIME_SECS} seconds",
                regulation.window_secs
            ),
        });
    }
    if regulation.soft_threshold < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.regulation.soft_threshold must be at least 1".to_owned(),
        });
    }
    if regulation.base_delay_secs < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.regulation.base_delay_secs must be at least 1 second".to_owned(),
        });
    }
    if regulation.max_delay_secs < regulation.base_delay_secs {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.regulation.max_delay_secs ({}) must be at least \
                 oidc.regulation.base_delay_secs ({})",
                regulation.max_delay_secs, regulation.base_delay_secs
            ),
        });
    }
    if regulation.hard_lockout_threshold < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.regulation.hard_lockout_threshold must be at least 1".to_owned(),
        });
    }
    if regulation.hard_lockout_duration_secs < 1
        || regulation.hard_lockout_duration_secs > OIDC_MAX_LIFETIME_SECS
    {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.regulation.hard_lockout_duration_secs ({}) must be between 1 and \
                 {OIDC_MAX_LIFETIME_SECS} seconds",
                regulation.hard_lockout_duration_secs
            ),
        });
    }
    Ok(())
}

/// Validate the minimal risk-engine settings (issue #79), kept out of
/// [`Config::validate`] so each stays within the readable-length lint. The bounds hold
/// even when the engine is off, so an out-of-band value cannot take effect the moment it
/// is enabled. The step-up threshold is a closed set, the velocity thresholds are ordered
/// and non-degenerate, the impossible-travel floor stays above ordinary travel, and the
/// disavowal TTL is bounded.
fn validate_risk(oidc: &OidcConfig) -> Result<(), ConfigError> {
    let risk = &oidc.risk;
    if !OIDC_RISK_THRESHOLDS.contains(&risk.require_mfa_at.as_str()) {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.risk.require_mfa_at ({}) must be one of off, low, med, high",
                risk.require_mfa_at
            ),
        });
    }
    if risk.velocity_window_secs < 1 || risk.velocity_window_secs > OIDC_MAX_LIFETIME_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.risk.velocity_window_secs ({}) must be between 1 and \
                 {OIDC_MAX_LIFETIME_SECS} seconds",
                risk.velocity_window_secs
            ),
        });
    }
    if risk.notify_cooldown_secs > OIDC_MAX_LIFETIME_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.risk.notify_cooldown_secs ({}) must be at most \
                 {OIDC_MAX_LIFETIME_SECS} seconds (0 disables the throttle)",
                risk.notify_cooldown_secs
            ),
        });
    }
    if risk.velocity_med_threshold < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.risk.velocity_med_threshold must be at least 1".to_owned(),
        });
    }
    if risk.velocity_high_threshold < risk.velocity_med_threshold {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.risk.velocity_high_threshold ({}) must be at least \
                 velocity_med_threshold ({})",
                risk.velocity_high_threshold, risk.velocity_med_threshold
            ),
        });
    }
    if risk.impossible_travel_kmh < OIDC_RISK_MIN_IMPOSSIBLE_TRAVEL_KMH {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.risk.impossible_travel_kmh ({}) must be at least \
                 {OIDC_RISK_MIN_IMPOSSIBLE_TRAVEL_KMH} km/h",
                risk.impossible_travel_kmh
            ),
        });
    }
    if !(OIDC_RISK_MIN_DISAVOWAL_TTL_SECS..=OIDC_RISK_MAX_DISAVOWAL_TTL_SECS)
        .contains(&risk.disavowal_ttl_secs)
    {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.risk.disavowal_ttl_secs ({}) must be between \
                 {OIDC_RISK_MIN_DISAVOWAL_TTL_SECS} and {OIDC_RISK_MAX_DISAVOWAL_TTL_SECS} seconds",
                risk.disavowal_ttl_secs
            ),
        });
    }
    Ok(())
}

/// Validate the registration abuse defenses (issue #80), kept out of
/// [`Config::validate`] so each stays within the readable-length lint. Bounds the `PoW`
/// difficulty and TTL, pins the `PoW` challenge threshold to the closed #79 risk set, and
/// pins the disposable-email mode to its closed set, so a misconfiguration is a boot-time
/// error rather than a per-request surprise.
fn validate_registration_abuse(oidc: &OidcConfig) -> Result<(), ConfigError> {
    let pow = &oidc.registration_abuse.pow;
    if !OIDC_RISK_THRESHOLDS.contains(&pow.challenge_at.as_str()) {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.registration_abuse.pow.challenge_at ({}) must be one of off, low, med, high",
                pow.challenge_at
            ),
        });
    }
    if !(OIDC_POW_MIN_DIFFICULTY_BITS..=OIDC_POW_MAX_DIFFICULTY_BITS).contains(&pow.difficulty_bits)
    {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.registration_abuse.pow.difficulty_bits ({}) must be between \
                 {OIDC_POW_MIN_DIFFICULTY_BITS} and {OIDC_POW_MAX_DIFFICULTY_BITS} leading zero bits",
                pow.difficulty_bits
            ),
        });
    }
    if pow.challenge_ttl_secs < 1 || pow.challenge_ttl_secs > OIDC_MAX_LIFETIME_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.registration_abuse.pow.challenge_ttl_secs ({}) must be between 1 and \
                 {OIDC_MAX_LIFETIME_SECS} seconds",
                pow.challenge_ttl_secs
            ),
        });
    }
    let mode = oidc.registration_abuse.disposable_email.mode.as_str();
    if !OIDC_DISPOSABLE_EMAIL_MODES.contains(&mode) {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.registration_abuse.disposable_email.mode ({mode}) must be one of \
                 off, flag, block"
            ),
        });
    }
    Ok(())
}

/// Validate the TOTP second-factor settings (issue #69), kept out of
/// [`Config::validate`] so each stays within the readable-length lint. Bounds the
/// parameters (digits, period, drift window, recovery-code count) to the ranges the
/// `ironauth-jose` primitive and the schema accept, and checks the factor order is a
/// duplicate-free subset of the closed factor set, so a misconfiguration is a
/// boot-time error rather than a per-request surprise.
fn validate_totp(oidc: &OidcConfig) -> Result<(), ConfigError> {
    if !(6..=8).contains(&oidc.totp_digits) {
        return Err(ConfigError::Invalid {
            message: format!("oidc.totp_digits ({}) must be in 6..=8", oidc.totp_digits),
        });
    }
    if !(15..=60).contains(&oidc.totp_period_secs) {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.totp_period_secs ({}) must be in 15..=60",
                oidc.totp_period_secs
            ),
        });
    }
    if oidc.totp_drift_steps > 2 {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.totp_drift_steps ({}) must be at most 2 (plus or minus two \
                 periods); a wider window aids brute force",
                oidc.totp_drift_steps
            ),
        });
    }
    if !(8..=16).contains(&oidc.totp_recovery_code_count) {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.totp_recovery_code_count ({}) must be in 8..=16",
                oidc.totp_recovery_code_count
            ),
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    for factor in &oidc.mfa_factor_order {
        if !matches!(factor.as_str(), "passkey" | "totp" | "password") {
            return Err(ConfigError::Invalid {
                message: format!(
                    "oidc.mfa_factor_order contains an unknown factor '{factor}'; the closed \
                     set is passkey, totp, password"
                ),
            });
        }
        if !seen.insert(factor.clone()) {
            return Err(ConfigError::Invalid {
                message: format!(
                    "oidc.mfa_factor_order lists '{factor}' more than once; each factor appears \
                     at most once"
                ),
            });
        }
    }
    // The step-up acr order (issue #72) must be a PERMUTATION of the canonical rung set
    // ([`OIDC_DEFAULT_ACR_ORDER`]): no unknown value (a silently-unranked floor), no
    // duplicate (an ambiguous rank comparison), and every known rung present (so nothing
    // the ladder can ACHIEVE is left unranked, which would fail closed and spuriously
    // block a legitimate login). An EMPTY list is allowed: it falls back to the canonical
    // order at read time.
    if !oidc.acr_order.is_empty() {
        let known: std::collections::BTreeSet<&str> =
            OIDC_DEFAULT_ACR_ORDER.iter().copied().collect();
        let mut seen_acr = std::collections::BTreeSet::new();
        for acr in &oidc.acr_order {
            if !known.contains(acr.as_str()) {
                return Err(ConfigError::Invalid {
                    message: format!(
                        "oidc.acr_order contains an unknown acr '{acr}'; the known rungs are \
                         {OIDC_DEFAULT_ACR_ORDER:?}"
                    ),
                });
            }
            if !seen_acr.insert(acr.as_str()) {
                return Err(ConfigError::Invalid {
                    message: format!(
                        "oidc.acr_order lists '{acr}' more than once; each acr appears at most once"
                    ),
                });
            }
        }
        if seen_acr.len() != known.len() {
            return Err(ConfigError::Invalid {
                message: format!(
                    "oidc.acr_order must rank every known acr (a permutation of \
                     {OIDC_DEFAULT_ACR_ORDER:?}); otherwise an achievable level is left \
                     unranked and would fail closed"
                ),
            });
        }
        // The remembered-device honesty floor (issue #71): `mfa_remembered` MUST rank
        // strictly BELOW `mfa`, so a remembered device (which attests only a PRIOR second
        // factor) can never satisfy a genuine `mfa` step-up floor. Both are guaranteed
        // present by the permutation check above.
        let rank = |value: &str| oidc.acr_order.iter().position(|acr| acr == value);
        if let (Some(remembered_rank), Some(mfa_rank)) =
            (rank(OIDC_ACR_MFA_REMEMBERED), rank(OIDC_ACR_MFA))
        {
            if remembered_rank >= mfa_rank {
                return Err(ConfigError::Invalid {
                    message: format!(
                        "oidc.acr_order must rank '{OIDC_ACR_MFA_REMEMBERED}' strictly below \
                         '{OIDC_ACR_MFA}': a remembered device attests only a prior second \
                         factor and must never satisfy a genuine mfa step-up floor"
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Validate the email-OTP and scanner-safe magic-link settings (issue #68), kept out of
/// [`Config::validate`] so each stays within the readable-length lint. Every bound has a
/// safe default in range, so an empty configuration is valid.
///
/// # Errors
///
/// [`ConfigError::Invalid`] if any parameter is outside its documented range.
/// Validate the remembered-device (trusted-device) duration policy (issue #71): the
/// absolute max age must sit inside the accepted band, and the idle window must be at
/// least the floor and no wider than the absolute max age (an idle window wider than the
/// absolute cap is meaningless). The bounds hold even when the feature is off, so a
/// deployment cannot ship an out-of-band value that would take effect the moment it is
/// enabled.
fn validate_trusted_device(oidc: &OidcConfig) -> Result<(), ConfigError> {
    if !(OIDC_TRUSTED_DEVICE_MIN_MAX_AGE_SECS..=OIDC_TRUSTED_DEVICE_MAX_MAX_AGE_SECS)
        .contains(&oidc.trusted_device_max_age_secs)
    {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.trusted_device_max_age_secs ({}) must be in \
                 {OIDC_TRUSTED_DEVICE_MIN_MAX_AGE_SECS}..={OIDC_TRUSTED_DEVICE_MAX_MAX_AGE_SECS} \
                 (up to the NIST SP 800-63B 30-day reauthentication ceiling)",
                oidc.trusted_device_max_age_secs
            ),
        });
    }
    if oidc.trusted_device_idle_secs < OIDC_TRUSTED_DEVICE_MIN_IDLE_SECS
        || oidc.trusted_device_idle_secs > oidc.trusted_device_max_age_secs
    {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.trusted_device_idle_secs ({}) must be at least \
                 {OIDC_TRUSTED_DEVICE_MIN_IDLE_SECS} and no greater than \
                 oidc.trusted_device_max_age_secs ({})",
                oidc.trusted_device_idle_secs, oidc.trusted_device_max_age_secs
            ),
        });
    }
    Ok(())
}

fn validate_email_otp(oidc: &OidcConfig) -> Result<(), ConfigError> {
    if !(6..=8).contains(&oidc.email_otp_code_digits) {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.email_otp_code_digits ({}) must be in 6..=8",
                oidc.email_otp_code_digits
            ),
        });
    }
    if !(OIDC_EMAIL_OTP_MIN_TTL_SECS..=OIDC_EMAIL_OTP_MAX_TTL_SECS)
        .contains(&oidc.email_otp_code_ttl_secs)
    {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.email_otp_code_ttl_secs ({}) must be in \
                 {OIDC_EMAIL_OTP_MIN_TTL_SECS}..={OIDC_EMAIL_OTP_MAX_TTL_SECS} (the 5-10 \
                 minute band)",
                oidc.email_otp_code_ttl_secs
            ),
        });
    }
    if oidc.email_otp_max_attempts < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.email_otp_max_attempts must be at least 1".to_owned(),
        });
    }
    if !(6..=8).contains(&oidc.magic_link_short_code_digits) {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.magic_link_short_code_digits ({}) must be in 6..=8",
                oidc.magic_link_short_code_digits
            ),
        });
    }
    if !(OIDC_EMAIL_OTP_MIN_TTL_SECS..=OIDC_MAGIC_LINK_MAX_TTL_SECS)
        .contains(&oidc.magic_link_ttl_secs)
    {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.magic_link_ttl_secs ({}) must be in \
                 {OIDC_EMAIL_OTP_MIN_TTL_SECS}..={OIDC_MAGIC_LINK_MAX_TTL_SECS}",
                oidc.magic_link_ttl_secs
            ),
        });
    }
    Ok(())
}

/// Validate the guarded SMS-OTP settings (issue #70), kept out of [`Config::validate`]
/// so each stays within the readable-length lint. Every bound has a safe default in
/// range, so an empty configuration is valid (and leaves SMS OFF).
///
/// # Errors
///
/// [`ConfigError::Invalid`] if any parameter is outside its documented range.
fn validate_sms_otp(oidc: &OidcConfig) -> Result<(), ConfigError> {
    let invalid = |message: String| Err(ConfigError::Invalid { message });
    if !(6..=8).contains(&oidc.sms_otp_code_digits) {
        return invalid(format!(
            "oidc.sms_otp_code_digits ({}) must be in 6..=8",
            oidc.sms_otp_code_digits
        ));
    }
    if !(OIDC_SMS_OTP_MIN_TTL_SECS..=OIDC_SMS_OTP_MAX_TTL_SECS)
        .contains(&oidc.sms_otp_code_ttl_secs)
    {
        return invalid(format!(
            "oidc.sms_otp_code_ttl_secs ({}) must be in \
             {OIDC_SMS_OTP_MIN_TTL_SECS}..={OIDC_SMS_OTP_MAX_TTL_SECS}",
            oidc.sms_otp_code_ttl_secs
        ));
    }
    if oidc.sms_otp_max_attempts < 1 {
        return invalid("oidc.sms_otp_max_attempts must be at least 1".to_owned());
    }
    // Every velocity cap, window, and cooldown must be a positive quantity: a zero cap
    // or window would make the counter meaningless (a zero window rolls every call).
    for (name, value) in [
        (
            "oidc.sms_per_number_send_cap",
            u64::from(oidc.sms_per_number_send_cap),
        ),
        (
            "oidc.sms_per_number_window_secs",
            oidc.sms_per_number_window_secs,
        ),
        ("oidc.sms_send_cooldown_secs", oidc.sms_send_cooldown_secs),
        (
            "oidc.sms_per_tenant_send_cap",
            u64::from(oidc.sms_per_tenant_send_cap),
        ),
        (
            "oidc.sms_per_tenant_window_secs",
            oidc.sms_per_tenant_window_secs,
        ),
        (
            "oidc.sms_per_route_send_cap",
            u64::from(oidc.sms_per_route_send_cap),
        ),
        (
            "oidc.sms_per_route_window_secs",
            oidc.sms_per_route_window_secs,
        ),
        (
            "oidc.sms_conversion_window_secs",
            oidc.sms_conversion_window_secs,
        ),
        (
            "oidc.sms_conversion_min_samples",
            u64::from(oidc.sms_conversion_min_samples),
        ),
        ("oidc.sms_route_throttle_secs", oidc.sms_route_throttle_secs),
    ] {
        if value < 1 {
            return invalid(format!("{name} must be at least 1"));
        }
    }
    if !(1..=100).contains(&oidc.sms_conversion_alarm_threshold_percent) {
        return invalid(format!(
            "oidc.sms_conversion_alarm_threshold_percent ({}) must be in 1..=100",
            oidc.sms_conversion_alarm_threshold_percent
        ));
    }
    Ok(())
}

/// Validate the password-hashing settings (issue #62), kept out of
/// [`Config::validate`] so each stays within the readable-length lint.
///
/// The Argon2id parameters are bounded so a tuning mistake can neither ship a
/// hash weaker than a defensible floor nor one so costly it would exhaust host
/// memory or wedge the pool; the pool sizing and probe target are bounded to
/// sane operational ranges. Every bound has a safe default in range, so an empty
/// `[password_hashing]` table (or none at all) is valid.
///
/// # Errors
///
/// [`ConfigError::Invalid`] if any parameter is outside its documented range.
fn validate_password_hashing(hashing: &PasswordHashingConfig) -> Result<(), ConfigError> {
    if !(PASSWORD_HASHING_MIN_MEMORY_KIB..=PASSWORD_HASHING_MAX_MEMORY_KIB)
        .contains(&hashing.memory_kib)
    {
        return Err(ConfigError::Invalid {
            message: format!(
                "password_hashing.memory_kib ({}) must be between \
                 {PASSWORD_HASHING_MIN_MEMORY_KIB} and {PASSWORD_HASHING_MAX_MEMORY_KIB} KiB",
                hashing.memory_kib
            ),
        });
    }
    if hashing.iterations < 1 || hashing.iterations > PASSWORD_HASHING_MAX_ITERATIONS {
        return Err(ConfigError::Invalid {
            message: format!(
                "password_hashing.iterations ({}) must be between 1 and \
                 {PASSWORD_HASHING_MAX_ITERATIONS}",
                hashing.iterations
            ),
        });
    }
    if hashing.parallelism < 1 || hashing.parallelism > PASSWORD_HASHING_MAX_PARALLELISM {
        return Err(ConfigError::Invalid {
            message: format!(
                "password_hashing.parallelism ({}) must be between 1 and \
                 {PASSWORD_HASHING_MAX_PARALLELISM}",
                hashing.parallelism
            ),
        });
    }
    if hashing.pool_threads > PASSWORD_HASHING_MAX_POOL_THREADS {
        return Err(ConfigError::Invalid {
            message: format!(
                "password_hashing.pool_threads ({}) must not exceed \
                 {PASSWORD_HASHING_MAX_POOL_THREADS} (0 derives from the host core count)",
                hashing.pool_threads
            ),
        });
    }
    if hashing.max_queue_depth < 1 {
        return Err(ConfigError::Invalid {
            message: "password_hashing.max_queue_depth must be at least 1".to_owned(),
        });
    }
    if !(PASSWORD_HASHING_MIN_PROBE_TARGET_LATENCY_MS
        ..=PASSWORD_HASHING_MAX_PROBE_TARGET_LATENCY_MS)
        .contains(&hashing.probe_target_latency_ms)
    {
        return Err(ConfigError::Invalid {
            message: format!(
                "password_hashing.probe_target_latency_ms ({}) must be between \
                 {PASSWORD_HASHING_MIN_PROBE_TARGET_LATENCY_MS} and \
                 {PASSWORD_HASHING_MAX_PROBE_TARGET_LATENCY_MS} milliseconds",
                hashing.probe_target_latency_ms
            ),
        });
    }
    Ok(())
}

/// Validate the breached-password screening and 800-63B-4 policy settings (issue #63),
/// kept out of [`Config::validate`] for readability. The numeric bounds ensure a policy
/// is always usable (a minimum never exceeds the maximum, lengths are non-zero and
/// bounded); the 63B-4 SHALLs (15 / 8 / 64) are DEFAULTS, not floors, so a lower value
/// is accepted and surfaced as a deviation rather than refused. A provider that needs an
/// input (the offline corpus path, an https HIBP base) is checked so a misconfiguration
/// fails fast at boot rather than silently screening nothing.
///
/// # Errors
///
/// [`ConfigError::Invalid`] if a length is zero, a minimum exceeds the maximum, the
/// maximum exceeds the ceiling, the rotation interval exceeds its ceiling, an alternate
/// HIBP base is not https, or the offline provider is selected with no corpus path.
fn validate_password_policy(policy: &PasswordPolicyConfig) -> Result<(), ConfigError> {
    if policy.min_length_sole_factor < 1 {
        return Err(ConfigError::Invalid {
            message: "password_policy.min_length_sole_factor must be at least 1".to_owned(),
        });
    }
    if policy.min_length_mfa_factor < 1 {
        return Err(ConfigError::Invalid {
            message: "password_policy.min_length_mfa_factor must be at least 1".to_owned(),
        });
    }
    if !(1..=PASSWORD_POLICY_MAX_LENGTH_CEILING).contains(&policy.max_length) {
        return Err(ConfigError::Invalid {
            message: format!(
                "password_policy.max_length ({}) must be between 1 and \
                 {PASSWORD_POLICY_MAX_LENGTH_CEILING}",
                policy.max_length
            ),
        });
    }
    if policy.min_length_sole_factor > policy.max_length {
        return Err(ConfigError::Invalid {
            message: format!(
                "password_policy.min_length_sole_factor ({}) must not exceed \
                 password_policy.max_length ({})",
                policy.min_length_sole_factor, policy.max_length
            ),
        });
    }
    if policy.min_length_mfa_factor > policy.max_length {
        return Err(ConfigError::Invalid {
            message: format!(
                "password_policy.min_length_mfa_factor ({}) must not exceed \
                 password_policy.max_length ({})",
                policy.min_length_mfa_factor, policy.max_length
            ),
        });
    }
    if policy.min_password_strength_score > 4 {
        return Err(ConfigError::Invalid {
            message: format!(
                "password_policy.min_password_strength_score ({}) must be between 0 and 4 \
                 (0 disables strength scoring)",
                policy.min_password_strength_score
            ),
        });
    }
    if policy.rotation_max_age_days > PASSWORD_POLICY_MAX_ROTATION_DAYS {
        return Err(ConfigError::Invalid {
            message: format!(
                "password_policy.rotation_max_age_days ({}) must not exceed \
                 {PASSWORD_POLICY_MAX_ROTATION_DAYS} (0 disables forced rotation)",
                policy.rotation_max_age_days
            ),
        });
    }
    if let Some(base) = &policy.hibp_base_url {
        if !base.starts_with("https://") {
            return Err(ConfigError::Invalid {
                message: format!("password_policy.hibp_base_url ({base}) must be an https URL"),
            });
        }
    }
    // The offline provider needs a corpus; screening enabled with the offline provider
    // and no dataset would silently screen NOTHING, so fail fast at config load.
    if policy.screening_enabled
        && policy.screening_provider == ScreeningProvider::Offline
        && policy.offline_corpus_path.is_none()
    {
        return Err(ConfigError::Invalid {
            message: "password_policy.offline_corpus_path must be set when \
                      screening_provider is 'offline' and screening_enabled is true"
                .to_owned(),
        });
    }
    Ok(())
}

/// Validate the WebAuthn passkey settings (issue #65), kept out of
/// [`Config::validate`] for readability.
///
/// The challenge lifetime is bounded like the other credential lifetimes. The RP
/// ID is validated against the serving origin at STARTUP so a misconfiguration is
/// a boot-time error, never a per-ceremony runtime surprise: when
/// `oidc.webauthn_rp_id` is set, `server.public_url` must be set and the RP ID must
/// be the serving origin's host or a parent (registrable-suffix) domain of it (an
/// authenticator scopes a credential to a registrable-domain suffix of the origin;
/// an RP ID that is not such a suffix would make every ceremony fail at runtime).
///
/// # Errors
///
/// [`ConfigError::Invalid`] if the challenge lifetime is out of range, or the RP ID
/// is set without a serving origin or is not a suffix of the origin host.
fn validate_webauthn(oidc: &OidcConfig, server: &ServerConfig) -> Result<(), ConfigError> {
    check_oidc_lifetime(
        "oidc.webauthn_challenge_ttl_secs",
        oidc.webauthn_challenge_ttl_secs,
    )?;
    // The MDS3 BLOB endpoint override (issue #66, PR B) rides the SSRF-hardened outbound
    // fetch path, so a plaintext override is refused at load, mirroring the HIBP base-URL
    // rule. Validated regardless of webauthn_enabled so a misconfiguration is caught even
    // when the surface is off.
    if let Some(base) = &oidc.mds3_base_url {
        if !base.starts_with("https://") {
            return Err(ConfigError::Invalid {
                message: format!("oidc.mds3_base_url ({base}) must be an https URL"),
            });
        }
    }
    if !oidc.webauthn_enabled {
        return Ok(());
    }
    if let Some(rp_id) = oidc.webauthn_rp_id.as_deref() {
        if rp_id.is_empty() {
            return Err(ConfigError::Invalid {
                message: "oidc.webauthn_rp_id must not be empty when set".to_owned(),
            });
        }
        // A single-label RP ID (no dot, for example a bare TLD like `com`) is never
        // a valid relying-party identifier: the browser rejects it at ceremony time
        // against the effective-TLD+1 rule, so accepting it here would defer a boot
        // misconfiguration to a runtime ceremony failure. `localhost` is the one
        // single-label exception (the dev origin). A registrable domain must contain
        // a dot; the browser enforces the full public-suffix rule, this catches the
        // outright-invalid case cheaply without a public-suffix-list dependency.
        if rp_id != "localhost" && !rp_id.contains('.') {
            return Err(ConfigError::Invalid {
                message: format!(
                    "oidc.webauthn_rp_id ({rp_id}) is a single-label identifier; it must be a \
                     registrable domain (containing a dot, for example auth.example.com) or the \
                     dev value 'localhost'. A bare label like a TLD fails every ceremony in the \
                     browser"
                ),
            });
        }
        let Some(public_url) = server.public_url.as_deref() else {
            return Err(ConfigError::Invalid {
                message: "oidc.webauthn_rp_id is set but server.public_url is not: the RP ID \
                          must be validated against the serving origin, so the origin must be \
                          configured"
                    .to_owned(),
            });
        };
        let Some(host) = uri_host(public_url) else {
            return Err(ConfigError::Invalid {
                message: "server.public_url has no parseable host to validate \
                          oidc.webauthn_rp_id against"
                    .to_owned(),
            });
        };
        // The RP ID must be the origin host or a parent domain of it (a
        // registrable-domain suffix). The browser enforces the effective-TLD+1
        // rule at ceremony time; this startup check catches an outright mismatch.
        let is_suffix = host == rp_id || host.ends_with(&format!(".{rp_id}"));
        if !is_suffix {
            return Err(ConfigError::Invalid {
                message: format!(
                    "oidc.webauthn_rp_id ({rp_id}) must be the serving origin host ({host}) \
                     or a parent domain of it; an RP ID outside the origin's registrable \
                     domain fails every ceremony at runtime"
                ),
            });
        }
    }
    validate_webauthn_related_origins(oidc)?;
    Ok(())
}

/// The browser related-origin label budget (issue #67): current implementations
/// (Chrome, Safari) accept a `/.well-known/webauthn` document that spans at most
/// this many DISTINCT registrable labels, silently ignoring origins beyond it.
/// This is ADVISORY: the browser is the real enforcer of its own cap, so an estate
/// that reaches or exceeds this budget emits a [`Warning`], never a boot error.
pub(crate) const WEBAUTHN_RELATED_ORIGIN_LABEL_BUDGET: usize = 5;

/// A curated set of common multi-label public suffixes (issue #67). A browser groups
/// related origins by the leading label of the registrable domain (the eTLD+1), so
/// `example.co.uk` is the label `example`, not `co.uk`. To approximate that leading
/// label without a heavy public-suffix-list dependency (which the repo deliberately
/// avoids), we treat a host whose last two labels appear here as having a two-label
/// public suffix. This is a CONSERVATIVE approximation for an advisory soft-guard: an
/// uncommon multi-label suffix not listed here is treated as a single-label suffix, so
/// the label count may be off for exotic ccTLD structures; the browser enforces the
/// real limit. It is deliberately short and covers the common ccTLD second levels.
const WEBAUTHN_COMMON_MULTI_LABEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "co.jp", "or.jp", "ne.jp", "ac.jp",
    "go.jp", "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz", "co.za", "org.za", "com.br",
    "net.br", "org.br", "gov.br", "com.mx", "org.mx", "gob.mx", "co.in", "net.in", "org.in",
    "gov.in", "ac.in", "com.cn", "net.cn", "org.cn", "gov.cn", "com.sg", "com.tr", "com.ar",
    "com.hk", "co.kr", "co.il", "co.id", "com.tw",
];

/// Validate the WebAuthn related origins (issue #67, WebAuthn Level 3 Related Origin
/// Requests). Each entry must be a well-formed https origin. The label-budget check
/// is NOT here: it is advisory (a [`Warning`] in [`Config::collect_warnings`]), not a
/// boot error, because the browser enforces its own label cap and an over-budget error
/// would wrongly reject a valid one-brand-many-ccTLD estate.
///
/// # Errors
///
/// [`ConfigError::Invalid`] if a related origin is not a well-formed https origin.
fn validate_webauthn_related_origins(oidc: &OidcConfig) -> Result<(), ConfigError> {
    for origin in &oidc.webauthn_related_origins {
        if !is_well_formed_https_origin(origin) {
            return Err(ConfigError::Invalid {
                message: format!(
                    "oidc.webauthn_related_origins entry ({origin}) is not a well-formed https \
                     origin; a related origin must be an absolute https origin of the form \
                     scheme://host[:port] with a numeric port, no trailing-dot or bracketed-IP \
                     host, and no path, query, or fragment"
                ),
            });
        }
    }
    Ok(())
}

/// The set of distinct registrable labels the well-known document would span: the
/// serving origin's label (when a `server.public_url` is configured) plus each
/// related origin's. Used for the browser label-budget check (issue #67).
fn webauthn_related_origin_labels(oidc: &OidcConfig, server: &ServerConfig) -> BTreeSet<String> {
    let mut labels = BTreeSet::new();
    if let Some(host) = server.public_url.as_deref().and_then(uri_host) {
        labels.insert(registrable_domain_label(&host));
    }
    for origin in &oidc.webauthn_related_origins {
        if let Some(host) = uri_host(origin) {
            labels.insert(registrable_domain_label(&host));
        }
    }
    labels
}

/// The registrable-domain label of a host: the leading label of the eTLD+1, which is
/// how a browser groups related origins for its label budget (issue #67). For
/// `auth.example.com` and `example.de` and `example.co.uk` this is `example`, so one
/// brand across many ccTLDs counts as ONE label (the feature's headline estate), while
/// `a.co.uk` and `b.co.uk` are the distinct labels `a` and `b`.
///
/// The eTLD is approximated from a curated common multi-label suffix table
/// ([`WEBAUTHN_COMMON_MULTI_LABEL_SUFFIXES`]), defaulting to a single-label suffix; a
/// host that is itself a public suffix (or shorter) falls back to the whole host so
/// distinct suffix-only hosts still count distinctly. This is a conservative
/// approximation for an advisory soft-guard, NOT an authoritative registrable-domain
/// computation; the browser enforces the real label cap.
fn registrable_domain_label(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').filter(|label| !label.is_empty()).collect();
    if labels.is_empty() {
        return host;
    }
    let suffix_len = if labels.len() >= 2
        && WEBAUTHN_COMMON_MULTI_LABEL_SUFFIXES.contains(
            &format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]).as_str(),
        ) {
        2
    } else {
        1
    };
    // The registrable domain's leading label sits just before the public suffix.
    if labels.len() > suffix_len {
        labels[labels.len() - suffix_len - 1].to_owned()
    } else {
        // The host IS a public suffix (or shorter than one): no registrable label to
        // group by, so treat the whole host as its own distinct label.
        host
    }
}

/// Whether `origin` is a well-formed absolute https origin: `scheme://host[:port]`
/// with the https scheme, a non-empty host, no userinfo, and no path, query, or
/// fragment (issue #67). An origin is stricter than an endpoint URL: it carries no
/// path. Purely syntactic; it never resolves DNS or touches the network.
///
/// `http::Uri` is lenient about several malformed-but-inert authorities that no
/// browser ever emits as a `clientData.origin` (a non-numeric port
/// `https://host:notaport`, a trailing-root-dot host `https://host.`, a bracketed
/// IP-literal host `https://[::1]`). Those are dead weight in the allowlist rather
/// than an exploit, but a related origin must be a clean `https://host[:port]`, so we
/// reject them at load to keep the allowlist honest and the doc claim true.
fn is_well_formed_https_origin(origin: &str) -> bool {
    if origin.contains(|c: char| c.is_whitespace() || c.is_control()) || origin.contains('#') {
        return false;
    }
    let Ok(uri) = http::Uri::try_from(origin) else {
        return false;
    };
    if uri.scheme_str() != Some("https") || !matches!(uri.path(), "" | "/") || uri.query().is_some()
    {
        return false;
    }
    let Some(authority) = uri.authority().map(http::uri::Authority::as_str) else {
        return false;
    };
    if authority.contains('@') {
        return false;
    }
    let Some(host) = uri.host().filter(|host| !host.is_empty()) else {
        return false;
    };
    // Reject a bracketed IP-literal host (`[::1]`) and a trailing-root-dot host
    // (`host.`): both canonicalize to something no browser reports as an origin.
    if host.contains(['[', ']', ':']) || host.ends_with('.') {
        return false;
    }
    // Reject a non-numeric port. With userinfo already excluded, the authority is
    // `host[:port]`; a longer authority than the host means a `:port` suffix is
    // present, and it must parse as a valid numeric port (`http::Uri` keeps a
    // non-numeric port in the authority while returning `None` from `port_u16`).
    if authority.len() > host.len() && uri.port_u16().is_none() {
        return false;
    }
    true
}

/// The host of an absolute URL, or [`None`] if it does not parse or has no host.
fn uri_host(url: &str) -> Option<String> {
    http::Uri::try_from(url)
        .ok()
        .and_then(|uri| uri.host().map(str::to_owned))
}

/// Validate the inbound lazy-migration hook settings (issue #56), kept out of
/// [`Config::validate`] so each stays within the readable-length lint.
///
/// The breaker and timeout bounds are enforced ALWAYS (they have safe defaults in
/// range); the endpoint constraint (present and a well-formed absolute https URL) is
/// enforced only when the hook is `enabled`, so a disabled hook with no endpoint is a
/// valid, inert configuration. Validating the URL at config load is defense in depth: the
/// SSRF-hardened fetcher also refuses a plaintext target at call time, but a malformed
/// endpoint that would silently fail every login is caught at startup instead.
///
/// # Errors
///
/// [`ConfigError::Invalid`] if the hook is enabled without a well-formed absolute https
/// endpoint, the timeout is zero or above [`OIDC_MAX_LAZY_MIGRATION_TIMEOUT_SECS`], or a
/// breaker bound is zero.
fn validate_lazy_migration(oidc: &OidcConfig) -> Result<(), ConfigError> {
    let hook = &oidc.lazy_migration;
    if hook.enabled {
        match hook.endpoint.as_deref() {
            None => {
                return Err(ConfigError::Invalid {
                    message: "oidc.lazy_migration.endpoint must be set when \
                              oidc.lazy_migration.enabled is true"
                        .to_owned(),
                });
            }
            Some(endpoint) if !is_well_formed_https_endpoint(endpoint) => {
                // A malformed-but-https endpoint (`https://`, an embedded space, an
                // unterminated `[` host) must fail at LOAD, not silently fail every
                // unknown-identifier login at runtime and trip the breaker (criterion 6).
                return Err(ConfigError::Invalid {
                    message: "oidc.lazy_migration.endpoint must be a well-formed absolute \
                              https URL with a host (a plaintext http target or a malformed \
                              URL is refused; the hook rides the SSRF-hardened fetcher)"
                        .to_owned(),
                });
            }
            Some(_) => {}
        }
    }
    if hook.timeout_secs < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.lazy_migration.timeout_secs must be at least 1 second".to_owned(),
        });
    }
    if hook.timeout_secs > OIDC_MAX_LAZY_MIGRATION_TIMEOUT_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.lazy_migration.timeout_secs ({}) must not exceed \
                 {OIDC_MAX_LAZY_MIGRATION_TIMEOUT_SECS} seconds",
                hook.timeout_secs
            ),
        });
    }
    if hook.breaker_failure_threshold < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.lazy_migration.breaker_failure_threshold must be at least 1".to_owned(),
        });
    }
    if hook.breaker_window_secs < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.lazy_migration.breaker_window_secs must be at least 1 second".to_owned(),
        });
    }
    if hook.breaker_cooldown_secs < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.lazy_migration.breaker_cooldown_secs must be at least 1 second"
                .to_owned(),
        });
    }
    Ok(())
}

/// Validate the generic OIDC upstream federation settings (issue #75, PR B), kept out of
/// [`Config::validate`] so each stays within the readable-length lint. The TTL bounds are
/// enforced ALWAYS (they have safe in-range defaults), so a misconfigured cache window fails
/// fast at load even while federation is otherwise disabled.
///
/// # Errors
///
/// [`ConfigError::Invalid`] if a discovery / JWKS TTL is zero or above
/// [`OIDC_MAX_FEDERATION_TTL_SECS`].
fn validate_federation(oidc: &OidcConfig) -> Result<(), ConfigError> {
    let federation = &oidc.federation;
    for (name, value) in [
        ("discovery_ttl_secs", federation.discovery_ttl_secs),
        ("jwks_ttl_secs", federation.jwks_ttl_secs),
        (
            "health_probe_window_secs",
            federation.health_probe_window_secs,
        ),
    ] {
        if value < 1 {
            return Err(ConfigError::Invalid {
                message: format!("oidc.federation.{name} must be at least 1 second"),
            });
        }
        if value > OIDC_MAX_FEDERATION_TTL_SECS {
            return Err(ConfigError::Invalid {
                message: format!(
                    "oidc.federation.{name} ({value}) must not exceed \
                     {OIDC_MAX_FEDERATION_TTL_SECS} seconds"
                ),
            });
        }
    }
    // The manual-link fresh-re-auth window (issue #78, FORK C) has its own bound: a
    // freshness window beyond a day defeats the "fresh re-auth of the target" defense.
    let link_reauth = federation.link_reauth_max_age_secs;
    if link_reauth < 1 {
        return Err(ConfigError::Invalid {
            message: "oidc.federation.link_reauth_max_age_secs must be at least 1 second"
                .to_string(),
        });
    }
    if link_reauth > OIDC_MAX_LINK_REAUTH_MAX_AGE_SECS {
        return Err(ConfigError::Invalid {
            message: format!(
                "oidc.federation.link_reauth_max_age_secs ({link_reauth}) must not exceed \
                 {OIDC_MAX_LINK_REAUTH_MAX_AGE_SECS} seconds"
            ),
        });
    }
    Ok(())
}

/// Whether `endpoint` is a well-formed absolute https URL with a non-empty host and no
/// userinfo: the syntactic gate the lazy-migration endpoint must pass at config LOAD.
///
/// Parsing catches the structurally broken cases the old `starts_with("https://")` check
/// let through (`https://` with no host, `https://exa mple.test/verify` with an embedded
/// space, `https://[not-an-ip/verify` with an unterminated IPv6 literal), so a malformed
/// endpoint is a clear load error rather than a silent per-login failure at runtime. This
/// is purely syntactic: it never resolves DNS or touches the network (the SSRF-hardened
/// fetcher still applies its address policy at call time).
fn is_well_formed_https_endpoint(endpoint: &str) -> bool {
    // Whitespace and control characters are never valid in a URL; reject them up front so
    // an embedded space cannot slip through a lenient parse.
    if endpoint.contains(|c: char| c.is_whitespace() || c.is_control()) {
        return false;
    }
    http::Uri::try_from(endpoint).is_ok_and(|uri| {
        uri.scheme_str() == Some("https")
            && uri.host().is_some_and(|host| !host.is_empty())
            // Userinfo (`user:pass@host`) would smuggle a credential into the URL; refuse it.
            && uri.authority().is_some_and(|authority| !authority.as_str().contains('@'))
    })
}

/// Validate the quota fairness settings (issue #50), kept out of
/// [`Config::validate`] so each stays within the readable-length lint.
///
/// The limits themselves are free (a 0 burst is the documented unlimited form,
/// and any sustained rate is admissible), so the only structural constraint is
/// on the usage-threshold list: it is bounded in length, every entry is a real
/// percentage (1 to 100, since 0 percent would fire immediately and above 100 is
/// unreachable), and it carries no duplicates (a duplicate threshold would emit
/// the same saturation webhook twice).
fn validate_quota(quota: &QuotaConfig) -> Result<(), ConfigError> {
    let thresholds = &quota.usage_thresholds_percent;
    if thresholds.len() > QUOTA_MAX_USAGE_THRESHOLDS {
        return Err(ConfigError::Invalid {
            message: format!(
                "quota.usage_thresholds_percent has {} entries; at most \
                 {QUOTA_MAX_USAGE_THRESHOLDS} are allowed",
                thresholds.len()
            ),
        });
    }
    let mut seen = Vec::with_capacity(thresholds.len());
    for &threshold in thresholds {
        if !(1..=100).contains(&threshold) {
            return Err(ConfigError::Invalid {
                message: format!(
                    "quota.usage_thresholds_percent entry {threshold} must be between 1 and 100"
                ),
            });
        }
        if seen.contains(&threshold) {
            return Err(ConfigError::Invalid {
                message: format!(
                    "quota.usage_thresholds_percent contains a duplicate entry {threshold}"
                ),
            });
        }
        seen.push(threshold);
    }
    Ok(())
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

    // The issue #73 flag matrix: both exploratory features are OFF by default and are
    // independently toggleable per environment, so neither one turns the other on.
    #[test]
    fn issue_73_feature_flags_are_off_by_default() {
        let config = Config::from_toml_str("", "<inline>")
            .expect("empty config is valid")
            .config;
        assert!(
            !config.oidc.webauthn_signal_api_enabled,
            "the WebAuthn Signal API is off by default"
        );
        assert!(
            !config.oidc.webauthn_conditional_create_enabled,
            "conditional-create is off by default"
        );
        assert!(
            !config.admin.sudo_mode_enabled,
            "admin sudo mode is off by default"
        );
        // The supporting tunables keep their documented safe defaults.
        assert_eq!(
            config.oidc.webauthn_conditional_create_min_interval_secs,
            604_800
        );
        assert_eq!(config.admin.sudo_mode_window_secs, 600);
    }

    #[test]
    fn issue_73_feature_flags_toggle_independently() {
        // Turning the signal API on does not turn sudo mode on.
        let signal_only =
            Config::from_toml_str("[oidc]\nwebauthn_signal_api_enabled = true\n", "<inline>")
                .expect("valid")
                .config;
        assert!(signal_only.oidc.webauthn_signal_api_enabled);
        assert!(!signal_only.admin.sudo_mode_enabled);

        // Turning sudo mode on does not turn the signal API (or conditional-create) on.
        let sudo_only = Config::from_toml_str("[admin]\nsudo_mode_enabled = true\n", "<inline>")
            .expect("valid")
            .config;
        assert!(sudo_only.admin.sudo_mode_enabled);
        assert!(!sudo_only.oidc.webauthn_signal_api_enabled);
        assert!(!sudo_only.oidc.webauthn_conditional_create_enabled);
    }

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
    fn quota_section_defaults_and_validates_thresholds() {
        // Defaults: the per-tenant envelope is larger than the per-environment
        // share, and the saturation webhooks fire at 80 and 100 percent.
        let config = Config::from_toml_str("", "<inline>").expect("valid").config;
        assert_eq!(config.quota.tenant.requests_per_second, 500);
        assert_eq!(config.quota.tenant.requests_burst, 1_000);
        assert_eq!(config.quota.environment.requests_per_second, 100);
        assert_eq!(config.quota.environment.requests_burst, 200);
        assert_eq!(config.quota.usage_thresholds_percent, vec![80, 100]);
        // The idle-bucket reaper defaults to a one-hour window (issue #50).
        assert_eq!(config.quota.idle_bucket_ttl_secs, 3600);

        // A burst of 0 is the documented unlimited form for a self-hoster.
        let unlimited = "[quota.tenant]\nrequests_burst = 0\n";
        let config = Config::from_toml_str(unlimited, "<inline>")
            .expect("valid")
            .config;
        assert_eq!(config.quota.tenant.requests_burst, 0);

        // The reaper is disable-able (0) for operators who want process-lifetime
        // buckets; the key space is still bounded by verified tenancy.
        let no_reaper = "[quota]\nidle_bucket_ttl_secs = 0\n";
        let config = Config::from_toml_str(no_reaper, "<inline>")
            .expect("valid")
            .config;
        assert_eq!(config.quota.idle_bucket_ttl_secs, 0);

        // A threshold outside 1..=100 is rejected.
        let bad = "[quota]\nusage_thresholds_percent = [0, 80]\n";
        let err = Config::from_toml_str(bad, "ironauth.toml").expect_err("bad threshold");
        assert!(
            err.to_string().contains("usage_thresholds_percent"),
            "{err}"
        );

        // A duplicate threshold is rejected.
        let dup = "[quota]\nusage_thresholds_percent = [80, 80]\n";
        let err = Config::from_toml_str(dup, "ironauth.toml").expect_err("duplicate threshold");
        assert!(err.to_string().contains("duplicate"), "{err}");

        // Unknown quota keys abort with the accepted fields.
        let err = Config::from_toml_str("[quota.tenant]\nrps = 5\n", "ironauth.toml")
            .expect_err("unknown quota key");
        assert!(err.to_string().contains("requests_per_second"), "{err}");

        // The password-hashing dimension has safe defaults (issue #62).
        let config = Config::from_toml_str("", "<inline>").expect("valid").config;
        assert_eq!(config.quota.tenant.password_hashing_burst, 100);
        assert_eq!(config.quota.environment.password_hashing_burst, 40);
    }

    #[test]
    fn password_hashing_section_defaults_and_validates() {
        // Defaults: the OWASP Argon2id parameters and a derived pool (issue #62).
        let config = Config::from_toml_str("", "<inline>").expect("valid").config;
        assert_eq!(config.password_hashing.memory_kib, 19_456);
        assert_eq!(config.password_hashing.iterations, 2);
        assert_eq!(config.password_hashing.parallelism, 1);
        assert_eq!(config.password_hashing.pool_threads, 0); // derive from cores.
        assert_eq!(config.password_hashing.max_queue_depth, 512);
        assert_eq!(config.password_hashing.probe_target_latency_ms, 250);

        // A memory cost below the security floor is refused (no weaker-than-defensible
        // hash can ship).
        let weak = "[password_hashing]\nmemory_kib = 4096\n";
        let err = Config::from_toml_str(weak, "ironauth.toml").expect_err("below the floor");
        assert!(err.to_string().contains("memory_kib"), "{err}");

        // A memory cost above the 4 GiB ceiling is refused.
        let huge = "[password_hashing]\nmemory_kib = 5000000\n";
        let err = Config::from_toml_str(huge, "ironauth.toml").expect_err("above the ceiling");
        assert!(err.to_string().contains("memory_kib"), "{err}");

        // Zero iterations is refused (Argon2 needs at least one pass).
        let zero_t = "[password_hashing]\niterations = 0\n";
        let err = Config::from_toml_str(zero_t, "ironauth.toml").expect_err("zero iterations");
        assert!(err.to_string().contains("iterations"), "{err}");

        // A zero queue depth is refused (the pool must accept at least one job).
        let zero_q = "[password_hashing]\nmax_queue_depth = 0\n";
        let err = Config::from_toml_str(zero_q, "ironauth.toml").expect_err("zero queue");
        assert!(err.to_string().contains("max_queue_depth"), "{err}");

        // A probe target latency outside the range is refused.
        let bad_target = "[password_hashing]\nprobe_target_latency_ms = 1\n";
        let err = Config::from_toml_str(bad_target, "ironauth.toml").expect_err("target too low");
        assert!(err.to_string().contains("probe_target_latency_ms"), "{err}");

        // A valid tuned configuration loads.
        let tuned = "[password_hashing]\nmemory_kib = 12288\niterations = 3\nparallelism = 2\n\
                     pool_threads = 4\nmax_queue_depth = 256\nprobe_target_latency_ms = 500\n";
        let config = Config::from_toml_str(tuned, "<inline>")
            .expect("valid tuned config")
            .config;
        assert_eq!(config.password_hashing.memory_kib, 12_288);
        assert_eq!(config.password_hashing.iterations, 3);
        assert_eq!(config.password_hashing.parallelism, 2);
        assert_eq!(config.password_hashing.pool_threads, 4);

        // Unknown keys abort with the accepted fields.
        let err = Config::from_toml_str("[password_hashing]\nmem = 5\n", "ironauth.toml")
            .expect_err("unknown key");
        assert!(err.to_string().contains("memory_kib"), "{err}");
    }

    #[test]
    fn webauthn_rp_id_is_validated_against_the_serving_origin_at_startup() {
        // An RP ID that is the origin host is accepted.
        let ok = "[server]\npublic_url = \"https://auth.example.com\"\n\
                  [oidc]\nwebauthn_rp_id = \"auth.example.com\"\n";
        assert!(Config::from_toml_str(ok, "ironauth.toml").is_ok());

        // A parent (registrable-suffix) domain is accepted.
        let parent = "[server]\npublic_url = \"https://auth.example.com\"\n\
                      [oidc]\nwebauthn_rp_id = \"example.com\"\n";
        assert!(Config::from_toml_str(parent, "ironauth.toml").is_ok());

        // An RP ID outside the origin's domain is a STARTUP error.
        let bad = "[server]\npublic_url = \"https://auth.example.com\"\n\
                   [oidc]\nwebauthn_rp_id = \"evil.test\"\n";
        let err = Config::from_toml_str(bad, "ironauth.toml").expect_err("mismatched rp id");
        assert!(err.to_string().contains("webauthn_rp_id"), "{err}");

        // An RP ID set without a serving origin is a STARTUP error.
        let no_origin = "[oidc]\nwebauthn_rp_id = \"auth.example.com\"\n";
        let err =
            Config::from_toml_str(no_origin, "ironauth.toml").expect_err("rp id without origin");
        assert!(err.to_string().contains("server.public_url"), "{err}");

        // Unset RP ID (derive from origin) is valid.
        let derived = "[server]\npublic_url = \"https://auth.example.com\"\n";
        assert!(Config::from_toml_str(derived, "ironauth.toml").is_ok());
    }

    #[test]
    fn a_single_label_public_suffix_rp_id_is_a_startup_error() {
        // A bare TLD/public suffix (`com`) is a suffix of `auth.example.com`, so the
        // old ends_with heuristic accepted it; the browser then rejects it at
        // ceremony time. It must now be a BOOT error.
        let bare_tld = "[server]\npublic_url = \"https://auth.example.com\"\n\
                        [oidc]\nwebauthn_rp_id = \"com\"\n";
        let err = Config::from_toml_str(bare_tld, "ironauth.toml").expect_err("single-label rp id");
        assert!(err.to_string().contains("single-label"), "{err}");

        // A valid registrable domain still loads.
        let registrable = "[server]\npublic_url = \"https://auth.example.com\"\n\
                           [oidc]\nwebauthn_rp_id = \"example.com\"\n";
        assert!(Config::from_toml_str(registrable, "ironauth.toml").is_ok());

        // `localhost` (the single-label dev exception) still loads.
        let localhost = "[server]\npublic_url = \"http://localhost:8080\"\n\
                         [oidc]\nwebauthn_rp_id = \"localhost\"\n";
        assert!(Config::from_toml_str(localhost, "ironauth.toml").is_ok());
    }

    #[test]
    fn webauthn_related_origins_validate_as_https_origins() {
        // A well-formed cross-registrable-domain related origin loads (the multi-brand
        // estate the related-origin document is for).
        let ok = "[server]\npublic_url = \"https://auth.example.com\"\n\
                  [oidc]\nwebauthn_rp_id = \"example.com\"\n\
                  webauthn_related_origins = [\"https://example.de\", \"https://brand2.com\"]\n";
        let loaded = Config::from_toml_str(ok, "ironauth.toml").expect("valid related origins");
        assert_eq!(
            loaded.config.oidc.webauthn_related_origins,
            vec![
                "https://example.de".to_owned(),
                "https://brand2.com".to_owned()
            ]
        );

        // A non-https origin is a boot error.
        let http = "[server]\npublic_url = \"https://auth.example.com\"\n\
                    [oidc]\nwebauthn_related_origins = [\"http://example.de\"]\n";
        let err = Config::from_toml_str(http, "ironauth.toml").expect_err("http origin");
        assert!(
            err.to_string().contains("well-formed https origin"),
            "{err}"
        );

        // An origin carrying a path is not an origin; boot error.
        let path = "[server]\npublic_url = \"https://auth.example.com\"\n\
                    [oidc]\nwebauthn_related_origins = [\"https://example.de/login\"]\n";
        let err = Config::from_toml_str(path, "ironauth.toml").expect_err("origin with path");
        assert!(
            err.to_string().contains("well-formed https origin"),
            "{err}"
        );

        // LOW-2 (issue #67 review): malformed-but-inert forms `http::Uri` tolerates are
        // now rejected at load so the allowlist is clean and the doc claim is true. Each
        // canonicalizes to something no browser reports as clientData.origin.
        for bad in [
            "https://example.de:notaport", // non-numeric port
            "https://example.de.",         // trailing-root-dot host
            "https://[::1]",               // bracketed IP-literal host
            "https://[::1]:8443",          // bracketed IP-literal host with port
        ] {
            let toml = format!(
                "[server]\npublic_url = \"https://auth.example.com\"\n\
                 [oidc]\nwebauthn_related_origins = [\"{bad}\"]\n"
            );
            let err = Config::from_toml_str(&toml, "ironauth.toml")
                .expect_err(&format!("{bad} must be rejected at load"));
            assert!(
                err.to_string().contains("well-formed https origin"),
                "{bad}: {err}"
            );
        }

        // Valid `https://host` and `https://host:port` still load.
        let ports = "[server]\npublic_url = \"https://auth.example.com\"\n\
                     [oidc]\nwebauthn_related_origins = [\
                     \"https://example.de\", \"https://example.de:8443\"]\n";
        Config::from_toml_str(ports, "ironauth.toml").expect("host and host:port load");
    }

    #[test]
    fn webauthn_related_origins_label_budget_is_advisory_not_a_boot_error() {
        // The feature's HEADLINE estate: one brand across five ccTLDs (auth.example.com
        // plus example.de/.fr/.es/.it/.co.uk) is a SINGLE registrable label (`example`)
        // to a browser, so it must LOAD with no boot error and no label-budget warning.
        // The old last-two-labels count saw six labels here and wrongly boot-errored.
        let cctld = "[server]\npublic_url = \"https://auth.example.com\"\n\
                     [oidc]\nwebauthn_rp_id = \"example.com\"\n\
                     webauthn_related_origins = [\
                     \"https://example.de\", \"https://example.fr\", \"https://example.es\", \
                     \"https://example.it\", \"https://example.co.uk\"]\n";
        let loaded = Config::from_toml_str(cctld, "ironauth.toml")
            .expect("the one-brand five-ccTLD estate loads (a single label to a browser)");
        assert!(
            !loaded
                .warnings
                .iter()
                .any(|w| matches!(w, Warning::WebauthnRelatedOriginLabelBudget { .. })),
            "one brand across ccTLDs is one label, so no budget warning: {:?}",
            loaded.warnings
        );

        // A genuinely oversized SINGLE-registrable-domain estate: seven distinct SLD
        // labels under `.com` (serving `example` plus six brands) exceeds the budget.
        // This is advisory now: it LOADS but WARNS (the browser enforces the real cap).
        let over = "[server]\npublic_url = \"https://auth.example.com\"\n\
                    [oidc]\nwebauthn_related_origins = [\
                    \"https://brand1.com\", \"https://brand2.com\", \"https://brand3.com\", \
                    \"https://brand4.com\", \"https://brand5.com\", \"https://brand6.com\"]\n";
        let loaded = Config::from_toml_str(over, "ironauth.toml")
            .expect("an over-budget estate loads (advisory warn, never a boot error)");
        assert!(
            loaded.warnings.iter().any(|w| matches!(
                w,
                Warning::WebauthnRelatedOriginLabelBudget {
                    count: 7,
                    budget: 5
                }
            )),
            "seven distinct SLD labels warn over the budget: {:?}",
            loaded.warnings
        );

        // Distinct registrable domains that share the multi-label suffix `co.uk` are
        // counted by their SLD label, matching the browser: six `x.co.uk` are six
        // labels (a..f), NOT the single label `co.uk`. Warns over the budget.
        let couk = "[server]\npublic_url = \"https://a.co.uk\"\n\
                    [oidc]\nwebauthn_rp_id = \"a.co.uk\"\n\
                    webauthn_related_origins = [\
                    \"https://b.co.uk\", \"https://c.co.uk\", \"https://d.co.uk\", \
                    \"https://e.co.uk\", \"https://f.co.uk\"]\n";
        let loaded = Config::from_toml_str(couk, "ironauth.toml").expect("six co.uk labels load");
        assert!(
            loaded.warnings.iter().any(|w| matches!(
                w,
                Warning::WebauthnRelatedOriginLabelBudget {
                    count: 6,
                    budget: 5
                }
            )),
            "six distinct x.co.uk are six SLD labels, warning over budget: {:?}",
            loaded.warnings
        );

        // Exactly at the budget (serving + four distinct brands = five labels) loads
        // but warns (no headroom).
        let at = "[server]\npublic_url = \"https://auth.example.com\"\n\
                  [oidc]\nwebauthn_related_origins = [\
                  \"https://a.test\", \"https://b.test\", \"https://c.test\", \"https://d.test\"]\n";
        let loaded = Config::from_toml_str(at, "ironauth.toml").expect("at budget loads");
        assert!(
            loaded.warnings.iter().any(|w| matches!(
                w,
                Warning::WebauthnRelatedOriginLabelBudget {
                    count: 5,
                    budget: 5
                }
            )),
            "a warning fires at the budget ceiling: {:?}",
            loaded.warnings
        );

        // A valid small estate (multiple origins sharing ONE registrable domain count
        // as one label) loads clean with no warning.
        let same_domain = "[server]\npublic_url = \"https://auth.example.com\"\n\
                           [oidc]\nwebauthn_related_origins = [\
                           \"https://app.example.com\", \"https://id.example.com\", \
                           \"https://shop.example.com\"]\n";
        let loaded =
            Config::from_toml_str(same_domain, "ironauth.toml").expect("same registrable domain");
        assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
    }

    #[test]
    fn registrable_domain_label_groups_by_sld_label() {
        // One brand across ccTLDs shares a single SLD label.
        assert_eq!(registrable_domain_label("auth.example.com"), "example");
        assert_eq!(registrable_domain_label("example.de"), "example");
        assert_eq!(registrable_domain_label("example.co.uk"), "example");
        assert_eq!(registrable_domain_label("EXAMPLE.CO.UK."), "example");
        // Distinct registrable domains under a shared multi-label suffix are distinct
        // labels (co.uk is the suffix, not the label).
        assert_eq!(registrable_domain_label("a.co.uk"), "a");
        assert_eq!(registrable_domain_label("b.co.uk"), "b");
        // A host that is itself a public suffix falls back to the whole host.
        assert_eq!(registrable_domain_label("co.uk"), "co.uk");
    }

    #[test]
    fn rp_id_migration_guide_exists_and_its_config_example_matches_the_schema() {
        // The published RP ID migration guide (issue #67) must exist and its TOML
        // example must parse against the SHIPPED config schema (deny_unknown_fields),
        // so a documented `oidc.webauthn_rp_id` / `oidc.webauthn_related_origins`
        // snippet cannot drift from the real keys.
        let guide = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/design/PASSKEY-RP-ID-MIGRATION.md"
        );
        let text = std::fs::read_to_string(guide).expect("the migration guide is published");
        assert!(
            text.contains("oidc.webauthn_related_origins") && text.contains("oidc.webauthn_rp_id"),
            "the guide documents both RP ID knobs"
        );
        // Extract the fenced ```toml example and prove it is valid config.
        let toml = text
            .split_once("```toml")
            .and_then(|(_, rest)| rest.split_once("```"))
            .map(|(block, _)| block.trim())
            .expect("the guide carries a toml example");
        Config::from_toml_str(toml, "PASSKEY-RP-ID-MIGRATION.md")
            .expect("the documented example matches the shipped schema");
    }

    #[test]
    fn webauthn_rp_id_continuity_holds_across_a_custom_serving_host() {
        // RP-ID continuity (issue #67): the RP ID is set to the tenant's registrable
        // domain, INDEPENDENT of the exact serving hostname, so passkeys registered
        // against `example.com` survive a move to `auth.example.com`. The RP ID must
        // still be a registrable suffix of the serving origin (WebAuthn validity), and
        // the config loads with related origins on other registrable domains too.
        let continuity = "[server]\npublic_url = \"https://auth.example.com\"\n\
                          [oidc]\nwebauthn_rp_id = \"example.com\"\n\
                          webauthn_related_origins = [\"https://example.de\"]\n";
        let loaded = Config::from_toml_str(continuity, "ironauth.toml").expect("continuity loads");
        assert_eq!(
            loaded.config.oidc.webauthn_rp_id.as_deref(),
            Some("example.com")
        );

        // An RP ID that is NOT a suffix of the serving origin is still a boot error
        // (the base #65 rule is unchanged; continuity does not weaken it).
        let bad = "[server]\npublic_url = \"https://auth.example.com\"\n\
                   [oidc]\nwebauthn_rp_id = \"other.example\"\n\
                   webauthn_related_origins = [\"https://example.de\"]\n";
        let err = Config::from_toml_str(bad, "ironauth.toml").expect_err("rp id not a suffix");
        assert!(err.to_string().contains("webauthn_rp_id"), "{err}");
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
    fn federation_is_disabled_by_default_with_sane_ttls_and_validates_bounds() {
        // Default: OFF, with the one-hour discovery/JWKS cache TTLs.
        let config = Config::from_toml_str("", "<inline>").expect("valid").config;
        assert!(!config.oidc.federation.enabled);
        assert_eq!(config.oidc.federation.discovery_ttl_secs, 3600);
        assert_eq!(config.oidc.federation.jwks_ttl_secs, 3600);

        // It parses on and accepts in-range TTLs.
        let input = "[oidc.federation]\nenabled = true\n\
                     discovery_ttl_secs = 600\njwks_ttl_secs = 900\n";
        let config = Config::from_toml_str(input, "<inline>")
            .expect("valid")
            .config;
        assert!(config.oidc.federation.enabled);
        assert_eq!(config.oidc.federation.discovery_ttl_secs, 600);
        assert_eq!(config.oidc.federation.jwks_ttl_secs, 900);

        // A zero TTL and an over-cap TTL both fail at load, naming the offending key.
        let zero = "[oidc.federation]\njwks_ttl_secs = 0\n";
        let err = Config::from_toml_str(zero, "ironauth.toml").expect_err("zero ttl");
        assert!(err.to_string().contains("jwks_ttl_secs"), "{err}");

        let over = format!(
            "[oidc.federation]\ndiscovery_ttl_secs = {}\n",
            OIDC_MAX_FEDERATION_TTL_SECS + 1
        );
        let err = Config::from_toml_str(&over, "ironauth.toml").expect_err("over cap");
        assert!(err.to_string().contains("discovery_ttl_secs"), "{err}");
    }

    #[test]
    fn byok_is_disabled_by_default_and_rejects_unknown_keys() {
        // BYOK is exploratory and DEFAULT-OFF: an empty config leaves it disabled,
        // with the local (customer-supplied, no external service) driver selected
        // and no external endpoint.
        let config = Config::from_toml_str("", "<inline>").expect("valid").config;
        assert!(!config.byok.enabled);
        assert_eq!(config.byok.provider, ByokProvider::Local);
        assert!(config.byok.endpoint.is_none());

        // The section can be turned on explicitly and parses an external driver.
        let input = "[byok]\nenabled = true\nprovider = \"aws\"\n\
                     endpoint = \"https://kms.example.test/wrap\"\n";
        let config = Config::from_toml_str(input, "<inline>")
            .expect("valid")
            .config;
        assert!(config.byok.enabled);
        assert_eq!(config.byok.provider, ByokProvider::Aws);
        assert_eq!(
            config.byok.endpoint.as_deref(),
            Some("https://kms.example.test/wrap")
        );

        // A typo in the section is a hard startup failure, never silently ignored.
        let err = Config::from_toml_str("[byok]\nenabld = true\n", "<inline>")
            .expect_err("unknown key rejected");
        assert!(format!("{err}").contains("enabld"), "{err}");
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
    fn registration_abuse_config_round_trips_and_the_adapter_secret_is_a_reference() {
        // The registration-abuse settings are per-environment config that promotes with the
        // config snapshot (issue #80); the adapter secret is a REFERENCE, never a value.
        let input = "\
[oidc.registration_abuse.pow]
enabled = true
difficulty_bits = 14
challenge_at = \"med\"
provider = \"turnstile\"
fail_policy = \"fail_open\"
adapter_secret = \"site-secret-value\"

[oidc.registration_abuse.disposable_email]
mode = \"block\"
denylist = [\"mailinator.com\"]
allowlist = [\"vip.mailinator.com\"]

[oidc.registration_abuse.waitlist]
enabled = true
";
        let loaded = Config::from_toml_str(input, "<inline>").expect("valid");
        let abuse = &loaded.config.oidc.registration_abuse;
        assert!(abuse.pow.enabled);
        assert_eq!(abuse.pow.difficulty_bits, 14);
        assert_eq!(abuse.pow.challenge_at, "med");
        assert_eq!(abuse.pow.provider, PowProvider::Turnstile);
        assert_eq!(abuse.pow.fail_policy, AdapterFailPolicy::FailOpen);
        assert_eq!(abuse.disposable_email.mode, "block");
        assert_eq!(abuse.disposable_email.denylist, vec!["mailinator.com"]);
        assert_eq!(abuse.disposable_email.allowlist, vec!["vip.mailinator.com"]);
        assert!(abuse.waitlist.enabled);

        // A config dump (the snapshot vehicle) carries the promotable settings but the
        // adapter SECRET value NEVER appears: it degrades to the redaction placeholder.
        let dump = toml::to_string(&loaded.config).expect("dumps");
        assert!(
            dump.contains("difficulty_bits = 14"),
            "settings export: {dump}"
        );
        assert!(
            dump.contains("mailinator.com"),
            "the domain list exports: {dump}"
        );
        assert!(
            !dump.contains("site-secret-value"),
            "the adapter secret VALUE must never appear in a config dump: {dump}"
        );
        assert!(
            dump.contains(REDACTED),
            "the secret degrades to the placeholder: {dump}"
        );

        // An env-indirection secret round-trips as a NAMED REFERENCE (never a value).
        let env_input =
            "[oidc.registration_abuse.pow]\nadapter_secret = { env = \"TURNSTILE_SECRET\" }\n";
        let loaded = Config::from_toml_str(env_input, "<inline>").expect("valid");
        let dump = toml::to_string(&loaded.config).expect("dumps");
        assert!(
            dump.contains("TURNSTILE_SECRET"),
            "only the reference to the secret travels: {dump}"
        );
    }

    #[test]
    fn password_policy_defaults_are_the_63b4_posture() {
        let config = Config::from_toml_str("", "<inline>").expect("valid").config;
        let policy = &config.password_policy;
        assert_eq!(policy.min_length_sole_factor, 15);
        assert_eq!(policy.min_length_mfa_factor, 8);
        assert_eq!(policy.max_length, 64);
        assert!(!policy.require_lowercase && !policy.require_uppercase);
        assert!(!policy.require_digit && !policy.require_symbol);
        assert_eq!(policy.rotation_max_age_days, 0);
        assert!(
            policy.screening_enabled,
            "screening is mandatory by default"
        );
        assert_eq!(policy.screening_provider, ScreeningProvider::Hibp);
        assert_eq!(
            policy.screening_failure_policy,
            ScreeningFailurePolicy::FailOpen
        );
        assert!(!policy.screen_on_login);
    }

    #[test]
    fn password_policy_rejects_a_minimum_above_the_maximum() {
        let bad = "[password_policy]\nmin_length_sole_factor = 100\nmax_length = 64\n";
        let err = Config::from_toml_str(bad, "ironauth.toml").expect_err("min > max");
        assert!(err.to_string().contains("min_length_sole_factor"), "{err}");
    }

    #[test]
    fn offline_provider_requires_a_corpus_path() {
        let bad = "[password_policy]\nscreening_provider = \"offline\"\n";
        let err = Config::from_toml_str(bad, "ironauth.toml").expect_err("offline needs a corpus");
        assert!(err.to_string().contains("offline_corpus_path"), "{err}");

        // With a path it loads.
        let ok = "[password_policy]\nscreening_provider = \"offline\"\n\
                  offline_corpus_path = \"/var/lib/ironauth/breach-corpus.txt\"\n";
        Config::from_toml_str(ok, "<inline>").expect("offline with a corpus path loads");

        // Disabling screening also lets the offline provider load without a corpus.
        let disabled = "[password_policy]\nscreening_provider = \"offline\"\n\
                        screening_enabled = false\n";
        Config::from_toml_str(disabled, "<inline>").expect("disabled screening needs no corpus");
    }

    #[test]
    fn hibp_base_url_must_be_https() {
        let bad = "[password_policy]\nhibp_base_url = \"http://mirror.internal\"\n";
        let err = Config::from_toml_str(bad, "ironauth.toml").expect_err("plaintext base");
        assert!(err.to_string().contains("https"), "{err}");
        let ok = "[password_policy]\nhibp_base_url = \"https://mirror.example.test\"\n";
        Config::from_toml_str(ok, "<inline>").expect("https base loads");
    }

    #[test]
    fn mds3_base_url_must_be_https() {
        // The MDS3 BLOB endpoint override rides the SSRF-hardened outbound path, so a
        // plaintext override is refused at load, exactly like the HIBP base URL.
        let bad = "[oidc]\nmds3_base_url = \"http://mds3.internal\"\n";
        let err = Config::from_toml_str(bad, "ironauth.toml").expect_err("plaintext base");
        assert!(err.to_string().contains("https"), "{err}");
        let ok = "[oidc]\nmds3_base_url = \"https://mds3.example.test/\"\n";
        Config::from_toml_str(ok, "<inline>").expect("https base loads");
    }

    #[test]
    fn a_legacy_composition_and_rotation_override_loads_as_settings() {
        // A legacy regime enables composition and a 90-day rotation via settings only.
        let legacy = "[password_policy]\nrequire_uppercase = true\nrequire_digit = true\n\
                      rotation_max_age_days = 90\nscreening_failure_policy = \"fail_closed\"\n";
        let config = Config::from_toml_str(legacy, "<inline>")
            .expect("legacy override loads")
            .config;
        let policy = &config.password_policy;
        assert!(policy.require_uppercase && policy.require_digit);
        assert_eq!(policy.rotation_max_age_days, 90);
        assert_eq!(
            policy.screening_failure_policy,
            ScreeningFailurePolicy::FailClosed
        );
    }

    #[test]
    fn lazy_migration_rejects_a_malformed_https_endpoint_at_load() {
        // A well-formed absolute https endpoint loads cleanly.
        let ok = "[oidc.lazy_migration]\nenabled = true\n\
                  endpoint = \"https://legacy.example.test/verify\"\n";
        Config::from_toml_str(ok, "<inline>").expect("a well-formed https endpoint loads");

        // Every malformed endpoint is a LOAD error (criterion 6), not a silent per-login
        // failure at runtime that also trips the breaker. The old `starts_with("https://")`
        // check let the first three through.
        for bad in [
            "https://",                          // no host
            "https://exa mple.test/verify",      // embedded space
            "https://[not-an-ip/verify",         // unterminated IPv6 literal
            "http://legacy.example.test/verify", // plaintext (still refused)
            "ftp://legacy.example.test/verify",  // wrong scheme
            "https://user:pass@legacy.test/v",   // userinfo smuggled into the URL
        ] {
            let input = format!("[oidc.lazy_migration]\nenabled = true\nendpoint = \"{bad}\"\n");
            let err = Config::from_toml_str(&input, "<inline>")
                .expect_err(&format!("{bad} must be a load error"));
            assert!(
                err.to_string().contains("well-formed absolute"),
                "{bad}: unexpected error {err}"
            );
        }
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

    /// Minor-7: the TOTP config bounds are enforced at boot. The default is valid, and
    /// each out-of-range parameter (digits, period, drift, recovery count) and a
    /// malformed factor order (unknown or duplicate) is a boot-time `Invalid`.
    #[test]
    #[allow(clippy::field_reassign_with_default)] // one-field mutations off a large default read clearest
    fn validate_totp_enforces_the_documented_bounds() {
        // The default config is valid.
        validate_totp(&OidcConfig::default()).expect("defaults are valid");

        // digits must be in 6..=8.
        for bad in [5u32, 9] {
            let mut oidc = OidcConfig::default();
            oidc.totp_digits = bad;
            assert!(
                matches!(validate_totp(&oidc), Err(ConfigError::Invalid { .. })),
                "totp_digits {bad} must be rejected"
            );
        }
        for ok in [6u32, 7, 8] {
            let mut oidc = OidcConfig::default();
            oidc.totp_digits = ok;
            validate_totp(&oidc).unwrap_or_else(|_| panic!("totp_digits {ok} is valid"));
        }

        // period must be in 15..=60.
        for bad in [14u64, 61] {
            let mut oidc = OidcConfig::default();
            oidc.totp_period_secs = bad;
            assert!(
                matches!(validate_totp(&oidc), Err(ConfigError::Invalid { .. })),
                "totp_period_secs {bad} must be rejected"
            );
        }
        for ok in [15u64, 30, 60] {
            let mut oidc = OidcConfig::default();
            oidc.totp_period_secs = ok;
            validate_totp(&oidc).unwrap_or_else(|_| panic!("totp_period_secs {ok} is valid"));
        }

        // drift must be at most 2.
        for ok in [0u32, 1, 2] {
            let mut oidc = OidcConfig::default();
            oidc.totp_drift_steps = ok;
            validate_totp(&oidc).unwrap_or_else(|_| panic!("totp_drift_steps {ok} is valid"));
        }
        let mut oidc = OidcConfig::default();
        oidc.totp_drift_steps = 3;
        assert!(
            matches!(validate_totp(&oidc), Err(ConfigError::Invalid { .. })),
            "a drift window over 2 must be rejected"
        );

        // recovery count must be in 8..=16.
        for bad in [7u32, 17] {
            let mut oidc = OidcConfig::default();
            oidc.totp_recovery_code_count = bad;
            assert!(
                matches!(validate_totp(&oidc), Err(ConfigError::Invalid { .. })),
                "totp_recovery_code_count {bad} must be rejected"
            );
        }
        for ok in [8u32, 10, 16] {
            let mut oidc = OidcConfig::default();
            oidc.totp_recovery_code_count = ok;
            validate_totp(&oidc)
                .unwrap_or_else(|_| panic!("totp_recovery_code_count {ok} is valid"));
        }

        // An unknown factor in the order is rejected.
        let mut oidc = OidcConfig::default();
        oidc.mfa_factor_order = vec!["passkey".to_owned(), "sms".to_owned()];
        assert!(
            matches!(validate_totp(&oidc), Err(ConfigError::Invalid { .. })),
            "an unknown mfa_factor_order entry must be rejected"
        );
        // A duplicate factor is rejected.
        let mut oidc = OidcConfig::default();
        oidc.mfa_factor_order = vec!["totp".to_owned(), "totp".to_owned()];
        assert!(
            matches!(validate_totp(&oidc), Err(ConfigError::Invalid { .. })),
            "a duplicate mfa_factor_order entry must be rejected"
        );
        // The closed set in any order is accepted.
        let mut oidc = OidcConfig::default();
        oidc.mfa_factor_order = vec![
            "password".to_owned(),
            "totp".to_owned(),
            "passkey".to_owned(),
        ];
        validate_totp(&oidc).expect("the closed set is valid in any order");
    }

    /// The step-up acr order (issues #66/#71/#72): the shipped default is valid, an empty
    /// list is allowed (it falls back to the canonical order), and a non-empty override
    /// must be a permutation of the known rungs that keeps `mfa_remembered` strictly below
    /// `mfa`.
    #[test]
    #[allow(clippy::field_reassign_with_default)] // one-field mutations off a large default read clearest
    fn validate_acr_order_enforces_permutation_and_the_remembered_floor() {
        // The shipped default is the canonical order and is valid.
        let default = OidcConfig::default();
        assert_eq!(
            default.acr_order,
            OIDC_DEFAULT_ACR_ORDER
                .iter()
                .map(|acr| (*acr).to_owned())
                .collect::<Vec<_>>()
        );
        validate_totp(&default).expect("the canonical default acr order is valid");

        // An empty list is allowed: it falls back to the canonical order at read time.
        let mut empty = OidcConfig::default();
        empty.acr_order = Vec::new();
        validate_totp(&empty).expect("an empty acr order falls back to the default");

        // Ranking mfa_remembered AT or ABOVE mfa is the honesty footgun and is rejected.
        let mut remembered_too_high = OidcConfig::default();
        remembered_too_high.acr_order = vec![
            OIDC_ACR_PWD.to_owned(),
            OIDC_ACR_MFA.to_owned(),
            OIDC_ACR_MFA_REMEMBERED.to_owned(),
            OIDC_ACR_PHR.to_owned(),
            OIDC_ACR_PHRH.to_owned(),
            OIDC_ACR_ATTESTED.to_owned(),
        ];
        assert!(
            matches!(
                validate_totp(&remembered_too_high),
                Err(ConfigError::Invalid { .. })
            ),
            "mfa_remembered ranked at or above mfa must be rejected"
        );

        // An unknown acr value is rejected (a silently-unranked floor).
        let mut unknown = OidcConfig::default();
        unknown.acr_order = vec![
            OIDC_ACR_PWD.to_owned(),
            OIDC_ACR_MFA_REMEMBERED.to_owned(),
            OIDC_ACR_MFA.to_owned(),
            OIDC_ACR_PHR.to_owned(),
            OIDC_ACR_PHRH.to_owned(),
            "urn:custom:acr:made_up".to_owned(),
        ];
        assert!(
            matches!(validate_totp(&unknown), Err(ConfigError::Invalid { .. })),
            "an unknown acr value must be rejected"
        );

        // A partial order that leaves a known rung unranked is rejected.
        let mut partial = OidcConfig::default();
        partial.acr_order = vec![
            OIDC_ACR_PWD.to_owned(),
            OIDC_ACR_MFA.to_owned(),
            OIDC_ACR_PHR.to_owned(),
            OIDC_ACR_PHRH.to_owned(),
        ];
        assert!(
            matches!(validate_totp(&partial), Err(ConfigError::Invalid { .. })),
            "an order missing a known rung must be rejected"
        );

        // A duplicate value is rejected.
        let mut duplicate = OidcConfig::default();
        duplicate.acr_order = vec![
            OIDC_ACR_PWD.to_owned(),
            OIDC_ACR_PWD.to_owned(),
            OIDC_ACR_MFA_REMEMBERED.to_owned(),
            OIDC_ACR_MFA.to_owned(),
            OIDC_ACR_PHR.to_owned(),
            OIDC_ACR_PHRH.to_owned(),
        ];
        assert!(
            matches!(validate_totp(&duplicate), Err(ConfigError::Invalid { .. })),
            "a duplicate acr value must be rejected"
        );

        // A valid permutation that trusts TOTP over synced passkeys (mfa above phr) is
        // accepted as long as mfa_remembered stays below mfa.
        let mut reordered = OidcConfig::default();
        reordered.acr_order = vec![
            OIDC_ACR_PWD.to_owned(),
            OIDC_ACR_MFA_REMEMBERED.to_owned(),
            OIDC_ACR_PHR.to_owned(),
            OIDC_ACR_MFA.to_owned(),
            OIDC_ACR_PHRH.to_owned(),
            OIDC_ACR_ATTESTED.to_owned(),
        ];
        validate_totp(&reordered).expect("a valid permutation with mfa_remembered below mfa");
    }

    /// The remembered-device duration policy (issue #71): the defaults are valid and off,
    /// the max age must sit inside the accepted band, and the idle window must be at least
    /// the floor and never wider than the absolute max age.
    #[test]
    #[allow(clippy::field_reassign_with_default)] // one-field mutations off a large default read clearest
    fn validate_trusted_device_enforces_the_duration_bounds() {
        let default = OidcConfig::default();
        assert!(!default.trusted_devices_enabled);
        validate_trusted_device(&default).expect("defaults are valid");

        // The max age must sit inside the accepted band (up to the NIST 30-day ceiling).
        for bad in [
            OIDC_TRUSTED_DEVICE_MIN_MAX_AGE_SECS - 1,
            OIDC_TRUSTED_DEVICE_MAX_MAX_AGE_SECS + 1,
        ] {
            let mut oidc = OidcConfig::default();
            oidc.trusted_device_max_age_secs = bad;
            assert!(
                matches!(
                    validate_trusted_device(&oidc),
                    Err(ConfigError::Invalid { .. })
                ),
                "trusted_device_max_age_secs {bad} must be rejected"
            );
        }

        // The idle window must be at least the floor and never wider than the max age.
        let mut too_small = OidcConfig::default();
        too_small.trusted_device_idle_secs = OIDC_TRUSTED_DEVICE_MIN_IDLE_SECS - 1;
        assert!(matches!(
            validate_trusted_device(&too_small),
            Err(ConfigError::Invalid { .. })
        ));
        let mut wider_than_max = OidcConfig::default();
        wider_than_max.trusted_device_max_age_secs = OIDC_TRUSTED_DEVICE_MIN_MAX_AGE_SECS;
        wider_than_max.trusted_device_idle_secs = OIDC_TRUSTED_DEVICE_MIN_MAX_AGE_SECS + 1;
        assert!(
            matches!(
                validate_trusted_device(&wider_than_max),
                Err(ConfigError::Invalid { .. })
            ),
            "an idle window wider than the absolute max age must be rejected"
        );
    }
}
