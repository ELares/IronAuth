// SPDX-License-Identifier: MIT OR Apache-2.0

//! Discovery metadata, generated ENTIRELY from live configuration (issue #18).
//!
//! There is no hand-maintained discovery JSON anywhere in the repository. The
//! document is produced at serve time by [`discovery_document`], a pure function
//! of three inputs:
//!
//! - the per-environment issuer STRING (from the `(tenant, environment)` scope),
//! - the endpoint and capability registries the owning subsystems expose, and
//! - the per-tenant/per-environment signing-algorithm [`SigningPolicy`] (issue
//!   #19).
//!
//! The [`discovery_router`] resolves the `(tenant, environment)` scope from the URL
//! path and renders from that environment's loaded key set: it consults the SAME
//! store-backed [`IssuerRegistry`](crate::issuer::IssuerRegistry) the mint and the
//! JWKS surface read (issue #194), deriving the per-environment signing policy from
//! exactly the keys that environment signs with. Discovery, JWKS, and the minted
//! tokens therefore cannot advertise divergent algorithms. An unprovisioned or
//! cross-tenant scope resolves to no entry and returns a uniform `404`, exactly
//! like the JWKS surface in [`crate::jwks`].
//!
//! # What is advertised, and where it comes from
//!
//! Every `*_supported` array is sourced from the registry or const its owning
//! subsystem exposes, never hand-listed here, so a subsystem change flows into
//! discovery with no edit to the generator:
//!
//! - `response_types_supported`   <- [`ResponseType::DEFAULT`] (+ per-env legacy, #17)
//! - `grant_types_supported`      <- [`GrantType::ALL`]
//! - `code_challenge_methods_supported` <- [`PkceMethod::ALL`]
//! - `token_endpoint_auth_methods_supported` <- [`ClientAuthMethod::ALL`]
//! - `token_endpoint_auth_signing_alg_values_supported` <- the asymmetric assertion
//!   matrix ([`crate::client_auth::assertion_signing_alg_values`]), REQUIRED by
//!   Discovery section 3 because `private_key_jwt` is advertised
//! - `subject_types_supported`    <- [`SubjectType::ALL`]
//! - `response_modes_supported`   <- [`ResponseMode::DEFAULT`] (+ per-env `fragment`/`form_post`, #17)
//! - `prompt_values_supported`    <- [`PromptValue::ALL`] (`none login consent select_account create`, #16)
//! - `display_values_supported`   <- [`Display::SUPPORTED`] (the page layouts honored, #16)
//! - `ui_locales_supported` / `claims_locales_supported` <- the bootstrap page
//!   locales ([`UI_LOCALES_SUPPORTED`] / [`CLAIMS_LOCALES_SUPPORTED`], #16)
//! - `id_token_signing_alg_values_supported` <- the environment policy, with the
//!   Discovery section 3 RS256 FLOOR (see [`id_token_signing_alg_values`]).
//!
//! Adding an endpoint (revocation, introspection, `end_session`, `userinfo`,
//! registration) is a one-line addition to [`ADVERTISED_ENDPOINTS`]; the generator
//! advertises it with no further change. Disabling a per-environment feature (a
//! legacy response type, `form_post`) is a [`DiscoveryCapabilities`] toggle, not a
//! code change.
//!
//! # Both well-known forms
//!
//! The [`discovery_router`] serves all three probe shapes RPs and MCP clients use,
//! every one returning the identical document with an issuer value that
//! exact-string-matches the URL it was derived from (no trailing-slash drift):
//!
//! - OIDC Discovery (suffix APPENDED):
//!   `{issuer}/.well-known/openid-configuration`
//! - RFC 8414 (well-known segment INSERTED between host and issuer path), for both
//!   variants MCP clients probe:
//!   `{host}/.well-known/oauth-authorization-server/{issuer-path}`
//!   `{host}/.well-known/openid-configuration/{issuer-path}`

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use ironauth_config::OidcConfig;
use ironauth_jose::{JwsAlgorithm, SigningPolicy};
use ironauth_store::Scope;
use serde_json::{Value, json};

use crate::client_auth::ClientAuthMethod;
use crate::hints::Display;
use crate::issuer::{IssuerRegistry, JwksCacheWindow};
use crate::registry::{GrantType, PkceMethod, PromptValue, ResponseMode, ResponseType};
use crate::subject::SubjectType;
use crate::wellknown::{cacheable_response, not_found, parse_scope};

/// The media type for the discovery document (OIDC Discovery 1.0).
const DISCOVERY_MEDIA_TYPE: &str = "application/json";

/// The `ui_locales_supported` the discovery document advertises (issue #16): the
/// end-user UI languages the bootstrap interaction pages are written in. The pages
/// are English, so this is the honest minimal set; it grows when real translations
/// land, so discovery never advertises a language the pages do not render.
pub const UI_LOCALES_SUPPORTED: &[&str] = &["en"];

/// The `claims_locales_supported` the discovery document advertises (issue #16):
/// the languages this OP can return claim values in. Only English today (the
/// bootstrap stores claim values verbatim), so the honest minimal set.
pub const CLAIMS_LOCALES_SUPPORTED: &[&str] = &["en"];

/// The scopes IronAuth advertises. `openid` is the OIDC-mandated scope the
/// authorization-code flow is defined against; `profile`, `email`, `address`, and
/// `phone` are the OIDC Core 5.4 claim-bearing scopes `UserInfo` backs (issue #15);
/// `offline_access` (OIDC Core 11) requests a refresh token, which the provider now
/// issues and rotates (issue #21), so an RP can learn the capability from discovery.
/// This is the authoritative source until a scope subsystem exposes its own
/// registry.
pub const SCOPES_SUPPORTED: &[&str] = &[
    "openid",
    "profile",
    "email",
    "address",
    "phone",
    "offline_access",
];

/// The claim names IronAuth may supply in an ID token today. `iss`/`aud`/`exp`/
/// `iat` are protocol claims and `sub` is the user identifier; `nonce` is echoed
/// when the request carries it. `amr` and `acr` are emitted on every token-endpoint
/// ID token (derived from the recorded authentication event, issue #14), and
/// `auth_time` when `max_age` was requested or the client registered
/// `require_auth_time`. The diff harness fails the build if a minted token carries
/// a claim not advertised here (so when #17 adds front-channel `at_hash`/`c_hash`
/// this const must grow to match).
pub const ID_TOKEN_CLAIMS_SUPPORTED: &[&str] = &[
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "nonce",
    "auth_time",
    "acr",
    "amr",
];

/// The `claims_supported` array the discovery document advertises: every claim
/// this OP may put in an ID token OR return from `UserInfo`, de-duplicated. It is the
/// union of [`ID_TOKEN_CLAIMS_SUPPORTED`] and the `UserInfo`-returnable standard
/// claims (issue #15's scope claim sets plus `sub`), so every `UserInfo`-returnable
/// claim is advertised and the two surfaces never drift from what discovery
/// announces.
#[must_use]
pub fn claims_supported() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = ID_TOKEN_CLAIMS_SUPPORTED.to_vec();
    for name in crate::scope_claims::userinfo_standard_claims() {
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// One endpoint advertised in the discovery document.
///
/// The single source of truth for which protocol endpoints exist: the generator
/// loops over [`ADVERTISED_ENDPOINTS`], so an endpoint appears in discovery iff it
/// has an entry here. Its URL is `{base}{path}` (endpoints live at the deployment
/// root, shared across environments; only the issuer and `jwks_uri` are per
/// environment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryEndpoint {
    /// The discovery metadata key (for example `authorization_endpoint`).
    pub metadata_key: &'static str,
    /// The path the endpoint is served at, relative to the deployment base.
    pub path: &'static str,
}

/// Every protocol endpoint served on the live data plane, in the order they are
/// advertised. Adding an endpoint here advertises it with no change to the
/// generator; removing one un-advertises it. `jwks_uri` is NOT here: it is a
/// required top-level field handled directly by the generator, and its serving
/// (the JWKS surface) is mounted by issue #194 once keys load.
///
/// The remaining M3/M4 endpoint (`end_session_endpoint`) joins this list when its
/// issue lands; `userinfo_endpoint` landed with issue #15, and the RFC 7009
/// `revocation_endpoint` and RFC 7662 `introspection_endpoint` with issue #22.
/// `registration_endpoint` (issue #30) is NOT here: it is PER ENVIRONMENT (served
/// under the issuer path, like `jwks_uri`), so the generator emits it directly as
/// `{issuer}/connect/register` and only when
/// [`DiscoveryCapabilities::registration_endpoint_enabled`] is set.
pub const ADVERTISED_ENDPOINTS: &[DiscoveryEndpoint] = &[
    DiscoveryEndpoint {
        metadata_key: "authorization_endpoint",
        path: "/authorize",
    },
    DiscoveryEndpoint {
        metadata_key: "token_endpoint",
        path: "/token",
    },
    DiscoveryEndpoint {
        metadata_key: "userinfo_endpoint",
        path: "/userinfo",
    },
    DiscoveryEndpoint {
        metadata_key: "pushed_authorization_request_endpoint",
        path: "/par",
    },
    DiscoveryEndpoint {
        metadata_key: "revocation_endpoint",
        path: "/revoke",
    },
    DiscoveryEndpoint {
        metadata_key: "introspection_endpoint",
        path: "/introspect",
    },
    // RFC 8628 device-authorization endpoint (issue #24). A deployment-root endpoint
    // like /par and /token; the constrained device POSTs here to start a flow. This
    // metadata key must live ONLY in this generator module (scripts/discovery-scan.sh
    // forbids the literal `authorization_endpoint` substring elsewhere).
    DiscoveryEndpoint {
        metadata_key: "device_authorization_endpoint",
        path: "/device_authorization",
    },
];

/// The per-environment, config-driven capability toggles the generator layers on
/// top of the fixed registries.
///
/// Everything here is either a per-environment feature owned by a later issue
/// (whose flag flows in through [`DiscoveryCapabilities::from_config`] once that
/// issue lands) or a deployment default. The FIXED capabilities (`code`,
/// `authorization_code`, `S256`, the client-auth methods, the subject types, the
/// `query` response mode, the `prompt` values, the `display` values, and the
/// supported locales) are read straight from the registries and consts and are
/// never represented here.
//
// This is a bag of INDEPENDENT per-environment capability toggles, each a distinct
// discovery field sourced from its own config flag; they do not form a state machine
// and collapsing them into two-variant enums would only obscure that. The bool count
// crossed clippy's `struct_excessive_bools` threshold when the #27 PAR and #30 DCR
// toggles landed together, so the lint is allowed here with intent.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryCapabilities {
    /// Legacy response types enabled for this environment (issue #17). Empty by
    /// default; when non-empty they are advertised ALONGSIDE the structurally
    /// guaranteed `code`. This is the seam #17 populates per environment.
    additional_response_types: Vec<String>,
    /// Additional response modes enabled for this environment (issue #17
    /// `form_post`). Empty by default; the `query` mode is always advertised from
    /// the registry.
    additional_response_modes: Vec<String>,
    /// Whether the authorization response carries the RFC 9207 `iss` parameter
    /// (issue #13). `false` until #13 lands and the authorization endpoint echoes
    /// `iss`, so discovery never claims a behavior the server does not yet have.
    authorization_response_iss_parameter_supported: bool,
    /// Whether the `claims` request parameter is supported (OIDC Core 5.5, issue
    /// #15). `true` once the authorization endpoint parses `claims` and both
    /// placements honor it; [`DiscoveryCapabilities::from_config`] sets it, so
    /// discovery advertises exactly what the server does.
    claims_parameter_supported: bool,
    /// Whether EVERY authorization request in this environment must be pushed (RFC
    /// 9126 section 5, issue #27). Sourced from `oidc.require_pushed_authorization_requests`
    /// so discovery's `require_pushed_authorization_requests` reflects exactly what
    /// the authorization endpoint enforces. `false` by default (PAR is optional).
    require_pushed_authorization_requests: bool,
    /// Whether the Dynamic Client Registration endpoint is enabled (issue #30). When
    /// `true`, the document advertises the per-environment `registration_endpoint`
    /// (`{issuer}/connect/register`); when `false` the field is absent, so discovery
    /// never advertises an endpoint the server does not serve. Default-off, gated by
    /// `oidc.registration_enabled`.
    registration_endpoint_enabled: bool,
}

impl DiscoveryCapabilities {
    /// The capabilities implied by live configuration.
    ///
    /// The `claims` request parameter is supported (issue #15) and the
    /// authorization endpoint emits the RFC 9207 `iss` on every authorization
    /// response, success and error, on every response mode (issue #13); discovery
    /// advertises both. The per-environment legacy response types and modes (issue
    /// #17) are advertised ONLY where enabled: each enabled legacy type is added,
    /// `fragment` is advertised when any front-channel type is enabled (it is that
    /// feature's default and only-useful mode), and `form_post` when its own toggle
    /// is set. Discovery therefore reflects exactly what the authorization endpoint
    /// will accept.
    #[must_use]
    pub fn from_config(config: &OidcConfig) -> Self {
        let mut caps = Self::default()
            .with_claims_parameter(true)
            .with_authorization_response_iss(true)
            .with_require_pushed_authorization_requests(
                config.require_pushed_authorization_requests,
            );
        if config.enable_response_type_id_token {
            caps = caps.with_additional_response_type(ResponseType::IdToken.as_str());
        }
        if config.enable_response_type_code_id_token {
            caps = caps.with_additional_response_type(ResponseType::CodeIdToken.as_str());
        }
        if config.enable_response_type_none {
            caps = caps.with_additional_response_type(ResponseType::None.as_str());
        }
        // fragment is usable exactly when a front-channel type is enabled.
        if config.enable_response_type_id_token || config.enable_response_type_code_id_token {
            caps = caps.with_additional_response_mode(ResponseMode::Fragment.as_str());
        }
        if config.enable_response_mode_form_post {
            caps = caps.with_additional_response_mode(ResponseMode::FormPost.as_str());
        }
        caps.with_registration_endpoint(config.registration_enabled)
    }

    /// Declare whether the `claims` request parameter is supported (issue #15).
    #[must_use]
    pub fn with_claims_parameter(mut self, supported: bool) -> Self {
        self.claims_parameter_supported = supported;
        self
    }

    /// Declare whether EVERY authorization request must be pushed (RFC 9126, issue
    /// #27).
    #[must_use]
    pub fn with_require_pushed_authorization_requests(mut self, required: bool) -> Self {
        self.require_pushed_authorization_requests = required;
        self
    }

    /// Enable a legacy response type for this environment (issue #17).
    #[must_use]
    pub fn with_additional_response_type(mut self, response_type: impl Into<String>) -> Self {
        self.additional_response_types.push(response_type.into());
        self
    }

    /// Enable an additional response mode for this environment, e.g. `form_post`
    /// (issue #17).
    #[must_use]
    pub fn with_additional_response_mode(mut self, response_mode: impl Into<String>) -> Self {
        self.additional_response_modes.push(response_mode.into());
        self
    }

    /// Declare that the authorization response carries the RFC 9207 `iss`
    /// parameter (issue #13).
    #[must_use]
    pub fn with_authorization_response_iss(mut self, supported: bool) -> Self {
        self.authorization_response_iss_parameter_supported = supported;
        self
    }

    /// Declare whether the Dynamic Client Registration endpoint is served (issue
    /// #30), so discovery advertises `registration_endpoint` only when the endpoint
    /// is actually mounted.
    #[must_use]
    pub fn with_registration_endpoint(mut self, enabled: bool) -> Self {
        self.registration_endpoint_enabled = enabled;
        self
    }
}

/// The `id_token_signing_alg_values_supported` array for `policy`, applying the
/// OIDC Discovery section 3 RS256 FLOOR.
///
/// The array is the policy's allowed algorithms, in preference order, PLUS `RS256`
/// if the policy does not already permit it. RS256 is the mandated floor: a
/// relying party that understands only RS256 must always find it advertised, even
/// in an environment whose policy bans RS256 from being SELECTED to sign (the
/// zero-friction downgrade covenant, mirrored by
/// [`SigningPolicy::retains_in_jwks`](ironauth_jose::SigningPolicy::retains_in_jwks)).
/// This is the SINGLE algorithm that may be advertised without observed use.
#[must_use]
pub fn id_token_signing_alg_values(policy: &SigningPolicy) -> Vec<String> {
    let mut algs: Vec<String> = policy
        .allowed()
        .iter()
        .map(|alg| alg.as_jose_name().to_owned())
        .collect();
    let floor = JwsAlgorithm::Rs256.as_jose_name();
    if !algs.iter().any(|alg| alg == floor) {
        algs.push(floor.to_owned());
    }
    algs
}

/// Generate the discovery document for one issuer.
///
/// A pure function of the issuer string, the deployment `base` (which the shared
/// protocol endpoints are derived from), the `jwks_uri`, the environment signing
/// `policy`, and the per-environment `capabilities`. The `issuer` value in the
/// returned document is `issuer` verbatim, so it exact-string-matches whatever URL
/// it was derived from.
//
// The generator is one long, flat sequence of `document.insert(...)` statements, one
// per advertised metadata field; it grew past the line threshold as endpoints and
// their auth-method arrays landed (issue #22). Splitting it would only scatter the
// single source of truth across helpers for no clarity gain, so the lint is allowed.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn discovery_document(
    issuer: &str,
    base: &str,
    jwks_uri: &str,
    policy: &SigningPolicy,
    capabilities: &DiscoveryCapabilities,
) -> Value {
    // The always-on registry base (`code`, `query`) plus the per-environment
    // legacy types and modes enabled by config (issue #17). The base is the
    // DEFAULT registry subset, NOT ALL: the legacy members of the registry are
    // advertised only where explicitly enabled.
    let mut response_types = to_strings(ResponseType::DEFAULT.iter().map(|value| value.as_str()));
    response_types.extend(capabilities.additional_response_types.iter().cloned());

    let mut response_modes = to_strings(ResponseMode::DEFAULT.iter().map(|value| value.as_str()));
    response_modes.extend(capabilities.additional_response_modes.iter().cloned());

    let mut document = serde_json::Map::new();
    document.insert("issuer".to_owned(), json!(issuer));
    document.insert("jwks_uri".to_owned(), json!(jwks_uri));

    // Endpoints live at the deployment root, shared across environments. Every
    // served endpoint is advertised, and only served endpoints are (the registry
    // is the single source both this loop and the mounted routes agree on).
    for endpoint in ADVERTISED_ENDPOINTS {
        document.insert(
            endpoint.metadata_key.to_owned(),
            json!(format!("{base}{}", endpoint.path)),
        );
    }

    // The Dynamic Client Registration endpoint (issue #30) is PER ENVIRONMENT, like
    // `jwks_uri`: it is served under the issuer path (`{issuer}/connect/register`),
    // so a registration lands in the same (tenant, environment) the client will
    // operate in. It is advertised ONLY when enabled, so discovery never announces
    // an endpoint the server does not mount (the abuse-controls split of issue #31
    // owns the real gating; here it is a plain on/off).
    if capabilities.registration_endpoint_enabled {
        document.insert(
            "registration_endpoint".to_owned(),
            json!(format!("{issuer}/connect/register")),
        );
    }

    document.insert("scopes_supported".to_owned(), json!(SCOPES_SUPPORTED));
    document.insert("response_types_supported".to_owned(), json!(response_types));
    document.insert("response_modes_supported".to_owned(), json!(response_modes));
    document.insert(
        "grant_types_supported".to_owned(),
        json!(to_strings(
            GrantType::ALL.iter().map(|value| value.as_str())
        )),
    );
    document.insert(
        "subject_types_supported".to_owned(),
        json!(to_strings(
            SubjectType::ALL.iter().map(|value| value.as_str())
        )),
    );
    document.insert(
        "id_token_signing_alg_values_supported".to_owned(),
        json!(id_token_signing_alg_values(policy)),
    );
    document.insert(
        "token_endpoint_auth_methods_supported".to_owned(),
        json!(to_strings(
            ClientAuthMethod::ALL.iter().map(|value| value.as_str())
        )),
    );
    // OIDC Discovery 1.0 section 3 REQUIRES this field whenever `private_key_jwt`
    // (or `client_secret_jwt`) is advertised above. It is the asymmetric matrix the
    // token endpoint verifies a `private_key_jwt` assertion against (EdDSA + the
    // RS/ES/PS family), sourced from the client-auth module so it can never drift
    // from what verification accepts; `none` and ES512 are excluded by construction.
    document.insert(
        "token_endpoint_auth_signing_alg_values_supported".to_owned(),
        json!(crate::client_auth::assertion_signing_alg_values()),
    );
    // The RFC 7009 revocation and RFC 7662 introspection endpoints authenticate the
    // client through the SAME token-endpoint client-auth suite (issue #22), sourced
    // from the one client-auth module so the advertised set can never drift from what
    // the endpoints accept. They differ in ONE method: `/revoke` accepts a public
    // `none` client (RFC 7009 allows public clients), so it advertises the full
    // `ClientAuthMethod::ALL`; `/introspect` REQUIRES a confidential client (RFC 7662
    // section 2.1, and a `client_id` is not secret), so it advertises exactly
    // `ClientAuthMethod::CONFIDENTIAL` (ALL minus `none`). RFC 8414 section 2 then
    // REQUIRES the matching `*_endpoint_auth_signing_alg_values_supported` whenever
    // `private_key_jwt` is advertised, which it is on both; the values are the same
    // asymmetric assertion matrix the token endpoint verifies against.
    document.insert(
        "revocation_endpoint_auth_methods_supported".to_owned(),
        json!(to_strings(
            ClientAuthMethod::ALL.iter().map(|value| value.as_str())
        )),
    );
    document.insert(
        "revocation_endpoint_auth_signing_alg_values_supported".to_owned(),
        json!(crate::client_auth::assertion_signing_alg_values()),
    );
    document.insert(
        "introspection_endpoint_auth_methods_supported".to_owned(),
        json!(to_strings(
            ClientAuthMethod::CONFIDENTIAL
                .iter()
                .map(|value| value.as_str())
        )),
    );
    document.insert(
        "introspection_endpoint_auth_signing_alg_values_supported".to_owned(),
        json!(crate::client_auth::assertion_signing_alg_values()),
    );
    document.insert(
        "code_challenge_methods_supported".to_owned(),
        json!(to_strings(
            PkceMethod::ALL.iter().map(|value| value.as_str())
        )),
    );
    document.insert(
        "prompt_values_supported".to_owned(),
        json!(to_strings(
            PromptValue::ALL.iter().map(|value| value.as_str())
        )),
    );
    // The interaction hints the authorization endpoint acts on (issue #16). Only
    // the `display` values and locales the bootstrap actually honors are advertised
    // (no advertise/refuse mismatch): `page` (the layout rendered) and English (the
    // language the pages are written in).
    document.insert(
        "display_values_supported".to_owned(),
        json!(to_strings(
            Display::SUPPORTED.iter().map(|value| value.as_str())
        )),
    );
    document.insert(
        "ui_locales_supported".to_owned(),
        json!(UI_LOCALES_SUPPORTED),
    );
    document.insert(
        "claims_locales_supported".to_owned(),
        json!(CLAIMS_LOCALES_SUPPORTED),
    );
    document.insert("claims_supported".to_owned(), json!(claims_supported()));
    // The ACR values this OP can actually achieve, sourced from the authentication
    // registry (issue #14) so discovery never advertises a level we cannot reach.
    document.insert(
        "acr_values_supported".to_owned(),
        json!(crate::authn::acr_values_supported()),
    );

    // The defaults-if-omitted traps, published EXPLICITLY so a relying party never
    // has to fall back to a spec default that does not match our behavior. Each is
    // false because the backing feature has not landed (JAR/PAR request objects,
    // the `claims` request parameter) or is owned by a later issue (RFC 9207 `iss`,
    // issue #13).
    document.insert("request_parameter_supported".to_owned(), json!(false));
    document.insert("request_uri_parameter_supported".to_owned(), json!(false));
    document.insert(
        "claims_parameter_supported".to_owned(),
        json!(capabilities.claims_parameter_supported),
    );
    document.insert(
        "authorization_response_iss_parameter_supported".to_owned(),
        json!(capabilities.authorization_response_iss_parameter_supported),
    );
    // RFC 9126 section 5 (issue #27): the PAR endpoint is advertised through
    // ADVERTISED_ENDPOINTS above, and this flag says whether pushing is MANDATORY
    // for every client in this environment (sourced from live config, so it reflects
    // exactly what the authorization endpoint enforces).
    document.insert(
        "require_pushed_authorization_requests".to_owned(),
        json!(capabilities.require_pushed_authorization_requests),
    );

    Value::Object(document)
}

/// Collect an iterator of string slices into owned `String`s.
fn to_strings<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    values.map(ToOwned::to_owned).collect()
}

/// The shared state for the discovery surface.
///
/// Holds the deployment base URL, the JWKS/discovery cache window, the
/// per-environment capabilities, and the shared [`IssuerRegistry`]: the SAME
/// store-backed registry the mint and the JWKS surface read (issue #194). Discovery
/// resolves each environment's signing policy from that registry, so it can never
/// advertise an algorithm the served JWKS and the minted tokens do not use.
#[derive(Clone)]
pub struct DiscoveryState {
    issuer_base: String,
    cache: JwksCacheWindow,
    capabilities: DiscoveryCapabilities,
    registry: Arc<IssuerRegistry>,
}

impl DiscoveryState {
    /// Build the discovery state from the deployment base URL, the cache window,
    /// the per-environment capabilities, and the shared [`IssuerRegistry`].
    ///
    /// Discovery resolves the per-environment signing policy from the loaded key set
    /// (the SAME registry the mint and the JWKS surface read, issue #194), so
    /// discovery, JWKS, and the minted tokens can never advertise divergent
    /// algorithms. An unprovisioned or cross-tenant scope resolves to no entry and
    /// returns a uniform `404`, exactly like the JWKS surface.
    #[must_use]
    pub fn new(
        issuer_base: impl Into<String>,
        cache: JwksCacheWindow,
        capabilities: DiscoveryCapabilities,
        registry: Arc<IssuerRegistry>,
    ) -> Self {
        Self {
            issuer_base: issuer_base.into(),
            cache,
            capabilities,
            registry,
        }
    }

    /// The deployment base URL (issuer root), with any trailing slash trimmed.
    fn base(&self) -> &str {
        self.issuer_base.trim_end_matches('/')
    }

    /// The per-environment issuer STRING for `scope`. Mirrors
    /// [`OidcState::issuer_for`](crate::OidcState::issuer_for) exactly, so the
    /// issuer discovery advertises is byte-identical to the one tokens carry.
    fn issuer_for(&self, scope: &Scope) -> String {
        format!(
            "{}/t/{}/e/{}",
            self.base(),
            scope.tenant(),
            scope.environment()
        )
    }

    /// Render the discovery document for an already-parsed `scope` as a cacheable
    /// response, resolving the environment's policy from the shared registry.
    ///
    /// Returns a uniform `404` when the scope has no entry (unprovisioned or
    /// cross-tenant, which loads zero rows under row-level security), the SAME
    /// not-found the caller returns for a malformed scope, so the two are
    /// indistinguishable and match the JWKS surface.
    async fn respond(&self, scope: &Scope, headers: &HeaderMap) -> Response {
        let Some(entry) = self.registry.entry_for(scope).await else {
            return not_found();
        };
        let issuer = self.issuer_for(scope);
        let jwks_uri = format!("{issuer}/jwks.json");
        let document = discovery_document(
            &issuer,
            self.base(),
            &jwks_uri,
            entry.policy(),
            &self.capabilities,
        );
        cacheable_response(
            headers,
            DISCOVERY_MEDIA_TYPE,
            self.cache.max_age_secs(),
            &document.to_string(),
        )
    }
}

impl std::fmt::Debug for DiscoveryState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryState")
            .field("issuer_base", &self.issuer_base)
            .finish_non_exhaustive()
    }
}

/// Build the per-issuer discovery router, serving both well-known forms.
///
/// Mount it on the PUBLIC data plane alongside the protocol and JWKS routers. Every
/// route resolves the `(tenant, environment)` scope from the URL path and renders
/// the document from that environment's loaded key set (via the shared
/// [`IssuerRegistry`](crate::issuer::IssuerRegistry)); a malformed, unprovisioned,
/// or cross-tenant scope is a uniform `404`.
pub fn discovery_router(state: DiscoveryState) -> Router {
    Router::new()
        // OIDC Discovery 1.0 section 4: the well-known suffix is APPENDED to the
        // issuer path.
        .route(
            "/t/{tenant_id}/e/{environment_id}/.well-known/openid-configuration",
            get(appended_openid_configuration),
        )
        // RFC 8414 section 3: the well-known segment is INSERTED between the host
        // and the issuer path. MCP clients specifically probe this host-inserted
        // form, for both the OAuth server-metadata and the openid-configuration
        // variants.
        .route(
            "/.well-known/oauth-authorization-server/t/{tenant_id}/e/{environment_id}",
            get(inserted_oauth_authorization_server),
        )
        .route(
            "/.well-known/openid-configuration/t/{tenant_id}/e/{environment_id}",
            get(inserted_openid_configuration),
        )
        .with_state(state)
}

/// `GET {issuer}/.well-known/openid-configuration` (OIDC Discovery, appended).
async fn appended_openid_configuration(
    State(state): State<DiscoveryState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    serve(&state, &tenant_id, &environment_id, &headers).await
}

/// `GET {host}/.well-known/oauth-authorization-server/{issuer-path}` (RFC 8414,
/// host-inserted).
async fn inserted_oauth_authorization_server(
    State(state): State<DiscoveryState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    serve(&state, &tenant_id, &environment_id, &headers).await
}

/// `GET {host}/.well-known/openid-configuration/{issuer-path}` (host-inserted
/// openid-configuration; the MCP-probed variant).
async fn inserted_openid_configuration(
    State(state): State<DiscoveryState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    serve(&state, &tenant_id, &environment_id, &headers).await
}

/// Resolve the scope and render from the environment's registry entry, or a uniform
/// `404` for a malformed, unprovisioned, or cross-tenant scope. All three
/// well-known forms funnel through here, so every one returns the identical document
/// for a given issuer.
async fn serve(
    state: &DiscoveryState,
    tenant_id: &str,
    environment_id: &str,
    headers: &HeaderMap,
) -> Response {
    let Some(scope) = parse_scope(tenant_id, environment_id) else {
        return not_found();
    };
    state.respond(&scope, headers).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_jose::JwsAlgorithm;

    fn policy(algs: &[JwsAlgorithm]) -> SigningPolicy {
        SigningPolicy::new(algs.to_vec()).expect("non-empty policy")
    }

    #[test]
    fn rs256_floor_is_appended_to_the_default_policy() {
        // A default-policy environment advertises EdDSA and RS256 (the floor).
        let algs = id_token_signing_alg_values(&SigningPolicy::eddsa_default());
        assert_eq!(algs, vec!["EdDSA".to_owned(), "RS256".to_owned()]);
    }

    #[test]
    fn rs256_floor_is_not_duplicated_when_policy_permits_it() {
        let algs =
            id_token_signing_alg_values(&policy(&[JwsAlgorithm::Rs256, JwsAlgorithm::EdDsa]));
        assert_eq!(
            algs.iter().filter(|alg| *alg == "RS256").count(),
            1,
            "RS256 appears exactly once"
        );
        assert_eq!(algs, vec!["RS256".to_owned(), "EdDSA".to_owned()]);
    }

    #[test]
    fn es256_only_environment_bans_eddsa_but_keeps_the_rs256_floor() {
        let algs = id_token_signing_alg_values(&policy(&[JwsAlgorithm::Es256]));
        assert!(algs.contains(&"ES256".to_owned()));
        assert!(algs.contains(&"RS256".to_owned()), "the floor stays");
        assert!(!algs.contains(&"EdDSA".to_owned()), "policy bans EdDSA");
    }

    #[test]
    fn document_advertises_every_served_endpoint_and_the_required_fields() {
        let policy = SigningPolicy::eddsa_default();
        let doc = discovery_document(
            "https://issuer.test/t/tnt/e/env",
            "https://issuer.test",
            "https://issuer.test/t/tnt/e/env/jwks.json",
            &policy,
            &DiscoveryCapabilities::default(),
        );
        assert_eq!(doc["issuer"], json!("https://issuer.test/t/tnt/e/env"));
        assert_eq!(
            doc["jwks_uri"],
            json!("https://issuer.test/t/tnt/e/env/jwks.json")
        );
        assert_eq!(
            doc["authorization_endpoint"],
            json!("https://issuer.test/authorize")
        );
        assert_eq!(doc["token_endpoint"], json!("https://issuer.test/token"));
        // The issue #22 revocation and introspection endpoints (and #27's PAR
        // endpoint) this test is named for: each is advertised at its path.
        assert_eq!(
            doc["pushed_authorization_request_endpoint"],
            json!("https://issuer.test/par")
        );
        assert_eq!(
            doc["revocation_endpoint"],
            json!("https://issuer.test/revoke")
        );
        assert_eq!(
            doc["introspection_endpoint"],
            json!("https://issuer.test/introspect")
        );
        // Their auth-method arrays DIFFER by exactly `none`: `/revoke` accepts a public
        // client (RFC 7009), `/introspect` requires a confidential one (RFC 7662).
        assert_eq!(
            doc["revocation_endpoint_auth_methods_supported"],
            json!([
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
                "none"
            ]),
            "revocation advertises the full method set including none"
        );
        assert_eq!(
            doc["introspection_endpoint_auth_methods_supported"],
            json!([
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt"
            ]),
            "introspection advertises the confidential methods, excluding none"
        );
        // RFC 8414 section 2: the signing-alg arrays accompany private_key_jwt on both.
        assert!(doc["revocation_endpoint_auth_signing_alg_values_supported"].is_array());
        assert!(doc["introspection_endpoint_auth_signing_alg_values_supported"].is_array());
        // The explicit defaults-if-omitted traps.
        assert_eq!(doc["request_uri_parameter_supported"], json!(false));
        assert_eq!(doc["request_parameter_supported"], json!(false));
        assert_eq!(doc["claims_parameter_supported"], json!(false));
        assert_eq!(
            doc["authorization_response_iss_parameter_supported"],
            json!(false)
        );
    }

    #[test]
    fn from_config_advertises_iss_and_only_s256_pkce() {
        // Issue #13 flips the RFC 9207 capability on: the authorization endpoint
        // now emits iss on every response, so discovery advertises it.
        let caps = DiscoveryCapabilities::from_config(&OidcConfig::default());
        let policy = SigningPolicy::eddsa_default();
        let doc = discovery_document(
            "https://i.test/t/a/e/b",
            "https://i.test",
            "https://i.test/t/a/e/b/jwks.json",
            &policy,
            &caps,
        );
        assert_eq!(
            doc["authorization_response_iss_parameter_supported"],
            json!(true)
        );
        // PKCE is S256-only: plain is structurally absent from the registry, so it
        // can never be advertised.
        assert_eq!(doc["code_challenge_methods_supported"], json!(["S256"]));
    }

    #[test]
    fn from_config_advertises_only_the_enabled_legacy_types_and_modes() {
        // Issue #17: with everything off (the default), discovery advertises only
        // the always-on code flow with the query mode.
        let off = DiscoveryCapabilities::from_config(&OidcConfig::default());
        let policy = SigningPolicy::eddsa_default();
        let doc = |caps: &DiscoveryCapabilities| {
            discovery_document(
                "https://i.test/t/a/e/b",
                "https://i.test",
                "https://i.test/t/a/e/b/jwks.json",
                &policy,
                caps,
            )
        };
        let base = doc(&off);
        assert_eq!(base["response_types_supported"], json!(["code"]));
        assert_eq!(base["response_modes_supported"], json!(["query"]));

        // Enabling the hybrid flow adds `code id_token` and the `fragment` mode
        // (its default), and nothing else.
        let hybrid = DiscoveryCapabilities::from_config(&OidcConfig {
            enable_response_type_code_id_token: true,
            ..OidcConfig::default()
        });
        let doc_h = doc(&hybrid);
        assert_eq!(
            doc_h["response_types_supported"],
            json!(["code", "code id_token"])
        );
        assert_eq!(
            doc_h["response_modes_supported"],
            json!(["query", "fragment"])
        );

        // Enabling every legacy type plus form_post advertises the full set.
        let all = DiscoveryCapabilities::from_config(&OidcConfig {
            enable_response_type_id_token: true,
            enable_response_type_code_id_token: true,
            enable_response_type_none: true,
            enable_response_mode_form_post: true,
            ..OidcConfig::default()
        });
        let doc_a = doc(&all);
        assert_eq!(
            doc_a["response_types_supported"],
            json!(["code", "id_token", "code id_token", "none"])
        );
        assert_eq!(
            doc_a["response_modes_supported"],
            json!(["query", "fragment", "form_post"])
        );

        // form_post alone (no front-channel type) advertises form_post but NOT
        // fragment: fragment rides the front-channel feature.
        let fp = DiscoveryCapabilities::from_config(&OidcConfig {
            enable_response_mode_form_post: true,
            ..OidcConfig::default()
        });
        assert_eq!(
            doc(&fp)["response_modes_supported"],
            json!(["query", "form_post"])
        );
    }

    #[test]
    fn registration_endpoint_is_advertised_per_environment_only_when_enabled() {
        // Issue #30: the DCR registration_endpoint is per-environment
        // ({issuer}/connect/register) and advertised ONLY when enabled, so
        // discovery never announces an endpoint the server does not mount.
        let policy = SigningPolicy::eddsa_default();
        let doc = |caps: &DiscoveryCapabilities| {
            discovery_document(
                "https://i.test/t/a/e/b",
                "https://i.test",
                "https://i.test/t/a/e/b/jwks.json",
                &policy,
                caps,
            )
        };
        // Default off: absent.
        assert!(
            doc(&DiscoveryCapabilities::default())
                .get("registration_endpoint")
                .is_none(),
            "registration_endpoint is absent when the endpoint is disabled"
        );
        // Enabled: the per-environment issuer path, not the deployment root.
        let on = DiscoveryCapabilities::default().with_registration_endpoint(true);
        assert_eq!(
            doc(&on)["registration_endpoint"],
            json!("https://i.test/t/a/e/b/connect/register")
        );
        // from_config wires it from oidc.registration_enabled.
        let caps = DiscoveryCapabilities::from_config(&OidcConfig {
            registration_enabled: true,
            ..OidcConfig::default()
        });
        assert_eq!(
            doc(&caps)["registration_endpoint"],
            json!("https://i.test/t/a/e/b/connect/register")
        );
    }

    #[test]
    fn capabilities_toggle_response_modes_and_types_without_code_changes() {
        let policy = SigningPolicy::eddsa_default();
        let base = discovery_document(
            "https://i.test/t/a/e/b",
            "https://i.test",
            "https://i.test/t/a/e/b/jwks.json",
            &policy,
            &DiscoveryCapabilities::default(),
        );
        // Default: only the registry-sourced query mode; no legacy response type.
        assert_eq!(base["response_modes_supported"], json!(["query"]));
        assert_eq!(base["response_types_supported"], json!(["code"]));

        let extended = discovery_document(
            "https://i.test/t/a/e/b",
            "https://i.test",
            "https://i.test/t/a/e/b/jwks.json",
            &policy,
            &DiscoveryCapabilities::default()
                .with_additional_response_mode("form_post")
                .with_additional_response_type("code id_token"),
        );
        assert_eq!(
            extended["response_modes_supported"],
            json!(["query", "form_post"])
        );
        assert_eq!(
            extended["response_types_supported"],
            json!(["code", "code id_token"])
        );
    }
}
