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
//! It needs NONE of the loaded signing keys, so per-request discovery serving is
//! achievable without the operator-plane key enumeration issue #194 defers: the
//! [`discovery_router`] resolves the scope from the URL path and generates from
//! config. (The JWKS surface in [`crate::jwks`] does need the loaded keys and is
//! mounted by #194.)
//!
//! # What is advertised, and where it comes from
//!
//! Every `*_supported` array is sourced from the registry or const its owning
//! subsystem exposes, never hand-listed here, so a subsystem change flows into
//! discovery with no edit to the generator:
//!
//! - `response_types_supported`   <- [`ResponseType::ALL`] (+ per-env legacy, #17)
//! - `grant_types_supported`      <- [`GrantType::ALL`]
//! - `code_challenge_methods_supported` <- [`PkceMethod::ALL`]
//! - `token_endpoint_auth_methods_supported` <- [`ClientAuthMethod::ALL`]
//! - `subject_types_supported`    <- [`SubjectType::ALL`]
//! - `response_modes_supported`   <- [`ResponseMode::ALL`] (+ per-env `form_post`, #17)
//! - `prompt_values_supported`    <- [`PromptValue::ALL`]
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
use crate::issuer::JwksCacheWindow;
use crate::registry::{GrantType, PkceMethod, PromptValue, ResponseMode, ResponseType};
use crate::subject::SubjectType;
use crate::wellknown::{cacheable_response, not_found, parse_scope};

/// The media type for the discovery document (OIDC Discovery 1.0).
const DISCOVERY_MEDIA_TYPE: &str = "application/json";

/// The scopes IronAuth advertises. `openid` is the OIDC-mandated scope the
/// authorization-code flow is defined against; richer scopes (`profile`, `email`)
/// arrive with the claims that back them. This is the authoritative source until a
/// scope subsystem exposes its own registry.
pub const SCOPES_SUPPORTED: &[&str] = &["openid"];

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
/// The M3/M4 endpoints (`end_session_endpoint`, `revocation_endpoint`,
/// `introspection_endpoint`, `registration_endpoint`, `userinfo_endpoint`) join
/// this list when their issues land.
pub const ADVERTISED_ENDPOINTS: &[DiscoveryEndpoint] = &[
    DiscoveryEndpoint {
        metadata_key: "authorization_endpoint",
        path: "/authorize",
    },
    DiscoveryEndpoint {
        metadata_key: "token_endpoint",
        path: "/token",
    },
];

/// The per-environment, config-driven capability toggles the generator layers on
/// top of the fixed registries.
///
/// Everything here is either a per-environment feature owned by a later issue
/// (whose flag flows in through [`DiscoveryCapabilities::from_config`] once that
/// issue lands) or a deployment default. The FIXED capabilities (`code`,
/// `authorization_code`, `S256`, the client-auth methods, the subject types, the
/// `query` response mode, the `create` prompt) are read straight from the
/// registries and are never represented here.
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
}

impl DiscoveryCapabilities {
    /// The capabilities implied by live configuration.
    ///
    /// The authorization endpoint now emits the RFC 9207 `iss` on every
    /// authorization response, success and error, on every response mode (issue
    /// #13), so discovery advertises
    /// `authorization_response_iss_parameter_supported = true`. The remaining
    /// per-environment features (legacy response types, `form_post`) stay off until
    /// their owning issue (#17) wires their flags in here; discovery reflects each
    /// with no change to the generator.
    #[must_use]
    pub fn from_config(_config: &OidcConfig) -> Self {
        Self::default().with_authorization_response_iss(true)
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
#[must_use]
pub fn discovery_document(
    issuer: &str,
    base: &str,
    jwks_uri: &str,
    policy: &SigningPolicy,
    capabilities: &DiscoveryCapabilities,
) -> Value {
    let mut response_types = to_strings(ResponseType::ALL.iter().map(|value| value.as_str()));
    response_types.extend(capabilities.additional_response_types.iter().cloned());

    let mut response_modes = to_strings(ResponseMode::ALL.iter().map(|value| value.as_str()));
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
    document.insert(
        "claims_supported".to_owned(),
        json!(ID_TOKEN_CLAIMS_SUPPORTED),
    );
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
    document.insert("claims_parameter_supported".to_owned(), json!(false));
    document.insert(
        "authorization_response_iss_parameter_supported".to_owned(),
        json!(capabilities.authorization_response_iss_parameter_supported),
    );

    Value::Object(document)
}

/// Collect an iterator of string slices into owned `String`s.
fn to_strings<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    values.map(ToOwned::to_owned).collect()
}

/// The shared state for the discovery surface.
///
/// Holds only what discovery needs: the deployment base URL, the JWKS/discovery
/// cache window, the per-environment capabilities, and the algorithm policy
/// source. It deliberately carries NO signing keys and NO store handle, which is
/// why it mounts on the live data plane today (issue #18) ahead of the key loading
/// issue #194 defers.
#[derive(Clone)]
pub struct DiscoveryState {
    issuer_base: String,
    cache: JwksCacheWindow,
    capabilities: DiscoveryCapabilities,
    default_policy: SigningPolicy,
}

impl DiscoveryState {
    /// Build the discovery state from the deployment base URL, the cache window,
    /// and the per-environment capabilities.
    ///
    /// The algorithm policy defaults to [`SigningPolicy::eddsa_default`] for every
    /// scope. Per-environment policy resolution ([`SigningPolicy::resolve`]) is the
    /// generator's input and is fully unit-tested; the LIVE mount feeds it the
    /// deployment default until per-environment policy sources load (alongside the
    /// keys, issue #194). Swapping in a per-scope policy source is a change to
    /// [`DiscoveryState::policy_for`] only.
    #[must_use]
    pub fn new(
        issuer_base: impl Into<String>,
        cache: JwksCacheWindow,
        capabilities: DiscoveryCapabilities,
    ) -> Self {
        Self {
            issuer_base: issuer_base.into(),
            cache,
            capabilities,
            default_policy: SigningPolicy::eddsa_default(),
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

    /// The signing-algorithm policy for `scope`.
    ///
    /// Today the deployment default for every scope (see [`DiscoveryState::new`]);
    /// the seam a per-environment policy source plugs into.
    fn policy_for(&self, _scope: &Scope) -> &SigningPolicy {
        &self.default_policy
    }

    /// Render the discovery document for an already-parsed `scope` as a cacheable
    /// response (the malformed-scope `404` is handled by the caller before this).
    fn respond(&self, scope: &Scope, headers: &HeaderMap) -> Response {
        let issuer = self.issuer_for(scope);
        let jwks_uri = format!("{issuer}/jwks.json");
        let document = discovery_document(
            &issuer,
            self.base(),
            &jwks_uri,
            self.policy_for(scope),
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
/// Mount it on the PUBLIC data plane alongside the protocol router. Every route
/// resolves the `(tenant, environment)` scope from the URL path and generates the
/// document from live config; a malformed scope is a uniform `404`.
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
    serve(&state, &tenant_id, &environment_id, &headers)
}

/// `GET {host}/.well-known/oauth-authorization-server/{issuer-path}` (RFC 8414,
/// host-inserted).
async fn inserted_oauth_authorization_server(
    State(state): State<DiscoveryState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    serve(&state, &tenant_id, &environment_id, &headers)
}

/// `GET {host}/.well-known/openid-configuration/{issuer-path}` (host-inserted
/// openid-configuration; the MCP-probed variant).
async fn inserted_openid_configuration(
    State(state): State<DiscoveryState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    serve(&state, &tenant_id, &environment_id, &headers)
}

/// Resolve the scope and render, or a uniform `404` for a malformed scope. All
/// three well-known forms funnel through here, so every one returns the identical
/// document for a given issuer.
fn serve(
    state: &DiscoveryState,
    tenant_id: &str,
    environment_id: &str,
    headers: &HeaderMap,
) -> Response {
    let Some(scope) = parse_scope(tenant_id, environment_id) else {
        return not_found();
    };
    state.respond(&scope, headers)
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
