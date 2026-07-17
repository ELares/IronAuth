// SPDX-License-Identifier: MIT OR Apache-2.0

//! Declarative federation connectors and the capability matrix (issue #75).
//!
//! Every identity provider faces the same fork: absorb the provider long tail as
//! in-tree code, or make it configuration. This crate is the second path. A
//! [`ConnectorDefinition`] is a pure DATA description of an OIDC-shaped upstream:
//! its issuer or explicit endpoint set, scopes, client credentials, PKCE mode,
//! declarative claim mapping, quirks, and a machine-readable [`CapabilityMatrix`].
//! Adding a new OIDC-shaped provider becomes a definition, never a code change and
//! never a release.
//!
//! # No raw fetch by construction
//!
//! This crate parses ATTACKER-INFLUENCED input (a connector's `issuer`,
//! `jwks_uri`, and endpoint URLs are all values a tenant controls). It has NO
//! dependency on `ironauth-fetch` and NO HTTP-client dependency, so a connector
//! definition cannot even NAME a raw outbound fetch: the crate that parses the
//! hostile document is structurally incapable of performing a request. Every
//! federation fetch (discovery, JWKS, userinfo) rides the SSRF-hardened
//! `ironauth-fetch` path in a later slice; `scripts/http-audit.sh` enforces that
//! this crate stays fetch-free.
//!
//! # Two-phase strict validation
//!
//! A definition is rejected at WRITE time, never at login time, in two phases:
//!
//! 1. **Deserialization.** Every nested struct carries `#[serde(deny_unknown_fields)]`,
//!    so an unknown key fails the parse (the strict-config rule). The `endpoints`
//!    field is a hand-validated one-of that NAMES the two accepted forms in its
//!    error (mirroring `ironauth_config`'s `SecretVisitor`), never serde's opaque
//!    "did not match any variant".
//! 2. **Semantics.** [`ConnectorDefinition::validate`] returns
//!    [`ValidationError`]s carrying RFC 6901 JSON POINTERS to the offending node:
//!    the `openid` scope must be present, and every endpoint URL must be an
//!    absolute `https` URL (the issuer additionally with no query or fragment).
//!
//! The URL check here is SYNTACTIC only. The SSRF network check (a private-range
//! host) happens at fetch time in the federation slice, so a private-range host
//! passes syntax here and blocks on the wire later. No `url` crate is pulled in
//! for the syntactic check; it is done inline.
//!
//! # The claim-mapping evaluator
//!
//! [`ClaimMapping`] is the parsed-and-stored declarative SHAPE; the [`claim_mapping`]
//! module is its EVALUATOR (issue #75, PR C). [`claim_mapping::evaluate`] is a pure,
//! I/O-free transform from an upstream's verified claims to an IronAuth trait
//! document, with a fail-closed contract: on any missing required claim, malformed
//! claim, or trait-schema type-check failure it returns a typed error and NO document,
//! so a mapping failure never provisions a partial identity. It stays store-free (the
//! trait-schema type check is injected via [`claim_mapping::TraitSchemaView`]), so this
//! crate remains pure and fetch-free.

pub mod claim_mapping;
pub mod discovery;
pub mod error;

pub use claim_mapping::{
    ClaimMappingError, ClaimSources, TraitDocument, TraitPointerFailure, TraitSchemaView, evaluate,
};
pub use discovery::{ResolvedEndpoints, discovery_url, parse_discovery, resolve_explicit};
pub use error::ConnectorError;

use std::collections::BTreeMap;
use std::fmt;

use ironauth_config::Secret;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema, schema_for};
use serde::de::{self, Deserializer};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

/// The federation protocol a connector speaks. A CLOSED enum with one variant:
/// SAML is deliberately UNREPRESENTABLE (the hostile-parser SAML SP inbound is a
/// later milestone), so a definition can never assert a protocol this slice does
/// not implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// OpenID Connect (the generic OIDC upstream).
    Oidc,
}

/// How PKCE is applied to the UPSTREAM authorization request (RFC 7636). Only the
/// `S256` challenge method is ever used; `plain` is never offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PkceMode {
    /// Use PKCE when the upstream advertises support, otherwise omit it (the
    /// conservative interoperable default).
    #[default]
    AutoWhereSupported,
    /// Always send a PKCE challenge; refuse to proceed if the upstream cannot
    /// accept one.
    Required,
    /// Never send a PKCE challenge (only for an upstream that rejects the extra
    /// parameters).
    Disabled,
}

/// How much IronAuth trusts an upstream's `email_verified` claim. Defaults to
/// [`EmailVerifiedTrust::Untrusted`]: a connector's assertion that an email is
/// verified is NOT believed unless the definition explicitly raises the trust, a
/// named conservative default (issue #75 acceptance criterion).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EmailVerifiedTrust {
    /// The upstream's `email_verified` is not trusted (the conservative default).
    #[default]
    Untrusted,
    /// The upstream's `email_verified` is trusted as authoritative.
    Trusted,
}

impl EmailVerifiedTrust {
    /// The stable wire string (`untrusted`, `trusted`), the value the capability
    /// column stores and the management API serves.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EmailVerifiedTrust::Untrusted => "untrusted",
            EmailVerifiedTrust::Trusted => "trusted",
        }
    }
}

/// Where a connector's email address is sourced from. Expressed as DATA (a new
/// upstream's non-standard email resolution is a new field value, never a new
/// code branch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EmailSource {
    /// Read the email from the ID token claims (the OIDC-standard default).
    #[default]
    IdToken,
    /// Read the email from the `UserInfo` response.
    Userinfo,
    /// Prefer the ID token, then fall back to `UserInfo`.
    FallbackOrder,
}

/// The machine-readable, per-connector capability record (issue #75).
///
/// "Which upstream supports refresh, groups, logout propagation, or a trustworthy
/// `email_verified`" is a recurring ecosystem surprise because it varies silently
/// by connector. This record makes it introspectable. Every value comes from the
/// connector definition with CONSERVATIVE DEFAULTS: all capabilities are absent
/// (`false`) and `email_verified_trust` is [`EmailVerifiedTrust::Untrusted`] until
/// the definition asserts otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct CapabilityMatrix {
    /// Whether the upstream supports refresh tokens.
    pub refresh: bool,
    /// Whether the upstream delivers group memberships.
    pub groups: bool,
    /// Whether the upstream supports logout propagation.
    pub logout_propagation: bool,
    /// How much the upstream's `email_verified` claim is trusted.
    pub email_verified_trust: EmailVerifiedTrust,
}

impl Default for CapabilityMatrix {
    /// The conservative defaults: no capability asserted, email-verified trust
    /// UNTRUSTED. This is the single place the safe defaults are encoded.
    fn default() -> Self {
        Self {
            refresh: false,
            groups: false,
            logout_propagation: false,
            email_verified_trust: EmailVerifiedTrust::Untrusted,
        }
    }
}

/// Provider quirks expressed as DATA (issue #75). A new upstream's idiosyncrasy is
/// a new field value here, never a new code branch: the generic upstream reads
/// these flags rather than switching on a provider name.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Quirks {
    /// The upstream delivers the user profile only on the FIRST authorization (for
    /// example Apple); a subsequent login must reuse the stored profile.
    pub profile_delivered_first_auth_only: bool,
    /// Where the email address is sourced from.
    pub email_source: EmailSource,
    /// Whether a `UserInfo` request is required to assemble the identity (some
    /// upstreams omit standard claims from the ID token).
    pub userinfo_required: bool,
}

/// One declarative claim-mapping rule: an ordered list of upstream claim paths to
/// try (the first that resolves wins) and whether a value is required.
///
/// [`claim_mapping::evaluate`] resolves a rule against the merged ID-token /
/// `UserInfo` claims, type-checks the assembled document against the trait schema,
/// and fails closed on a missing required or malformed claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimRule {
    /// The ordered upstream claim paths to try, in fallback order.
    pub source: Vec<String>,
    /// Whether a resolved value is required (a missing required value fails the
    /// login in the evaluator slice, never provisions a partial identity).
    #[serde(default = "default_true")]
    pub required: bool,
}

/// The default for [`ClaimRule::required`]: a mapped claim is required unless the
/// definition says otherwise.
const fn default_true() -> bool {
    true
}

/// The declarative mapping from upstream claims to IronAuth identity traits (issue
/// #75). The stored SHAPE; [`claim_mapping::evaluate`] is its evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ClaimMapping {
    /// The rule that maps the stable upstream subject, if the definition overrides
    /// the default (`sub`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<ClaimRule>,
    /// Per-trait-field rules, keyed by the IronAuth trait field name.
    pub traits: BTreeMap<String, ClaimRule>,
}

/// The discovery endpoint form: an `issuer` whose `.well-known/openid-configuration`
/// the upstream advertises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryEndpoints {
    /// The upstream issuer identifier (an absolute `https` URL, no query or
    /// fragment). Discovery derives every endpoint from it.
    pub issuer: String,
}

/// The explicit endpoint form: the individual endpoint URLs, for an upstream that
/// does not publish a discovery document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplicitEndpoints {
    /// The upstream authorization endpoint (mandatory).
    pub authorization_endpoint: String,
    /// The upstream token endpoint (mandatory).
    pub token_endpoint: String,
    /// The upstream JWKS URI (mandatory: ID-token signatures are verified against
    /// it).
    pub jwks_uri: String,
    /// The upstream `UserInfo` endpoint (optional).
    pub userinfo_endpoint: Option<String>,
}

/// A connector's endpoints: EITHER a discovery `issuer` OR an explicit endpoint
/// set, never both. Hand-validated (like `ironauth_config`'s `Secret`) so a
/// malformed value fails with the accepted forms spelled out, not serde's opaque
/// "did not match any variant".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoints {
    /// The discovery form (`{ issuer }`).
    Discovery(DiscoveryEndpoints),
    /// The explicit form (`{ authorization_endpoint, token_endpoint, jwks_uri,
    /// userinfo_endpoint? }`).
    Explicit(ExplicitEndpoints),
}

/// The accepted endpoint forms, named in every rejection so an operator can fix a
/// malformed definition.
const ENDPOINTS_FORMS: &str = "endpoints must be EITHER { issuer } for discovery \
     OR { authorization_endpoint, token_endpoint, jwks_uri, userinfo_endpoint? } \
     for an explicit set";

impl Endpoints {
    /// Assemble the endpoints from the flat, deny-unknown-fields raw form,
    /// enforcing the one-of and the mandatory explicit fields, naming the accepted
    /// forms on any failure.
    fn from_raw(raw: RawEndpoints) -> Result<Self, String> {
        let explicit_present = raw.authorization_endpoint.is_some()
            || raw.token_endpoint.is_some()
            || raw.jwks_uri.is_some()
            || raw.userinfo_endpoint.is_some();
        if let Some(issuer) = raw.issuer {
            if explicit_present {
                return Err(format!(
                    "endpoints carries both an issuer and explicit endpoints; {ENDPOINTS_FORMS}, not both"
                ));
            }
            return Ok(Endpoints::Discovery(DiscoveryEndpoints { issuer }));
        }
        if !explicit_present {
            return Err(format!("endpoints is empty; {ENDPOINTS_FORMS}"));
        }
        match (raw.authorization_endpoint, raw.token_endpoint, raw.jwks_uri) {
            (Some(authorization_endpoint), Some(token_endpoint), Some(jwks_uri)) => {
                Ok(Endpoints::Explicit(ExplicitEndpoints {
                    authorization_endpoint,
                    token_endpoint,
                    jwks_uri,
                    userinfo_endpoint: raw.userinfo_endpoint,
                }))
            }
            _ => Err(format!(
                "the explicit endpoint set requires authorization_endpoint, token_endpoint, \
                 and jwks_uri (userinfo_endpoint is optional); {ENDPOINTS_FORMS}"
            )),
        }
    }
}

/// The flat wire form of [`Endpoints`], with `deny_unknown_fields` so an unknown
/// endpoint key fails the parse. The one-of and mandatory-field rules are applied
/// by [`Endpoints::from_raw`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEndpoints {
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    jwks_uri: Option<String>,
}

impl<'de> Deserialize<'de> for Endpoints {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawEndpoints::deserialize(deserializer)?;
        Endpoints::from_raw(raw).map_err(de::Error::custom)
    }
}

impl Serialize for Endpoints {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Endpoints::Discovery(discovery) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("issuer", &discovery.issuer)?;
                map.end()
            }
            Endpoints::Explicit(explicit) => {
                let len = 3 + usize::from(explicit.userinfo_endpoint.is_some());
                let mut map = serializer.serialize_map(Some(len))?;
                map.serialize_entry("authorization_endpoint", &explicit.authorization_endpoint)?;
                map.serialize_entry("token_endpoint", &explicit.token_endpoint)?;
                if let Some(userinfo) = &explicit.userinfo_endpoint {
                    map.serialize_entry("userinfo_endpoint", userinfo)?;
                }
                map.serialize_entry("jwks_uri", &explicit.jwks_uri)?;
                map.end()
            }
        }
    }
}

impl JsonSchema for Endpoints {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("Endpoints")
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed(concat!(module_path!(), "::Endpoints"))
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A connector's endpoints: EITHER a discovery issuer OR an explicit endpoint set, never both.",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "issuer": {
                            "type": "string",
                            "description": "The upstream issuer (an absolute https URL with no query or fragment); discovery derives every endpoint from it."
                        }
                    },
                    "required": ["issuer"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "authorization_endpoint": { "type": "string", "description": "The upstream authorization endpoint (an absolute https URL)." },
                        "token_endpoint": { "type": "string", "description": "The upstream token endpoint (an absolute https URL)." },
                        "jwks_uri": { "type": "string", "description": "The upstream JWKS URI (an absolute https URL)." },
                        "userinfo_endpoint": { "type": "string", "description": "The upstream UserInfo endpoint (an absolute https URL), optional." }
                    },
                    "required": ["authorization_endpoint", "token_endpoint", "jwks_uri"],
                    "additionalProperties": false
                }
            ]
        })
    }
}

/// A declarative connector definition (issue #75): a pure DATA description of an
/// OIDC-shaped upstream. Parsed with strict serde (`deny_unknown_fields` on every
/// nested struct) and semantically checked by [`ConnectorDefinition::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorDefinition {
    /// The connector slug: a stable, human-readable identifier unique per
    /// environment (lowercase ASCII alphanumerics, hyphen, and underscore).
    pub connector_id: String,
    /// The human-facing display name.
    pub display_name: String,
    /// The federation protocol (a closed set; `oidc` only in this slice).
    pub protocol: Protocol,
    /// The upstream endpoints: a discovery issuer or an explicit set.
    pub endpoints: Endpoints,
    /// The scopes requested from the upstream. `openid` is required for `oidc`.
    pub scopes: Vec<String>,
    /// The client identifier IronAuth registers at the upstream.
    pub client_id: String,
    /// The upstream client secret, by indirection (file / env / literal), redacted
    /// in every debug, display, and serialization. Never stored inline in the
    /// definition projection; sealed under the envelope substrate at write time.
    pub client_secret: Secret,
    /// How PKCE is applied to the upstream authorization request.
    #[serde(default)]
    pub pkce: PkceMode,
    /// The declarative claim mapping (the stored SHAPE; the evaluator is later).
    #[serde(default)]
    pub claim_mapping: ClaimMapping,
    /// The machine-readable capability matrix (conservative defaults).
    #[serde(default)]
    pub capabilities: CapabilityMatrix,
    /// Provider quirks expressed as data.
    #[serde(default)]
    pub quirks: Quirks,
    /// Whether the connector is active. Defaults to `true` (a new connector is
    /// enabled); an operator can set it `false` on an update to disable the
    /// connector without deleting it. This is operational state the management API
    /// carries on the definition body; the store persists it in the `enabled`
    /// column and every read projects it.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

/// A connector is enabled by default (the `enabled` field's serde default).
fn default_enabled() -> bool {
    true
}

/// The SECRET-FREE runtime view of a connector definition (issue #75, PR B): exactly the
/// fields the federation login path reads back from the stored `definition_json`.
///
/// The stored projection ([`ConnectorDefinition::secret_free_json`]) STRIPS the
/// `client_secret`, so it cannot be deserialized into a [`ConnectorDefinition`] (whose
/// `client_secret` is mandatory). This projection deserializes what the login path needs
/// (the endpoints, the requested scopes, the client id, and the PKCE policy) and IGNORES
/// every other field, so it round-trips the secret-free document. It is deliberately NOT
/// `deny_unknown_fields`: it is a forward-compatible READ projection, not the strict,
/// exhaustive write-time parse.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ConnectorRuntimeConfig {
    /// The upstream endpoints (a discovery issuer or an explicit set).
    pub endpoints: Endpoints,
    /// The scopes requested from the upstream.
    pub scopes: Vec<String>,
    /// The client identifier IronAuth registers at the upstream (the ID token audience).
    pub client_id: String,
    /// How PKCE is applied to the upstream authorization request.
    #[serde(default)]
    pub pkce: PkceMode,
    /// The declarative claim mapping the callback evaluates the verified upstream claims
    /// through to assemble the local identity's traits (issue #75, PR C).
    #[serde(default)]
    pub claim_mapping: ClaimMapping,
    /// Provider quirks read as data (issue #75, PR C): the email source order the claim
    /// mapping resolves email through, and whether `UserInfo` is required.
    #[serde(default)]
    pub quirks: Quirks,
}

/// One semantic validation failure, carrying an RFC 6901 JSON POINTER to the
/// offending node and a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// An RFC 6901 JSON Pointer to the offending location (for example
    /// `/endpoints/issuer` or `/scopes`).
    pub pointer: String,
    /// A human-readable description of the violation.
    pub message: String,
}

impl ValidationError {
    /// Build a validation error at `pointer` with `message`.
    fn new(pointer: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            pointer: pointer.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.pointer, self.message)
    }
}

impl ConnectorDefinition {
    /// Semantically validate the definition (phase two), returning EVERY violation
    /// with its JSON Pointer, or `Ok(())` when the definition is well-formed.
    ///
    /// The deserialization phase (unknown keys, the endpoints one-of) has already
    /// run by the time a value of this type exists; this phase enforces the
    /// semantics serde cannot: a non-empty slug, the required `openid` scope, and
    /// the SYNTACTIC shape of every URL (absolute `https`; the issuer additionally
    /// with no query or fragment). The SSRF network check is deliberately NOT here.
    ///
    /// # Errors
    ///
    /// A non-empty `Vec<ValidationError>` of every violation found.
    pub fn validate(&self) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();

        if !is_slug(&self.connector_id) {
            errors.push(ValidationError::new(
                "/connector_id",
                "must be a non-empty slug of lowercase ASCII alphanumerics, hyphen, or underscore",
            ));
        }
        if self.display_name.trim().is_empty() {
            errors.push(ValidationError::new(
                "/display_name",
                "must be a non-empty string",
            ));
        }
        if self.client_id.is_empty() {
            errors.push(ValidationError::new(
                "/client_id",
                "must be a non-empty string",
            ));
        }

        // The `oidc` protocol requires the `openid` scope.
        if !self.scopes.iter().any(|scope| scope == "openid") {
            errors.push(ValidationError::new(
                "/scopes",
                "the openid scope is required for an oidc connector",
            ));
        }

        // Every endpoint URL is checked SYNTACTICALLY only.
        match &self.endpoints {
            Endpoints::Discovery(discovery) => {
                check_url(
                    &discovery.issuer,
                    "/endpoints/issuer",
                    UrlShape::IssuerNoQueryFragment,
                    &mut errors,
                );
            }
            Endpoints::Explicit(explicit) => {
                check_url(
                    &explicit.authorization_endpoint,
                    "/endpoints/authorization_endpoint",
                    UrlShape::AbsoluteHttps,
                    &mut errors,
                );
                check_url(
                    &explicit.token_endpoint,
                    "/endpoints/token_endpoint",
                    UrlShape::AbsoluteHttps,
                    &mut errors,
                );
                check_url(
                    &explicit.jwks_uri,
                    "/endpoints/jwks_uri",
                    UrlShape::AbsoluteHttps,
                    &mut errors,
                );
                if let Some(userinfo) = &explicit.userinfo_endpoint {
                    check_url(
                        userinfo,
                        "/endpoints/userinfo_endpoint",
                        UrlShape::AbsoluteHttps,
                        &mut errors,
                    );
                }
            }
        }

        // The subject cannot be remapped. A federated identity is ALWAYS keyed on the
        // verified, issuer-namespaced upstream `sub` (the composite the federation layer
        // establishes), never on the mapped subject; the mapping's `subject` rule feeds
        // only a cosmetic view. So a CUSTOM subject rule can never change the identity and
        // can only FAIL a login (when the mapped claim is absent or the wrong type) for
        // zero benefit. Reject anything other than the canonical default (`sub`, required)
        // at write time, so an operator gets a clear config error instead of a login-time
        // trap. The default (an absent `subject`, or an explicit `{ source: ["sub"] }`) is
        // accepted.
        if let Some(subject_rule) = &self.claim_mapping.subject {
            let is_default = subject_rule.required
                && subject_rule.source.len() == 1
                && subject_rule.source[0] == "sub";
            if !is_default {
                errors.push(ValidationError::new(
                    "/claim_mapping/subject",
                    "the subject cannot be remapped: a federated identity is always keyed on \
                     the verified upstream `sub` claim, so a custom subject rule can only fail \
                     logins for no benefit; remove the subject rule (the default `sub` is \
                     always used)",
                ));
            }
        }

        // Reject a connector that REQUIRES a UserInfo fetch to assemble the identity. The
        // federation callback passes `userinfo: None` (the UserInfo fetch is deferred to
        // issue #74), so any connector that sources a claim from UserInfo would fail EVERY
        // login. Rejecting at write time turns a silent, per-login availability cliff (a
        // failure that would even be misclassified as an upstream fault) into one actionable
        // config error. Two forms require UserInfo: `email_source: "userinfo"` (email sourced
        // ONLY from UserInfo) and `userinfo_required: true`. `fallback_order` always tries the
        // ID token first, so it does not require UserInfo and is accepted.
        if self.quirks.userinfo_required {
            errors.push(ValidationError::new(
                "/quirks/userinfo_required",
                "userinfo_required is not yet supported: the UserInfo fetch is deferred \
                 (issue #74), so a userinfo-required connector would fail every login; set it \
                 false until UserInfo fetch lands",
            ));
        }
        if self.quirks.email_source == EmailSource::Userinfo {
            errors.push(ValidationError::new(
                "/quirks/email_source",
                "email_source \"userinfo\" is not yet supported: the UserInfo fetch is deferred \
                 (issue #74), so a userinfo-sourced email would fail every login; use \
                 \"id_token\" or \"fallback_order\" until UserInfo fetch lands",
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// The SECRET-FREE JSON projection of this definition, for the `definition_json`
    /// column. The `client_secret` field is removed entirely (its VALUE is sealed
    /// separately under the envelope substrate and referenced by id), so the stored
    /// document can never carry secret material even in principle.
    ///
    /// # Errors
    ///
    /// The underlying [`serde_json::Error`] if the definition cannot be serialized to
    /// a JSON value. A serialize fault is surfaced rather than swallowed to `null`, so
    /// a corrupt projection can never be persisted silently as the stored definition.
    pub fn secret_free_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        if let Some(object) = value.as_object_mut() {
            object.remove("client_secret");
        }
        Ok(value)
    }

    /// The capability matrix, the single source the persisted capability columns
    /// and the management API read from.
    #[must_use]
    pub fn capabilities(&self) -> &CapabilityMatrix {
        &self.capabilities
    }

    /// The upstream client secret indirection, for sealing at write time.
    #[must_use]
    pub fn client_secret(&self) -> &Secret {
        &self.client_secret
    }
}

/// Whether `value` is a non-empty slug: lowercase ASCII alphanumerics, hyphen, and
/// underscore. Restricting to ASCII sidesteps any Unicode normalization concern.
fn is_slug(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// The syntactic URL shape a field must match.
#[derive(Clone, Copy)]
enum UrlShape {
    /// An absolute `https` URL with an authority.
    AbsoluteHttps,
    /// An absolute `https` URL with an authority and NO query or fragment (an
    /// issuer identifier).
    IssuerNoQueryFragment,
}

/// Push a violation at `pointer` unless `url` matches `shape`. SYNTACTIC only: no
/// DNS, no reachability, no SSRF check (that is the fetch-time concern).
fn check_url(url: &str, pointer: &str, shape: UrlShape, errors: &mut Vec<ValidationError>) {
    if let Err(reason) = validate_https_url(url, shape) {
        errors.push(ValidationError::new(pointer, reason));
    }
}

/// Validate that `url` is an absolute `https` URL with a non-empty authority,
/// inline and without the `url` crate. For [`UrlShape::IssuerNoQueryFragment`] the
/// URL must additionally carry no query (`?`) and no fragment (`#`).
///
/// This is a deliberately minimal syntactic gate: the scheme must be `https`
/// (case-insensitive), an authority must be present, and (for an issuer) there
/// must be no query or fragment. It does not parse userinfo, ports, or paths
/// beyond confirming an authority exists, because the SSRF-hardened fetcher parses
/// and resolves the URL authoritatively at fetch time.
fn validate_https_url(url: &str, shape: UrlShape) -> Result<(), String> {
    // Scheme: case-insensitive `https://`.
    let scheme_len = "https://".len();
    let starts_https =
        url.len() >= scheme_len && url[..scheme_len].eq_ignore_ascii_case("https://");
    if !starts_https {
        return Err(format!(
            "must be an absolute https URL (got {})",
            truncate_for_error(url)
        ));
    }
    let rest = &url[scheme_len..];
    // The authority runs to the first '/', '?', or '#'.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err("must be an absolute https URL with a host".to_owned());
    }
    // A host must carry no whitespace or control characters (a syntactic sanity
    // gate; the fetcher validates the host authoritatively).
    if authority
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err("the host contains an invalid character".to_owned());
    }
    // Reject userinfo (`user:pass@host`) in the authority: a credential-bearing
    // authority is a host-confusion vector (the host a human reads is not the host
    // resolved), so it is barred at validation time exactly like the #13 redirect
    // userinfo-reject. The network SSRF block is a later, fetch-time concern.
    if authority.contains('@') {
        return Err("must not contain userinfo credentials (user:pass@host)".to_owned());
    }
    if let UrlShape::IssuerNoQueryFragment = shape {
        if url.contains('?') || url.contains('#') {
            return Err("an issuer must not contain a query or fragment".to_owned());
        }
    }
    Ok(())
}

/// A short, safe rendering of a URL for an error message (bounded so a hostile
/// definition cannot blow up a log line).
fn truncate_for_error(url: &str) -> String {
    const MAX: usize = 64;
    if url.len() <= MAX {
        return url.to_owned();
    }
    let mut end = MAX;
    while end > 0 && !url.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &url[..end])
}

/// The published JSON Schema for [`ConnectorDefinition`], emitted to
/// `docs/connector-schema.json` and CI-freshness-checked (see
/// `scripts/connector-schema.sh`). Deterministic (schemars emits sorted maps).
#[must_use]
pub fn connector_definition_schema() -> Schema {
    schema_for!(ConnectorDefinition)
}

/// The published JSON Schema for [`CapabilityMatrix`], emitted to
/// `docs/capability-matrix.schema.json` and CI-freshness-checked. This is the
/// schema-stability CONTRACT the acceptance criteria pin.
#[must_use]
pub fn capability_matrix_schema() -> Schema {
    schema_for!(CapabilityMatrix)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"{
        "connector_id": "acme-oidc",
        "display_name": "Acme OIDC",
        "protocol": "oidc",
        "endpoints": { "issuer": "https://issuer.example.com" },
        "scopes": ["openid", "email"],
        "client_id": "ironauth-at-acme",
        "client_secret": { "env": "ACME_CLIENT_SECRET" }
    }"#;

    fn parse(json: &str) -> Result<ConnectorDefinition, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn a_valid_definition_parses_and_validates() {
        let def = parse(VALID).expect("parses");
        def.validate().expect("valid");
        assert_eq!(def.connector_id, "acme-oidc");
        assert_eq!(def.protocol, Protocol::Oidc);
        // The conservative defaults hold when the fields are absent.
        assert_eq!(def.pkce, PkceMode::AutoWhereSupported);
        assert_eq!(
            def.capabilities.email_verified_trust,
            EmailVerifiedTrust::Untrusted
        );
        assert!(!def.capabilities.refresh);
    }

    #[test]
    fn unknown_key_is_rejected_at_parse_time() {
        let json = VALID.replace("\"scopes\"", "\"scopez\"");
        let err = parse(&json).expect_err("unknown key rejected");
        assert!(err.to_string().contains("scopez") || err.to_string().contains("unknown field"));
    }

    #[test]
    fn both_endpoint_forms_are_rejected_naming_the_forms() {
        let json = VALID.replace(
            "{ \"issuer\": \"https://issuer.example.com\" }",
            "{ \"issuer\": \"https://issuer.example.com\", \"token_endpoint\": \"https://issuer.example.com/token\" }",
        );
        let err = parse(&json).expect_err("both forms rejected");
        let message = err.to_string();
        assert!(message.contains("issuer"), "{message}");
        assert!(message.contains("authorization_endpoint"), "{message}");
    }

    #[test]
    fn an_incomplete_explicit_set_is_rejected() {
        let json = VALID.replace(
            "{ \"issuer\": \"https://issuer.example.com\" }",
            "{ \"authorization_endpoint\": \"https://issuer.example.com/authorize\" }",
        );
        let err = parse(&json).expect_err("incomplete explicit set rejected");
        assert!(err.to_string().contains("token_endpoint"), "{err}");
    }

    #[test]
    fn a_complete_explicit_set_parses_and_validates() {
        let json = VALID.replace(
            "{ \"issuer\": \"https://issuer.example.com\" }",
            "{ \"authorization_endpoint\": \"https://up.example.com/authorize\", \
               \"token_endpoint\": \"https://up.example.com/token\", \
               \"jwks_uri\": \"https://up.example.com/jwks\" }",
        );
        let def = parse(&json).expect("parses");
        def.validate().expect("valid");
        match def.endpoints {
            Endpoints::Explicit(explicit) => {
                assert!(explicit.userinfo_endpoint.is_none());
            }
            Endpoints::Discovery(_) => panic!("expected explicit"),
        }
    }

    #[test]
    fn missing_openid_scope_is_rejected_with_a_pointer() {
        let json = VALID.replace("[\"openid\", \"email\"]", "[\"email\"]");
        let def = parse(&json).expect("parses");
        let errors = def.validate().expect_err("missing openid scope");
        assert!(
            errors.iter().any(|error| error.pointer == "/scopes"),
            "{errors:?}"
        );
    }

    #[test]
    fn a_non_https_issuer_is_rejected_with_a_pointer() {
        let json = VALID.replace("https://issuer.example.com", "http://issuer.example.com");
        let def = parse(&json).expect("parses");
        let errors = def.validate().expect_err("non-https issuer");
        assert!(
            errors
                .iter()
                .any(|error| error.pointer == "/endpoints/issuer"),
            "{errors:?}"
        );
    }

    #[test]
    fn an_issuer_with_a_query_is_rejected() {
        let json = VALID.replace(
            "https://issuer.example.com",
            "https://issuer.example.com/?a=b",
        );
        let def = parse(&json).expect("parses");
        let errors = def.validate().expect_err("issuer with query");
        assert!(
            errors
                .iter()
                .any(|error| error.pointer == "/endpoints/issuer"),
            "{errors:?}"
        );
    }

    #[test]
    fn an_issuer_with_userinfo_credentials_is_rejected() {
        // A credential-bearing authority (user:pass@host) is a host-confusion vector
        // and is barred at validation time (mirrors the #13 redirect userinfo-reject).
        let json = VALID.replace(
            "https://issuer.example.com",
            "https://user:pass@issuer.example.com",
        );
        let def = parse(&json).expect("parses");
        let errors = def.validate().expect_err("issuer with userinfo");
        assert!(
            errors
                .iter()
                .any(|error| error.pointer == "/endpoints/issuer"
                    && error.message.contains("userinfo")),
            "{errors:?}"
        );
    }

    #[test]
    fn an_explicit_endpoint_with_userinfo_credentials_is_rejected() {
        let json = VALID.replace(
            "{ \"issuer\": \"https://issuer.example.com\" }",
            "{ \"authorization_endpoint\": \"https://user:pass@up.example.com/authorize\", \
               \"token_endpoint\": \"https://up.example.com/token\", \
               \"jwks_uri\": \"https://up.example.com/jwks\" }",
        );
        let def = parse(&json).expect("parses");
        let errors = def.validate().expect_err("endpoint with userinfo");
        assert!(
            errors
                .iter()
                .any(|error| error.pointer == "/endpoints/authorization_endpoint"
                    && error.message.contains("userinfo")),
            "{errors:?}"
        );
    }

    #[test]
    fn a_connector_is_enabled_by_default_and_the_flag_parses() {
        // Absent, a connector is enabled; the flag round-trips when set false.
        let def = parse(VALID).expect("parses");
        assert!(def.enabled, "a new connector defaults to enabled");
        let json = VALID.replace(
            "\"client_id\": \"ironauth-at-acme\",",
            "\"client_id\": \"ironauth-at-acme\", \"enabled\": false,",
        );
        let def = parse(&json).expect("parses");
        def.validate().expect("valid");
        assert!(!def.enabled, "the enabled flag round-trips as submitted");
    }

    #[test]
    fn the_capability_matrix_default_is_untrusted() {
        // The NAMED conservative default, checked directly on the Default impl.
        let matrix = CapabilityMatrix::default();
        assert_eq!(matrix.email_verified_trust, EmailVerifiedTrust::Untrusted);
        assert_eq!(EmailVerifiedTrust::default().as_str(), "untrusted");
        assert!(!matrix.refresh && !matrix.groups && !matrix.logout_propagation);
    }

    #[test]
    fn capabilities_parse_and_project_from_the_definition() {
        let json = VALID.replace(
            "\"client_id\": \"ironauth-at-acme\",",
            "\"client_id\": \"ironauth-at-acme\", \
             \"capabilities\": { \"refresh\": true, \"email_verified_trust\": \"trusted\" },",
        );
        let def = parse(&json).expect("parses");
        def.validate().expect("valid");
        assert!(def.capabilities().refresh);
        assert_eq!(
            def.capabilities().email_verified_trust,
            EmailVerifiedTrust::Trusted
        );
    }

    #[test]
    fn the_secret_free_projection_omits_the_client_secret() {
        // Even a LITERAL secret (which Secret redacts to "[redacted]") is removed
        // entirely from the projection, so the stored document names no secret slot.
        let json = VALID.replace(
            "{ \"env\": \"ACME_CLIENT_SECRET\" }",
            "\"super-secret-value\"",
        );
        let def = parse(&json).expect("parses");
        let projection = def.secret_free_json().expect("projection serializes");
        let object = projection.as_object().expect("object");
        assert!(
            !object.contains_key("client_secret"),
            "the projection must not carry the client_secret field: {projection}"
        );
        let rendered = projection.to_string();
        assert!(
            !rendered.contains("super-secret-value"),
            "the secret value must never appear in the projection: {rendered}"
        );
    }

    #[test]
    fn an_unknown_capability_key_is_rejected() {
        let json = VALID.replace(
            "\"client_id\": \"ironauth-at-acme\",",
            "\"client_id\": \"ironauth-at-acme\", \"capabilities\": { \"teleport\": true },",
        );
        let err = parse(&json).expect_err("unknown capability key rejected");
        assert!(
            err.to_string().contains("teleport") || err.to_string().contains("unknown field"),
            "{err}"
        );
    }

    #[test]
    fn a_bad_slug_is_rejected_with_a_pointer() {
        let json = VALID.replace("acme-oidc", "Acme OIDC!");
        let def = parse(&json).expect("parses");
        let errors = def.validate().expect_err("bad slug");
        assert!(
            errors.iter().any(|error| error.pointer == "/connector_id"),
            "{errors:?}"
        );
    }

    #[test]
    fn a_custom_subject_rule_is_rejected_but_the_default_is_accepted() {
        // The default (an absent subject rule) validates: the identity is always keyed on
        // the verified upstream `sub`, which the evaluator uses by default.
        let def = parse(VALID).expect("parses");
        def.validate().expect("the default subject is accepted");

        // An explicit-but-equivalent `{ source: ["sub"] }` is still the default and accepted.
        let json = VALID.replace(
            "\"client_id\": \"ironauth-at-acme\",",
            "\"client_id\": \"ironauth-at-acme\", \"claim_mapping\": { \
               \"subject\": { \"source\": [\"sub\"] } },",
        );
        let def = parse(&json).expect("parses");
        def.validate()
            .expect("an explicit default subject is accepted");

        // A CUSTOM subject rule (a different claim path) is rejected at validation with a
        // pointer to the subject rule, because it can only ever break a login for no benefit.
        let json = VALID.replace(
            "\"client_id\": \"ironauth-at-acme\",",
            "\"client_id\": \"ironauth-at-acme\", \"claim_mapping\": { \
               \"subject\": { \"source\": [\"oid\"] } },",
        );
        let def = parse(&json).expect("parses");
        let errors = def.validate().expect_err("custom subject rejected");
        assert!(
            errors
                .iter()
                .any(|error| error.pointer == "/claim_mapping/subject"),
            "{errors:?}"
        );
    }

    #[test]
    fn a_userinfo_requiring_connector_is_rejected_until_userinfo_lands() {
        // An id_token-only connector (the default email_source, userinfo_required false) is
        // accepted: it needs no UserInfo fetch.
        let def = parse(VALID).expect("parses");
        def.validate()
            .expect("an id_token-only connector validates");

        // `userinfo_required: true` is rejected (the UserInfo fetch is deferred to #74, so it
        // would fail every login).
        let json = VALID.replace(
            "\"client_id\": \"ironauth-at-acme\",",
            "\"client_id\": \"ironauth-at-acme\", \"quirks\": { \"userinfo_required\": true },",
        );
        let def = parse(&json).expect("parses");
        let errors = def.validate().expect_err("userinfo_required rejected");
        assert!(
            errors
                .iter()
                .any(|error| error.pointer == "/quirks/userinfo_required"),
            "{errors:?}"
        );

        // `email_source: "userinfo"` (email sourced only from UserInfo) is rejected too.
        let json = VALID.replace(
            "\"client_id\": \"ironauth-at-acme\",",
            "\"client_id\": \"ironauth-at-acme\", \"quirks\": { \"email_source\": \"userinfo\" },",
        );
        let def = parse(&json).expect("parses");
        let errors = def.validate().expect_err("userinfo email_source rejected");
        assert!(
            errors
                .iter()
                .any(|error| error.pointer == "/quirks/email_source"),
            "{errors:?}"
        );

        // `fallback_order` tries the ID token first, so it does not require UserInfo: accepted.
        let json = VALID.replace(
            "\"client_id\": \"ironauth-at-acme\",",
            "\"client_id\": \"ironauth-at-acme\", \"quirks\": { \"email_source\": \"fallback_order\" },",
        );
        let def = parse(&json).expect("parses");
        def.validate()
            .expect("a fallback_order email_source validates");
    }

    #[test]
    fn claim_mapping_shape_parses_and_round_trips() {
        let json = VALID.replace(
            "\"client_id\": \"ironauth-at-acme\",",
            "\"client_id\": \"ironauth-at-acme\", \"claim_mapping\": { \
               \"subject\": { \"source\": [\"sub\"] }, \
               \"traits\": { \"email\": { \"source\": [\"email\", \"emails.0\"], \"required\": false } } },",
        );
        let def = parse(&json).expect("parses");
        def.validate().expect("valid");
        let mapping = &def.claim_mapping;
        assert_eq!(
            mapping.subject.as_ref().expect("subject rule").source,
            vec!["sub".to_string()]
        );
        let email = mapping.traits.get("email").expect("email rule");
        assert!(!email.required);
        assert_eq!(email.source.len(), 2);
    }
}
